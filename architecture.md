# Cerberus Architecture

## 1. Design goals

Cerberus is a red-team framework written for:

1. **Evidence over assumption** — facts live in a provenance store; plugins should not re-discover blindly.
2. **Phase discipline** — ordered kill-chain; skips need explicit force.
3. **Stealth by default** — profiles (`noisy` / `balanced` / `ninja`) tune noise.
4. **Plugins as contracts** — metadata (phase, OPSEC, produces) + async `run()`.
5. **Python core + Rust implant** — operator tooling in Python; beacon in Rust.
6. **Agent-ready** — MCP server exposes the same capabilities to local/remote agents.

---

## 2. Layered structure

```
┌─────────────────────────────────────────────────────────────┐
│  Surfaces                                                    │
│  CLI (Typer+Rich)  ·  MCP (stdio)  ·  future HTTP/API        │
└────────────┬───────────────────┬────────────────────────────┘
             │                   │
┌────────────▼───────────────────▼────────────────────────────┐
│  Plugin layer (67 plugins)                                   │
│  recon · enum · c2 · creds · lateral · persist · evasion ·  │
│  ops · ai                                                    │
└────────────┬────────────────────────────────────────────────┘
             │ injects config + evidence + phase
┌────────────▼────────────────────────────────────────────────┐
│  Core kernel                                                 │
│  config · evidence · phase · plugin_api · opsec · ops        │
│  c2 · crypto                                                 │
└────────────┬────────────────────────────────────────────────┘
             │
     ┌───────┴────────┐
     │ sessions/      │  evidence JSON, notes, pivots, tasks,
     │                │  loot/, credentials.txt, world model
     └───────┬────────┘
             │
┌────────────▼────────────────────────────────────────────────┐
│  Implant (Rust)                                              │
│  AES-GCM TCP beacon · post-ex cmds · evasion primitives      │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Core kernel

| Module | Role |
|--------|------|
| `core/config.py` | Pydantic `Config` singleton fields; load/save `cerberus.json` |
| `core/evidence.py` | File-backed `EvidenceStore` with provenance + index |
| `core/phase.py` | `Phase` enum + `PhaseEngine` transition rules |
| `core/plugin_api.py` | `Plugin` ABC, `PluginMeta`, registry, `discover_plugins()` |
| `core/opsec.py` | Stealth profiles, jittered delay, UA rotation |
| `core/ops.py` | Notes, pivots, tasks, tgrep, loot, scan file index |
| `core/crypto.py` | SHA-256 key derive + AES-256-GCM seal/open |
| `core/c2.py` | Async multi-session TCP server + pending queues |

### Plugin contract

Every plugin declares:

- `name`, `description`
- `phase: list[Phase]` — where it is legal
- `opsec: OpsecLevel` — safe → dangerous
- `requires` / `produces` — config keys and evidence kinds
- `async run(**kwargs) -> {success, message, ...}`

Discovery walks `cerberus/plugins/**` and runs `@register_plugin`.

### Evidence model

```
EvidenceItem
  id, kind, target, data{}
  provenance: source, plugin, timestamp, confidence, notes
  tags[]
```

Kinds in use: `host`, `port`, `service`, `credential`, `dir`, `c2`, `persistence`, `opsec`, …

Layout under `sessions/`:

- `evidence/<uuid>.json`
- `index.json` — kind:target → ids
- `world_model.json` — aggregated sitrep
- `notes.jsonl`, `pivots.jsonl`, `tasks.json`, `credentials.txt`
- `loot/<beacon_id>/` — exfil from implants

### Phase machine

Order: `recon → enum → exploit → privesc → lateral → exfil → report`

- Next phase: allowed  
- Skip / backward: blocked unless `force=True`  
- Progress exposed via `engine.progress()` and CLI `phase`

---

## 4. Control surfaces

### CLI (`cli/main.py`)

- **Config:** `wizard`, `set`, `show`, `phase`
- **Execution:** `plugins`, `run <name> [flags]`
- **Awareness:** `sitrep`, `evidence`, `ctx`
- **Workflow aliases:** `note`, `loot`, `pivot`, `tasks`, `scans`, `tgrep`, `engage`, `surface`, `payload`, `revshell`

`run` builds kwargs from flags (`--target`, `--beacon`, `--cmd`, `--user`, …) and instantiates the plugin with `(config, evidence, phase)`.

### MCP (`mcp/server.py`)

Stdio MCP server; tools mirror core ops:

- sitrep, config get/set, list/run plugins  
- evidence query, phase  
- C2 beacons/shell  
- Ollama ask, recommend_next  

Same runtime path as CLI → plugins → evidence.

---

## 5. C2 architecture

```
Operator ──CLI/MCP──► c2_* plugins ──► C2Server (in-process)
                                              │
                              AES-GCM length-prefixed JSON
                                              │
                                         Rust implant(s)
```

- **Multi-session:** `beacons: dict[id, Beacon]`
- **Active focus:** `active_id` for default target of shell/post-ex
- **Delivery:** live writer if connected, else `pending` queue until next check-in
- **Wire:** `4-byte BE length || (nonce+AES-GCM(JSON) | clear JSON)`
- **Key:** `SHA-256(c2_key)` both sides (`CERBERUS_KEY` on implant)

Implant command types: `checkin`, `shell`, `ls`, `cat`, `ps`, `env`, `pwd`, `write`, `download`/`upload`, `sleep`, `masq`, `selfdelete`, `evade`, `exit`.

---

## 6. Plugin taxonomy

| Package | Responsibility |
|---------|----------------|
| `plugins/recon` | Reachability, nmap, DNS, whois |
| `plugins/enum` | Web dir brute, HTTP probe, SSH/SMB |
| `plugins/c2` | Listener lifecycle + post-ex tasking |
| `plugins/creds` | Harvest, secretsdump, spray, show |
| `plugins/lateral` | SSH/psexec/WMI/WinRM/SCP |
| `plugins/persist` | Cron, systemd, bashrc, SSH keys |
| `plugins/evasion` | Profile, jitter, masq, timestomp, encode |
| `plugins/ops` | `cerb_*` workflow (note/pivot/tasks/…) |
| `plugins/ai` | auto_loop, Ollama, recommend_next |

---

## 7. Data / control flow (typical engagement)

```
wizard / set rhost
    → config
run ping → evidence(host)
run nmap_basic → evidence(port, service)
run recommend_next → suggestions from evidence + phase
run gobuster_dir / http_probe → evidence(dir, service)
run c2_start → C2Server listening
implant check-in → Beacon session
c2_shell / c2_ls / cred_harvest_linux → results + loot/
persist_* / lateral_* → evidence(persistence, host)
note / pivot / tasks / loot → sessions/*.jsonl
sitrep / ctx / surface → operator picture
```

---

## 8. Strengths

- Clear separation: **kernel vs plugins vs surfaces**
- Evidence + provenance is first-class
- Phase + OPSEC metadata ready for policy gates
- C2 multi-session + crypto without a separate daemon process
- MCP path reuses the same plugin runtime (no dual implementation)
- Rust implant is small, rebuildable, env-configured

## 9. Gaps / evolution points

| Area | Current state | Natural next step |
|------|---------------|-------------------|
| Phase enforcement | Metadata only; `run` does not block by phase | Gate `run` on `meta.phase` vs engine |
| OPSEC policy | `allow_opsec()` exists; not wired into `run` | Block `dangerous` under `ninja` |
| C2 process model | In-process with CLI | Optional long-lived C2 daemon + client attach |
| Transport | Raw TCP | HTTP/S or DNS beacon profile |
| World model | Basic sitrep aggregate | Richer host graph, service→plugin triggers |
| Tests | `tests/` placeholder | Contract tests per plugin |
| Persistence of C2 | Lost on CLI exit | Background service or separate `cerberus-c2` binary |

---

## 10. Dependency profile

**Required:** pydantic, rich, typer, httpx, aiofiles, orjson, cryptography (C2 crypto)

**Optional:** mcp, ollama (agent + local LLM)

**External tools (best-effort):** nmap, gobuster, curl, dig, whois, smbclient, impacket, netexec, evil-winrm, ssh/sshpass

**Implant:** Rust 2021, aes-gcm, serde, sha2, …

---

## 11. Mental model

Cerberus is not a monolithic shell of scripts. It is a **small kernel** (config, evidence, phase, C2) plus a **plugin marketplace** with strict metadata, operated through **CLI or MCP**, with a **Rust beacon** for post-exploitation. LazyOwn’s operator habits (ctx, note, loot, pivot, tasks, engage) are preserved as Cerberus-named surfaces on top of that kernel.
