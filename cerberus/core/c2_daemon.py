"""Long-lived Cerberus C2 daemon (data plane + control plane).

Usage:
  PYTHONPATH=. python -m cerberus.core.c2_daemon
  # or: cerberus c2-daemon
"""

from __future__ import annotations

import argparse
import asyncio
import signal
from pathlib import Path

from cerberus.core.c2 import C2Server, set_c2
from cerberus.core.c2_control import ControlPlane
from cerberus.core.config import load_config


async def run_daemon(
    c2_host: str = "0.0.0.0",
    c2_port: int = 8443,
    ctrl_host: str = "127.0.0.1",
    ctrl_port: int = 8444,
    secret: str | None = None,
    loot: Path | None = None,
) -> None:
    cfg = load_config()
    secret = secret if secret is not None else getattr(cfg, "c2_key", None)
    if secret == "":
        secret = None
    loot = loot or (cfg.sessions_dir / "loot")
    c2 = C2Server(host=c2_host, port=c2_port, loot_dir=loot, secret=secret)
    await c2.start()
    set_c2(c2)
    ctrl = ControlPlane(c2, host=ctrl_host, port=ctrl_port)
    await ctrl.start()
    print(
        f"[cerberus-c2] data={c2_host}:{c2_port} encrypted={bool(secret)} "
        f"control={ctrl_host}:{ctrl_port}",
        flush=True,
    )

    stop = asyncio.Event()

    def _stop(*_args):
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except NotImplementedError:
            pass

    await stop.wait()
    print("[cerberus-c2] shutting down…", flush=True)
    await ctrl.stop()
    await c2.stop()
    set_c2(None)


def main() -> None:
    cfg = load_config()
    p = argparse.ArgumentParser(description="Cerberus C2 daemon")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=cfg.c2_port)
    p.add_argument("--ctrl-host", default="127.0.0.1")
    p.add_argument("--ctrl-port", type=int, default=8444)
    p.add_argument("--key", default=None, help="Override c2_key (empty string = cleartext)")
    args = p.parse_args()
    asyncio.run(
        run_daemon(
            c2_host=args.host,
            c2_port=args.port,
            ctrl_host=args.ctrl_host,
            ctrl_port=args.ctrl_port,
            secret=args.key,
        )
    )


if __name__ == "__main__":
    main()
