"""Container entrypoint for the CTF execution image.

The container needs a long-running foreground process so host-side workers can
attach with ``docker exec``.  A tiny static file server keeps the behaviour of
the old entrypoint while using standard logging and signal-aware shutdown.
"""

from __future__ import annotations

import logging
import os
import signal
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


LOGGER = logging.getLogger("ctfenv.entrypoint")
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8000


class LoggingRequestHandler(SimpleHTTPRequestHandler):
    """Route request logs through ``logging`` instead of stderr writes."""

    def log_message(self, format: str, *args: object) -> None:
        LOGGER.info(
            "http request",
            extra={
                "client": self.client_address[0],
                "request": format % args,
            },
        )


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        LOGGER.warning(
            "invalid integer environment value",
            extra={"env_name": name, "value": raw},
        )
        return default


def configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("CTFENV_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s [pid=%(process)d]: %(message)s",
    )


def main() -> int:
    configure_logging()
    host = os.getenv("CTFENV_HTTP_HOST", DEFAULT_HOST)
    port = _env_int("CTFENV_HTTP_PORT", DEFAULT_PORT)
    root = Path(os.getenv("CTFENV_HTTP_ROOT", str(Path.home()))).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    handler = partial(LoggingRequestHandler, directory=str(root))
    server = ThreadingHTTPServer((host, port), handler)

    def stop(signum: int, _frame: object) -> None:
        LOGGER.info("shutdown requested", extra={"signal": signum})
        server.shutdown()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    LOGGER.info(
        "ctf execution container ready",
        extra={"host": host, "port": port, "root": str(root)},
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
        LOGGER.info("ctf execution container stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
