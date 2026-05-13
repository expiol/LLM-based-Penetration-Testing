"""Module entrypoint for `python -m killchain_docker`."""

from __future__ import annotations

from killchain_docker.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
