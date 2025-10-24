"""Backward-compatible shim for the relocated CLI implementation."""

from cipmaster.cli.app import CIPCLI, RunConfiguration, main

__all__ = ["CIPCLI", "RunConfiguration", "main"]


if __name__ == "__main__":  # pragma: no cover - legacy entry point
    main()
