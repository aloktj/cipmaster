"""Presentation helpers used by :mod:`cipmaster.cli.app`."""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional

import pyfiglet
from tabulate import tabulate
from termcolor import colored


@dataclass
class BannerSections:
    """Structured representation of the CLI banner content."""

    heading: str
    footer_lines: list[str]


class CLIUIHelpers:
    """Utility helpers for rendering CLI feedback and banners."""

    def __init__(self, *, stream=None) -> None:
        self._stream = stream or sys.stdout

    def spinning_cursor(self, *, sequence: Iterable[str] | None = None) -> Iterator[str]:
        """Yield characters used to render a spinner animation."""

        tokens = sequence or "|/-\\"
        while True:
            for cursor in tokens:
                yield cursor

    def loading_message(
        self,
        message: str,
        duration: float,
        *,
        spinner: Optional[Iterator[str]] = None,
        now: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Render a loading message with a spinner for ``duration`` seconds."""

        spinner = spinner or self.spinning_cursor()
        current_time = now or time.time
        sleeper = sleep or time.sleep

        stream = self._stream
        stream.write(message)
        stream.flush()

        start_time = current_time()
        while current_time() - start_time < duration:
            stream.write(next(spinner))
            stream.flush()
            sleeper(0.1)
            stream.write("\b")
        stream.write("\r")
        stream.write(" " * len(message))
        stream.write("\r")
        stream.flush()

    def progress_bar(
        self,
        message: str,
        duration: float,
        *,
        width: int = 75,
        echo: Optional[Callable[[str], None]] = None,
        now: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        """Display a simple textual progress bar for ``duration`` seconds."""

        echo = echo or (lambda text: None)
        current_time = now or time.time
        sleeper = sleep or time.sleep

        echo("\n")
        start_time = current_time()
        stream = self._stream

        def _render(elapsed: float) -> None:
            progress = min(int((elapsed / duration) * width) if duration > 0 else width, width)
            remaining = width - progress
            bar = f"[{('=' * progress) + (' ' * remaining)}]"
            stream.write("\r")
            stream.write(f"{message} {bar} {elapsed:.1f}s/{duration:.1f}s")
            stream.flush()

        _render(0.0)
        while duration > 0 and current_time() - start_time < duration:
            sleeper(0.1)
            elapsed_time = current_time() - start_time
            _render(elapsed_time)
        _render(duration)
        stream.write("\n")
        stream.flush()
        echo("\n")

    def render_banner(self, table_width: int = 75) -> BannerSections:
        """Return the banner text to display to the user."""

        banner_text = pyfiglet.figlet_format("\t\t\t\t\t CIP Tool \t\t\t\t\t", font="slant")
        colored_banner = colored(banner_text, color="green")
        heading = tabulate([[colored_banner]], tablefmt="plain")
        footer_lines = [
            "=" * 100,
            ("Welcome to CIP Tool").center(table_width),
            ("Version: 3.0").center(table_width),
            ("Author: Alok T J").center(table_width),
            ("Copyright (c) 2024 Wabtec (based on plc.py)").center(table_width),
            "=" * 100,
        ]
        return BannerSections(heading=heading, footer_lines=footer_lines)

    def display_banner(self, echo: Callable[[str], None], write: Callable[..., None], *, table_width: int = 75) -> None:
        """Display the CLI banner using the provided IO callbacks."""

        sections = self.render_banner(table_width=table_width)
        echo("\n\n")
        echo(sections.heading)
        for line in sections.footer_lines:
            write(*line, sep="")


__all__ = ["CLIUIHelpers", "BannerSections"]
