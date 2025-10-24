"""User interface abstractions for the CIP command line tool."""

from __future__ import annotations

from typing import Any, Protocol

import click


class UserInterface(Protocol):
    """Protocol describing the required console IO operations."""

    def prompt(self, text: str, **kwargs: Any) -> Any:
        """Prompt the user for input and return the provided value."""

    def confirm(self, text: str, **kwargs: Any) -> bool:
        """Prompt the user for confirmation and return ``True`` on acceptance."""

    def echo(self, message: str = "", *, nl: bool = True) -> None:
        """Write a message to the console using Click semantics."""

    def write(self, *args: Any, sep: str = " ", end: str = "\n") -> None:
        """Write raw output to stdout using ``print`` semantics."""


class ClickUserInterface:
    """Default :mod:`click`-backed implementation of :class:`UserInterface`."""

    def prompt(self, text: str, **kwargs: Any) -> Any:
        return click.prompt(text, **kwargs)

    def confirm(self, text: str, **kwargs: Any) -> bool:
        return click.confirm(text, **kwargs)

    def echo(self, message: str = "", *, nl: bool = True) -> None:
        click.echo(message, nl=nl)

    def write(self, *args: Any, sep: str = " ", end: str = "\n") -> None:
        print(*args, sep=sep, end=end)


__all__ = ["UserInterface", "ClickUserInterface"]
