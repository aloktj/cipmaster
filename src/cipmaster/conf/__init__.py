"""Packaged CIP configuration examples."""

from importlib import resources
from pathlib import Path
from typing import Iterator


def iter_example_files() -> Iterator[Path]:
    """Iterate over the packaged CIP XML example files."""

    with resources.as_file(resources.files(__name__)) as package_dir:
        for path in Path(package_dir).iterdir():
            if path.is_file() and path.suffix.lower() == ".xml":
                yield path


__all__ = ["iter_example_files"]
