"""Service wrappers for loading and validating CIP configuration resources."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Mapping, Optional

from cipmaster.cip import config as cip_config


PromptFunc = Callable[..., str]
ConfirmFunc = Callable[..., bool]


@dataclass
class ConfigOptions:
    """Discovered CIP configuration files."""

    mapping: Dict[str, Path]
    names: list[str]

    @property
    def count(self) -> int:
        return len(self.names)

    @property
    def last(self) -> Optional[str]:
        return self.names[-1] if self.names else None


@dataclass
class ConfigSelectionResult:
    """Result of choosing a CIP configuration file."""

    filename: Optional[str]
    prompted: bool = False


class ConfigLoaderService:
    """Wrapper around :mod:`cipmaster.cip.config` helpers with extra utilities."""

    def get_available_config_files(self) -> Dict[str, Path]:
        return cip_config.get_available_config_files()

    def resolve_config_path(
        self,
        filename: str,
        *,
        available: Optional[Mapping[str, Path]] = None,
    ) -> Path:
        return cip_config.resolve_config_path(filename, available=available)

    def iter_config_directories(self) -> Iterable[Path]:
        return cip_config.iter_config_directories()

    def validate_cip_config(self, xml_path: str):
        return cip_config.validate_cip_config(xml_path)

    def discover_configurations(self) -> ConfigOptions:
        mapping = self.get_available_config_files()
        names = sorted(mapping)
        return ConfigOptions(mapping=mapping, names=names)

    def select_configuration(
        self,
        options: ConfigOptions,
        *,
        attempts: int,
        preselected: Optional[str] = None,
        current_selection: Optional[str] = None,
        prompt: Optional[PromptFunc] = None,
        confirm: Optional[ConfirmFunc] = None,
    ) -> ConfigSelectionResult:
        if not options.names:
            return ConfigSelectionResult(filename=None, prompted=False)

        if preselected and attempts == 0:
            return ConfigSelectionResult(filename=preselected, prompted=False)

        if options.count == 1:
            return ConfigSelectionResult(filename=options.names[0], prompted=False)

        if attempts == 0:
            if prompt is None:
                raise ValueError("A prompt callback is required to select configurations.")
            filename = prompt("CIP Configuration Filename")
            return ConfigSelectionResult(filename=filename, prompted=True)

        if confirm is not None and confirm('Do you want to change CIP Configuration?', default=True):
            if prompt is None:
                raise ValueError("A prompt callback is required to change configurations.")
            filename = prompt("CIP Configuration Filename")
            return ConfigSelectionResult(filename=filename, prompted=True)

        fallback = current_selection or preselected or options.last
        return ConfigSelectionResult(filename=fallback, prompted=False)

    def resolve_selection(self, selection: str, options: ConfigOptions) -> Path:
        return self.resolve_config_path(selection, available=options.mapping)

    def validate_selection(self, xml_path: Path):
        return self.validate_cip_config(os.fspath(xml_path))

    def __getattr__(self, item):
        return getattr(cip_config, item)


__all__ = [
    "ConfigLoaderService",
    "ConfigOptions",
    "ConfigSelectionResult",
]
