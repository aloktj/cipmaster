"""Service wrappers for loading and validating CIP configuration resources."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional

from cipmaster.cip import config as cip_config


class ConfigLoaderService:
    """Wrapper around :mod:`cipmaster.cip.config` helpers."""

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

    def __getattr__(self, item):
        return getattr(cip_config, item)


__all__ = ["ConfigLoaderService"]
