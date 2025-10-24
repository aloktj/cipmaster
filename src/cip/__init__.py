"""Compatibility package that re-exports :mod:`cipmaster.cip`."""

from __future__ import annotations

import importlib
import sys

from cipmaster.cip import config, fields, network, session, ui

for _name in ("config", "fields", "network", "session", "ui"):
    module = importlib.import_module(f"cipmaster.cip.{_name}")
    sys.modules[f"cip.{_name}"] = module

__all__ = ["config", "fields", "network", "session", "ui"]
