"""Compatibility package that exposes vendored third-party modules."""

from __future__ import annotations

import importlib
import sys

from cipmaster.thirdparty import scapy_cip_enip

sys.modules.setdefault("thirdparty.scapy_cip_enip", scapy_cip_enip)

for _submodule in ("tgv2020", "utils"):
    module = importlib.import_module(f"cipmaster.thirdparty.scapy_cip_enip.{_submodule}")
    sys.modules[f"thirdparty.scapy_cip_enip.{_submodule}"] = module

__all__ = ["scapy_cip_enip"]
