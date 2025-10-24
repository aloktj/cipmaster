"""Utilities for parsing and validating CIP XML configuration files."""

from __future__ import annotations

import operator
import os
import xml.etree.ElementTree as ET
from contextlib import ExitStack
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Tuple, Type

from scapy import all as scapy_all


@dataclass
class PacketClassInfo:
    """Container describing a dynamically created packet class."""

    packet_class: Type[scapy_all.Packet]
    assembly: ET.Element
    assembly_size: int


@dataclass
class CIPValidationResult:
    """Summary of CIP configuration validation."""

    results: List[List[str]]
    overall_status: bool
    root: Optional[ET.Element] = None
    ot_info: Optional[PacketClassInfo] = None
    to_info: Optional[PacketClassInfo] = None


class ConfigNotFoundError(FileNotFoundError):
    """Raised when no CIP configuration directory can be located."""


def iter_config_directories() -> Iterable[Path]:
    """Yield candidate directories that may contain CIP XML definitions.

    The search order is:

    1. Installed package resources under the ``conf`` package when the
       project has been installed via ``pip install``.
    2. The ``conf`` directory that ships with the source checkout. This keeps
       development and editable installations working without extra steps.
    """

    with ExitStack() as stack:
        package_candidates = ["cipmaster.conf", "conf"]
        for package in package_candidates:
            try:
                package_files = resources.files(package)
            except ModuleNotFoundError:
                continue
            package_path = stack.enter_context(resources.as_file(package_files))
            yield Path(package_path)
            break

        repo_path = Path(__file__).resolve().parent.parent / "conf"
        if repo_path.exists():
            yield repo_path


def get_available_config_files() -> Dict[str, Path]:
    """Return a mapping of available CIP configuration file names to paths."""

    available: Dict[str, Path] = {}
    for directory in iter_config_directories():
        if not directory.exists():
            continue
        for file in directory.iterdir():
            if file.is_file() and file.suffix.lower() == ".xml":
                available.setdefault(file.name, file)
    return available


def resolve_config_path(
    filename: str,
    *,
    available: Optional[Mapping[str, Path]] = None,
) -> Path:
    """Return the absolute path to a configuration file.

    Parameters
    ----------
    filename:
        The configuration file name selected by the user.
    available:
        Optional pre-computed mapping produced by
        :func:`get_available_config_files`. Supplying this avoids repeating the
        directory scan when the caller already has the data.

    Raises
    ------
    ConfigNotFoundError
        If the requested configuration file cannot be located.
    """

    files = available or get_available_config_files()
    try:
        return files[filename]
    except KeyError as exc:
        raise ConfigNotFoundError(f"CIP configuration '{filename}' not found") from exc


def create_packet_dict(fields_dict: List[Dict[str, int]], assembly_size: int) -> Dict[int, List[Dict[str, int]]]:
    """Replicate the packet dictionary construction from the legacy CLI implementation."""

    max_packet_size_bits = assembly_size
    pack_bools: Dict[int, List[Dict[str, int]]] = {}
    signals: Dict[int, List[Dict[str, int]]] = {}

    cip_data_type_size = {
        "usint": 1,
        "uint": 2,
        "udint": 4,
        "real": 4,
        "string": 1,
        "sint": 1,
        "int": 2,
        "dint": 4,
        "lreal": 8,
        "lint": 8,
    }

    fields_dict.sort(key=operator.itemgetter("offset"))

    sorted_dict: Dict[str, Dict[str, int]] = {}
    for item in fields_dict:
        sorted_dict[item["id"]] = {
            "offset": item["offset"],
            "type": item["type"],
            "length": item["length"],
        }

    for field_id, field_info in sorted_dict.items():
        offset = field_info["offset"]
        field_type = field_info["type"]
        byte_index = offset // 8

        if byte_index not in signals:
            signals[byte_index] = []

        if field_type == "bool":
            signals[byte_index].append({"id": field_id, "offset": offset, "type": "bool", "length": 1})

    len_counter = 0
    temp_pad_index = 0
    temp_pad_len = 0
    for byte_index in range(max_packet_size_bits // 8):
        if len_counter != 0:
            len_counter -= 1
            continue

        pack = signals.get(byte_index, [])
        if not pack:
            signals[byte_index] = []
            field_data = None
            for field_id, field_info in sorted_dict.items():
                if field_info["offset"] == byte_index * 8 and field_info["type"] != "bool":
                    field_data = (field_id, field_info["type"], field_info["length"])
                    break

            if field_data:
                if temp_pad_len > 0:
                    signals[temp_pad_index].append(
                        {
                            "id": f"spare_byte_{temp_pad_index}",
                            "offset": temp_pad_index * 8,
                            "type": "string",
                            "length": temp_pad_len,
                        }
                    )
                    temp_pad_len = 0
                    temp_pad_index = 0

                field_name, field_type, field_length = field_data
                signals[byte_index].append(
                    {
                        "id": field_name,
                        "offset": byte_index * 8,
                        "type": field_type,
                        "length": field_length,
                    }
                )
                len_counter_field_size = cip_data_type_size.get(field_type, 1)
                len_counter = field_length * len_counter_field_size - 1
            else:
                len_counter = 0
                if temp_pad_len == 0:
                    temp_pad_index = byte_index
                temp_pad_len += 1
        else:
            if temp_pad_len > 0:
                signals[temp_pad_index].append(
                    {
                        "id": f"spare_byte_{temp_pad_index}",
                        "offset": temp_pad_index * 8,
                        "type": "string",
                        "length": temp_pad_len,
                    }
                )
                temp_pad_len = 0
                temp_pad_index = 0

            occupied_offsets = {signal["offset"] % 8 for signal in pack}
            for bit_index in range(8):
                if bit_index not in occupied_offsets:
                    bit_offset = byte_index * 8 + bit_index
                    signals[byte_index].append(
                        {
                            "id": f"spare_bit_{byte_index}_{bit_index}",
                            "offset": bit_offset,
                            "type": "bool",
                            "length": 1,
                        }
                    )
            signals[byte_index].sort(key=lambda x: x["offset"])

    if temp_pad_len > 0:
        signals[temp_pad_index].append(
            {
                "id": f"spare_byte_{temp_pad_index}",
                "offset": temp_pad_index * 8,
                "type": "string",
                "length": temp_pad_len,
            }
        )

    return signals


def sorted_fields(packet: Dict[int, List[Dict[str, int]]]) -> List[Dict[str, int]]:
    """Flatten the packet dictionary into a sorted list of field definitions."""

    fields: List[Dict[str, int]] = []
    for signals in packet.values():
        for signal in signals:
            fields.append(
                {
                    "id": signal["id"],
                    "offset": signal["offset"],
                    "type": signal["type"],
                    "length": signal["length"],
                }
            )
    return sorted(fields, key=lambda item: item["offset"])


def create_packet_class(assembly_element: ET.Element) -> Tuple[Optional[Type[scapy_all.Packet]], int]:
    """Create a Scapy packet class from an assembly element."""

    subtype = assembly_element.attrib.get("subtype")
    if subtype not in {"OT_EO", "TO"}:
        return None, 0

    assembly_size = int(assembly_element.attrib.get("size", 0))
    class_name = assembly_element.attrib.get("id", f"Assembly_{subtype}")

    fields_dict: List[Dict[str, int]] = []
    for field in assembly_element.findall(".//"):
        field_len = int(field.attrib.get("length", 1))
        fields_dict.append(
            {
                "id": field.attrib.get("id", field.tag),
                "offset": int(field.attrib.get("offset", 0)),
                "type": field.tag,
                "length": field_len,
            }
        )

    byte_packet_field = create_packet_dict(fields_dict, assembly_size)
    sorted_field = sorted_fields(byte_packet_field)
    field_desc = []
    signal_info: Dict[str, Dict[str, int]] = {}

    for field in sorted_field:
        field_id = field["id"]
        field_type = field["type"]
        field_length = field["length"]
        signal_info[field_id] = {
            "type": field_type,
            "length": field_length,
            "offset": field["offset"],
        }

        if field_type == "usint":
            field_desc.append(scapy_all.ByteField(field_id, 0))
        elif field_type == "bool":
            field_desc.append(scapy_all.BitField(field_id, 0, 1))
        elif field_type == "real":
            field_desc.append(scapy_all.IEEEFloatField(field_id, 0))
        elif field_type == "string":
            field_desc.append(scapy_all.StrFixedLenField(field_id, b"", int(field_length)))
        elif field_type == "udint":
            field_desc.append(scapy_all.LEIntField(field_id, 0))
        elif field_type == "uint":
            field_desc.append(scapy_all.ShortField(field_id, 0))
        elif field_type == "sint":
            field_desc.append(scapy_all.SignedByteField(field_id, 0))

    dynamic_packet_class = type(
        class_name,
        (scapy_all.Packet,),
        {"name": class_name, "fields_desc": field_desc, "signal_info": signal_info},
    )
    return dynamic_packet_class, assembly_size


def _validate_assembly(root: ET.Element, subtype: str) -> Optional[PacketClassInfo]:
    assemblies = [assembly for assembly in root.findall("./assembly") if assembly.get("subtype") == subtype and list(assembly)]
    if len(assemblies) != 1:
        return None

    packet_class, assembly_size = create_packet_class(assemblies[0])
    if packet_class is None:
        return None

    return PacketClassInfo(packet_class=packet_class, assembly=assemblies[0], assembly_size=assembly_size)


def validate_cip_config(xml_filepath: str) -> CIPValidationResult:
    """Validate a CIP XML configuration file."""

    results: List[List[str]] = []
    directory = os.path.dirname(xml_filepath) or "."
    has_xml = False
    if os.path.isdir(directory):
        has_xml = any(filename.lower().endswith(".xml") for filename in os.listdir(directory))
    results.append(["Detect XML in Config Folder", "OK" if has_xml else "FAILED"])

    file_exists = os.path.exists(xml_filepath)
    results.append(["CIP Conf File Exists", "OK" if file_exists else "FAILED"])

    is_xml = xml_filepath.lower().endswith(".xml")
    results.append(["File is XML", "OK" if is_xml else "FAILED"])

    root: Optional[ET.Element] = None
    parse_status: str
    if file_exists and is_xml:
        try:
            tree = ET.parse(xml_filepath)
            root = tree.getroot()
            parse_status = "OK"
        except ET.ParseError as exc:
            parse_status = f"FAILED: {exc}"
    else:
        parse_status = "SKIPPED"
    results.append(["Parse XML", parse_status])

    ot_info: Optional[PacketClassInfo] = None
    to_info: Optional[PacketClassInfo] = None
    if parse_status == "OK" and root is not None:
        ot_info = _validate_assembly(root, "OT_EO")
        results.append(["One Assembly with Subtype 'OT_EO'", "OK" if ot_info else "FAILED"])

        to_info = _validate_assembly(root, "TO")
        results.append(["One Assembly with Subtype 'TO'", "OK" if to_info else "FAILED"])
    else:
        results.append(["One Assembly with Subtype 'OT_EO'", "SKIPPED"])
        results.append(["One Assembly with Subtype 'TO'", "SKIPPED"])

    overall_status = all(status == "OK" for _, status in results if status in {"OK", "FAILED"})
    results.append(["Overall Status", "OK" if overall_status else "FAILED"])

    return CIPValidationResult(
        results=results,
        overall_status=overall_status,
        root=root,
        ot_info=ot_info,
        to_info=to_info,
    )


__all__ = [
    "PacketClassInfo",
    "CIPValidationResult",
    "create_packet_class",
    "create_packet_dict",
    "sorted_fields",
    "validate_cip_config",
]
