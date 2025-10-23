"""Field encoding and decoding helpers for CIP packets."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Type

from scapy import all as scapy_all

Metadata = Dict[str, Any]
ValidationInfo = Dict[str, Any]


@dataclass(frozen=True)
class FieldCodec:
    """Container describing how to encode, decode and validate a field."""

    name: str
    encode_func: Any
    decode_func: Any
    validation_provider: Any


def _coerce_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value.strip())
    raise ValueError("value is not a floating point number")


def _coerce_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        raise ValueError("value must be an integer without fractional component")
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            raise ValueError("value cannot be empty")
        base = 10
        if stripped.lower().startswith("0x"):
            base = 16
            stripped = stripped[2:]
        return int(stripped, base)
    raise ValueError("value must be an integer")


def _build_error(
    field_name: Optional[str],
    base_message: str,
    validation: ValidationInfo,
    metadata: Optional[Metadata],
) -> str:
    detail_items = []
    value_range: Optional[Tuple[Any, Any]] = validation.get("range")
    if value_range:
        detail_items.append(f"allowed range {value_range[0]}–{value_range[1]}")

    allowed_values = validation.get("allowed_values")
    if allowed_values:
        allowed = ", ".join(str(item) for item in allowed_values)
        detail_items.append(f"allowed values {allowed}")

    max_length = validation.get("max_length")
    if max_length is None and metadata and metadata.get("type") == "string":
        max_length = metadata.get("length")
    if max_length:
        unit = validation.get("length_unit", "bytes")
        detail_items.append(f"max length {max_length} {unit}")

    fmt = validation.get("format")
    if fmt:
        detail_items.append(f"format {fmt}")

    if metadata:
        field_type = metadata.get("type")
        if field_type:
            detail_items.append(f"type {field_type}")
        offset = metadata.get("offset")
        if offset is not None:
            detail_items.append(f"offset {offset}")

    detail_text = "; ".join(detail_items)
    message = base_message
    if detail_text:
        message = f"{message} ({detail_text})"

    if field_name:
        message = f"Field {field_name} {message}"

    return f"{message}."


def _validation_float(metadata: Optional[Metadata], packet: Optional[scapy_all.Packet], field: scapy_all.Field) -> ValidationInfo:
    return {"format": "floating point number"}


def _encode_float(
    value: Any,
    field_name: Optional[str],
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> float:
    validation = _validation_float(metadata, packet, field)
    try:
        numeric = _coerce_float(value)
    except (TypeError, ValueError):
        raise ValueError(_build_error(field_name, "expects a floating point value", validation, metadata)) from None

    byte_array = struct.pack("f", numeric)
    reversed_byte_array = byte_array[::-1]
    return struct.unpack("f", reversed_byte_array)[0]


def _decode_float(
    value: Any,
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> Any:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return value

    byte_array = struct.pack("f", numeric)
    reversed_byte_array = byte_array[::-1]
    return struct.unpack("f", reversed_byte_array)[0]


def _validation_byte(metadata: Optional[Metadata], packet: Optional[scapy_all.Packet], field: scapy_all.Field) -> ValidationInfo:
    return {"range": (0, 0xFF), "format": "decimal or hex (0x00-0xFF)"}


def _encode_byte(
    value: Any,
    field_name: Optional[str],
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> int:
    validation = _validation_byte(metadata, packet, field)
    try:
        numeric = _coerce_int(value)
    except ValueError:
        raise ValueError(_build_error(field_name, "expects an integer value", validation, metadata)) from None

    if not (0 <= numeric <= 0xFF):
        raise ValueError(_build_error(field_name, "expects a value within range", validation, metadata))

    return int(numeric)


def _decode_byte(
    value: Any,
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> Any:
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _validation_short(metadata: Optional[Metadata], packet: Optional[scapy_all.Packet], field: scapy_all.Field) -> ValidationInfo:
    return {"range": (0, 0xFFFF), "format": "decimal or hex (0x0000-0xFFFF)"}


def _encode_short(
    value: Any,
    field_name: Optional[str],
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> int:
    validation = _validation_short(metadata, packet, field)
    try:
        numeric = _coerce_int(value)
    except ValueError:
        raise ValueError(_build_error(field_name, "expects an integer value", validation, metadata)) from None

    if not (0 <= numeric <= 0xFFFF):
        raise ValueError(_build_error(field_name, "expects a value within range", validation, metadata))

    try:
        byte_array = int(numeric).to_bytes(2, byteorder="big", signed=False)
    except OverflowError:
        raise ValueError(_build_error(field_name, "expects a 16-bit value", validation, metadata)) from None

    reversed_byte_array = byte_array[::-1]
    return int.from_bytes(reversed_byte_array, byteorder="big", signed=False)


def _decode_short(
    value: Any,
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> Any:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return value

    try:
        byte_array = int(numeric).to_bytes(2, byteorder="big", signed=False)
    except OverflowError:
        return numeric

    reversed_byte_array = byte_array[::-1]
    return int.from_bytes(reversed_byte_array, byteorder="big", signed=False)


def _validation_bool(metadata: Optional[Metadata], packet: Optional[scapy_all.Packet], field: scapy_all.Field) -> ValidationInfo:
    return {"allowed_values": ["0", "1", "true", "false"]}


def _encode_bool(
    value: Any,
    field_name: Optional[str],
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> int:
    validation = _validation_bool(metadata, packet, field)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true"}:
            return 1
        if lowered in {"0", "false"}:
            return 0
    elif isinstance(value, bool):
        return int(value)
    elif isinstance(value, (int, float)):
        if value in {0, 1}:
            return int(value)

    raise ValueError(_build_error(field_name, "expects a boolean value", validation, metadata))


def _decode_bool(
    value: Any,
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> Any:
    try:
        return 1 if bool(int(value)) else 0
    except (TypeError, ValueError):
        return 1 if bool(value) else 0


def _validation_string(metadata: Optional[Metadata], packet: Optional[scapy_all.Packet], field: scapy_all.Field) -> ValidationInfo:
    max_length: Optional[int] = None
    if metadata and metadata.get("length"):
        max_length = int(metadata["length"])
    elif hasattr(field, "length_from"):
        try:
            max_length = int(field.length_from(packet))  # type: ignore[arg-type]
        except Exception:
            max_length = None
    return {"max_length": max_length, "length_unit": "bytes", "format": "UTF-8 text"}


def _encode_string(
    value: Any,
    field_name: Optional[str],
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> bytes:
    validation = _validation_string(metadata, packet, field)
    if isinstance(value, bytes):
        encoded = value
    elif isinstance(value, str):
        encoded = value.encode("utf-8")
    else:
        raise ValueError(_build_error(field_name, "expects text or bytes", validation, metadata))

    max_length = validation.get("max_length")
    if max_length is not None and len(encoded) > max_length:
        raise ValueError(
            _build_error(
                field_name,
                f"expects at most {max_length} bytes",
                validation,
                metadata,
            )
        )

    return encoded


def _decode_string(
    value: Any,
    metadata: Optional[Metadata],
    packet: Optional[scapy_all.Packet],
    field: scapy_all.Field,
) -> Any:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return value
    return value


_CODEC_MAP: Tuple[Tuple[Type[scapy_all.Field], FieldCodec], ...] = (
    (
        scapy_all.IEEEFloatField,
        FieldCodec(
            name="float",
            encode_func=_encode_float,
            decode_func=_decode_float,
            validation_provider=_validation_float,
        ),
    ),
    (
        scapy_all.BitField,
        FieldCodec(
            name="bool",
            encode_func=_encode_bool,
            decode_func=_decode_bool,
            validation_provider=_validation_bool,
        ),
    ),
    (
        scapy_all.ByteField,
        FieldCodec(
            name="byte",
            encode_func=_encode_byte,
            decode_func=_decode_byte,
            validation_provider=_validation_byte,
        ),
    ),
    (
        scapy_all.ShortField,
        FieldCodec(
            name="short",
            encode_func=_encode_short,
            decode_func=_decode_short,
            validation_provider=_validation_short,
        ),
    ),
    (
        scapy_all.StrFixedLenField,
        FieldCodec(
            name="string",
            encode_func=_encode_string,
            decode_func=_decode_string,
            validation_provider=_validation_string,
        ),
    ),
)


def get_field_codec(field: scapy_all.Field) -> Optional[FieldCodec]:
    for field_type, codec in _CODEC_MAP:
        if isinstance(field, field_type):
            if field_type is scapy_all.BitField and getattr(field, "size", None) != 1:
                continue
            return codec
    return None


def encode_field_value(
    field: scapy_all.Field,
    value: Any,
    *,
    field_name: Optional[str] = None,
    packet: Optional[scapy_all.Packet] = None,
    metadata: Optional[Metadata] = None,
) -> Any:
    codec = get_field_codec(field)
    if codec is None:
        return value
    return codec.encode_func(value, field_name, metadata, packet, field)


def decode_field_value(
    field: scapy_all.Field,
    value: Any,
    *,
    packet: Optional[scapy_all.Packet] = None,
    metadata: Optional[Metadata] = None,
) -> Any:
    codec = get_field_codec(field)
    if codec is None:
        return value
    return codec.decode_func(value, metadata, packet, field)


def describe_validation(
    field: scapy_all.Field,
    *,
    packet: Optional[scapy_all.Packet] = None,
    metadata: Optional[Metadata] = None,
) -> ValidationInfo:
    codec = get_field_codec(field)
    if codec is None:
        base: ValidationInfo = {}
    else:
        base = codec.validation_provider(metadata, packet, field)

    if metadata:
        base = {**base, **{k: v for k, v in metadata.items() if v is not None}}

    return base


def get_field_metadata(packet: scapy_all.Packet, field_name: str) -> Optional[Metadata]:
    signal_info = getattr(packet.__class__, "signal_info", {})
    if isinstance(signal_info, dict):
        return signal_info.get(field_name)
    return None


__all__ = [
    "FieldCodec",
    "Metadata",
    "ValidationInfo",
    "describe_validation",
    "decode_field_value",
    "encode_field_value",
    "get_field_codec",
    "get_field_metadata",
]
