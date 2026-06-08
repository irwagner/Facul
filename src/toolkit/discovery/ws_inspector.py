"""
WebSocket protobuf inspector.

Pure (side-effect-free) helpers for analysing WebSocket frames captured
from a target.  Two entry points:

    * :func:`decode_protobuf` — best-effort field-by-field decoder.
      Walks varints, length-delimited and fixed-width fields.  Useful
      when no ``.proto`` schema is available.
    * :func:`extract_message_catalog` — pulls protobuf message names
      from a JavaScript bundle.  Looks for both ``protobufjs`` and
      hand-rolled patterns.

Live capture is *not* part of this module.  Callers wire the async
WebSocket client themselves and feed the bytes here for analysis.  This
keeps governance gating (authorization → scope → rate limiter) at the
caller layer and the inspector trivially testable in isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Field-level decoder
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProtoField:
    field_number: int
    wire_type: int
    type_name: str  # "varint" | "fixed64" | "length" | "fixed32" | "unknown"
    value: int | bytes | str
    length: int | None = None


@dataclass(frozen=True)
class ProtoDecode:
    fields: list[ProtoField] = field(default_factory=list)
    bytes_consumed: int = 0
    error: str | None = None


_WIRE_NAMES = {0: "varint", 1: "fixed64", 2: "length", 5: "fixed32"}


def _read_varint(blob: bytes, i: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while i < len(blob):
        b = blob[i]
        value |= (b & 0x7F) << shift
        i += 1
        if not (b & 0x80):
            return value, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def decode_protobuf(blob: bytes, *, max_fields: int = 50) -> ProtoDecode:
    """Best-effort decode of a protobuf frame *blob*.

    Returns a :class:`ProtoDecode` containing every field that could be
    parsed.  When the binary is malformed the decoder stops and reports
    an ``error`` but keeps everything successfully parsed so far.
    """
    fields: list[ProtoField] = []
    i = 0
    try:
        while i < len(blob) and len(fields) < max_fields:
            tag, i = _read_varint(blob, i)
            field_num = tag >> 3
            wire_type = tag & 0x7
            type_name = _WIRE_NAMES.get(wire_type, "unknown")
            if wire_type == 0:
                value, i = _read_varint(blob, i)
                fields.append(ProtoField(field_num, wire_type, type_name, value))
            elif wire_type == 1:
                if i + 8 > len(blob):
                    raise ValueError("truncated fixed64")
                value = int.from_bytes(blob[i:i + 8], "little")
                i += 8
                fields.append(ProtoField(field_num, wire_type, type_name, value))
            elif wire_type == 2:
                length, i = _read_varint(blob, i)
                if i + length > len(blob):
                    raise ValueError("truncated length-delimited")
                payload = blob[i:i + length]
                i += length
                # Try to decode as UTF-8 string when printable
                try:
                    text = payload.decode("utf-8")
                    if text and all(c.isprintable() or c in ("\n", "\t") for c in text):
                        fields.append(ProtoField(
                            field_num, wire_type, type_name, text, length=length,
                        ))
                        continue
                except UnicodeDecodeError:
                    pass
                fields.append(ProtoField(
                    field_num, wire_type, type_name, payload, length=length,
                ))
            elif wire_type == 5:
                if i + 4 > len(blob):
                    raise ValueError("truncated fixed32")
                value = int.from_bytes(blob[i:i + 4], "little")
                i += 4
                fields.append(ProtoField(field_num, wire_type, type_name, value))
            else:
                raise ValueError(f"unknown wire_type {wire_type}")
    except (ValueError, IndexError) as exc:
        return ProtoDecode(fields=fields, bytes_consumed=i, error=str(exc))
    return ProtoDecode(fields=fields, bytes_consumed=i)


# ---------------------------------------------------------------------------
# Message catalog extraction from a JS bundle
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MessageCatalog:
    """Catalog of protobuf message names extracted from a JS bundle."""

    messages: list[str] = field(default_factory=list)
    by_suffix: dict[str, list[str]] = field(default_factory=dict)
    raw_bundle_size: int = 0


_NAME_RE = re.compile(
    r"\b([A-Z][a-zA-Z0-9_]{2,40}(?:Req|Res|Resp|Notice|Push|Event|Cmd|Msg|Message))\b"
)


def extract_message_catalog(bundle_text: str) -> MessageCatalog:
    """Pull protobuf-style message names from a JavaScript bundle."""
    found = sorted(set(_NAME_RE.findall(bundle_text)))
    by_suffix: dict[str, list[str]] = {}
    for name in found:
        for suffix in ("Req", "Resp", "Res", "Notice", "Push", "Event", "Cmd", "Msg", "Message"):
            if name.endswith(suffix):
                by_suffix.setdefault(suffix, []).append(name)
                break
    return MessageCatalog(
        messages=found,
        by_suffix=by_suffix,
        raw_bundle_size=len(bundle_text),
    )


# ---------------------------------------------------------------------------
# Frame heuristics
# ---------------------------------------------------------------------------


def looks_like_timestamp_ms(value: int) -> bool:
    """True when *value* is plausibly a Unix epoch millisecond timestamp.

    Range: 2010-01-01 to 2050-12-31 (1262304000000 .. 2556143999000).
    """
    return 1_262_304_000_000 <= value <= 2_556_143_999_000


def summarise_frame(blob: bytes) -> dict:
    """Cheap summary used in reports.  Combines decode + heuristics."""
    decode = decode_protobuf(blob)
    has_timestamp = False
    timestamp_field = None
    for f in decode.fields:
        if f.type_name == "varint" and looks_like_timestamp_ms(int(f.value)):
            has_timestamp = True
            timestamp_field = f.field_number
            break
    return {
        "size": len(blob),
        "fields_parsed": len(decode.fields),
        "decode_error": decode.error,
        "has_timestamp_ms": has_timestamp,
        "timestamp_field": timestamp_field,
        "first_3_fields": [
            {"field": f.field_number, "type": f.type_name,
             "preview": str(f.value)[:60]}
            for f in decode.fields[:3]
        ],
    }
