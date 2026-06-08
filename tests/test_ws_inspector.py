"""Tests for the WebSocket protobuf inspector."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from toolkit.discovery import ws_inspector as ws


# ---------------------------------------------------------------------------
# decode_protobuf
# ---------------------------------------------------------------------------


def test_decode_protobuf_varint():
    # field 1, varint, value 1780943449233
    blob = bytes.fromhex("0891d981c4ea33")
    out = ws.decode_protobuf(blob)
    assert out.error is None
    assert len(out.fields) == 1
    f = out.fields[0]
    assert f.field_number == 1
    assert f.type_name == "varint"
    assert f.value == 1780943449233


def test_decode_protobuf_string_field():
    # field 2, length-delimited (string), value "hi"
    blob = b"\x12\x02hi"
    out = ws.decode_protobuf(blob)
    assert out.error is None
    assert len(out.fields) == 1
    f = out.fields[0]
    assert f.field_number == 2
    assert f.type_name == "length"
    assert f.value == "hi"


def test_decode_protobuf_truncated_returns_partial_with_error():
    # field 1 (varint), value 1, then truncated field 2 length-delimited
    blob = b"\x08\x01\x12\x05ab"
    out = ws.decode_protobuf(blob)
    assert out.error is not None
    # First field still parsed
    assert any(f.field_number == 1 for f in out.fields)


def test_decode_protobuf_fixed32_and_fixed64():
    # field 1 fixed32 (wire 5)
    blob = b"\x0d\x01\x00\x00\x00"
    out = ws.decode_protobuf(blob)
    assert out.error is None
    assert out.fields[0].type_name == "fixed32"
    assert out.fields[0].value == 1


# ---------------------------------------------------------------------------
# Property: decode never crashes on arbitrary input
# ---------------------------------------------------------------------------

# Feature: web-security-audit-toolkit, Property 32: decode_protobuf never raises
# on arbitrary input; it returns either a clean ProtoDecode or one with error.
@given(blob=st.binary(min_size=0, max_size=200))
@settings(max_examples=200, deadline=None)
def test_decode_never_raises(blob):
    out = ws.decode_protobuf(blob)
    # Decode either succeeds or returns an error object — never raises
    assert isinstance(out, ws.ProtoDecode)
    if out.error is None:
        # When successful, bytes_consumed must not exceed input length
        assert out.bytes_consumed <= len(blob)


# ---------------------------------------------------------------------------
# extract_message_catalog
# ---------------------------------------------------------------------------


def test_extract_message_catalog_finds_protobuf_names():
    bundle = """
    var ABBetReq = ...;
    function GameStartResp() {}
    class EnterRoomReq {}
    GlobalNotice.create();
    """
    catalog = ws.extract_message_catalog(bundle)
    assert "ABBetReq" in catalog.messages
    assert "GameStartResp" in catalog.messages
    assert "EnterRoomReq" in catalog.messages
    assert "GlobalNotice" in catalog.messages
    assert "Req" in catalog.by_suffix
    assert "ABBetReq" in catalog.by_suffix["Req"]


def test_extract_message_catalog_dedupes_and_sorts():
    bundle = "ABBetReq ABBetReq ABBetReq"
    catalog = ws.extract_message_catalog(bundle)
    assert catalog.messages == ["ABBetReq"]


def test_extract_message_catalog_empty_when_no_matches():
    catalog = ws.extract_message_catalog("foo bar baz no_messages_here")
    assert catalog.messages == []
    assert catalog.by_suffix == {}


# ---------------------------------------------------------------------------
# looks_like_timestamp_ms
# ---------------------------------------------------------------------------


def test_timestamp_heuristic_recognises_recent_value():
    assert ws.looks_like_timestamp_ms(1780943449233) is True
    assert ws.looks_like_timestamp_ms(1262304000000) is True  # 2010
    assert ws.looks_like_timestamp_ms(2556143999000) is True  # 2050


def test_timestamp_heuristic_rejects_seconds_and_huge_values():
    assert ws.looks_like_timestamp_ms(1700) is False
    assert ws.looks_like_timestamp_ms(1700000000) is False  # seconds, not ms
    assert ws.looks_like_timestamp_ms(99999999999999) is False


# ---------------------------------------------------------------------------
# summarise_frame
# ---------------------------------------------------------------------------


def test_summarise_frame_detects_server_timestamp():
    blob = bytes.fromhex("0891d981c4ea33")  # field 1 varint, recent ms
    summary = ws.summarise_frame(blob)
    assert summary["has_timestamp_ms"] is True
    assert summary["timestamp_field"] == 1
    assert summary["fields_parsed"] == 1


def test_summarise_frame_handles_empty_blob():
    summary = ws.summarise_frame(b"")
    assert summary["fields_parsed"] == 0
    assert summary["has_timestamp_ms"] is False
