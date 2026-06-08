"""Tests for the static JWT inspector."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone, timedelta

from toolkit.execution.checks import jwt_inspector as jwt


def _b64(obj: dict) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_token(header: dict, payload: dict, sig_bytes: int = 32) -> str:
    sig = base64.urlsafe_b64encode(b"x" * sig_bytes).rstrip(b"=").decode()
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


def test_alg_none_is_high_severity():
    token = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "u1", "exp": 9999999999})
    rep = jwt.inspect(token)
    assert rep.valid_structure
    codes = [i.code for i in rep.issues]
    assert "alg_none" in codes
    assert any(i.severity == "high" for i in rep.issues if i.code == "alg_none")


def test_short_signature_for_hs256_flagged():
    token = _make_token({"alg": "HS256"}, {"sub": "u1", "exp": 9999999999}, sig_bytes=8)
    rep = jwt.inspect(token)
    assert "short_signature" in [i.code for i in rep.issues]


def test_missing_exp_flagged():
    token = _make_token({"alg": "HS256"}, {"sub": "u1"})
    rep = jwt.inspect(token)
    assert "missing_exp" in [i.code for i in rep.issues]


def test_long_lifetime_flagged():
    iat = int((datetime.now(timezone.utc) - timedelta(days=1)).timestamp())
    exp = iat + 60 * 60 * 24 * 90  # 90 days
    token = _make_token({"alg": "HS256"}, {"sub": "u1", "iat": iat, "exp": exp})
    rep = jwt.inspect(token)
    assert "long_lifetime" in [i.code for i in rep.issues]


def test_pii_detection_masks_values():
    payload = {"sub": "u1", "email": "victim@example.com", "phone": "21998498419", "exp": 9999999999}
    token = _make_token({"alg": "HS256"}, payload)
    rep = jwt.inspect(token)
    assert "pii_in_payload" in [i.code for i in rep.issues]
    # Masked values keep first/last 4 chars only.
    for vals in rep.pii_hits.values():
        for v in vals:
            assert "***" in v
            assert "victim@example.com" not in v


def test_invalid_token_returns_not_a_jwt():
    rep = jwt.inspect("not.a.jwt.too_many_parts")
    assert not rep.valid_structure
    assert any(i.code == "not_a_jwt" for i in rep.issues)


def test_is_jwt_helper():
    valid = _make_token({"alg": "HS256"}, {"sub": "u"})
    assert jwt.is_jwt(valid)
    assert not jwt.is_jwt("just-a-string")
    assert not jwt.is_jwt("a.b")
    assert not jwt.is_jwt("a..c")
