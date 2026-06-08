"""Tests for WAF / CDN fingerprinting."""

from __future__ import annotations

from toolkit.discovery import waf_fingerprint as wf


def test_cloudflare_via_cf_ray_and_cookie():
    fp = wf.fingerprint(
        headers={"cf-ray": "abc-XX1", "server": "cloudflare"},
        cookies=["__cf_bm"],
    )
    assert "cloudflare" in fp.detected
    assert fp.is_protected
    assert fp.confidence in {"medium", "high"}


def test_cloudfront_via_amz_headers():
    fp = wf.fingerprint(
        headers={"via": "1.1 d123.cloudfront.net (CloudFront)", "X-Amz-Cf-Id": "abc"},
    )
    assert "cloudfront" in fp.detected


def test_unknown_when_no_signals():
    fp = wf.fingerprint(headers={"content-type": "text/html"})
    assert fp.detected == []
    assert not fp.is_protected


def test_multiple_vendors_ordered_by_match_count():
    fp = wf.fingerprint(
        headers={
            "cf-ray": "abc",
            "cf-cache-status": "HIT",
            "server": "cloudflare",
            "X-Amz-Cf-Id": "x",
        },
    )
    assert fp.detected[0] == "cloudflare"
    assert "cloudfront" in fp.detected
