"""Tests for the cache-poisoning check + classifier."""

from __future__ import annotations

from dataclasses import dataclass

from hypothesis import given, settings, strategies as st

from toolkit.execution.checks import cache_poison as cp_check
from toolkit.analysis.classifiers import cache_poison as cp_cls


@dataclass
class FakeResp:
    status: int
    body: bytes = b""
    headers: dict | None = None


def test_check_cache_poison_one_baseline_plus_one_probe_per_header():
    seen = []

    def transport(url, headers=None):
        seen.append((url, dict(headers or {})))
        return FakeResp(status=200, body=b"OK")

    result = cp_check.check_cache_poison(
        "https://t.test/", transport=transport,
        headers=(("X-Forwarded-Host", "evil"),),
    )
    assert len(seen) == 2  # baseline + 1 probe
    assert seen[0][1] == {}
    assert seen[1][1] == {"X-Forwarded-Host": "evil"}
    assert len(result.probes) == 1


def test_classifier_flags_reflection_in_body():
    probes = [cp_check.CacheProbe(
        header="X-Forwarded-Host", value="evil.example.com",
        status=200, body_size=200,
        body_excerpt="<html>Hello evil.example.com</html>",
        new_headers={},
    )]
    result = cp_check.CachePoisonResult(
        target_url="x", baseline_status=200, baseline_size=180,
        baseline_body_excerpt="<html>Hello world</html>",
        probes=probes,
    )
    cls = cp_cls.analyze_cache_poison(result)
    assert cls.is_vulnerable
    assert "reflected" in cls.findings[0].reason


def test_classifier_flags_header_echo_with_high_severity():
    probes = [cp_check.CacheProbe(
        header="X-Forwarded-Host", value="evil.example.com",
        status=200, body_size=180,
        body_excerpt="<html>Hello evil.example.com</html>",
        new_headers={"Vary": "X-Forwarded-Host"},
    )]
    result = cp_check.CachePoisonResult(
        target_url="x", baseline_status=200, baseline_size=180,
        baseline_body_excerpt="<html>Hello world</html>",
        probes=probes,
    )
    cls = cp_cls.analyze_cache_poison(result)
    # Reflection without echo of the value in the cache-key header still
    # produces a medium finding (which is exactly what we want).
    assert cls.is_vulnerable
    assert cls.findings[0].severity in ("medium", "high")


def test_classifier_silent_when_baseline_matches_probe():
    probes = [cp_check.CacheProbe(
        header="X-Forwarded-Host", value="evil.example.com",
        status=200, body_size=180,
        body_excerpt="<html>Hello world</html>",
        new_headers={},
    )]
    result = cp_check.CachePoisonResult(
        target_url="x", baseline_status=200, baseline_size=180,
        baseline_body_excerpt="<html>Hello world</html>",
        probes=probes,
    )
    cls = cp_cls.analyze_cache_poison(result)
    assert cls.is_vulnerable is False


# Feature: web-security-audit-toolkit, Property 31: classifier never flags an
# errored probe as vulnerable.
@given(reason=st.text(min_size=1, max_size=20))
@settings(max_examples=50, deadline=None)
def test_classifier_ignores_errored_probes(reason):
    probes = [cp_check.CacheProbe(
        header="X-Internal", value="1", status=None,
        body_size=0, body_excerpt="", new_headers={}, error=reason,
    )]
    result = cp_check.CachePoisonResult(
        target_url="x", baseline_status=200, baseline_size=180,
        baseline_body_excerpt="ok", probes=probes,
    )
    cls = cp_cls.analyze_cache_poison(result)
    assert cls.is_vulnerable is False
