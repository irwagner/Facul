"""Tests for the SSRF check + classifier."""

from __future__ import annotations

from dataclasses import dataclass

from hypothesis import given, settings, strategies as st

from toolkit.execution.checks import ssrf as ssrf_check
from toolkit.analysis.classifiers import ssrf as ssrf_cls


@dataclass
class FakeResp:
    status: int
    body: str = ""
    elapsed_ms: int = 50


# ---------------------------------------------------------------------------
# inject_param
# ---------------------------------------------------------------------------


def test_inject_param_replaces_existing_value():
    target = "https://t.test/page?url=https://safe.test&page=1"
    out = ssrf_check.inject_param(target, "url", "http://127.0.0.1/")
    assert "url=http%3A%2F%2F127.0.0.1%2F" in out
    assert "page=1" in out
    # The injected value must appear exactly once
    assert out.count("url=") == 1


def test_inject_param_appends_when_absent():
    target = "https://t.test/page?page=1"
    out = ssrf_check.inject_param(target, "redirect", "http://localhost/")
    assert "redirect=" in out
    assert "page=1" in out


# ---------------------------------------------------------------------------
# Property: every payload produces exactly one attempt
# ---------------------------------------------------------------------------

# Feature: web-security-audit-toolkit, Property 30: SSRF check produces one
# attempt per payload and never opens a socket itself.
@given(num_payloads=st.integers(min_value=1, max_value=10))
@settings(max_examples=50, deadline=None)
def test_check_ssrf_param_one_attempt_per_payload(num_payloads):
    payloads = ssrf_check.DEFAULT_PAYLOADS[:num_payloads]
    seen: list[str] = []

    def transport(url):
        seen.append(url)
        return FakeResp(status=200, body="hello")

    result = ssrf_check.check_ssrf_param(
        "https://t.test/api", "url", transport=transport, payloads=payloads,
    )

    assert len(result.attempts) == num_payloads
    assert len(seen) == num_payloads
    # No collisions between attempts (each payload produced its own URL)
    assert len({a.payload for a in result.attempts}) == num_payloads


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


def _make_result(*, payload: str, body: str) -> ssrf_check.SsrfResult:
    return ssrf_check.SsrfResult(
        target_url="https://t.test/api",
        parameter="url",
        attempts=[ssrf_check.SsrfAttempt(
            parameter="url", payload=payload, status=200,
            body_excerpt=body, elapsed_ms=20,
        )],
    )


def test_classifier_flags_aws_metadata_leak():
    body = '{"ami-id":"ami-12345","instance-id":"i-abc"}'
    result = _make_result(
        payload="http://169.254.169.254/latest/meta-data/", body=body,
    )
    cls = ssrf_cls.analyze_ssrf(result)
    assert cls.is_vulnerable is True
    assert any(f.severity == "critical" for f in cls.findings)
    assert any(f.category in ("aws_metadata", "linux_passwd") for f in cls.findings)


def test_classifier_flags_etc_passwd_leak():
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    result = _make_result(payload="file:///etc/passwd", body=body)
    cls = ssrf_cls.analyze_ssrf(result)
    assert cls.is_vulnerable is True
    assert any(f.category == "linux_passwd" for f in cls.findings)


def test_classifier_silent_when_body_is_clean():
    body = '{"status":"ok","data":[]}'
    result = _make_result(payload="http://127.0.0.1/", body=body)
    cls = ssrf_cls.analyze_ssrf(result)
    assert cls.is_vulnerable is False
    assert cls.findings == []


def test_classifier_ignores_errored_attempts():
    result = ssrf_check.SsrfResult(
        target_url="x", parameter="url",
        attempts=[ssrf_check.SsrfAttempt(
            parameter="url", payload="http://127.0.0.1/",
            status=None, body_excerpt="", elapsed_ms=None,
            error="ConnectionRefused",
        )],
    )
    assert ssrf_cls.analyze_ssrf(result).is_vulnerable is False


def test_timing_oracle_flags_internal_payloads_only():
    attempts = [
        ssrf_check.SsrfAttempt("url", "http://127.0.0.1/", 200, "ok", elapsed_ms=10),
        ssrf_check.SsrfAttempt("url", "http://172.16.0.245/", 200, "ok", elapsed_ms=15),
        ssrf_check.SsrfAttempt("url", "https://external.test/", 200, "ok", elapsed_ms=200),
        ssrf_check.SsrfAttempt("url", "https://other-external.test/", 200, "ok", elapsed_ms=180),
    ]
    result = ssrf_check.SsrfResult(target_url="x", parameter="url", attempts=attempts)
    suspects = ssrf_cls.detect_timing_oracle(result, threshold_ratio=0.5)
    suspect_payloads = {s.payload for s in suspects}
    assert "http://127.0.0.1/" in suspect_payloads
    assert "https://external.test/" not in suspect_payloads
