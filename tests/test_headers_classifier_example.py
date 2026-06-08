"""
Example-based tests for the HTTP security headers classifier.

Tests cover:
- Missing headers → medium severity finding
- Valid headers → no finding
- Misconfigured headers → medium severity finding
- CSP unsafe-inline / unsafe-eval → medium severity finding
- HSTS max-age below threshold → medium severity finding
- check_failed status → empty result
"""

from __future__ import annotations

import pytest

from toolkit.analysis.classifiers.headers import HeadersResult, analyze_headers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(headers: dict[str, str], url: str = "https://example.com") -> HeadersResult:
    return HeadersResult(url=url, headers=headers, status="ok")


def _finding_titles(findings):
    return [f.title for f in findings]


def _finding_severities(findings):
    return [f.severity for f in findings]


# ---------------------------------------------------------------------------
# check_failed status
# ---------------------------------------------------------------------------

class TestCheckFailed:
    def test_check_failed_returns_empty_list(self):
        result = HeadersResult(
            url="https://example.com",
            headers={},
            status="check_failed",
        )
        assert analyze_headers(result) == []


# ---------------------------------------------------------------------------
# All headers present and valid → no findings
# ---------------------------------------------------------------------------

VALID_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=()",
}


class TestValidHeaders:
    def test_all_valid_headers_produce_no_findings(self):
        result = _make_result(VALID_HEADERS)
        assert analyze_headers(result) == []

    def test_sameorigin_is_valid_for_x_frame_options(self):
        headers = dict(VALID_HEADERS)
        headers["X-Frame-Options"] = "SAMEORIGIN"
        assert analyze_headers(_make_result(headers)) == []

    def test_hsts_exact_minimum_max_age(self):
        headers = dict(VALID_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=31536000"
        assert analyze_headers(_make_result(headers)) == []

    def test_hsts_above_minimum_max_age(self):
        headers = dict(VALID_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        assert analyze_headers(_make_result(headers)) == []

    def test_csp_multiple_directives(self):
        headers = dict(VALID_HEADERS)
        headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'"
        )
        assert analyze_headers(_make_result(headers)) == []

    def test_referrer_policy_non_empty(self):
        headers = dict(VALID_HEADERS)
        headers["Referrer-Policy"] = "strict-origin"
        assert analyze_headers(_make_result(headers)) == []

    def test_permissions_policy_multiple_features(self):
        headers = dict(VALID_HEADERS)
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        assert analyze_headers(_make_result(headers)) == []

    def test_header_names_case_insensitive(self):
        """Scanner may normalise header names; classifier accepts both cases."""
        # Use lowercase keys (as Scanner would deliver)
        lowercase_headers = {k.lower(): v for k, v in VALID_HEADERS.items()}
        assert analyze_headers(_make_result(lowercase_headers)) == []


# ---------------------------------------------------------------------------
# Missing headers → finding per missing header
# ---------------------------------------------------------------------------

class TestMissingHeaders:
    def test_missing_csp_generates_medium_finding(self):
        headers = {k: v for k, v in VALID_HEADERS.items() if k != "Content-Security-Policy"}
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "Content-Security-Policy" in findings[0].evidence

    def test_missing_hsts_generates_medium_finding(self):
        headers = {k: v for k, v in VALID_HEADERS.items() if k != "Strict-Transport-Security"}
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_missing_x_frame_options_generates_finding(self):
        headers = {k: v for k, v in VALID_HEADERS.items() if k != "X-Frame-Options"}
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_missing_x_content_type_options_generates_finding(self):
        headers = {k: v for k, v in VALID_HEADERS.items() if k != "X-Content-Type-Options"}
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_missing_referrer_policy_generates_finding(self):
        headers = {k: v for k, v in VALID_HEADERS.items() if k != "Referrer-Policy"}
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_missing_permissions_policy_generates_finding(self):
        headers = {k: v for k, v in VALID_HEADERS.items() if k != "Permissions-Policy"}
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_all_headers_missing_generates_six_findings(self):
        findings = analyze_headers(_make_result({}))
        assert len(findings) == 6
        assert all(f.severity == "medium" for f in findings)


# ---------------------------------------------------------------------------
# Misconfigured headers → finding per misconfiguration
# ---------------------------------------------------------------------------

class TestMisconfiguredHeaders:
    def test_hsts_max_age_below_minimum(self):
        headers = dict(VALID_HEADERS)
        headers["Strict-Transport-Security"] = "max-age=86400"
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "max-age" in findings[0].evidence

    def test_hsts_missing_max_age_directive(self):
        headers = dict(VALID_HEADERS)
        headers["Strict-Transport-Security"] = "includeSubDomains"
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert "max-age" in findings[0].evidence

    def test_x_frame_options_invalid_value(self):
        headers = dict(VALID_HEADERS)
        headers["X-Frame-Options"] = "ALLOW-FROM https://example.com"
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_x_content_type_options_invalid_value(self):
        headers = dict(VALID_HEADERS)
        headers["X-Content-Type-Options"] = "sniff"
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_referrer_policy_empty_value(self):
        headers = dict(VALID_HEADERS)
        headers["Referrer-Policy"] = "   "  # whitespace only
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_permissions_policy_empty_value(self):
        headers = dict(VALID_HEADERS)
        headers["Permissions-Policy"] = ""
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_permissions_policy_no_directives_no_equals(self):
        headers = dict(VALID_HEADERS)
        headers["Permissions-Policy"] = "camera microphone"  # no "=" signs
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1

    def test_csp_empty_value(self):
        headers = dict(VALID_HEADERS)
        headers["Content-Security-Policy"] = "   ;  ;  "  # only semicolons
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"


# ---------------------------------------------------------------------------
# CSP unsafe directives (Req. 7.5)
# ---------------------------------------------------------------------------

class TestCspUnsafeDirectives:
    def test_csp_with_unsafe_inline(self):
        headers = dict(VALID_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'unsafe-inline'"
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "unsafe-inline" in findings[0].evidence

    def test_csp_with_unsafe_eval(self):
        headers = dict(VALID_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-eval'"
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "unsafe-eval" in findings[0].evidence

    def test_csp_with_both_unsafe_inline_and_unsafe_eval(self):
        headers = dict(VALID_HEADERS)
        headers["Content-Security-Policy"] = (
            "script-src 'unsafe-inline' 'unsafe-eval'"
        )
        findings = analyze_headers(_make_result(headers))
        # One finding per unsafe directive
        assert len(findings) == 2
        evidences = " ".join(f.evidence for f in findings)
        assert "unsafe-inline" in evidences
        assert "unsafe-eval" in evidences

    def test_csp_safe_self_no_finding(self):
        headers = dict(VALID_HEADERS)
        headers["Content-Security-Policy"] = "default-src 'self'"
        assert analyze_headers(_make_result(headers)) == []


# ---------------------------------------------------------------------------
# Finding fields completeness
# ---------------------------------------------------------------------------

class TestFindingFields:
    def test_finding_has_all_required_fields(self):
        findings = analyze_headers(_make_result({}))
        for f in findings:
            assert f.id
            assert f.title
            assert f.summary
            assert f.severity == "medium"
            assert f.confidence == "high"
            assert f.status == "confirmed"
            assert f.evidence
            assert f.impact
            assert f.remediation
            assert isinstance(f.next_steps, list)
            assert isinstance(f.references, list)

    def test_finding_affected_endpoint_matches_url(self):
        url = "https://target.example.com"
        findings = analyze_headers(HeadersResult(url=url, headers={}, status="ok"))
        for f in findings:
            assert f.affected_endpoint == url

    def test_finding_remediation_contains_nginx_directive(self):
        headers = {k: v for k, v in VALID_HEADERS.items() if k != "X-Frame-Options"}
        findings = analyze_headers(_make_result(headers))
        assert len(findings) == 1
        assert "add_header" in findings[0].remediation

    def test_finding_references_not_empty(self):
        findings = analyze_headers(_make_result({}))
        for f in findings:
            assert len(f.references) > 0
