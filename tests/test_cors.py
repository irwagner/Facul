"""Tests for the CORS check + classifier."""

from __future__ import annotations

from dataclasses import dataclass

from toolkit.execution.checks import cors as cors_check
from toolkit.analysis.classifiers import cors as cors_cls


@dataclass
class FakeResp:
    status: int
    headers: dict


def _make_probe(origin, acao=None, acac=None, allow_methods=None,
                allow_headers=None, method="GET"):
    return cors_check.CorsProbe(
        origin=origin, method=method, status=200,
        acao=acao, acac=acac,
        allow_methods=allow_methods, allow_headers=allow_headers,
    )


def _wrap(probes):
    return cors_check.CorsResult(target_url="https://t.test/api", probes=probes)


def test_origin_reflection_with_credentials_is_critical():
    probes = [_make_probe("https://evil.example.com",
                          acao="https://evil.example.com", acac="true")]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert cls.is_vulnerable
    assert cls.findings[0].severity == "critical"
    assert "credentials" in cls.findings[0].reason.lower()


def test_origin_reflection_without_credentials_is_high():
    probes = [_make_probe("https://evil.example.com",
                          acao="https://evil.example.com", acac=None)]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert cls.is_vulnerable
    assert cls.findings[0].severity == "high"


def test_wildcard_with_credentials_flagged_critical():
    probes = [_make_probe("https://evil.example.com", acao="*", acac="true")]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert any(f.severity == "critical" for f in cls.findings)


def test_null_origin_with_credentials_flagged():
    probes = [_make_probe("null", acao="null", acac="true")]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert any(f.severity == "critical" for f in cls.findings)


def test_wildcard_without_credentials_flagged_medium():
    probes = [_make_probe("https://evil.example.com", acao="*", acac=None)]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert any(f.severity == "medium" for f in cls.findings)


def test_options_with_sensitive_headers_flagged():
    probes = [_make_probe(
        "https://evil.example.com", method="OPTIONS",
        acao=None, acac=None,
        allow_methods="GET, POST",
        allow_headers="Authorization, Content-Type",
    )]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert any(f.severity == "medium" for f in cls.findings)


def test_safe_acao_explicit_origin_not_flagged():
    probes = [_make_probe("https://evil.example.com",
                          acao="https://trusted.test", acac="true")]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert not cls.is_vulnerable


def test_check_cors_runs_origin_x_method_combinations():
    seen = []

    def transport(url, *, method="GET", headers=None):
        seen.append((url, method, (headers or {}).get("Origin")))
        return FakeResp(status=200, headers={})

    cors_check.check_cors("https://t.test/", transport=transport,
                          origins=("https://a.test", "https://b.test"))
    # 2 origins * 2 methods (GET + OPTIONS) = 4 probes
    assert len(seen) == 4


def test_classifier_skips_errored_probes():
    probes = [cors_check.CorsProbe(
        origin="https://evil.example.com", method="GET", status=None,
        acao=None, acac=None, allow_methods=None, allow_headers=None,
        error="ConnectionRefused",
    )]
    cls = cors_cls.analyze_cors(_wrap(probes))
    assert not cls.is_vulnerable
