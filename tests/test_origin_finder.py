"""Tests for the origin-IP discovery aggregator."""

from __future__ import annotations

from toolkit.discovery import origin_finder as of


def test_classify_cdn_recognises_cloudflare_range():
    assert of._classify_cdn("104.16.1.1") == "cloudflare"


def test_classify_cdn_recognises_cloudfront_range():
    assert of._classify_cdn("18.64.207.51") == "cloudfront"


def test_classify_cdn_returns_none_for_random_ip():
    assert of._classify_cdn("203.0.113.10") is None


def test_classify_cdn_handles_invalid_ip():
    assert of._classify_cdn("not-an-ip") is None


def test_origin_report_separates_promising_vs_behind_cdn(monkeypatch):
    """find_origin_candidates must shortlist non-CDN IPs as promising."""
    from toolkit.discovery import dns_records, subdomain_sources

    fake_profile = dns_records.DnsProfile(
        domain="example.com",
        records={
            "A": dns_records.DnsRecordSet("A", values=["104.16.1.1", "203.0.113.10"]),
            "AAAA": dns_records.DnsRecordSet("AAAA"),
            "MX": dns_records.DnsRecordSet("MX"),
        },
        has_spf=False,
        has_dmarc=False,
        has_caa=False,
        cname_chain=[],
    )

    monkeypatch.setattr(
        dns_records, "query_records",
        lambda domain: fake_profile,
    )
    monkeypatch.setattr(
        subdomain_sources, "aggregate_subdomains",
        lambda d: subdomain_sources.AggregatedResult(domain=d, sources=[], subdomains=[]),
    )
    monkeypatch.setattr(of, "_resolve", lambda host: [])

    report = of.find_origin_candidates("example.com")
    addrs = {c.address: c for c in report.candidates}
    assert "104.16.1.1" in addrs and addrs["104.16.1.1"].cdn == "cloudflare"
    assert "203.0.113.10" in addrs and addrs["203.0.113.10"].cdn is None
    assert any(c.address == "203.0.113.10" for c in report.promising)
    assert any(c.address == "104.16.1.1" for c in report.behind_cdn)
