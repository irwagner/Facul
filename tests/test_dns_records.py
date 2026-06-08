"""Tests for the DNS records module (unit, no external network)."""

from __future__ import annotations

from dataclasses import dataclass

from toolkit.discovery import dns_records as dr


@dataclass
class FakeAnswer:
    text: str

    def to_text(self) -> str:
        return self.text


class FakeResolver:
    """Replays a fixed mapping of (name, rtype) → list[str] | Exception."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def resolve(self, name, rtype, lifetime=None):
        self.calls.append((name, rtype))
        key = (name, rtype)
        if key not in self.mapping:
            raise LookupError("NXDOMAIN")
        value = self.mapping[key]
        if isinstance(value, Exception):
            raise value
        return [FakeAnswer(v) for v in value]


def test_query_records_aggregates_record_set():
    resolver = FakeResolver({
        ("example.com", "A"): ["93.184.216.34"],
        ("example.com", "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "TXT"): ["v=spf1 -all"],
        ("example.com", "NS"): ["a.iana-servers.net."],
        ("example.com", "SOA"): ["ns.example.com. hostmaster 2024 7200 3600 1209600 3600"],
        ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"],
    })
    profile = dr.query_records("example.com", resolver=resolver)

    assert profile.has_spf is True
    assert profile.has_dmarc is True
    assert profile.has_caa is True
    assert profile.records["A"].values == ["93.184.216.34"]
    assert profile.records["MX"].values == ["10 mail.example.com."]


def test_extract_origin_candidates_pulls_a_aaaa_and_mx_hosts():
    resolver = FakeResolver({
        ("ex.com", "A"): ["1.2.3.4"],
        ("ex.com", "AAAA"): ["::1"],
        ("ex.com", "MX"): ["10 mail.ex.com."],
        ("ex.com", "TXT"): [],
        ("ex.com", "NS"): [],
        ("ex.com", "SOA"): [],
        ("ex.com", "CNAME"): [],
        ("ex.com", "CAA"): [],
        ("_dmarc.ex.com", "TXT"): [],
    })
    profile = dr.query_records("ex.com", resolver=resolver)
    cands = dr.extract_origin_candidates(profile)
    assert "1.2.3.4" in cands
    assert "::1" in cands
    assert "mail.ex.com" in cands
    # No duplicates
    assert len(cands) == len(set(cands))


def test_missing_records_become_errors_not_exceptions():
    resolver = FakeResolver({})  # everything is NXDOMAIN
    profile = dr.query_records("nope.example", resolver=resolver)
    for rt in dr.DEFAULT_RECORD_TYPES:
        assert profile.records[rt].error is not None
    assert profile.has_spf is False
    assert profile.has_dmarc is False
