"""Tests for the Wayback / OTX URL collector."""

from __future__ import annotations

from toolkit.discovery import wayback


def test_extract_parameters_groups_by_endpoint():
    urls = [
        "https://example.com/login?next=/home&token=abc",
        "https://example.com/login?next=/dashboard",
        "https://api.example.com/v1/items?page=1&limit=20",
        "https://api.example.com/v1/items?sort=desc",
    ]
    out = wayback.extract_parameters(urls)
    assert "example.com/login" in out
    assert {"next", "token"}.issubset(out["example.com/login"])
    assert {"page", "limit", "sort"}.issubset(out["api.example.com/v1/items"])


def test_extract_parameters_ignores_urls_without_query():
    urls = ["https://example.com/", "https://example.com/about"]
    assert wayback.extract_parameters(urls) == {}


def test_collect_handles_source_failures(monkeypatch):
    def boom(domain, *, timeout=20.0):
        raise RuntimeError("offline")

    monkeypatch.setattr(wayback, "fetch_wayback", boom)
    monkeypatch.setattr(wayback, "fetch_otx_urls", lambda d, *, timeout=20.0: ["https://x"])

    out = wayback.collect("example.com")
    assert "wayback" in out.errors
    assert out.sources.get("otx") == 1
    assert out.urls == ["https://x"]
