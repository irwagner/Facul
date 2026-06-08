"""Property tests for the subdomain-sources aggregator."""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from toolkit.discovery import subdomain_sources as ss


# Feature: web-security-audit-toolkit, Property 27: aggregator deduplicates and
# union-merges every source into the final subdomain list.
@given(st.lists(st.lists(st.text(min_size=1, max_size=20).map(lambda s: s.lower()), max_size=8), max_size=6))
@settings(max_examples=100, deadline=None)
def test_aggregator_unions_and_dedupes(per_source_lists):
    domain = "example.com"
    sources = []

    def make_fetcher(idx, items):
        def fetcher(d, *, timeout=15.0):
            cleaned = []
            for item in items:
                # Normalize to look like a real subdomain of *domain*.
                base = item.replace(".", "").replace(" ", "")[:10] or "x"
                cleaned.append(f"{base}.{domain}")
            return ss.SourceResult(name=f"src{idx}", subdomains=cleaned)
        fetcher.__name__ = f"fetcher_{idx}"
        return fetcher

    for i, items in enumerate(per_source_lists):
        sources.append(make_fetcher(i, items))

    result = ss.aggregate_subdomains(domain, sources=tuple(sources))

    # Property 1: result.subdomains == sorted(union of all sources).
    expected = set()
    for src in result.sources:
        expected.update(src.subdomains)
    assert sorted(expected) == result.subdomains

    # Property 2: every entry is unique.
    assert len(result.subdomains) == len(set(result.subdomains))

    # Property 3: every entry resolves to *domain* or is *domain*.
    for s in result.subdomains:
        assert s == domain or s.endswith("." + domain)


# Feature: web-security-audit-toolkit, Property 28: a failing source does not
# crash the aggregator and is recorded with an error.
@given(st.text(min_size=1, max_size=10))
@settings(max_examples=50, deadline=None)
def test_failing_source_is_isolated(reason):
    def good(d, *, timeout=15.0):
        return ss.SourceResult(name="good", subdomains=[f"a.{d}"])

    def bad(d, *, timeout=15.0):
        raise RuntimeError(reason or "boom")

    bad.__name__ = "bad"

    result = ss.aggregate_subdomains("example.com", sources=(good, bad))

    assert result.subdomains == ["a.example.com"]
    bad_src = next(s for s in result.sources if s.name == "bad")
    assert not bad_src.succeeded
    assert "RuntimeError" in (bad_src.error or "")


def test_normalize_filters_invalid_candidates():
    assert ss._normalize("example.com", "*.foo.example.com") == "foo.example.com"
    assert ss._normalize("example.com", "example.com") == "example.com"
    assert ss._normalize("example.com", "other.test") is None
    assert ss._normalize("example.com", "") is None
    assert ss._normalize("example.com", "bad space.example.com") is None
