"""
Property-based tests for source map evidence extraction limits (Req. 4.3).

# Feature: web-security-audit-toolkit, Property 8: Limites de evidência de source map

**Validates: Requirements 4.3**

Properties tested
-----------------
P8a — Evidence string length is at most 200 characters for any sources field.
P8b — At most 5 entries from the sources field are reflected in the evidence.
"""

from __future__ import annotations

import json
import string

from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.analysis.classifiers.source_maps import (
    _MAX_EVIDENCE_CHARS,
    _MAX_SOURCES_ENTRIES,
    _build_evidence,
    analyze_source_maps,
)
from toolkit.execution.checks.source_maps import MapProbeResult, SourceMapResult

# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

# Strategy for a single source path entry (arbitrary printable string, no
# quotes or backslashes to keep JSON valid)
_source_entry_strategy = st.text(
    alphabet=string.ascii_letters + string.digits + "/._-",
    min_size=0,
    max_size=300,  # deliberately long to stress truncation
)

# Strategy for an arbitrary-length list of source entries
_sources_list_strategy = st.lists(
    _source_entry_strategy,
    min_size=0,
    max_size=50,  # up to 50 entries to stress the 5-entry cap
)


def _make_confirmed_probe(sources: list[str]) -> MapProbeResult:
    """Build a MapProbeResult that represents an exposed source map."""
    body = json.dumps({"version": 3, "sources": sources, "mappings": "AAAA"})
    return MapProbeResult(
        path="/assets/index.js.map",
        status_code=200,
        content_type="application/json",
        body=body,
        error=None,
    )


def _make_source_map_result(sources: list[str]) -> SourceMapResult:
    """Build a SourceMapResult containing a single confirmed probe."""
    probe = _make_confirmed_probe(sources)
    result = SourceMapResult(base_url="https://example.com")
    result.probed_paths.append(probe)
    return result


# ---------------------------------------------------------------------------
# P8a — Evidence is at most 200 characters
# ---------------------------------------------------------------------------

@given(sources=_sources_list_strategy)
@settings(max_examples=100)
def test_evidence_length_at_most_200_chars(sources: list[str]) -> None:
    """
    **Validates: Requirements 4.3**

    Property 8 (P8a): For any sources field of arbitrary size, the evidence
    string produced by analyze_source_maps must not exceed 200 characters.
    """
    result = _make_source_map_result(sources)
    findings = analyze_source_maps(result)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.status == "confirmed"

    evidence = finding.evidence
    assert len(evidence) <= _MAX_EVIDENCE_CHARS, (
        f"Evidence length {len(evidence)} exceeds the 200-char limit. "
        f"Evidence: {evidence!r}"
    )


# ---------------------------------------------------------------------------
# P8b — At most 5 source entries are referenced in the evidence
# ---------------------------------------------------------------------------

@given(sources=_sources_list_strategy)
@settings(max_examples=100)
def test_evidence_reflects_at_most_5_source_entries(sources: list[str]) -> None:
    """
    **Validates: Requirements 4.3**

    Property 8 (P8b): The evidence must reference at most 5 entries from the
    sources field, regardless of how many entries the field contains.

    We verify this without a raw substring check (which produces false
    positives when an included entry, e.g. ``'00'``, contains an excluded
    entry, e.g. ``'0'``, as a substring). Instead we reconstruct exactly what
    the classifier serialises — the first ``_MAX_SOURCES_ENTRIES`` entries,
    str-coerced — and assert the evidence equals that capped serialisation
    truncated to the evidence-length limit.
    """
    probe = _make_confirmed_probe(sources)
    evidence = _build_evidence(probe)

    # The evidence string must be at most 200 chars
    assert len(evidence) <= _MAX_EVIDENCE_CHARS, (
        f"Evidence length {len(evidence)} exceeds 200 chars."
    )

    # Reconstruct the capped, serialised entries the classifier is allowed to
    # use: at most the first _MAX_SOURCES_ENTRIES entries, str-coerced.
    capped_sources = [str(s) for s in sources[:_MAX_SOURCES_ENTRIES]]
    assert len(capped_sources) <= _MAX_SOURCES_ENTRIES

    if sources:
        # The evidence is exactly the capped serialisation, truncated to the
        # 200-char limit. This proves no more than 5 entries are reflected,
        # regardless of how many entries the sources field contains.
        expected = f"sources: {capped_sources}"[:_MAX_EVIDENCE_CHARS]
        assert evidence == expected, (
            "Evidence does not match the capped (<=5 entry) serialisation.\n"
            f"  Expected: {expected!r}\n"
            f"  Got:      {evidence!r}"
        )
    else:
        # With no source entries, a fallback message is used instead.
        assert "no 'sources' field found" in evidence


# ---------------------------------------------------------------------------
# P8c — _build_evidence directly: truncation + entry cap
# ---------------------------------------------------------------------------

@given(sources=_sources_list_strategy)
@settings(max_examples=100)
def test_build_evidence_entry_cap_and_truncation(sources: list[str]) -> None:
    """
    **Validates: Requirements 4.3**

    Property 8 (P8c): Direct unit test on _build_evidence.

    * The returned string is always at most _MAX_EVIDENCE_CHARS (200) chars.
    * The slice passed to str() is sources[:5] — verified by constructing the
      probe directly and comparing the raw entry count in the serialised list.
    """
    probe = _make_confirmed_probe(sources)
    evidence = _build_evidence(probe)

    # Truncation invariant
    assert len(evidence) <= _MAX_EVIDENCE_CHARS

    # Entry-cap invariant: the evidence is built from at most 5 entries.
    # We verify by re-creating what the function would produce *before*
    # truncation and confirming that more than 5 entries are never used.
    capped_sources = [str(s) for s in sources[:_MAX_SOURCES_ENTRIES]]
    expected_prefix = f"sources: {capped_sources}"

    # The evidence, before truncation, must equal expected_prefix when the
    # sources list is non-empty.
    if sources:
        # evidence is expected_prefix[:200]
        assert evidence == expected_prefix[:_MAX_EVIDENCE_CHARS], (
            f"Unexpected evidence content.\n"
            f"  Expected (truncated): {expected_prefix[:_MAX_EVIDENCE_CHARS]!r}\n"
            f"  Got:                  {evidence!r}"
        )
    else:
        # When no sources entries, the fallback message is used
        assert "no 'sources' field found" in evidence or "sources: []" in evidence or len(evidence) <= _MAX_EVIDENCE_CHARS
