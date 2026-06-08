"""
Property-based tests for CDN bypass candidate selection.

# Feature: web-security-audit-toolkit, Property 11: Limite de candidatos a IP de origem

**Validates: Requirements 6.1**

Property under test
-------------------
For any collection of IP candidate strings (including duplicates),
``select_candidates()`` returns a list that:

  1. Contains no duplicate entries (every element is unique).
  2. Has at most 5 elements.
  3. Is a subset of the original input.
  4. Preserves insertion order (first occurrence of each unique IP is kept).
"""

from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.execution.checks.cdn_bypass import select_candidates

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# An IPv4-like string: four decimal octets separated by dots.
_octet = st.integers(min_value=0, max_value=255).map(str)
_ipv4_strategy = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    a=_octet,
    b=_octet,
    c=_octet,
    d=_octet,
)

# A small pool of distinct IPs from which we build lists with duplicates.
_SMALL_IP_POOL = [
    "1.2.3.4",
    "10.0.0.1",
    "192.168.1.1",
    "172.16.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
]

# Lists of IP candidates drawn from the pool — may contain duplicates.
_candidates_with_duplicates_strategy = st.lists(
    st.sampled_from(_SMALL_IP_POOL),
    min_size=0,
    max_size=30,
)

# General strategy: arbitrary IPv4 strings, possibly with duplicates.
_candidates_general_strategy = st.lists(
    _ipv4_strategy,
    min_size=0,
    max_size=50,
)


# ---------------------------------------------------------------------------
# Property 11 — result has at most 5 elements
# ---------------------------------------------------------------------------

@given(candidates=_candidates_with_duplicates_strategy)
@settings(max_examples=100)
def test_property11_result_has_at_most_5_elements(candidates):
    """
    Property 11: Limite de candidatos a IP de origem.

    **Validates: Requirements 6.1**

    ``select_candidates(candidates)`` must return at most 5 elements,
    regardless of how many IPs are provided.
    """
    # Feature: web-security-audit-toolkit, Property 11: Limite de candidatos a IP de origem
    result = select_candidates(candidates)

    assert len(result) <= 5, (
        f"Expected at most 5 candidates, got {len(result)}: {result!r}"
    )


# ---------------------------------------------------------------------------
# Property 11 — result contains no duplicates (unique set)
# ---------------------------------------------------------------------------

@given(candidates=_candidates_with_duplicates_strategy)
@settings(max_examples=100)
def test_property11_result_is_unique(candidates):
    """
    Property 11: Limite de candidatos a IP de origem.

    **Validates: Requirements 6.1**

    ``select_candidates(candidates)`` must return a list with no duplicate
    entries — every IP in the result is unique.
    """
    # Feature: web-security-audit-toolkit, Property 11: Limite de candidatos a IP de origem
    result = select_candidates(candidates)

    assert len(result) == len(set(result)), (
        f"Result contains duplicates: {result!r}"
    )


# ---------------------------------------------------------------------------
# Property 11 — combined: unique AND at most 5 (general inputs)
# ---------------------------------------------------------------------------

@given(candidates=_candidates_general_strategy)
@settings(max_examples=100)
def test_property11_unique_and_at_most_5_general(candidates):
    """
    Property 11: Limite de candidatos a IP de origem (general IPv4 inputs).

    **Validates: Requirements 6.1**

    For arbitrary collections of IPv4 candidate strings, the evaluated set
    returned by ``select_candidates`` is unique and has at most 5 elements.
    """
    # Feature: web-security-audit-toolkit, Property 11: Limite de candidatos a IP de origem
    result = select_candidates(candidates)

    # Must be unique
    assert len(result) == len(set(result)), (
        f"Result contains duplicates: {result!r}"
    )

    # Must be at most 5
    assert len(result) <= 5, (
        f"Expected at most 5 candidates, got {len(result)}: {result!r}"
    )


# ---------------------------------------------------------------------------
# Property 11 — result is a subset of the input
# ---------------------------------------------------------------------------

@given(candidates=_candidates_with_duplicates_strategy)
@settings(max_examples=100)
def test_property11_result_is_subset_of_input(candidates):
    """
    Property 11: Limite de candidatos a IP de origem.

    **Validates: Requirements 6.1**

    Every IP returned by ``select_candidates`` must have appeared in the
    original input — no IP is invented.
    """
    # Feature: web-security-audit-toolkit, Property 11: Limite de candidatos a IP de origem
    result = select_candidates(candidates)
    input_set = set(candidates)

    extra = set(result) - input_set
    assert not extra, (
        f"Result contains IPs not in input: {extra!r}"
    )


# ---------------------------------------------------------------------------
# Property 11 — order preservation (first-occurrence semantics)
# ---------------------------------------------------------------------------

@given(candidates=_candidates_with_duplicates_strategy)
@settings(max_examples=100)
def test_property11_preserves_first_occurrence_order(candidates):
    """
    Property 11: Limite de candidatos a IP de origem.

    **Validates: Requirements 6.1**

    ``select_candidates`` keeps the first occurrence of each IP in the order
    they appear in the input.  The result must match the first-seen order for
    each unique IP up to the 5-element cap.
    """
    # Feature: web-security-audit-toolkit, Property 11: Limite de candidatos a IP de origem
    result = select_candidates(candidates)

    # Build the expected order manually: first occurrence of each unique IP
    seen: dict[str, None] = {}
    for ip in candidates:
        if ip not in seen:
            seen[ip] = None
        if len(seen) == 5:
            break
    expected = list(seen.keys())

    assert result == expected, (
        f"Order mismatch.\n  Expected: {expected!r}\n  Got     : {result!r}"
    )


# ---------------------------------------------------------------------------
# Edge case: empty input → empty result
# ---------------------------------------------------------------------------

def test_property11_empty_input_yields_empty_result():
    """
    When the candidate list is empty, ``select_candidates`` must return an
    empty list.

    **Validates: Requirements 6.1**
    """
    result = select_candidates([])
    assert result == [], f"Expected [], got {result!r}"


# ---------------------------------------------------------------------------
# Edge case: all duplicates of a single IP → exactly one result
# ---------------------------------------------------------------------------

def test_property11_all_same_ip_yields_single_result():
    """
    When every candidate is the same IP, the result must contain exactly
    one entry.

    **Validates: Requirements 6.1**
    """
    ip = "1.2.3.4"
    result = select_candidates([ip] * 20)

    assert result == [ip], f"Expected ['{ip}'], got {result!r}"


# ---------------------------------------------------------------------------
# Edge case: 6+ distinct IPs → exactly 5 returned
# ---------------------------------------------------------------------------

def test_property11_more_than_5_distinct_ips_capped_at_5():
    """
    When more than 5 distinct IPs are provided, the result must contain
    exactly 5 entries.

    **Validates: Requirements 6.1**
    """
    ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6", "7.7.7.7"]
    result = select_candidates(ips)

    assert len(result) == 5, f"Expected 5 candidates, got {len(result)}: {result!r}"
    assert result == ips[:5], f"Expected first 5: {ips[:5]!r}, got {result!r}"
