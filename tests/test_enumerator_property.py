"""
Property-based tests for Enumerator path coverage.

# Feature: web-security-audit-toolkit, Property 5: Cobertura de paths de enumeração

**Validates: Requirements 3.1, 3.2**

Property under test
-------------------
For every arbitrary wordlist, the set of paths effectively tested by the
``Enumerator`` is the **union** of the complete wordlist with the fixed set
of common administrative panels:

    {"/admin", "/dashboard", "/panel", "/manage", "/api/v1/admin"}

Specifically:
  1. Every path in the wordlist is present in the result.
  2. Every admin panel path is present in the result.
  3. No path appears more than once in the result (no duplicates).
  4. No path outside wordlist ∪ ADMIN_PANEL_PATHS appears in the result.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.discovery.enumerator import ADMIN_PANEL_PATHS, Enumerator


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# A valid URL path segment: starts with '/', may contain letters, digits and
# common path characters.  We keep it simple to avoid confusion with the fixed
# set while still exercising arbitrary inputs.
_path_char_alphabet = string.ascii_lowercase + string.digits + "-_."

_path_strategy = st.builds(
    lambda segment: f"/{segment}",
    segment=st.text(
        alphabet=_path_char_alphabet,
        min_size=1,
        max_size=40,
    ),
)

# A wordlist is a list of path strings (may be empty, may contain duplicates,
# and may overlap with the fixed admin panel paths).
_wordlist_strategy = st.lists(
    _path_strategy,
    min_size=0,
    max_size=150,
)


# ---------------------------------------------------------------------------
# Property 5 — main property test
# ---------------------------------------------------------------------------

@given(wordlist=_wordlist_strategy)
@settings(max_examples=100)
def test_property5_path_coverage_is_union_of_wordlist_and_admin_panels(wordlist):
    """
    Property 5: Cobertura de paths de enumeração.

    **Validates: Requirements 3.1, 3.2**

    The set of paths returned by ``Enumerator.get_paths_to_test(wordlist)``
    must equal ``set(wordlist) | set(ADMIN_PANEL_PATHS)``.

    Sub-properties verified:
      1. Every path from the wordlist appears in the result.
      2. Every admin panel path appears in the result.
      3. The result contains no duplicates.
      4. The result contains no path outside wordlist ∪ ADMIN_PANEL_PATHS.
    """
    enumerator = Enumerator()
    result = enumerator.get_paths_to_test(wordlist)

    # --- Sub-property 1: every wordlist path is present ---
    wordlist_set = set(wordlist)
    result_set = set(result)

    missing_from_wordlist = wordlist_set - result_set
    assert not missing_from_wordlist, (
        f"Paths from wordlist missing in result: {missing_from_wordlist!r}"
    )

    # --- Sub-property 2: every admin panel path is present ---
    admin_set = set(ADMIN_PANEL_PATHS)
    missing_admin = admin_set - result_set
    assert not missing_admin, (
        f"Admin panel paths missing in result: {missing_admin!r}"
    )

    # --- Sub-property 3: no duplicates ---
    assert len(result) == len(result_set), (
        f"Result contains duplicates. len(result)={len(result)}, "
        f"len(set(result))={len(result_set)}"
    )

    # --- Sub-property 4: no extra paths ---
    expected_set = wordlist_set | admin_set
    extra_paths = result_set - expected_set
    assert not extra_paths, (
        f"Result contains unexpected paths: {extra_paths!r}"
    )


# ---------------------------------------------------------------------------
# Property 5 — result set equals the union (direct set equality)
# ---------------------------------------------------------------------------

@given(wordlist=_wordlist_strategy)
@settings(max_examples=100)
def test_property5_result_set_equals_union(wordlist):
    """
    Property 5 (set equality formulation): Cobertura de paths de enumeração.

    **Validates: Requirements 3.1, 3.2**

    ``set(get_paths_to_test(wordlist)) == set(wordlist) | set(ADMIN_PANEL_PATHS)``
    """
    enumerator = Enumerator()
    result = enumerator.get_paths_to_test(wordlist)

    expected = set(wordlist) | set(ADMIN_PANEL_PATHS)
    actual = set(result)

    assert actual == expected, (
        f"Path set mismatch.\n"
        f"  Expected : {sorted(expected)!r}\n"
        f"  Actual   : {sorted(actual)!r}\n"
        f"  Missing  : {sorted(expected - actual)!r}\n"
        f"  Extra    : {sorted(actual - expected)!r}"
    )


# ---------------------------------------------------------------------------
# Edge case: empty wordlist → only admin panel paths
# ---------------------------------------------------------------------------

def test_property5_empty_wordlist_yields_only_admin_paths():
    """
    When the wordlist is empty, the result must be exactly the fixed admin
    panel paths (no duplicates, no extras).

    **Validates: Requirements 3.2**
    """
    enumerator = Enumerator()
    result = enumerator.get_paths_to_test([])

    assert set(result) == set(ADMIN_PANEL_PATHS), (
        f"Expected exactly admin paths {ADMIN_PANEL_PATHS!r}, got {result!r}"
    )
    assert len(result) == len(set(ADMIN_PANEL_PATHS)), (
        f"Duplicate entries found in result: {result!r}"
    )


# ---------------------------------------------------------------------------
# Edge case: wordlist that is a superset of admin paths → still no duplicates
# ---------------------------------------------------------------------------

def test_property5_wordlist_containing_all_admin_paths_no_duplicates():
    """
    When the wordlist already contains every admin panel path, the result
    must not introduce duplicate entries.

    **Validates: Requirements 3.1, 3.2**
    """
    extra_paths = ["/api/users", "/login", "/logout"]
    wordlist = ADMIN_PANEL_PATHS + extra_paths

    enumerator = Enumerator()
    result = enumerator.get_paths_to_test(wordlist)

    assert len(result) == len(set(result)), (
        f"Duplicates found: {result!r}"
    )
    assert set(result) == set(ADMIN_PANEL_PATHS) | set(extra_paths), (
        f"Unexpected path set: {set(result)!r}"
    )


# ---------------------------------------------------------------------------
# Edge case: wordlist with duplicates → result deduplicated
# ---------------------------------------------------------------------------

@given(
    wordlist=st.lists(_path_strategy, min_size=2, max_size=20).flatmap(
        lambda paths: st.just(paths + paths)  # duplicate every entry
    )
)
@settings(max_examples=50)
def test_property5_wordlist_with_duplicates_result_is_deduplicated(wordlist):
    """
    Even if the wordlist contains duplicate entries, the result must have no
    duplicates.

    **Validates: Requirements 3.1, 3.2**
    """
    enumerator = Enumerator()
    result = enumerator.get_paths_to_test(wordlist)

    assert len(result) == len(set(result)), (
        f"Duplicates found in result: {result!r}"
    )


# ---------------------------------------------------------------------------
# Edge case: admin panel paths are always present regardless of wordlist
# ---------------------------------------------------------------------------

@given(wordlist=_wordlist_strategy)
@settings(max_examples=100)
def test_property5_admin_paths_always_present(wordlist):
    """
    Regardless of the wordlist content, all five admin panel paths must
    appear in the output.

    **Validates: Requirements 3.2**
    """
    enumerator = Enumerator()
    result = enumerator.get_paths_to_test(wordlist)

    result_set = set(result)
    for admin_path in ADMIN_PANEL_PATHS:
        assert admin_path in result_set, (
            f"Admin path {admin_path!r} missing from result with wordlist {wordlist!r}"
        )
