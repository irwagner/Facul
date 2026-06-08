"""
Property-based tests for IDOR identifier variation generation.

# Feature: web-security-audit-toolkit, Property 14: Geração e limite de variações de identificador

**Validates: Requirements 8.1, 8.6**

Property 14: Geração e limite de variações de identificador
-----------------------------------------------------------
For any integer identifier, ``generate_id_variations`` (i.e., ``generate_variations``)
produces a variation set that:
  - contains exactly {id+1, id-1, a random UUID, "0", "-1"}
  - has len <= 5 (and exactly 5 for integer inputs)

The set of variations never exceeds 5 elements for any input (integer or UUID).
"""

from __future__ import annotations

import re
import uuid as _uuid_mod

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from toolkit.execution.checks.idor import generate_variations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def _uuid_variations(variations: list[str]) -> list[str]:
    """Return only the UUID-formatted variations."""
    return [v for v in variations if _UUID_PATTERN.fullmatch(v)]


# ---------------------------------------------------------------------------
# Property 14a: For any integer identifier, the variation set is exactly
# {id+1, id-1, random UUID, "0", "-1"} and len <= 5
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(identifier=st.integers(min_value=2, max_value=10_000_000))
def test_integer_variations_exact_set(identifier: int) -> None:
    """
    **Validates: Requirements 8.1, 8.6**

    Property 14: For any integer identifier >= 2, generate_variations returns
    exactly the set {str(id+1), str(id-1), <uuid>, "0", "-1"} with len == 5.

    We use min_value=2 so that id-1 >= 1 and does not coincide with "0" or "-1",
    making the expected set size unambiguously 5 distinct values.
    """
    variations = generate_variations(identifier)

    # Must contain exactly 5 elements
    assert len(variations) == 5, (
        f"Expected 5 variations for id={identifier}, got {len(variations)}: {variations}"
    )

    # Must contain id+1
    assert str(identifier + 1) in variations, (
        f"Expected '{identifier + 1}' in variations for id={identifier}: {variations}"
    )

    # Must contain id-1
    assert str(identifier - 1) in variations, (
        f"Expected '{identifier - 1}' in variations for id={identifier}: {variations}"
    )

    # Must contain "0"
    assert "0" in variations, (
        f"Expected '0' in variations for id={identifier}: {variations}"
    )

    # Must contain "-1"
    assert "-1" in variations, (
        f"Expected '-1' in variations for id={identifier}: {variations}"
    )

    # Must contain exactly one UUID
    uuid_vars = _uuid_variations(variations)
    assert len(uuid_vars) == 1, (
        f"Expected exactly 1 UUID variation for id={identifier}, got {uuid_vars}"
    )

    # All variations must be strings
    for v in variations:
        assert isinstance(v, str), (
            f"All variations must be str, got {type(v)!r}: {v!r}"
        )


# ---------------------------------------------------------------------------
# Property 14b: The set never exceeds 5 variations for any integer input
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(identifier=st.integers(min_value=-(10 ** 9), max_value=10 ** 9))
def test_integer_variations_never_exceed_5(identifier: int) -> None:
    """
    **Validates: Requirements 8.1, 8.6**

    Property 14: For any integer identifier (including negative, zero, large),
    len(generate_variations(identifier)) <= 5.
    """
    variations = generate_variations(identifier)

    assert len(variations) <= 5, (
        f"Variation count exceeded 5 for id={identifier}: {variations}"
    )

    # All elements must be strings
    for v in variations:
        assert isinstance(v, str)


# ---------------------------------------------------------------------------
# Property 14c: The set never exceeds 5 variations for UUID string inputs
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    uuid_int=st.integers(min_value=1, max_value=2 ** 128 - 1)
)
def test_uuid_variations_never_exceed_5(uuid_int: int) -> None:
    """
    **Validates: Requirements 8.1, 8.6**

    Property 14: For any UUID string identifier, generate_variations returns
    at most 5 elements and always includes "0", "-1", and exactly one UUID.
    """
    uuid_str = str(_uuid_mod.UUID(int=uuid_int))
    variations = generate_variations(uuid_str)

    assert len(variations) <= 5, (
        f"Variation count exceeded 5 for uuid={uuid_str}: {variations}"
    )

    # "0" and "-1" must always be present
    assert "0" in variations, (
        f"Expected '0' in UUID variations: {variations}"
    )
    assert "-1" in variations, (
        f"Expected '-1' in UUID variations: {variations}"
    )

    # Exactly one UUID in the result
    uuid_vars = _uuid_variations(variations)
    assert len(uuid_vars) == 1, (
        f"Expected exactly 1 UUID variation for uuid={uuid_str}, got {uuid_vars}"
    )

    # All elements must be strings
    for v in variations:
        assert isinstance(v, str)
