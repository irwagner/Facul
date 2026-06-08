"""
Property-based tests for NucleiAdapter.deduplicate (Req. 10.4).

# Feature: web-security-audit-toolkit, Property 21: Deduplicação idempotente de findings do Nuclei

Properties tested
-----------------
21a. deduplicate() removes findings with same (template_id, host), keeping the
     first occurrence.
21b. The relative order of surviving elements is preserved.
21c. Applying deduplicate twice produces the same result (idempotence).

**Validates: Requirements 10.4**
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st
from hypothesis.strategies import composite

from tests.conftest import nuclei_finding_strategy
from toolkit.execution.nuclei_adapter import NucleiAdapter
from toolkit.models import NucleiFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

adapter = NucleiAdapter()


@composite
def nuclei_finding_list_strategy(draw: st.DrawFn) -> list[NucleiFinding]:
    """
    Generates a list of NucleiFinding instances, deliberately including
    duplicates (same template_id/host key) to exercise deduplication logic.
    """
    # Draw a base pool of unique findings
    base_pool = draw(st.lists(nuclei_finding_strategy(), min_size=0, max_size=10))

    if not base_pool:
        return []

    # For each finding in the pool, optionally insert additional copies
    # at random positions to create duplicates
    result: list[NucleiFinding] = []
    for finding in base_pool:
        result.append(finding)
        # With ~40% probability, insert a duplicate
        if draw(st.booleans()) and draw(st.booleans()):
            # Create a copy with the same (template_id, host) key but
            # potentially different other fields (e.g., different matched_at)
            duplicate = NucleiFinding(
                template_id=finding.template_id,
                host=finding.host,
                matched_at=draw(st.one_of(st.none(), st.text(min_size=1, max_size=80))),
                severity=finding.severity,
                name=finding.name,
                tags=list(finding.tags),
                info=dict(finding.info),
                timestamp=finding.timestamp,
                extra=dict(finding.extra),
            )
            # Insert the duplicate at a random position after the original
            insert_pos = draw(st.integers(min_value=len(result) - 1, max_value=len(result)))
            result.insert(insert_pos, duplicate)

    return result


# ---------------------------------------------------------------------------
# Property 21a: duplicate removal keeps first occurrence
# ---------------------------------------------------------------------------

@given(findings=nuclei_finding_list_strategy())
@settings(max_examples=100)
def test_property21a_dedup_removes_duplicates_keeping_first_occurrence(
    findings: list[NucleiFinding],
) -> None:
    """
    **Validates: Requirements 10.4**

    After deduplication every (template_id, host) pair appears exactly once,
    and the surviving finding is the FIRST one from the original list.
    """
    result = adapter.deduplicate(findings)

    # No (template_id, host) pair should appear more than once
    seen_keys: list[tuple[str, str]] = [(f.template_id, f.host) for f in result]
    assert len(seen_keys) == len(set(seen_keys)), (
        "Duplicate (template_id, host) keys found after deduplication"
    )

    # For every key in the result, it must correspond to the FIRST occurrence
    # in the original list
    for surviving in result:
        key = (surviving.template_id, surviving.host)
        first_occurrence = next(
            f for f in findings if (f.template_id, f.host) == key
        )
        # The surviving element must be the same object as the first occurrence
        assert surviving is first_occurrence, (
            f"Expected first occurrence to survive for key {key!r}, "
            f"but got a different object"
        )


# ---------------------------------------------------------------------------
# Property 21b: relative order is preserved
# ---------------------------------------------------------------------------

@given(findings=nuclei_finding_list_strategy())
@settings(max_examples=100)
def test_property21b_dedup_preserves_relative_order(
    findings: list[NucleiFinding],
) -> None:
    """
    **Validates: Requirements 10.4**

    The relative order of surviving elements in the deduplicated result matches
    their order in the original list.
    """
    result = adapter.deduplicate(findings)

    # Build the expected order: iterate original list, keep first occurrence
    seen: set[tuple[str, str]] = set()
    expected_order: list[NucleiFinding] = []
    for f in findings:
        key = (f.template_id, f.host)
        if key not in seen:
            seen.add(key)
            expected_order.append(f)

    assert result == expected_order, (
        "deduplicate() did not preserve the relative order of surviving elements"
    )


# ---------------------------------------------------------------------------
# Property 21c: idempotence — applying deduplicate twice gives the same result
# ---------------------------------------------------------------------------

@given(findings=nuclei_finding_list_strategy())
@settings(max_examples=100)
def test_property21c_deduplicate_is_idempotent(
    findings: list[NucleiFinding],
) -> None:
    """
    **Validates: Requirements 10.4**

    deduplicate(deduplicate(x)) == deduplicate(x) for any input list.
    The operation is idempotent: running it twice produces the same result
    as running it once.
    """
    once = adapter.deduplicate(findings)
    twice = adapter.deduplicate(once)

    assert once == twice, (
        "deduplicate is not idempotent: "
        "applying it twice produced a different result than applying it once"
    )
