"""
Property-based tests for the source map exposure classifier.

# Feature: web-security-audit-toolkit, Property 7: Decisão de exposição de source map

**Validates: Requirements 4.2, 4.5, 4.6**

Property under test
-------------------
For any combination of (status_code, Content-Type, body validity) across the
probed paths in a ``SourceMapResult``:

  1. **Confirmed (high severity)** — ``analyze_source_maps`` returns a
     ``Finding`` with ``status="confirmed"`` and ``severity="high"`` if and
     only if at least one non-error path has:
       - ``status_code == 200``, AND
       - ``content_type`` containing ``"application/json"``, AND
       - ``body`` that is valid JSON.
     (Req. 4.2)

  2. **Not vulnerable (medium confidence)** — when no path satisfies the
     three conditions above AND there are no confirmed paths, the result is
     ``status="not_vulnerable"`` with ``confidence="medium"``.  This applies
     when all non-error paths return HTTP 404 or non-JSON content.
     (Req. 4.5)

  3. **Error paths excluded** — paths with ``status_code`` outside {200, 404}
     (e.g. 403, 500) or with ``status_code=None`` and a non-None ``error``
     (timeout / network failure) are never counted as confirmation and do not
     prevent a "not vulnerable" result.
     (Req. 4.6)
"""

from __future__ import annotations

import json

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import composite

from toolkit.analysis.classifiers.source_maps import analyze_source_maps
from toolkit.execution.checks.source_maps import MapProbeResult, SourceMapResult

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Valid JSON bodies for source map content (dict so json.loads succeeds)
_valid_json_body_strategy = st.fixed_dictionaries(
    {"version": st.just(3)},
    optional={
        "sources": st.lists(st.text(min_size=1, max_size=60), max_size=5),
        "mappings": st.text(min_size=0, max_size=20),
    },
).map(json.dumps)

# Non-JSON bodies (strings that cannot be parsed as JSON)
_invalid_json_body_strategy = st.one_of(
    st.just(""),
    st.just("Not JSON"),
    st.just("<!DOCTYPE html><html></html>"),
    st.just("Internal Server Error"),
    st.text(min_size=1, max_size=100).filter(lambda s: not _is_valid_json(s)),
)

# Content-Type values that indicate JSON
_json_content_type_strategy = st.sampled_from([
    "application/json",
    "application/json; charset=utf-8",
    "application/json;charset=UTF-8",
])

# Content-Type values that do NOT indicate JSON
_non_json_content_type_strategy = st.sampled_from([
    "text/html",
    "text/html; charset=utf-8",
    "text/plain",
    "application/octet-stream",
    "application/javascript",
    "text/css",
])

# HTTP status codes considered "error" by the classifier (Req. 4.6)
_error_status_strategy = st.sampled_from([403, 500, 503, 401, 502])

# Paths used to populate the probed_paths list
_path_strategy = st.builds(
    lambda suffix: f"/assets/bundle{suffix}.js.map",
    suffix=st.integers(min_value=0, max_value=999),
)


def _is_valid_json(s: str) -> bool:
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Composite strategy: a single MapProbeResult
# ---------------------------------------------------------------------------

@composite
def _confirmed_probe_strategy(draw) -> MapProbeResult:
    """Probe that satisfies all three confirmation criteria (Req. 4.2)."""
    path = draw(_path_strategy)
    body = draw(_valid_json_body_strategy)
    content_type = draw(_json_content_type_strategy)
    return MapProbeResult(
        path=path,
        status_code=200,
        content_type=content_type,
        body=body,
        error=None,
    )


@composite
def _non_confirmed_probe_strategy(draw) -> MapProbeResult:
    """
    Probe that does NOT satisfy the confirmation criteria.

    Covers:
    - HTTP 404 (any content type / body)
    - HTTP 200 with non-JSON Content-Type
    - HTTP 200 with invalid JSON body
    - HTTP 200 with valid JSON body but non-JSON Content-Type
    """
    path = draw(_path_strategy)
    variant = draw(st.sampled_from(["404", "200_no_json_ct", "200_invalid_body", "200_no_ct"]))

    if variant == "404":
        return MapProbeResult(
            path=path,
            status_code=404,
            content_type=draw(_non_json_content_type_strategy),
            body=None,
            error=None,
        )
    elif variant == "200_no_json_ct":
        return MapProbeResult(
            path=path,
            status_code=200,
            content_type=draw(_non_json_content_type_strategy),
            body=draw(_valid_json_body_strategy),
            error=None,
        )
    elif variant == "200_invalid_body":
        return MapProbeResult(
            path=path,
            status_code=200,
            content_type=draw(_json_content_type_strategy),
            body=draw(_invalid_json_body_strategy),
            error=None,
        )
    else:  # 200_no_ct
        return MapProbeResult(
            path=path,
            status_code=200,
            content_type=None,
            body=draw(_valid_json_body_strategy),
            error=None,
        )


@composite
def _error_probe_strategy(draw) -> MapProbeResult:
    """Probe representing an error path excluded from analysis (Req. 4.6)."""
    path = draw(_path_strategy)
    variant = draw(st.sampled_from(["http_error", "timeout"]))

    if variant == "http_error":
        status = draw(_error_status_strategy)
        return MapProbeResult(
            path=path,
            status_code=status,
            content_type=None,
            body=None,
            error=f"Unexpected status {status} for path {path}",
        )
    else:  # timeout
        return MapProbeResult(
            path=path,
            status_code=None,
            content_type=None,
            body=None,
            error=f"Timeout probing {path}",
        )


# ---------------------------------------------------------------------------
# Helper to build a SourceMapResult from lists of probes
# ---------------------------------------------------------------------------

def _make_result(probes: list[MapProbeResult]) -> SourceMapResult:
    result = SourceMapResult(base_url="https://example.com")
    result.probed_paths = probes
    return result


# ---------------------------------------------------------------------------
# Property 7a: Confirmed iff at least one non-error path satisfies all criteria
# ---------------------------------------------------------------------------

@given(
    confirmed=st.lists(_confirmed_probe_strategy(), min_size=1, max_size=5),
    non_confirmed=st.lists(_non_confirmed_probe_strategy(), min_size=0, max_size=5),
    errors=st.lists(_error_probe_strategy(), min_size=0, max_size=5),
)
@settings(max_examples=100)
def test_property7_confirmed_when_at_least_one_valid_map_present(
    confirmed, non_confirmed, errors
):
    """
    Property 7: Decisão de exposição de source map.

    **Validates: Requirements 4.2, 4.6**

    When at least one probe satisfies all three conditions (status=200,
    Content-Type contains application/json, valid JSON body), the classifier
    MUST return a Finding with:
      - status == "confirmed"
      - severity == "high"

    Error paths (403/500/timeout) mixed in do not affect the confirmed outcome.
    """
    # Feature: web-security-audit-toolkit, Property 7: Decisão de exposição de source map
    import random
    all_probes = confirmed + non_confirmed + errors
    random.shuffle(all_probes)

    result = _make_result(all_probes)
    findings = analyze_source_maps(result)

    assert len(findings) == 1, f"Expected exactly 1 finding, got {len(findings)}"
    finding = findings[0]

    assert finding.status == "confirmed", (
        f"Expected status='confirmed', got {finding.status!r}. "
        f"Had {len(confirmed)} confirmed probe(s), {len(errors)} error probe(s)."
    )
    assert finding.severity == "high", (
        f"Expected severity='high', got {finding.severity!r}."
    )


# ---------------------------------------------------------------------------
# Property 7b: Not vulnerable when no path satisfies the criteria
# ---------------------------------------------------------------------------

@given(
    non_confirmed=st.lists(_non_confirmed_probe_strategy(), min_size=1, max_size=10),
    errors=st.lists(_error_probe_strategy(), min_size=0, max_size=5),
)
@settings(max_examples=100)
def test_property7_not_vulnerable_when_no_valid_map_present(non_confirmed, errors):
    """
    Property 7: Decisão de exposição de source map.

    **Validates: Requirements 4.5, 4.6**

    When no probed path satisfies the confirmation criteria and all non-error
    paths return 404 or non-JSON content, the classifier MUST return a Finding
    with:
      - status == "not_vulnerable"
      - confidence == "medium"

    Error paths (403/500/timeout) are excluded and do not prevent this result.
    """
    # Feature: web-security-audit-toolkit, Property 7: Decisão de exposição de source map
    import random
    all_probes = non_confirmed + errors
    random.shuffle(all_probes)

    result = _make_result(all_probes)
    findings = analyze_source_maps(result)

    assert len(findings) == 1, f"Expected exactly 1 finding, got {len(findings)}"
    finding = findings[0]

    assert finding.status == "not_vulnerable", (
        f"Expected status='not_vulnerable', got {finding.status!r}. "
        f"Probes: non_confirmed={len(non_confirmed)}, errors={len(errors)}."
    )
    assert finding.confidence == "medium", (
        f"Expected confidence='medium', got {finding.confidence!r}."
    )


# ---------------------------------------------------------------------------
# Property 7c: Error-only result is not_vulnerable (error paths excluded)
# ---------------------------------------------------------------------------

@given(
    errors=st.lists(_error_probe_strategy(), min_size=1, max_size=10),
)
@settings(max_examples=100)
def test_property7_only_error_paths_yields_not_vulnerable(errors):
    """
    Property 7: Decisão de exposição de source map.

    **Validates: Requirements 4.5, 4.6**

    When ALL probes are error paths (403/500/timeout), the classifier must
    return "not_vulnerable" with "medium" confidence — error paths are excluded
    from analysis and do not trigger a confirmed finding.
    """
    # Feature: web-security-audit-toolkit, Property 7: Decisão de exposição de source map
    result = _make_result(errors)
    findings = analyze_source_maps(result)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.status == "not_vulnerable", (
        f"Expected 'not_vulnerable' with only error paths, got {finding.status!r}."
    )
    assert finding.confidence == "medium", (
        f"Expected confidence='medium', got {finding.confidence!r}."
    )


# ---------------------------------------------------------------------------
# Property 7d: Confirmed status is a biconditional — iff all three criteria met
# ---------------------------------------------------------------------------

@given(
    status=st.sampled_from([200, 404, 403, 500, None]),
    content_type=st.one_of(
        _json_content_type_strategy,
        _non_json_content_type_strategy,
        st.none(),
    ),
    body=st.one_of(
        _valid_json_body_strategy,
        _invalid_json_body_strategy,
        st.none(),
    ),
    extra_non_confirmed=st.lists(_non_confirmed_probe_strategy(), min_size=0, max_size=3),
)
@settings(max_examples=200)
def test_property7_biconditional_confirmation_criteria(
    status, content_type, body, extra_non_confirmed
):
    """
    Property 7: Decisão de exposição de source map (bicondicional).

    **Validates: Requirements 4.2, 4.5, 4.6**

    The classifier confirms an exposed source map if and only if the probe
    satisfies ALL THREE conditions simultaneously:
      - status_code == 200
      - Content-Type contains "application/json"
      - body is valid JSON

    For any single probe that does NOT satisfy all three conditions, the
    finding must NOT be "confirmed".
    """
    # Feature: web-security-audit-toolkit, Property 7: Decisão de exposição de source map

    # Determine if probe meets all three criteria
    has_200 = status == 200
    has_json_ct = content_type is not None and "application/json" in content_type
    has_valid_json = body is not None and _is_valid_json(body)
    should_confirm = has_200 and has_json_ct and has_valid_json

    # Build error field for non-200/non-404 statuses
    if status not in (200, 404, None):
        error = f"Unexpected status {status}"
    elif status is None:
        error = "Timeout"
    else:
        error = None

    probe = MapProbeResult(
        path="/assets/test.js.map",
        status_code=status,
        content_type=content_type,
        body=body if status == 200 else None,
        error=error,
    )

    all_probes = [probe] + extra_non_confirmed
    result = _make_result(all_probes)
    findings = analyze_source_maps(result)

    assert len(findings) == 1
    finding = findings[0]

    if should_confirm:
        assert finding.status == "confirmed", (
            f"Expected 'confirmed' for status={status}, "
            f"content_type={content_type!r}, valid_json={has_valid_json}. "
            f"Got: {finding.status!r}."
        )
        assert finding.severity == "high", (
            f"Expected severity='high', got {finding.severity!r}."
        )
    else:
        assert finding.status != "confirmed", (
            f"Expected NOT 'confirmed' for status={status}, "
            f"content_type={content_type!r}, valid_json={has_valid_json}. "
            f"Got: {finding.status!r}. "
            f"(has_200={has_200}, has_json_ct={has_json_ct}, has_valid_json={has_valid_json})"
        )


# ---------------------------------------------------------------------------
# Property 7e: Error paths do not become confirmed findings
# ---------------------------------------------------------------------------

@given(
    error_probe=_error_probe_strategy(),
    extra_errors=st.lists(_error_probe_strategy(), min_size=0, max_size=4),
)
@settings(max_examples=100)
def test_property7_error_paths_never_confirmed(error_probe, extra_errors):
    """
    Property 7: Decisão de exposição de source map.

    **Validates: Requirements 4.6**

    Error paths (non-200/non-404 status or timeout) must NEVER produce a
    confirmed finding, regardless of how many error paths are present.
    """
    # Feature: web-security-audit-toolkit, Property 7: Decisão de exposição de source map
    all_probes = [error_probe] + extra_errors
    result = _make_result(all_probes)
    findings = analyze_source_maps(result)

    assert len(findings) == 1
    finding = findings[0]

    assert finding.status != "confirmed", (
        f"Error paths must never produce 'confirmed' finding. "
        f"Got: {finding.status!r} for probes: "
        f"{[f'status={p.status_code},error={p.error!r}' for p in all_probes]!r}"
    )


# ---------------------------------------------------------------------------
# Edge case: empty probed_paths → not_vulnerable
# ---------------------------------------------------------------------------

def test_property7_empty_probed_paths_yields_not_vulnerable():
    """
    When no paths were probed at all, the classifier must not report a
    confirmed finding. It should produce "not_vulnerable".

    **Validates: Requirements 4.5**
    """
    # Feature: web-security-audit-toolkit, Property 7: Decisão de exposição de source map
    result = _make_result([])
    findings = analyze_source_maps(result)

    assert len(findings) == 1
    assert findings[0].status == "not_vulnerable"
    assert findings[0].confidence == "medium"
