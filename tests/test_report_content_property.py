"""
Property-based tests for Property 24: mandatory finding content and phase analysis.

# Feature: web-security-audit-toolkit, Property 24: Conteúdo obrigatório de finding
e análise de fase

For every finding, the rendered report detail must contain all mandatory fields
(id, title, severity, confidence, description, affected endpoint, technical
evidence, impact, remediation guidance and references); and for every set of
findings, the phase analysis (PhaseAnalysis) must fill in summary, confidence,
estimated severity and next steps.

**Validates: Requirements 4.4, 6.4, 7.6, 11.3, 12.2**
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.analysis.analyzer import Analyzer, PhaseAnalysis
from toolkit.models import Authorization, SessionState
from toolkit.reporting.reporter import Reporter

from tests.conftest import authorization_strategy, finding_strategy

# Valid aggregate levels.
_SEVERITIES = {"low", "medium", "high", "critical"}
# When a phase produces no findings, summarize_phase reports an aggregate
# severity of "none" (see Analyzer._highest_severity / PhaseAnalysis), which is
# part of its documented Literal contract. The set of valid aggregate
# severities therefore includes "none" for the empty-findings case.
_AGGREGATE_SEVERITIES = _SEVERITIES | {"none"}
_CONFIDENCES = {"low", "medium", "high"}

_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_CONFIDENCE_RANK = {"high": 2, "medium": 1, "low": 0}


@st.composite
def _session_with_findings(draw: st.DrawFn) -> SessionState:
    """A SessionState whose findings list is generated independently (>=1 finding)."""
    auth: Authorization = draw(authorization_strategy())
    findings = draw(st.lists(finding_strategy(), min_size=1, max_size=8))
    return SessionState(
        authorization=auth,
        working_dir="/tmp/audit_report_test",
        completed_phases=[],
        findings=findings,
        tested_targets=[],
        surface_map=None,
        operations_log=[],
    )


# ---------------------------------------------------------------------------
# Part 1: rendered finding detail contains all mandatory fields (Req. 11.3)
# ---------------------------------------------------------------------------


@settings(max_examples=150)
@given(session=_session_with_findings())
def test_rendered_detail_contains_mandatory_fields(session: SessionState) -> None:
    """
    # Feature: web-security-audit-toolkit, Property 24: Conteúdo obrigatório de
    finding e análise de fase

    For every finding in the session, the rendered Markdown and HTML report
    details contain all mandatory fields.

    **Validates: Requirements 4.4, 6.4, 7.6, 11.3**
    """
    reporter = Reporter()
    markdown = reporter.render_markdown(session)
    html = reporter.render_html(session)

    for finding in session.findings:
        # The finding id and title must appear in both renderings.
        assert finding.id in markdown, f"id {finding.id!r} missing from markdown"
        assert finding.id in html, f"id {finding.id!r} missing from html"

        # The mandatory field labels must be present in the detail section.
        for label in (
            "Severidade",
            "Confiança",
            "Status",
            "Descrição",
            "Endpoint afetado",
            "Evidência técnica",
            "Impacto",
            "Orientação de correção",
            "Referências",
        ):
            assert label in markdown, f"label {label!r} missing from markdown detail"
            assert label in html, f"label {label!r} missing from html detail"

        # The severity/confidence values themselves must be rendered.
        assert finding.severity in markdown
        assert finding.confidence in markdown


@settings(max_examples=150)
@given(session=_session_with_findings())
def test_report_lists_every_finding(session: SessionState) -> None:
    """
    # Feature: web-security-audit-toolkit, Property 24: Conteúdo obrigatório de
    finding e análise de fase

    Every finding id appears in the rendered report (no findings dropped).

    **Validates: Requirements 11.3**
    """
    reporter = Reporter()
    markdown = reporter.render_markdown(session)
    for finding in session.findings:
        assert finding.id in markdown


# ---------------------------------------------------------------------------
# Part 2: summarize_phase fills summary, confidence, severity, next steps (Req. 12.2)
# ---------------------------------------------------------------------------


@settings(max_examples=150)
@given(findings=st.lists(finding_strategy(), min_size=0, max_size=10))
def test_summarize_phase_fills_all_fields(findings: list) -> None:
    """
    # Feature: web-security-audit-toolkit, Property 24: Conteúdo obrigatório de
    finding e análise de fase

    For every set of findings, summarize_phase fills summary, confidence,
    estimated severity and next steps with valid, non-empty values.

    **Validates: Requirements 12.2**
    """
    analyzer = Analyzer()
    analysis = analyzer.summarize_phase(findings)

    assert isinstance(analysis, PhaseAnalysis)

    # Summary is a non-empty string.
    assert isinstance(analysis.summary, str)
    assert analysis.summary.strip() != ""

    # Confidence and estimated severity are valid levels.
    assert analysis.confidence in _CONFIDENCES
    assert analysis.estimated_severity in _AGGREGATE_SEVERITIES

    # The "none" aggregate severity is only valid for the empty-findings case.
    if findings:
        assert analysis.estimated_severity in _SEVERITIES

    # Next steps is a non-empty list of non-empty strings.
    assert isinstance(analysis.next_steps, list)
    assert len(analysis.next_steps) >= 1
    assert all(isinstance(s, str) and s.strip() != "" for s in analysis.next_steps)


@settings(max_examples=150)
@given(findings=st.lists(finding_strategy(), min_size=1, max_size=10))
def test_summarize_phase_aggregates_highest_levels(findings: list) -> None:
    """
    # Feature: web-security-audit-toolkit, Property 24: Conteúdo obrigatório de
    finding e análise de fase

    The estimated severity and confidence are the highest observed among the
    findings.

    **Validates: Requirements 12.2**
    """
    analyzer = Analyzer()
    analysis = analyzer.summarize_phase(findings)

    expected_severity = max(
        (f.severity for f in findings), key=lambda s: _SEVERITY_RANK[s]
    )
    expected_confidence = max(
        (f.confidence for f in findings), key=lambda c: _CONFIDENCE_RANK[c]
    )

    assert _SEVERITY_RANK[analysis.estimated_severity] == _SEVERITY_RANK[expected_severity]
    assert _CONFIDENCE_RANK[analysis.confidence] == _CONFIDENCE_RANK[expected_confidence]
