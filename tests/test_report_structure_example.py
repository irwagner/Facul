"""
Example tests for report structure and the empty-report case (task 14.6).

These tests verify, with concrete fixtures:
  - the mandatory report sections are present in both Markdown and HTML
    (Cover, Executive Summary, Findings Table, Details, Recommended Next Steps);
  - the rendered HTML is self-contained (inline CSS, no external asset
    references such as <link>, external <script src>, <img src> or @import url);
  - the empty-session case (no findings) includes the
    "no vulnerabilities identified" note across every section.

**Validates: Requirements 11.2, 11.4, 11.7**
"""

from __future__ import annotations

import re
from datetime import date

import pytest

from toolkit.models import Authorization, Finding, SessionState
from toolkit.reporting.reporter import Reporter

# The note rendered whenever there are no vulnerabilities (Req. 11.7).
_NO_VULN_NOTE = "Nenhuma vulnerabilidade foi identificada"

# Mandatory section headings expected in every report (Req. 11.2).
_MANDATORY_SECTIONS = [
    "Capa",
    "Sumário Executivo",
    "Tabela de Achados",
    "Detalhes dos Achados",
    "Próximos Passos Recomendados",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _authorization() -> Authorization:
    return Authorization(
        domain="example.edu",
        institution="Universidade Exemplo",
        auth_date=date(2024, 1, 15),
        authorized_domains=["example.edu"],
        authorized_cidrs=["10.0.0.0/24"],
    )


def _finding(idx: int, severity: str, confidence: str) -> Finding:
    return Finding(
        id=f"SRCMAP-{idx:03d}",
        title=f"Achado de teste {idx}",
        summary=f"Resumo do achado {idx}.",
        severity=severity,
        confidence=confidence,
        status="confirmed",
        affected_endpoint=f"https://example.edu/path/{idx}",
        evidence=f"evidencia-{idx}",
        impact=f"impacto-{idx}",
        remediation=f"Aplicar correção {idx}.",
        next_steps=[f"passo-{idx}"],
        references=["CWE-200", "OWASP-A01"],
    )


@pytest.fixture
def session_with_findings() -> SessionState:
    findings = [
        _finding(1, "critical", "high"),
        _finding(2, "high", "medium"),
        _finding(3, "medium", "low"),
        _finding(4, "low", "low"),
    ]
    return SessionState(
        authorization=_authorization(),
        working_dir="/tmp/audit_report_example",
        completed_phases=["surface_discovery"],
        findings=findings,
        tested_targets=["example.edu"],
        surface_map=None,
        operations_log=[],
    )


@pytest.fixture
def empty_session() -> SessionState:
    return SessionState(
        authorization=_authorization(),
        working_dir="/tmp/audit_report_empty",
        completed_phases=["surface_discovery"],
        findings=[],
        tested_targets=["example.edu"],
        surface_map=None,
        operations_log=[],
    )


# ---------------------------------------------------------------------------
# Mandatory sections (Req. 11.2)
# ---------------------------------------------------------------------------


def test_markdown_contains_all_mandatory_sections(session_with_findings: SessionState) -> None:
    """The Markdown report exposes every mandatory section heading (Req. 11.2)."""
    markdown = Reporter().render_markdown(session_with_findings)
    for section in _MANDATORY_SECTIONS:
        assert f"## {section}" in markdown, f"missing markdown section {section!r}"


def test_html_contains_all_mandatory_sections(session_with_findings: SessionState) -> None:
    """The HTML report exposes every mandatory section heading (Req. 11.2)."""
    html = Reporter().render_html(session_with_findings)
    for section in _MANDATORY_SECTIONS:
        assert f"<h2>{section}</h2>" in html, f"missing html section {section!r}"


def test_markdown_findings_table_lists_each_finding(session_with_findings: SessionState) -> None:
    """The findings table renders one row per finding with id and severity."""
    markdown = Reporter().render_markdown(session_with_findings)
    for finding in session_with_findings.findings:
        assert finding.id in markdown
        assert finding.title in markdown


# ---------------------------------------------------------------------------
# Self-contained HTML (Req. 11.4)
# ---------------------------------------------------------------------------


def test_html_has_inline_css(session_with_findings: SessionState) -> None:
    """The HTML embeds CSS inline through a <style> block (Req. 11.4)."""
    html = Reporter().render_html(session_with_findings)
    assert "<style>" in html and "</style>" in html
    # Some real CSS rule must be present inside the style block.
    assert "font-family" in html


def test_html_has_no_external_asset_references(session_with_findings: SessionState) -> None:
    """
    The HTML must be self-contained: no external stylesheets, scripts, images
    or @import directives that would require fetching remote assets (Req. 11.4).
    """
    html = Reporter().render_html(session_with_findings)

    # No <link ...> tags (external stylesheets / favicons).
    assert not re.search(r"<link\b", html, flags=re.IGNORECASE)
    # No external script sources.
    assert not re.search(r"<script[^>]*\bsrc\s*=", html, flags=re.IGNORECASE)
    # No image references.
    assert not re.search(r"<img\b", html, flags=re.IGNORECASE)
    # No CSS @import of remote stylesheets.
    assert "@import" not in html
    # No http(s) URLs pointing to fetched assets (the only URLs come from
    # finding endpoints/references, which the empty/structure fixtures avoid
    # in href/src attributes).
    assert not re.search(r"(href|src)\s*=\s*[\"']https?://", html, flags=re.IGNORECASE)


# ---------------------------------------------------------------------------
# Empty report note (Req. 11.7)
# ---------------------------------------------------------------------------


def test_empty_markdown_includes_no_vulnerability_note(empty_session: SessionState) -> None:
    """An empty session yields the 'no vulnerabilities identified' note (Req. 11.7)."""
    markdown = Reporter().render_markdown(empty_session)
    assert _NO_VULN_NOTE in markdown
    # All mandatory sections still present even with no findings.
    for section in _MANDATORY_SECTIONS:
        assert f"## {section}" in markdown


def test_empty_html_includes_no_vulnerability_note(empty_session: SessionState) -> None:
    """The empty HTML report carries the note and stays self-contained (Req. 11.4, 11.7)."""
    html = Reporter().render_html(empty_session)
    assert _NO_VULN_NOTE in html
    assert "<style>" in html
    assert not re.search(r"<link\b", html, flags=re.IGNORECASE)
    for section in _MANDATORY_SECTIONS:
        assert f"<h2>{section}</h2>" in html


def test_empty_report_has_no_findings_table_rows(empty_session: SessionState) -> None:
    """With no findings, the report renders the note instead of a findings table."""
    reporter = Reporter()
    markdown = reporter.render_markdown(empty_session)
    # No markdown table separator row should be emitted for findings.
    assert "| --- | --- | --- | --- | --- |" not in markdown


def test_generate_writes_self_contained_files(tmp_path, empty_session: SessionState) -> None:
    """generate() writes report.md and report.html with the empty-session note."""
    artifacts = Reporter().generate(empty_session, str(tmp_path))

    md_text = open(artifacts.markdown_path, encoding="utf-8").read()
    html_text = open(artifacts.html_path, encoding="utf-8").read()

    assert _NO_VULN_NOTE in md_text
    assert _NO_VULN_NOTE in html_text
    assert "<style>" in html_text
    assert not re.search(r"<link\b", html_text, flags=re.IGNORECASE)
