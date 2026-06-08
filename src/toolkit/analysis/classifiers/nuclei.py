"""
Nuclei findings classifier — maps raw Nuclei output to the standard Finding format.

Converts each ``NucleiFinding`` produced by the Nuclei adapter into the
Toolkit's canonical ``Finding`` dataclass (Req. 10.3).
"""

from __future__ import annotations

from toolkit.models import Finding, NucleiFinding

__all__ = ["map_nuclei_findings"]

# Severity mapping: Nuclei severity strings → Toolkit severity literals.
# "info" and "low" both map to "low"; anything unrecognised defaults to "low".
_SEVERITY_MAP: dict[str, str] = {
    "info": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def map_nuclei_findings(findings: list[NucleiFinding]) -> list[Finding]:
    """Convert a list of ``NucleiFinding`` objects to the standard ``Finding`` format.

    Each Nuclei finding is translated as follows:

    * **summary** — ``finding.name`` if set, otherwise ``finding.template_id``
    * **severity** — mapped via ``_SEVERITY_MAP`` (``"info"`` → ``"low"``,
      ``"low"`` → ``"low"``, ``"medium"`` → ``"medium"``, ``"high"`` →
      ``"high"``, ``"critical"`` → ``"critical"``); unrecognised values
      default to ``"low"``.
    * **confidence** — always ``"medium"`` (Nuclei templates vary in
      reliability; a fixed medium default avoids false precision).
    * **evidence** — ``finding.matched_at`` or ``""`` when absent.
    * **next_steps** — ``["Review Nuclei template: " + finding.template_id]``
    * **references** — ``finding.tags``

    The remaining ``Finding`` fields are filled with sensible defaults:

    * ``id`` — ``"NUCLEI-" + finding.template_id``
    * ``title`` — same as ``summary``
    * ``status`` — ``"confirmed"``
    * ``affected_endpoint`` — ``finding.matched_at`` (may be ``None``)
    * ``impact`` — ``""``
    * ``remediation`` — ``""``

    Args:
        findings: List of :class:`~toolkit.models.NucleiFinding` objects as
            returned by the Nuclei adapter's output parser.

    Returns:
        A list of :class:`~toolkit.models.Finding` objects in the standard
        Toolkit format, one per input finding.

    Requirements: 10.3
    """
    result: list[Finding] = []

    for nf in findings:
        summary: str = nf.name if nf.name else nf.template_id
        severity = _SEVERITY_MAP.get(nf.severity.lower() if nf.severity else "", "low")
        evidence: str = nf.matched_at if nf.matched_at else ""

        finding = Finding(
            id=f"NUCLEI-{nf.template_id}",
            title=summary,
            summary=summary,
            severity=severity,  # type: ignore[arg-type]
            confidence="medium",
            status="confirmed",
            affected_endpoint=nf.matched_at,
            evidence=evidence,
            impact="",
            remediation="",
            next_steps=[f"Review Nuclei template: {nf.template_id}"],
            references=list(nf.tags),
        )
        result.append(finding)

    return result
