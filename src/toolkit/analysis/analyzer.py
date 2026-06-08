"""
Analyzer facade — aggregates the per-check classifiers and summarises phases.

The :class:`Analyzer` is the single entry point used by the orchestrator to
interpret raw results. It exposes the individual classifier functions as
methods and implements :meth:`Analyzer.summarize_phase`, which condenses a set
of classified :class:`~toolkit.models.Finding` objects into a
:class:`~toolkit.models.PhaseAnalysis` (summary, confidence, estimated
severity, next steps, and the exact commands for the following phase) per
Req. 12.2.
"""

from __future__ import annotations

from typing import Literal

from toolkit.analysis.classifiers.nuclei import map_nuclei_findings
from toolkit.models import Finding, NucleiFinding, PhaseAnalysis

__all__ = ["Analyzer"]


# Ordering used to pick the "highest" severity / confidence across findings.
_SEVERITY_ORDER: dict[str, int] = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_CONFIDENCE_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
}

#: Confirmed-status findings count towards an actionable summary.
_CONFIRMED_STATUS = "confirmed"


class Analyzer:
    """
    Interprets raw check results and produces standardised findings.

    Classification of each individual check is delegated to the dedicated
    classifier modules under :mod:`toolkit.analysis.classifiers`. The Analyzer
    additionally provides :meth:`summarize_phase` to roll a list of findings up
    into a :class:`~toolkit.models.PhaseAnalysis` (Req. 12.2).
    """

    def map_nuclei_findings(self, findings: list[NucleiFinding]) -> list[Finding]:
        """Map raw Nuclei findings to the standard ``Finding`` format (Req. 10.3)."""
        return map_nuclei_findings(findings)

    # -- Phase summarisation (Req. 12.2) ------------------------------------

    def summarize_phase(
        self,
        findings: list[Finding],
        next_phase_commands: list[str] | None = None,
    ) -> PhaseAnalysis:
        """
        Summarise the classified *findings* of a phase (Req. 12.2).

        Produces a :class:`~toolkit.models.PhaseAnalysis` presenting the
        finding summary, the overall confidence level, the estimated severity,
        the recommended next steps, and the exact commands for the following
        phase.

        Parameters
        ----------
        findings:
            The classified :class:`~toolkit.models.Finding` objects produced
            from the phase's raw results. May be empty.
        next_phase_commands:
            Exact commands the auditor should run in the following phase. When
            ``None`` (e.g. for the final phase) an empty list is used.

        Returns
        -------
        PhaseAnalysis
            The aggregated analysis. ``summary``, ``confidence``,
            ``estimated_severity`` and ``next_steps`` are always populated.
        """
        next_cmds = list(next_phase_commands) if next_phase_commands else []

        if not findings:
            return PhaseAnalysis(
                summary="No findings were produced from the results provided for this phase.",
                confidence="low",
                estimated_severity="none",
                next_steps=["Proceed to the next phase."],
                next_phase_commands=next_cmds,
                findings=[],
            )

        estimated_severity = self._highest_severity(findings)
        confidence = self._highest_confidence(findings)

        confirmed = [f for f in findings if f.status == _CONFIRMED_STATUS]
        total = len(findings)
        if confirmed:
            summary = (
                f"{len(confirmed)} of {total} finding(s) confirmed; "
                f"highest severity is {estimated_severity}."
            )
        else:
            summary = (
                f"{total} finding(s) recorded; none confirmed "
                f"(highest estimated severity {estimated_severity})."
            )

        next_steps = self._collect_next_steps(findings)

        return PhaseAnalysis(
            summary=summary,
            confidence=confidence,
            estimated_severity=estimated_severity,
            next_steps=next_steps,
            next_phase_commands=next_cmds,
            findings=list(findings),
        )

    # -- internal helpers ---------------------------------------------------

    @staticmethod
    def _highest_severity(
        findings: list[Finding],
    ) -> Literal["none", "low", "medium", "high", "critical"]:
        best = max(
            (_SEVERITY_ORDER.get(f.severity, 0) for f in findings),
            default=0,
        )
        for name, rank in _SEVERITY_ORDER.items():
            if rank == best:
                return name  # type: ignore[return-value]
        return "none"

    @staticmethod
    def _highest_confidence(
        findings: list[Finding],
    ) -> Literal["low", "medium", "high"]:
        best = max(
            (_CONFIDENCE_ORDER.get(f.confidence, 0) for f in findings),
            default=0,
        )
        for name, rank in _CONFIDENCE_ORDER.items():
            if rank == best:
                return name  # type: ignore[return-value]
        return "low"

    @staticmethod
    def _collect_next_steps(findings: list[Finding]) -> list[str]:
        """Aggregate the per-finding next steps, de-duplicated and order-preserving."""
        steps: list[str] = []
        seen: set[str] = set()
        for f in findings:
            for step in f.next_steps:
                if step not in seen:
                    seen.add(step)
                    steps.append(step)
        if not steps:
            steps.append("Review the recorded findings before proceeding.")
        return steps
