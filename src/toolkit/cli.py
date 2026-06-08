"""
CLI — Entry point for the iterative seven-phase audit flow (Req. 12.1, 12.5).

This module wires together the orchestration, analysis and reporting layers to
drive the iterative audit flow described in the design:

* For every phase, it displays the briefing produced by
  :meth:`~toolkit.orchestrator.PhaseOrchestrator.describe_phase` — objective,
  exact commands, and result-collection instructions (Req. 12.1).
* Before entering a phase it applies risk *gating* via
  :meth:`~toolkit.orchestrator.PhaseOrchestrator.can_enter_phase`. Medium- and
  high-risk phases require explicit auditor confirmation when the passive
  discovery phase has not yet completed (Req. 12.5, 12.6).
* It ingests the raw results of each phase through
  :meth:`~toolkit.orchestrator.PhaseOrchestrator.ingest_phase_results`, which
  classifies findings, updates and persists the session.
* The final phase triggers report generation through the
  :class:`~toolkit.reporting.reporter.Reporter`.

The :class:`IterativeAuditCLI` is deliberately decoupled from ``stdin``/``stdout``
through injectable ``input_fn``/``output_fn`` callables and a ``results_provider``
callable, so the whole flow can be driven and asserted in tests without real
terminal interaction or network access.
"""

from __future__ import annotations

import sys
from typing import Callable

from toolkit.models import PhaseAnalysis, SessionState
from toolkit.orchestrator import (
    PHASES,
    GateResult,
    Phase,
    PhaseBriefing,
    PhaseOrchestrator,
)
from toolkit.reporting.reporter import ReportArtifacts, Reporter

# Type aliases for the injectable IO callables.
OutputFn = Callable[[str], None]
InputFn = Callable[[str], str]
#: Given a phase, return the raw results dict for that phase (Req. 12.2 input).
ResultsProvider = Callable[[Phase], dict]

#: Name of the final phase that triggers report generation.
REPORT_PHASE = "report_generation"

#: Answers that count as an affirmative confirmation at a risk gate.
_AFFIRMATIVE = frozenset({"y", "yes", "s", "sim"})


class IterativeAuditCLI:
    """
    Drives the iterative seven-phase audit flow (Req. 12.1, 12.5).

    Parameters
    ----------
    orchestrator:
        The :class:`~toolkit.orchestrator.PhaseOrchestrator` used to describe
        phases, apply gating, and ingest results. A fresh instance is created
        when not supplied.
    reporter:
        The :class:`~toolkit.reporting.reporter.Reporter` used to generate the
        final report artefacts. A fresh instance is created when not supplied.
    output_fn:
        Callable used to emit text to the auditor. Defaults to :func:`print`.
    input_fn:
        Callable used to read a line of input from the auditor (used for risk
        gate confirmation). Defaults to :func:`input`.
    """

    def __init__(
        self,
        orchestrator: PhaseOrchestrator | None = None,
        reporter: Reporter | None = None,
        output_fn: OutputFn | None = None,
        input_fn: InputFn | None = None,
    ) -> None:
        self.orchestrator = orchestrator or PhaseOrchestrator()
        self.reporter = reporter or Reporter()
        self._out: OutputFn = output_fn or (lambda msg: print(msg))
        self._in: InputFn = input_fn or (lambda prompt: input(prompt))

    # ------------------------------------------------------------------
    # Briefing display (Req. 12.1)
    # ------------------------------------------------------------------

    def display_briefing(self, phase: Phase) -> PhaseBriefing:
        """
        Display the briefing for *phase* and return it (Req. 12.1).

        The briefing prints the phase objective, the exact commands to run, and
        the instructions for collecting and providing the results.
        """
        briefing = self.orchestrator.describe_phase(phase)
        self._out("")
        self._out("=" * 70)
        self._out(f"PHASE {phase.index}: {briefing.phase_name}  "
                  f"[risk: {phase.risk_level.value}]")
        self._out("=" * 70)
        self._out("")
        self._out("Objective:")
        self._out(f"  {briefing.objective}")
        self._out("")
        self._out("Commands:")
        for cmd in briefing.commands:
            self._out(f"  $ {cmd}")
        self._out("")
        self._out("How to collect and provide results:")
        self._out(f"  {briefing.collection_instructions}")
        self._out("")
        return briefing

    # ------------------------------------------------------------------
    # Risk gating (Req. 12.5, 12.6)
    # ------------------------------------------------------------------

    def check_gate(self, phase: Phase, state: SessionState) -> bool:
        """
        Apply risk gating for *phase* and return whether to proceed.

        Delegates the decision to
        :meth:`~toolkit.orchestrator.PhaseOrchestrator.can_enter_phase`. When
        the gate requires confirmation (medium/high-risk phase without the
        passive discovery phase completed), the auditor is prompted; the phase
        proceeds only on an affirmative answer (Req. 12.5, 12.6).

        Returns
        -------
        bool
            ``True`` if the phase may proceed, ``False`` if the auditor declined
            a required confirmation.
        """
        gate: GateResult = self.orchestrator.can_enter_phase(phase, state)

        if not gate.allowed:
            self._out(f"[BLOCKED] {gate.reason}")
            return False

        if gate.requires_confirmation:
            self._out(f"[WARNING] {gate.reason}")
            answer = self._in("Proceed anyway? [y/N]: ").strip().lower()
            if answer not in _AFFIRMATIVE:
                self._out("Phase skipped: confirmation not given.")
                return False

        return True

    # ------------------------------------------------------------------
    # Result ingestion (Req. 12.2)
    # ------------------------------------------------------------------

    def ingest(self, phase: Phase, raw_results: dict, state: SessionState) -> PhaseAnalysis:
        """
        Ingest *raw_results* for *phase* and present the resulting analysis.

        Delegates to
        :meth:`~toolkit.orchestrator.PhaseOrchestrator.ingest_phase_results`
        (which classifies findings, updates and persists the session) and then
        prints the summary, confidence, estimated severity, recommended next
        steps, and the exact commands for the following phase (Req. 12.2).
        """
        analysis = self.orchestrator.ingest_phase_results(phase, raw_results, state)
        self._out("--- Analysis ---")
        self._out(f"  Summary: {analysis.summary}")
        self._out(f"  Confidence: {analysis.confidence}")
        self._out(f"  Estimated severity: {analysis.estimated_severity}")
        if analysis.next_steps:
            self._out("  Next steps:")
            for step in analysis.next_steps:
                self._out(f"    - {step}")
        if analysis.next_phase_commands:
            self._out("  Commands for the next phase:")
            for cmd in analysis.next_phase_commands:
                self._out(f"    $ {cmd}")
        self._out("")
        return analysis

    # ------------------------------------------------------------------
    # Report generation (Req. 11 via final phase)
    # ------------------------------------------------------------------

    def generate_report(self, state: SessionState, out_dir: str | None = None) -> ReportArtifacts:
        """
        Trigger generation of the final report (Markdown + HTML).

        Parameters
        ----------
        state:
            The accumulated :class:`~toolkit.models.SessionState`.
        out_dir:
            Directory for the report artefacts. Defaults to ``state.working_dir``.
        """
        target_dir = out_dir or state.working_dir
        artifacts = self.reporter.generate(state, target_dir)
        self._out("Report generated:")
        self._out(f"  Markdown: {artifacts.markdown_path}")
        self._out(f"  HTML:     {artifacts.html_path}")
        return artifacts

    # ------------------------------------------------------------------
    # Full flow
    # ------------------------------------------------------------------

    def run(
        self,
        state: SessionState,
        results_provider: ResultsProvider,
        out_dir: str | None = None,
    ) -> SessionState:
        """
        Drive the complete iterative flow across the seven phases.

        For every phase in order this method:

        1. Displays the phase briefing (Req. 12.1).
        2. Applies risk gating, requesting confirmation when required
           (Req. 12.5, 12.6). A declined phase is skipped.
        3. For the final phase, triggers report generation.
        4. For all other phases, obtains the raw results via
           *results_provider* and ingests them (Req. 12.2).

        Parameters
        ----------
        state:
            The session state to drive and mutate through the flow.
        results_provider:
            Callable returning the raw results dict for a given phase. It is not
            invoked for the report-generation phase.
        out_dir:
            Optional directory for report artefacts (defaults to the session
            working directory).

        Returns
        -------
        SessionState
            The (mutated) session state after the flow completes.
        """
        for phase in sorted(PHASES, key=lambda p: p.index):
            self.display_briefing(phase)

            if not self.check_gate(phase, state):
                continue

            if phase.name == REPORT_PHASE:
                self.generate_report(state, out_dir=out_dir)
                continue

            raw_results = results_provider(phase)
            self.ingest(phase, raw_results, state)

        return state


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """
    Minimal command-line entry point for the iterative flow.

    Usage
    -----
    ``python -m toolkit.cli <working_dir>``

    Starts a fresh session in *working_dir* and displays the briefing for each
    of the seven phases (Req. 12.1) so the auditor can follow the guided flow.
    Interactive result ingestion is performed via the higher-level toolkit
    commands; this entry point focuses on presenting the phase guidance.

    Returns
    -------
    int
        Process exit code (0 on success, 2 on usage error).
    """
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("Usage: python -m toolkit.cli <working_dir>")
        return 2

    working_dir = args[0]
    cli = IterativeAuditCLI()
    orchestrator = cli.orchestrator
    state = orchestrator.start_session(working_dir)

    for phase in sorted(PHASES, key=lambda p: p.index):
        cli.display_briefing(phase)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
