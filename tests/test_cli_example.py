"""
Example tests for the iterative-flow CLI entry point (task 15.3).

Covers the wiring of the seven phases through the CLI:

* Req. 12.1 — the per-phase briefing (objective, commands, collection
  instructions) is displayed before each phase.
* Req. 12.5 / 12.6 — risk gating is applied: medium/high-risk phases require
  explicit confirmation when the passive discovery phase has not completed.
* The final phase triggers report generation, producing report.md / report.html.

The CLI is driven with injected output/input callables and a results provider,
so no real terminal interaction or network access is needed.
"""

from __future__ import annotations

import os
from datetime import date

import pytest

from toolkit.cli import IterativeAuditCLI, main
from toolkit.models import Authorization, Finding, SessionState
from toolkit.orchestrator import PHASES, PhaseOrchestrator
from toolkit.session import SessionManager

_PHASE_BY_NAME = {p.name: p for p in PHASES}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_auth(domain: str = "example.com") -> Authorization:
    return Authorization(
        domain=domain,
        institution="Test University",
        auth_date=date(2024, 1, 15),
        authorized_domains=[domain],
        authorized_cidrs=[],
    )


def _make_state(working_dir: str, completed: list[str] | None = None) -> SessionState:
    return SessionState(
        authorization=_make_auth(),
        working_dir=working_dir,
        completed_phases=list(completed or []),
        findings=[],
        tested_targets=[],
        surface_map=None,
        operations_log=[],
    )


def _make_finding(fid: str = "SRCMAP-001") -> Finding:
    return Finding(
        id=fid,
        title="Source map exposed",
        summary="A JavaScript source map is publicly accessible.",
        severity="high",
        confidence="high",
        status="confirmed",
        affected_endpoint="https://example.com/app.js.map",
        evidence='{"sources":["src/App.jsx"]}',
        impact="Source code disclosure.",
        remediation="Remove .map files from production builds.",
        next_steps=["Verify removal"],
        references=["CWE-200"],
    )


class _Recorder:
    """Collects emitted output lines and serves scripted input answers."""

    def __init__(self, answers: list[str] | None = None) -> None:
        self.lines: list[str] = []
        self._answers = list(answers or [])
        self.prompts: list[str] = []

    def out(self, msg: str) -> None:
        self.lines.append(msg)

    def inp(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self._answers.pop(0) if self._answers else "n"

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


# ---------------------------------------------------------------------------
# Briefing display (Req. 12.1)
# ---------------------------------------------------------------------------

class TestDisplayBriefing:
    def test_briefing_contains_objective_commands_instructions(self) -> None:
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        phase = _PHASE_BY_NAME["surface_discovery"]

        briefing = cli.display_briefing(phase)

        assert briefing.objective in rec.text
        # Every command must appear in the output.
        for cmd in briefing.commands:
            assert cmd in rec.text
        assert briefing.collection_instructions in rec.text

    def test_briefing_returns_briefing_for_phase(self) -> None:
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        phase = _PHASE_BY_NAME["passive_checks"]
        briefing = cli.display_briefing(phase)
        assert briefing.phase_name == "passive_checks"


# ---------------------------------------------------------------------------
# Risk gating (Req. 12.5, 12.6)
# ---------------------------------------------------------------------------

class TestGating:
    def test_low_risk_phase_proceeds_without_confirmation(self, tmp_path) -> None:
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["surface_discovery"]  # low risk

        assert cli.check_gate(phase, state) is True
        assert rec.prompts == []  # no confirmation requested

    def test_medium_risk_without_passive_requires_confirmation_declined(self, tmp_path) -> None:
        rec = _Recorder(answers=["n"])
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path))  # passive discovery NOT completed
        phase = _PHASE_BY_NAME["endpoint_enumeration"]  # medium risk

        assert cli.check_gate(phase, state) is False
        assert rec.prompts  # confirmation was requested
        assert "WARNING" in rec.text

    def test_medium_risk_without_passive_confirmed(self, tmp_path) -> None:
        rec = _Recorder(answers=["y"])
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["business_logic"]  # high risk

        assert cli.check_gate(phase, state) is True

    def test_medium_risk_with_passive_done_no_confirmation(self, tmp_path) -> None:
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path), completed=["surface_discovery"])
        phase = _PHASE_BY_NAME["endpoint_enumeration"]

        assert cli.check_gate(phase, state) is True
        assert rec.prompts == []


# ---------------------------------------------------------------------------
# Ingestion (Req. 12.2)
# ---------------------------------------------------------------------------

class TestIngest:
    def test_ingest_displays_analysis_and_persists(self, tmp_path) -> None:
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]

        analysis = cli.ingest(phase, {"findings": [_make_finding()]}, state)

        assert analysis.summary in rec.text
        assert "passive_checks" in state.completed_phases
        # State persisted to disk.
        reloaded = SessionManager().load(str(tmp_path))
        assert any(f.id == "SRCMAP-001" for f in reloaded.findings)


# ---------------------------------------------------------------------------
# Full flow (Req. 12.1, 12.5 + report generation)
# ---------------------------------------------------------------------------

class TestRunFlow:
    def test_run_full_flow_generates_report(self, tmp_path) -> None:
        rec = _Recorder(answers=["y", "y", "y"])  # confirm any gated phases
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path))

        # Provide a finding only for the passive_checks phase.
        def provider(phase):
            if phase.name == "passive_checks":
                return {"findings": [_make_finding()]}
            return {}

        result_state = cli.run(state, provider)

        # Report artefacts created.
        assert os.path.exists(os.path.join(str(tmp_path), "report.md"))
        assert os.path.exists(os.path.join(str(tmp_path), "report.html"))
        # Findings accumulated and the finding appears in the report.
        assert any(f.id == "SRCMAP-001" for f in result_state.findings)
        with open(os.path.join(str(tmp_path), "report.md"), encoding="utf-8") as fh:
            assert "SRCMAP-001" in fh.read()

    def test_run_displays_briefing_for_every_phase(self, tmp_path) -> None:
        rec = _Recorder(answers=["y", "y", "y"])
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path))

        cli.run(state, lambda phase: {})

        # Each phase name must appear in the displayed output.
        for phase in PHASES:
            assert phase.name in rec.text

    def test_run_ordered_flow_satisfies_gates_after_passive(self, tmp_path) -> None:
        """In the canonical order, surface_discovery completes first, so the
        medium/high-risk gates are satisfied and no confirmation is requested
        (Req. 12.5/12.6)."""
        rec = _Recorder()  # no scripted answers: any prompt would default to "n"
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_state(str(tmp_path))

        cli.run(state, lambda phase: {})

        # No confirmation prompt should have been needed.
        assert rec.prompts == []
        # All non-report phases completed (report phase does not ingest).
        for name in (
            "authorization",
            "surface_discovery",
            "passive_checks",
            "endpoint_enumeration",
            "nuclei_and_idor",
            "business_logic",
        ):
            assert name in state.completed_phases

    def test_run_skips_declined_gated_phase(self, tmp_path) -> None:
        """When a gated phase is reached before passive discovery completes and
        the auditor declines, the phase is skipped (Req. 12.6)."""
        rec = _Recorder(answers=["n"])
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        # Pre-mark surface_discovery as NOT done; drive only the gated phase.
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["endpoint_enumeration"]

        # Display + gate only this phase (simulating an out-of-order attempt).
        cli.display_briefing(phase)
        proceeded = cli.check_gate(phase, state)

        assert proceeded is False
        assert "endpoint_enumeration" not in state.completed_phases


# ---------------------------------------------------------------------------
# main() entry point
# ---------------------------------------------------------------------------

class TestMain:
    def test_main_without_args_returns_usage_error(self, capsys) -> None:
        assert main([]) == 2
        captured = capsys.readouterr()
        assert "Usage" in captured.out

    def test_main_with_working_dir_displays_phases(self, tmp_path, capsys) -> None:
        assert main([str(tmp_path)]) == 0
        captured = capsys.readouterr()
        for phase in PHASES:
            assert phase.name in captured.out
