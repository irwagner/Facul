"""
End-to-end integration test for the iterative seven-phase audit flow (task 15.4).

Drives the *entire* flow through the real :class:`~toolkit.cli.IterativeAuditCLI`
and :class:`~toolkit.orchestrator.PhaseOrchestrator`, exercising the genuine
check and classifier code, while mocking only the external boundaries:

* the network layer (``requests.get`` used by the passive security-headers
  check), and
* the subprocess layer (``subprocess.run`` used by the Nuclei adapter).

What is verified (Req. 12.1–12.5):

* Req. 12.1 — the per-phase briefing (objective, exact commands, collection
  instructions) is displayed before every phase.
* Req. 12.2 — phase results are ingested, classified and summarised
  (PhaseAnalysis with summary, confidence, estimated severity, next steps and
  the exact commands of the following phase).
* Req. 12.3 — the session state is persisted to ``session.json`` (completed
  phases, accumulated findings, ISO 8601 operation timestamps).
* Req. 12.4 — an existing session can be resumed from disk with its completed
  phases and recorded findings intact.
* Req. 12.5 / 12.6 — per-phase risk gating: in canonical order the passive
  discovery phase completes first so the medium/high-risk gates pass without a
  prompt; out of order, a gated phase requires explicit confirmation.

The final report-generation phase produces ``report.md`` / ``report.html``.

No real network access or subprocess execution happens during the test.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime
from types import SimpleNamespace
from unittest.mock import patch

from toolkit.analysis.classifiers.headers import analyze_headers
from toolkit.cli import IterativeAuditCLI
from toolkit.execution.checks.headers import check_security_headers
from toolkit.execution.nuclei_adapter import NucleiAdapter
from toolkit.models import Authorization, SessionState
from toolkit.orchestrator import PHASES, PhaseOrchestrator
from toolkit.session import SESSION_FILE_NAME, SessionManager

_PHASE_BY_NAME = {p.name: p for p in PHASES}

# A single Nuclei JSONL record returned by the (mocked) subprocess run.
_NUCLEI_JSONL = json.dumps(
    {
        "template-id": "http/exposed-panels/example-panel",
        "host": "example.com",
        "matched-at": "https://example.com/admin",
        "info": {
            "name": "Example Admin Panel Exposure",
            "severity": "high",
            "tags": ["panel", "exposure"],
        },
        "severity": "high",
        "name": "Example Admin Panel Exposure",
        "tags": ["panel", "exposure"],
        "timestamp": "2024-01-15T10:00:00Z",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_authorized_state(working_dir: str) -> SessionState:
    """Build a fresh, authorised session state rooted at *working_dir*."""
    auth = Authorization(
        domain="example.com",
        institution="Test University",
        auth_date=date(2024, 1, 15),
        authorized_domains=["example.com"],
        authorized_cidrs=[],
    )
    return SessionState(
        authorization=auth,
        working_dir=working_dir,
        completed_phases=[],
        findings=[],
        tested_targets=[],
        surface_map=None,
        operations_log=[],
    )


class _FakeHTTPResponse:
    """Minimal stand-in for a ``requests.Response`` (only ``.headers`` used)."""

    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


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


def _make_results_provider(subprocess_calls: list[list[str]]):
    """
    Build a ``results_provider`` that runs the *real* checks/classifiers under
    mocked network/subprocess boundaries.

    * ``passive_checks`` runs the genuine security-headers check (network
      mocked) and classifies the result into findings.
    * ``nuclei_and_idor`` runs the genuine Nuclei adapter (subprocess mocked)
      and maps the parsed output into findings.
    * other phases return empty results.

    ``subprocess_calls`` records the argv of each mocked subprocess invocation
    so the test can assert the subprocess boundary was actually exercised.
    """

    def provider(phase):
        if phase.name == "passive_checks":
            # Mock the network: respond with only a Content-Type header so the
            # classifier flags the missing security headers.
            fake_response = _FakeHTTPResponse({"Content-Type": "text/html"})
            with patch(
                "toolkit.execution.checks.headers.requests.get",
                return_value=fake_response,
            ) as mock_get:
                result = check_security_headers("https://example.com")
                assert mock_get.called  # network boundary exercised
            findings = analyze_headers(result)
            return {"findings": findings}

        if phase.name == "nuclei_and_idor":
            adapter = NucleiAdapter()

            def _fake_run(cmd, *args, **kwargs):
                subprocess_calls.append(list(cmd))
                return SimpleNamespace(stdout="", stderr="", returncode=0)

            with patch(
                "toolkit.execution.nuclei_adapter.subprocess.run",
                side_effect=_fake_run,
            ) as mock_run:
                adapter.run("https://example.com", ["cve", "misconfig"])
                assert mock_run.called  # subprocess boundary exercised

            nuclei_findings = adapter.parse_output(_NUCLEI_JSONL)
            return {"nuclei_findings": nuclei_findings}

        return {}

    return provider


# ---------------------------------------------------------------------------
# End-to-end flow tests
# ---------------------------------------------------------------------------


class TestPhaseFlowEndToEnd:
    """Drive the full seven-phase flow end to end via the CLI/orchestrator."""

    def test_full_flow_gating_persistence_and_report(self, tmp_path) -> None:
        """
        Canonical end-to-end run (Req. 12.1, 12.2, 12.3, 12.5):

        * every phase briefing is displayed,
        * passive findings (headers) and Nuclei findings are ingested and
          classified,
        * no gate prompt is needed because surface_discovery completes first,
        * the session is persisted, and the final report is generated.
        """
        working_dir = str(tmp_path)
        subprocess_calls: list[list[str]] = []
        # No scripted answers: any unexpected prompt defaults to "n" (decline),
        # which would skip phases and fail the completeness assertions below.
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_authorized_state(working_dir)

        provider = _make_results_provider(subprocess_calls)
        result_state = cli.run(state, provider)

        # --- Req. 12.1: every phase briefing displayed ----------------------
        for phase in PHASES:
            briefing = PhaseOrchestrator().describe_phase(phase)
            assert phase.name in rec.text
            assert briefing.objective in rec.text
            for cmd in briefing.commands:
                assert cmd in rec.text
            assert briefing.collection_instructions in rec.text

        # --- Req. 12.5/12.6: canonical order needs no confirmation ----------
        assert rec.prompts == []

        # --- Subprocess boundary actually exercised (mocked Nuclei) ---------
        assert subprocess_calls, "Nuclei subprocess.run was never invoked"
        assert subprocess_calls[0][0] == "nuclei"

        # --- Req. 12.2 + 12.3: findings classified and accumulated ----------
        # Passive headers check produced medium-severity findings.
        assert any(f.severity == "medium" for f in result_state.findings)
        # Nuclei finding was mapped into the standard format.
        assert any(
            f.id == "NUCLEI-http/exposed-panels/example-panel"
            for f in result_state.findings
        )

        # All non-report phases were completed and recorded.
        for name in (
            "authorization",
            "surface_discovery",
            "passive_checks",
            "endpoint_enumeration",
            "nuclei_and_idor",
            "business_logic",
        ):
            assert name in result_state.completed_phases

        # --- Req. 12.3: state persisted to session.json ---------------------
        session_path = os.path.join(working_dir, SESSION_FILE_NAME)
        assert os.path.exists(session_path)
        with open(session_path, encoding="utf-8") as fh:
            raw = json.load(fh)
        assert "passive_checks" in raw["completed_phases"]
        assert raw["operations_log"], "no operations recorded"
        # Every operation timestamp must parse as ISO 8601.
        for op in raw["operations_log"]:
            assert datetime.fromisoformat(op["timestamp"]) is not None

        # --- Report generation: artefacts created and contain findings ------
        md_path = os.path.join(working_dir, "report.md")
        html_path = os.path.join(working_dir, "report.html")
        assert os.path.exists(md_path)
        assert os.path.exists(html_path)
        with open(md_path, encoding="utf-8") as fh:
            md_content = fh.read()
        assert "NUCLEI-http/exposed-panels/example-panel" in md_content
        with open(html_path, encoding="utf-8") as fh:
            html_content = fh.read()
        assert "<!DOCTYPE html>" in html_content

    def test_session_can_be_resumed_from_disk(self, tmp_path) -> None:
        """
        Req. 12.3/12.4: after running the flow, a brand-new orchestrator can
        resume the session from disk with completed phases and findings intact.
        """
        working_dir = str(tmp_path)
        subprocess_calls: list[list[str]] = []
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_authorized_state(working_dir)

        cli.run(state, _make_results_provider(subprocess_calls))

        # Fresh orchestrator + manager — simulate resuming a later session.
        resumed = PhaseOrchestrator().resume_session(working_dir)

        assert "passive_checks" in resumed.completed_phases
        assert "nuclei_and_idor" in resumed.completed_phases
        assert resumed.authorization.domain == "example.com"
        # Findings recorded during the run survived the round-trip.
        assert any(
            f.id == "NUCLEI-http/exposed-panels/example-panel"
            for f in resumed.findings
        )
        assert len(resumed.findings) == len(state.findings)

    def test_out_of_order_gated_phase_requires_confirmation(self, tmp_path) -> None:
        """
        Req. 12.5/12.6: attempting a medium/high-risk phase before the passive
        discovery phase completes triggers a confirmation warning. Declining
        skips the phase; it is not recorded as completed.
        """
        working_dir = str(tmp_path)
        rec = _Recorder(answers=["n"])  # decline the confirmation
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_authorized_state(working_dir)  # surface_discovery NOT done

        phase = _PHASE_BY_NAME["business_logic"]  # high risk
        cli.display_briefing(phase)
        proceeded = cli.check_gate(phase, state)

        assert proceeded is False
        assert rec.prompts, "expected a confirmation prompt"
        assert "WARNING" in rec.text
        assert "business_logic" not in state.completed_phases

    def test_out_of_order_gated_phase_proceeds_on_confirmation(self, tmp_path) -> None:
        """
        Req. 12.6: when the auditor explicitly confirms, the gated phase
        proceeds, its results are ingested and the phase is recorded.
        """
        working_dir = str(tmp_path)
        rec = _Recorder(answers=["y"])  # confirm
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_authorized_state(working_dir)

        phase = _PHASE_BY_NAME["endpoint_enumeration"]  # medium risk
        cli.display_briefing(phase)
        assert cli.check_gate(phase, state) is True

        analysis = cli.ingest(phase, {}, state)
        assert analysis is not None
        assert "endpoint_enumeration" in state.completed_phases
        # Persisted to disk as part of ingestion.
        reloaded = SessionManager().load(working_dir)
        assert "endpoint_enumeration" in reloaded.completed_phases

    def test_empty_session_generates_report_without_findings(self, tmp_path) -> None:
        """
        Req. 11.7 via the flow: a run that yields no findings still produces a
        valid report noting that no vulnerabilities were identified.
        """
        working_dir = str(tmp_path)
        rec = _Recorder()
        cli = IterativeAuditCLI(output_fn=rec.out, input_fn=rec.inp)
        state = _make_authorized_state(working_dir)

        # Provider returns no findings for any phase.
        cli.run(state, lambda phase: {})

        md_path = os.path.join(working_dir, "report.md")
        assert os.path.exists(md_path)
        with open(md_path, encoding="utf-8") as fh:
            md_content = fh.read()
        assert "Nenhuma vulnerabilidade foi identificada" in md_content
        assert state.findings == []
