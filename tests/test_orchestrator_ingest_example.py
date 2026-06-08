"""
Example tests for PhaseOrchestrator.ingest_phase_results wiring (task 15.1).

Covers the integration of the orchestrator with the Analyzer and the
SessionManager:

* Req. 12.2 — ingesting results delegates to the Analyzer and returns a
  PhaseAnalysis with summary, confidence, estimated severity, next steps and
  the exact commands for the following phase.
* Req. 12.3 — the SessionState is updated (completed phase recorded, findings
  accumulated, an ISO 8601 OperationRecord appended) and persisted to disk.
"""

from __future__ import annotations

from datetime import date, datetime

from toolkit.models import (
    Authorization,
    Finding,
    NucleiFinding,
    PhaseAnalysis,
    SessionState,
)
from toolkit.orchestrator import PHASES, PhaseOrchestrator
from toolkit.session import SessionManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PHASE_BY_NAME = {p.name: p for p in PHASES}


def _make_state(working_dir: str) -> SessionState:
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


def _make_finding(fid: str = "SRCMAP-001", severity: str = "high",
                  confidence: str = "high", status: str = "confirmed") -> Finding:
    return Finding(
        id=fid,
        title="Source map exposed",
        summary="A JavaScript source map is publicly accessible.",
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        affected_endpoint="https://example.com/app.js.map",
        evidence='{"sources":["src/App.jsx"]}',
        impact="Source code disclosure.",
        remediation="Remove .map files from production builds.",
        next_steps=["Verify removal", "Rotate secrets"],
        references=["CWE-200"],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIngestPhaseResults:
    def setup_method(self) -> None:
        self.orchestrator = PhaseOrchestrator()

    def test_returns_phase_analysis(self, tmp_path) -> None:
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]
        result = self.orchestrator.ingest_phase_results(
            phase, {"findings": [_make_finding()]}, state
        )
        assert isinstance(result, PhaseAnalysis)

    def test_analysis_fields_populated(self, tmp_path) -> None:
        """Req. 12.2: summary, confidence, estimated severity and next steps populated."""
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]
        result = self.orchestrator.ingest_phase_results(
            phase, {"findings": [_make_finding()]}, state
        )
        assert result.summary.strip()
        assert result.confidence == "high"
        assert result.estimated_severity == "high"
        assert result.next_steps  # non-empty

    def test_next_phase_commands_present(self, tmp_path) -> None:
        """Req. 12.2: the analysis carries the exact commands for the next phase."""
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]  # next is endpoint_enumeration
        result = self.orchestrator.ingest_phase_results(
            phase, {"findings": [_make_finding()]}, state
        )
        expected = self.orchestrator.describe_phase(
            _PHASE_BY_NAME["endpoint_enumeration"]
        ).commands
        assert result.next_phase_commands == expected

    def test_last_phase_has_no_next_commands(self, tmp_path) -> None:
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["report_generation"]
        result = self.orchestrator.ingest_phase_results(phase, {}, state)
        assert result.next_phase_commands == []

    def test_completed_phase_recorded(self, tmp_path) -> None:
        """Req. 12.3: the ingested phase is added to completed_phases."""
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]
        self.orchestrator.ingest_phase_results(phase, {}, state)
        assert "passive_checks" in state.completed_phases

    def test_completed_phase_not_duplicated(self, tmp_path) -> None:
        state = _make_state(str(tmp_path))
        state.completed_phases.append("passive_checks")
        phase = _PHASE_BY_NAME["passive_checks"]
        self.orchestrator.ingest_phase_results(phase, {}, state)
        assert state.completed_phases.count("passive_checks") == 1

    def test_findings_accumulated(self, tmp_path) -> None:
        """Req. 12.3: findings are accumulated into the session state."""
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]
        self.orchestrator.ingest_phase_results(
            phase, {"findings": [_make_finding("A-001"), _make_finding("A-002")]}, state
        )
        ids = {f.id for f in state.findings}
        assert {"A-001", "A-002"} <= ids

    def test_operation_record_appended_iso8601(self, tmp_path) -> None:
        """Req. 12.3: an OperationRecord with an ISO 8601 timestamp is appended."""
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]
        self.orchestrator.ingest_phase_results(phase, {}, state)
        assert len(state.operations_log) == 1
        record = state.operations_log[0]
        assert record.phase == "passive_checks"
        assert record.action == "ingest_phase_results"
        # Must parse as a valid ISO 8601 timestamp
        parsed = datetime.fromisoformat(record.timestamp)
        assert parsed is not None

    def test_state_persisted_to_disk(self, tmp_path) -> None:
        """Req. 12.3: the updated state is persisted and reloadable."""
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]
        self.orchestrator.ingest_phase_results(
            phase, {"findings": [_make_finding("PERSIST-001")]}, state
        )
        reloaded = SessionManager().load(str(tmp_path))
        assert "passive_checks" in reloaded.completed_phases
        assert any(f.id == "PERSIST-001" for f in reloaded.findings)
        assert len(reloaded.operations_log) == 1

    def test_nuclei_findings_mapped(self, tmp_path) -> None:
        """nuclei_findings in raw results are mapped to standard findings via the Analyzer."""
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["nuclei_and_idor"]
        nf = NucleiFinding(
            template_id="cve/CVE-2021-1234",
            host="example.com",
            matched_at="https://example.com/x",
            severity="high",
            name="Example CVE",
            tags=["cve"],
            info={"name": "Example CVE", "severity": "high"},
            timestamp=None,
            extra={},
        )
        self.orchestrator.ingest_phase_results(
            phase, {"nuclei_findings": [nf]}, state
        )
        assert any(f.id == "NUCLEI-cve/CVE-2021-1234" for f in state.findings)

    def test_empty_results_summary(self, tmp_path) -> None:
        state = _make_state(str(tmp_path))
        phase = _PHASE_BY_NAME["passive_checks"]
        result = self.orchestrator.ingest_phase_results(phase, {}, state)
        assert result.estimated_severity == "none"
        assert result.confidence == "low"
        assert result.findings == []
