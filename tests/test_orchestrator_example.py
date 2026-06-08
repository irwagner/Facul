"""
Example tests for PhaseOrchestrator — phase briefings and session resumption.

Covers Req. 12.1 (describe_phase: objective, commands, collection instructions),
Req. 12.4 (resume_session: loads saved state and presents completed-phase summary),
and Req. 12.5 (low-risk phases before medium/high-risk phases; order reflected in
briefing collection instructions for MEDIUM/HIGH phases).
"""

from __future__ import annotations

import json
import os
from datetime import date

import pytest

from toolkit.exceptions import SessionPersistenceError
from toolkit.models import Authorization, Finding, SessionState
from toolkit.orchestrator import PHASES, PhaseOrchestrator, PhaseBriefing
from toolkit.session import SESSION_FILE_NAME, SessionManager


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _make_auth(domain: str = "example.com") -> Authorization:
    return Authorization(
        domain=domain,
        institution="Test University",
        auth_date=date(2024, 1, 15),
        authorized_domains=[domain],
        authorized_cidrs=[],
    )


def _make_minimal_state(working_dir: str, domain: str = "example.com") -> SessionState:
    return SessionState(
        authorization=_make_auth(domain),
        working_dir=working_dir,
        completed_phases=[],
        findings=[],
        tested_targets=[],
        surface_map=None,
        operations_log=[],
    )


def _make_state_with_phases_and_findings(working_dir: str) -> SessionState:
    """Return a richer SessionState with phases completed and findings recorded."""
    finding = Finding(
        id="SRCMAP-001",
        title="Source map exposed",
        summary="A JavaScript source map is publicly accessible.",
        severity="high",
        confidence="high",
        status="confirmed",
        affected_endpoint="https://example.com/app.js.map",
        evidence='{"sources":["src/App.jsx"]}',
        impact="Source code disclosure.",
        remediation="Remove .map files from production builds.",
        next_steps=["Verify removal", "Rotate secrets"],
        references=["CWE-200"],
    )
    return SessionState(
        authorization=_make_auth(),
        working_dir=working_dir,
        completed_phases=["authorization", "surface_discovery", "passive_checks"],
        findings=[finding],
        tested_targets=["example.com"],
        surface_map=None,
        operations_log=[],
    )


# ---------------------------------------------------------------------------
# Tests: describe_phase — structure (Req. 12.1)
# ---------------------------------------------------------------------------

class TestDescribePhaseStructure:
    """
    Every canonical phase briefing must expose a non-empty objective, at
    least one command, and non-empty collection instructions (Req. 12.1).
    """

    def setup_method(self) -> None:
        self.orchestrator = PhaseOrchestrator()

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_briefing_is_phase_briefing_instance(self, phase) -> None:
        """describe_phase always returns a PhaseBriefing."""
        briefing = self.orchestrator.describe_phase(phase)
        assert isinstance(briefing, PhaseBriefing)

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_phase_name_matches(self, phase) -> None:
        """briefing.phase_name must match the phase it was requested for."""
        briefing = self.orchestrator.describe_phase(phase)
        assert briefing.phase_name == phase.name

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_objective_is_non_empty_string(self, phase) -> None:
        """Every phase must have a non-empty, descriptive objective."""
        briefing = self.orchestrator.describe_phase(phase)
        assert isinstance(briefing.objective, str)
        assert len(briefing.objective.strip()) > 0, (
            f"Phase '{phase.name}' has an empty objective"
        )

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_commands_is_non_empty_list(self, phase) -> None:
        """Every phase must provide at least one command."""
        briefing = self.orchestrator.describe_phase(phase)
        assert isinstance(briefing.commands, list)
        assert len(briefing.commands) >= 1, (
            f"Phase '{phase.name}' must have at least one command"
        )

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_each_command_is_non_empty_string(self, phase) -> None:
        """Every individual command must be a non-empty string."""
        briefing = self.orchestrator.describe_phase(phase)
        for cmd in briefing.commands:
            assert isinstance(cmd, str)
            assert len(cmd.strip()) > 0, (
                f"Phase '{phase.name}' has a blank command entry"
            )

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_collection_instructions_is_non_empty_string(self, phase) -> None:
        """Every phase must explain how to collect and provide results."""
        briefing = self.orchestrator.describe_phase(phase)
        assert isinstance(briefing.collection_instructions, str)
        assert len(briefing.collection_instructions.strip()) > 0, (
            f"Phase '{phase.name}' has empty collection_instructions"
        )

    def test_all_seven_phases_have_briefings(self) -> None:
        """Every one of the seven canonical phases must have a briefing."""
        assert len(PHASES) == 7
        for phase in PHASES:
            # Must not raise KeyError
            briefing = self.orchestrator.describe_phase(phase)
            assert briefing is not None


# ---------------------------------------------------------------------------
# Tests: describe_phase — content per phase (Req. 12.1)
# ---------------------------------------------------------------------------

class TestDescribePhaseContent:
    """
    Phase-specific content checks: each briefing must mention domain-relevant
    concepts so that auditors receive contextualised guidance (Req. 12.1).
    """

    def setup_method(self) -> None:
        self.orchestrator = PhaseOrchestrator()
        self.phase_by_name = {p.name: p for p in PHASES}

    # --- authorization (Phase 0) ---

    def test_authorization_objective_mentions_authorization(self) -> None:
        phase = self.phase_by_name["authorization"]
        briefing = self.orchestrator.describe_phase(phase)
        assert "authorization" in briefing.objective.lower() or "authoriz" in briefing.objective.lower()

    def test_authorization_commands_mention_register_or_domain(self) -> None:
        phase = self.phase_by_name["authorization"]
        briefing = self.orchestrator.describe_phase(phase)
        combined = " ".join(briefing.commands).lower()
        assert "domain" in combined or "register" in combined or "auth" in combined

    # --- surface_discovery (Phase 1) ---

    def test_surface_discovery_objective_mentions_passive_discovery(self) -> None:
        phase = self.phase_by_name["surface_discovery"]
        briefing = self.orchestrator.describe_phase(phase)
        obj_lower = briefing.objective.lower()
        # Objective must mention subdomain/discovery/attack surface concepts
        assert any(kw in obj_lower for kw in ["subdomain", "surface", "passive", "dns"]), (
            f"surface_discovery objective should mention subdomain/surface/passive/DNS: "
            f"{briefing.objective!r}"
        )

    def test_surface_discovery_commands_include_port_scanning(self) -> None:
        phase = self.phase_by_name["surface_discovery"]
        briefing = self.orchestrator.describe_phase(phase)
        combined = " ".join(briefing.commands).lower()
        # Port scanning is part of Phase 1 (Req. 2.3)
        assert "nmap" in combined or "scan" in combined or "port" in combined

    def test_surface_discovery_collection_mentions_surface_map(self) -> None:
        phase = self.phase_by_name["surface_discovery"]
        briefing = self.orchestrator.describe_phase(phase)
        instr_lower = briefing.collection_instructions.lower()
        assert any(kw in instr_lower for kw in ["surface", "map", "subdomains", "hosts"]), (
            f"surface_discovery collection_instructions should mention surface map: "
            f"{briefing.collection_instructions!r}"
        )

    # --- passive_checks (Phase 2) ---

    def test_passive_checks_objective_mentions_passive_checks(self) -> None:
        phase = self.phase_by_name["passive_checks"]
        briefing = self.orchestrator.describe_phase(phase)
        obj_lower = briefing.objective.lower()
        assert any(kw in obj_lower for kw in ["passive", "source map", "secret", "header"]), (
            f"passive_checks objective should mention passive/source map/secrets/headers: "
            f"{briefing.objective!r}"
        )

    def test_passive_checks_commands_cover_main_passive_checks(self) -> None:
        phase = self.phase_by_name["passive_checks"]
        briefing = self.orchestrator.describe_phase(phase)
        combined = " ".join(briefing.commands).lower()
        # Must cover source maps, secrets/bundle, and headers
        checks_covered = sum([
            "source" in combined or "map" in combined,
            "secret" in combined or "bundle" in combined,
            "header" in combined or "cdn" in combined,
        ])
        assert checks_covered >= 2, (
            f"passive_checks commands should cover at least 2 of: source maps, "
            f"secrets/bundle, headers/CDN. Got: {briefing.commands}"
        )

    # --- endpoint_enumeration (Phase 3) ---

    def test_endpoint_enumeration_objective_mentions_enumeration(self) -> None:
        phase = self.phase_by_name["endpoint_enumeration"]
        briefing = self.orchestrator.describe_phase(phase)
        obj_lower = briefing.objective.lower()
        assert any(kw in obj_lower for kw in ["enumerate", "endpoint", "wordlist", "directory"]), (
            f"endpoint_enumeration objective should mention enumeration concepts: "
            f"{briefing.objective!r}"
        )

    def test_endpoint_enumeration_collection_mentions_medium_risk(self) -> None:
        """
        Req. 12.5: Medium-risk phases should note in collection instructions
        that low-risk (surface discovery) phase is recommended first.
        """
        phase = self.phase_by_name["endpoint_enumeration"]
        briefing = self.orchestrator.describe_phase(phase)
        instr_lower = briefing.collection_instructions.lower()
        # Must mention MEDIUM risk or the recommended ordering
        assert any(kw in instr_lower for kw in ["medium", "risk", "recommended", "discovery"]), (
            f"endpoint_enumeration collection_instructions should warn about MEDIUM risk "
            f"or ordering recommendation: {briefing.collection_instructions!r}"
        )

    # --- nuclei_and_idor (Phase 4) ---

    def test_nuclei_and_idor_commands_include_nuclei(self) -> None:
        phase = self.phase_by_name["nuclei_and_idor"]
        briefing = self.orchestrator.describe_phase(phase)
        combined = " ".join(briefing.commands).lower()
        assert "nuclei" in combined, (
            f"nuclei_and_idor commands must mention nuclei: {briefing.commands}"
        )

    def test_nuclei_and_idor_commands_include_idor_check(self) -> None:
        phase = self.phase_by_name["nuclei_and_idor"]
        briefing = self.orchestrator.describe_phase(phase)
        combined = " ".join(briefing.commands).lower()
        assert "idor" in combined or "check-idor" in combined, (
            f"nuclei_and_idor commands must mention IDOR check: {briefing.commands}"
        )

    def test_nuclei_and_idor_collection_mentions_medium_risk(self) -> None:
        """Req. 12.5: collection instructions for MEDIUM-risk phase warn about ordering."""
        phase = self.phase_by_name["nuclei_and_idor"]
        briefing = self.orchestrator.describe_phase(phase)
        instr_lower = briefing.collection_instructions.lower()
        assert any(kw in instr_lower for kw in ["medium", "risk", "recommended", "discovery"]), (
            f"nuclei_and_idor collection_instructions should warn about MEDIUM risk: "
            f"{briefing.collection_instructions!r}"
        )

    # --- business_logic (Phase 5) ---

    def test_business_logic_objective_mentions_business_logic(self) -> None:
        phase = self.phase_by_name["business_logic"]
        briefing = self.orchestrator.describe_phase(phase)
        obj_lower = briefing.objective.lower()
        assert any(kw in obj_lower for kw in ["business logic", "withdrawal", "deposit", "race"]), (
            f"business_logic objective should mention business logic concepts: "
            f"{briefing.objective!r}"
        )

    def test_business_logic_objective_mentions_test_values(self) -> None:
        """Req. 9.1: objective should reference the fixed set of manipulation values."""
        phase = self.phase_by_name["business_logic"]
        briefing = self.orchestrator.describe_phase(phase)
        # At least one of the canonical test values is mentioned
        assert any(v in briefing.objective for v in ["-1", "0.000000001", "9007199254740991", "'abc'"]), (
            f"business_logic objective should mention manipulation test values: "
            f"{briefing.objective!r}"
        )

    def test_business_logic_collection_mentions_high_risk(self) -> None:
        """Req. 12.5: HIGH-risk phase must note ordering recommendation."""
        phase = self.phase_by_name["business_logic"]
        briefing = self.orchestrator.describe_phase(phase)
        instr_lower = briefing.collection_instructions.lower()
        assert any(kw in instr_lower for kw in ["high", "risk", "recommended", "discovery"]), (
            f"business_logic collection_instructions should warn about HIGH risk: "
            f"{briefing.collection_instructions!r}"
        )

    # --- report_generation (Phase 6) ---

    def test_report_generation_objective_mentions_report(self) -> None:
        phase = self.phase_by_name["report_generation"]
        briefing = self.orchestrator.describe_phase(phase)
        obj_lower = briefing.objective.lower()
        assert any(kw in obj_lower for kw in ["report", "finding", "markdown", "html"]), (
            f"report_generation objective should mention report concepts: "
            f"{briefing.objective!r}"
        )

    def test_report_generation_collection_mentions_output_formats(self) -> None:
        """Req. 11.4: report output must be in Markdown and HTML."""
        phase = self.phase_by_name["report_generation"]
        briefing = self.orchestrator.describe_phase(phase)
        instr_lower = briefing.collection_instructions.lower()
        assert "html" in instr_lower or "markdown" in instr_lower or ".md" in instr_lower, (
            f"report_generation collection_instructions should mention output formats: "
            f"{briefing.collection_instructions!r}"
        )


# ---------------------------------------------------------------------------
# Tests: resume_session — summary of completed phases and findings (Req. 12.4)
# ---------------------------------------------------------------------------

class TestResumeSession:
    """
    When the auditor resumes an existing session, the Toolkit must load the
    saved state correctly (Req. 12.4).  The summary of completed phases and
    recorded findings is derived from the returned SessionState.
    """

    def setup_method(self) -> None:
        self.orchestrator = PhaseOrchestrator()

    def test_resume_returns_session_state(self, tmp_path) -> None:
        """resume_session must return a SessionState instance."""
        state = _make_minimal_state(str(tmp_path))
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert isinstance(resumed, SessionState)

    def test_resume_restores_authorization(self, tmp_path) -> None:
        """The authorization block must survive the save/resume round-trip."""
        state = _make_minimal_state(str(tmp_path), domain="audit.example.org")
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert resumed.authorization.domain == "audit.example.org"
        assert resumed.authorization.institution == "Test University"

    def test_resume_restores_completed_phases(self, tmp_path) -> None:
        """Completed phases recorded in the session must be present after resume."""
        state = _make_state_with_phases_and_findings(str(tmp_path))
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert "authorization" in resumed.completed_phases
        assert "surface_discovery" in resumed.completed_phases
        assert "passive_checks" in resumed.completed_phases

    def test_resume_restores_findings_count(self, tmp_path) -> None:
        """All findings accumulated in the session must be present after resume."""
        state = _make_state_with_phases_and_findings(str(tmp_path))
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert len(resumed.findings) == 1

    def test_resume_restores_finding_details(self, tmp_path) -> None:
        """Finding attributes (id, severity, status) must be preserved."""
        state = _make_state_with_phases_and_findings(str(tmp_path))
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        f = resumed.findings[0]
        assert f.id == "SRCMAP-001"
        assert f.severity == "high"
        assert f.status == "confirmed"
        assert f.affected_endpoint == "https://example.com/app.js.map"

    def test_resume_restores_tested_targets(self, tmp_path) -> None:
        """Tested targets must be preserved across save/resume."""
        state = _make_state_with_phases_and_findings(str(tmp_path))
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert "example.com" in resumed.tested_targets

    def test_resume_raises_when_no_session_exists(self, tmp_path) -> None:
        """Resuming from a directory without session.json must raise SessionPersistenceError."""
        with pytest.raises(SessionPersistenceError) as exc_info:
            self.orchestrator.resume_session(str(tmp_path))

        assert SESSION_FILE_NAME in exc_info.value.path
        assert exc_info.value.reason == "File not found"

    def test_resume_preserves_working_dir(self, tmp_path) -> None:
        """working_dir stored in the session must survive the round-trip."""
        state = _make_minimal_state(str(tmp_path))
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert resumed.working_dir == str(tmp_path)

    def test_resume_with_no_completed_phases(self, tmp_path) -> None:
        """A fresh session with no completed phases must resume to an empty list."""
        state = _make_minimal_state(str(tmp_path))
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert resumed.completed_phases == []
        assert resumed.findings == []

    def test_resume_with_multiple_findings(self, tmp_path) -> None:
        """All findings from a multi-finding session must be restored."""
        finding1 = Finding(
            id="SRCMAP-001",
            title="Source map exposed",
            summary="JS source map publicly accessible.",
            severity="high",
            confidence="high",
            status="confirmed",
            affected_endpoint="https://example.com/app.js.map",
            evidence='{"sources":["src/App.jsx"]}',
            impact="Source code disclosure.",
            remediation="Remove .map files.",
            next_steps=[],
            references=["CWE-200"],
        )
        finding2 = Finding(
            id="HDRCHK-001",
            title="Missing Content-Security-Policy",
            summary="CSP header not set.",
            severity="medium",
            confidence="high",
            status="confirmed",
            affected_endpoint="https://example.com/",
            evidence="CSP header absent",
            impact="XSS risk.",
            remediation="Add Content-Security-Policy header.",
            next_steps=["Add CSP directive"],
            references=["CWE-693"],
        )
        state = SessionState(
            authorization=_make_auth(),
            working_dir=str(tmp_path),
            completed_phases=["authorization", "surface_discovery", "passive_checks"],
            findings=[finding1, finding2],
            tested_targets=["example.com"],
            surface_map=None,
            operations_log=[],
        )
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert len(resumed.findings) == 2
        ids = {f.id for f in resumed.findings}
        assert "SRCMAP-001" in ids
        assert "HDRCHK-001" in ids

    def test_resume_summary_reflects_phase_count(self, tmp_path) -> None:
        """
        The number of completed phases in the resumed state must equal the
        number that was saved — auditors use this to know where they left off.
        """
        state = _make_state_with_phases_and_findings(str(tmp_path))
        num_saved = len(state.completed_phases)
        SessionManager().save(state, str(tmp_path))

        resumed = self.orchestrator.resume_session(str(tmp_path))
        assert len(resumed.completed_phases) == num_saved


# ---------------------------------------------------------------------------
# Tests: describe_phase — idempotency and determinism
# ---------------------------------------------------------------------------

class TestDescribePhaseIdempotency:
    """
    describe_phase must be pure and deterministic: calling it multiple times
    for the same phase must always return an equivalent briefing.
    """

    def setup_method(self) -> None:
        self.orchestrator = PhaseOrchestrator()

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_describe_phase_is_idempotent(self, phase) -> None:
        """Calling describe_phase twice yields equal PhaseBriefings."""
        b1 = self.orchestrator.describe_phase(phase)
        b2 = self.orchestrator.describe_phase(phase)
        assert b1 == b2, (
            f"describe_phase('{phase.name}') returned different results on second call"
        )

    @pytest.mark.parametrize("phase", PHASES, ids=lambda p: p.name)
    def test_describe_phase_from_two_orchestrators(self, phase) -> None:
        """Two independent PhaseOrchestrator instances return equal briefings."""
        orch1 = PhaseOrchestrator()
        orch2 = PhaseOrchestrator()
        assert orch1.describe_phase(phase) == orch2.describe_phase(phase)
