"""
PhaseOrchestrator — manages the iterative 7-phase audit flow.

Controls phase sequencing, gating by risk level, session persistence and
delegation to Scanner, Analyzer and Reporter (Req. 12.1, 12.4, 12.5, 12.6).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from toolkit.models import PhaseAnalysis, SessionState


# ---------------------------------------------------------------------------
# PhaseBriefing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PhaseBriefing:
    """
    Briefing displayed to the auditor at the start of each phase (Req. 12.1).

    Attributes
    ----------
    phase_name:
        The internal identifier of the phase.
    objective:
        A plain-language description of what this phase aims to achieve.
    commands:
        Exact commands to be executed during this phase.
    collection_instructions:
        How to collect and provide results back to the Toolkit for analysis.
    """
    phase_name: str
    objective: str
    commands: list[str]
    collection_instructions: str


# ---------------------------------------------------------------------------
# Phase definitions
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Risk level for a phase — used to determine gating requirements."""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Phase:
    """
    Descriptor for one of the seven canonical audit phases.

    Attributes
    ----------
    name:
        Internal identifier stored in ``SessionState.completed_phases``.
    risk_level:
        The risk category used by gating logic (Req. 12.6).
    index:
        Sequential order (0–6).  Phase 1 is the passive discovery gate.
    """
    name: str
    risk_level: RiskLevel
    index: int


# Canonical phase registry — order and names match ``conftest._PHASE_NAMES``
PHASES: list[Phase] = [
    Phase(name="authorization",          risk_level=RiskLevel.NONE,   index=0),
    Phase(name="surface_discovery",      risk_level=RiskLevel.LOW,    index=1),
    Phase(name="passive_checks",         risk_level=RiskLevel.LOW,    index=2),
    Phase(name="endpoint_enumeration",   risk_level=RiskLevel.MEDIUM, index=3),
    Phase(name="nuclei_and_idor",        risk_level=RiskLevel.MEDIUM, index=4),
    Phase(name="business_logic",         risk_level=RiskLevel.HIGH,   index=5),
    Phase(name="report_generation",      risk_level=RiskLevel.NONE,   index=6),
]

#: Name of the passive discovery gate phase (Req. 12.6).
PASSIVE_DISCOVERY_PHASE = "surface_discovery"


# ---------------------------------------------------------------------------
# GateResult
# ---------------------------------------------------------------------------

@dataclass
class GateResult:
    """
    Result of a gating decision for a requested phase.

    Attributes
    ----------
    allowed:
        Whether the phase may proceed without blocking.
    requires_confirmation:
        True when the phase can proceed *after* explicit auditor confirmation.
        Always False when ``allowed`` is False for a hard block.
    reason:
        Human-readable explanation of the gate decision.
    """
    allowed: bool
    requires_confirmation: bool
    reason: str


# ---------------------------------------------------------------------------
# PhaseOrchestrator
# ---------------------------------------------------------------------------

class PhaseOrchestrator:
    """
    Orchestrates the seven-phase iterative audit flow.

    Main responsibility: apply risk-based *gating* so that medium- and
    high-risk phases require explicit confirmation when the passive
    discovery phase has not yet been completed (Req. 12.5, 12.6).
    """

    def can_enter_phase(self, phase: Phase, state: SessionState) -> GateResult:
        """
        Decide whether the auditor may enter *phase* given the current *state*.

        Gating rule (Req. 12.6)
        -----------------------
        Confirmation is required if **both** conditions hold:
        1. The phase risk level is MEDIUM or HIGH.
        2. The passive discovery phase (``surface_discovery``) has **not**
           been recorded as completed in ``state.completed_phases``.

        When the passive discovery phase is complete, all phases are
        allowed without a confirmation warning.

        Parameters
        ----------
        phase:
            The :class:`Phase` the auditor wants to enter.
        state:
            The current :class:`~toolkit.models.SessionState` of the session.

        Returns
        -------
        GateResult
            ``requires_confirmation=True``  ↔  phase is MEDIUM/HIGH and
            passive discovery is not yet completed.
        """
        passive_done = PASSIVE_DISCOVERY_PHASE in state.completed_phases
        is_medium_or_high = phase.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

        if is_medium_or_high and not passive_done:
            return GateResult(
                allowed=True,
                requires_confirmation=True,
                reason=(
                    f"Phase '{phase.name}' is {phase.risk_level.value}-risk. "
                    f"The passive discovery phase (surface_discovery) has not "
                    f"been completed. Proceeding without it is not recommended. "
                    f"Please confirm to continue."
                ),
            )

        return GateResult(
            allowed=True,
            requires_confirmation=False,
            reason=f"Phase '{phase.name}' is cleared to proceed.",
        )

    # Canonical briefings for each audit phase (Req. 12.1)
    _PHASE_BRIEFINGS: dict[str, PhaseBriefing] = {}  # populated below

    def describe_phase(self, phase: Phase) -> PhaseBriefing:
        """
        Return the :class:`PhaseBriefing` for *phase* (Req. 12.1).

        The briefing includes:
        - ``objective``: what the phase aims to achieve.
        - ``commands``: the exact commands the auditor should run.
        - ``collection_instructions``: how to collect and hand back results.

        Parameters
        ----------
        phase:
            The :class:`Phase` whose briefing is requested.

        Returns
        -------
        PhaseBriefing
            A frozen briefing dataclass for the requested phase.

        Raises
        ------
        KeyError
            If *phase* is not in the canonical registry (should not happen
            with the seven canonical phases).
        """
        return self._PHASE_BRIEFINGS[phase.name]

    def start_session(self, working_dir: str) -> SessionState:
        """
        Create a fresh :class:`~toolkit.models.SessionState`.

        Initialises the session with the given *working_dir* and no
        completed phases, findings, or targets (Req. 12.3).

        Parameters
        ----------
        working_dir:
            Filesystem path where the session file and artefacts will be stored.

        Returns
        -------
        SessionState
            A brand-new, unpersisted session state.  The caller is responsible
            for persisting it via :class:`~toolkit.session.SessionManager`.
        """
        from toolkit.models import Authorization
        from datetime import date

        # Placeholder authorization — a real session would register auth first.
        placeholder_auth = Authorization(
            domain="",
            institution="",
            auth_date=date.today(),
            authorized_domains=[],
            authorized_cidrs=[],
        )
        return SessionState(
            authorization=placeholder_auth,
            working_dir=working_dir,
            completed_phases=[],
            findings=[],
            tested_targets=[],
        )

    def resume_session(self, working_dir: str) -> SessionState:
        """
        Load an existing session from *working_dir* via :class:`~toolkit.session.SessionManager`.

        Parameters
        ----------
        working_dir:
            Directory containing ``session.json``.

        Returns
        -------
        SessionState
            The restored session state.
        """
        from toolkit.session import SessionManager
        return SessionManager().load(working_dir)

    def ingest_phase_results(
        self,
        phase: Phase,
        raw_results: dict,
        state: SessionState,
    ) -> PhaseAnalysis:
        """
        Interpret a phase's raw results, update the session and persist it.

        Delegates classification and summarisation to the
        :class:`~toolkit.analysis.analyzer.Analyzer`, then updates *state*
        (records the completed phase, accumulates findings and appends an
        ISO 8601 :class:`~toolkit.models.OperationRecord`) and persists it via
        :class:`~toolkit.session.SessionManager` (Req. 12.2, 12.3).

        Parameters
        ----------
        phase:
            The :class:`Phase` whose results are being ingested.
        raw_results:
            Raw output from the phase. Recognised keys:

            * ``"findings"`` — a list of already-classified
              :class:`~toolkit.models.Finding` objects (or their ``dict``
              form) produced by per-check classifiers.
            * ``"nuclei_findings"`` — a list of
              :class:`~toolkit.models.NucleiFinding` objects (or their ``dict``
              form) to be mapped to standard findings by the Analyzer.

            Other keys are ignored by this generic wiring.
        state:
            The current :class:`~toolkit.models.SessionState`. It is mutated
            in place and persisted before returning.

        Returns
        -------
        PhaseAnalysis
            The aggregated analysis for the phase (Req. 12.2).
        """
        from datetime import datetime, timezone

        from toolkit.analysis.analyzer import Analyzer
        from toolkit.models import Finding, NucleiFinding, OperationRecord
        from toolkit.session import SessionManager

        analyzer = Analyzer()

        # 1. Collect / classify findings from the raw results.
        findings: list[Finding] = []

        for item in raw_results.get("findings", []):
            findings.append(item if isinstance(item, Finding) else Finding.from_dict(item))

        nuclei_raw = raw_results.get("nuclei_findings", [])
        if nuclei_raw:
            nuclei_findings = [
                item if isinstance(item, NucleiFinding) else NucleiFinding.from_dict(item)
                for item in nuclei_raw
            ]
            findings.extend(analyzer.map_nuclei_findings(nuclei_findings))

        # 2. Summarise the phase, including the commands for the next phase.
        analysis = analyzer.summarize_phase(
            findings,
            next_phase_commands=self._next_phase_commands(phase),
        )

        # 3. Update the session state.
        if phase.name not in state.completed_phases:
            state.completed_phases.append(phase.name)
        state.findings.extend(findings)
        state.operations_log.append(
            OperationRecord(
                phase=phase.name,
                action="ingest_phase_results",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
        )

        # 4. Persist the updated session.
        SessionManager().save(state, state.working_dir)

        return analysis

    def _next_phase_commands(self, phase: Phase) -> list[str]:
        """Return the exact commands for the phase following *phase* (Req. 12.2).

        Returns an empty list when *phase* is the last phase in the registry.
        """
        next_index = phase.index + 1
        for candidate in PHASES:
            if candidate.index == next_index:
                return list(self.describe_phase(candidate).commands)
        return []


# ---------------------------------------------------------------------------
# Phase briefings registry — one entry per canonical phase
# ---------------------------------------------------------------------------

PhaseOrchestrator._PHASE_BRIEFINGS = {
    "authorization": PhaseBriefing(
        phase_name="authorization",
        objective=(
            "Register the written authorization for the audit target. "
            "Ensure that domain, institution name, and authorization date "
            "are recorded before any scanning module is started (Req. 1.1)."
        ),
        commands=[
            "toolkit register-auth --domain <target_domain> "
            "--institution '<institution_name>' --date <YYYY-MM-DD>",
        ],
        collection_instructions=(
            "Confirm that the authorization record was saved successfully. "
            "Provide the path to the generated authorization config file as "
            "confirmation that the session can proceed."
        ),
    ),

    "surface_discovery": PhaseBriefing(
        phase_name="surface_discovery",
        objective=(
            "Map the complete attack surface of the target using passive "
            "techniques. Enumerate subdomains via DNS queries and Certificate "
            "Transparency logs, identify active hosts, scan the fixed port set, "
            "and fingerprint technologies (Req. 2.1–2.4)."
        ),
        commands=[
            "subfinder -d <target_domain> -o subdomains.txt",
            "httpx -l subdomains.txt -o active_hosts.txt",
            "nmap -p 80,443,8080,8443,8000,8888,9090,9443,3000,5000 "
            "-iL active_hosts.txt -oN ports.txt",
            "whatweb --input-file active_hosts.txt --log-json tech.json",
        ],
        collection_instructions=(
            "Provide the output files: subdomains.txt, active_hosts.txt, "
            "ports.txt, and tech.json. The Toolkit will build an "
            "AttackSurfaceMap from these results and exclude any out-of-scope "
            "hosts, logging each exclusion with host, reason, and timestamp."
        ),
    ),

    "passive_checks": PhaseBriefing(
        phase_name="passive_checks",
        objective=(
            "Execute passive, read-only security checks: verify whether Vite "
            "source maps are exposed, detect hardcoded secrets and addresses in "
            "JavaScript bundles, perform passive CDN bypass candidate discovery, "
            "and validate HTTP security headers (Req. 4–7)."
        ),
        commands=[
            "curl -s <target_url> | grep -oP 'src=\"[^\"]+\\.js\"' > assets.txt",
            "toolkit check-source-maps --target <target_url> --assets assets.txt",
            "toolkit check-bundle-secrets --target <target_url>",
            "toolkit check-cdn-bypass --domain <target_domain>",
            "toolkit check-headers --domain <target_domain>",
        ],
        collection_instructions=(
            "Run each command and capture its JSON output. Provide all output "
            "files to the Toolkit for analysis. Requests that fail with 403/500 "
            "or timeout will be logged and excluded from the result automatically."
        ),
    ),

    "endpoint_enumeration": PhaseBriefing(
        phase_name="endpoint_enumeration",
        objective=(
            "Enumerate directories, files, and API endpoints using configurable "
            "wordlists (≥100 entries) plus common administrative panel paths. "
            "Record HTTP 200 responses (status, size, title) and 301/302 "
            "redirects (path, status, Location header). Probe API parameters "
            "by varying one parameter at a time (Req. 3.1–3.5)."
        ),
        commands=[
            "ffuf -w /wordlists/common.txt -u <target_url>/FUZZ "
            "-o endpoints.json -of json",
            "toolkit enumerate-params --endpoints endpoints.json "
            "--output params.json",
        ],
        collection_instructions=(
            "Provide endpoints.json and params.json. "
            "NOTE: This is a MEDIUM-risk phase. Completing the surface "
            "discovery phase first is strongly recommended (Req. 12.5)."
        ),
    ),

    "nuclei_and_idor": PhaseBriefing(
        phase_name="nuclei_and_idor",
        objective=(
            "Run Nuclei with relevant tags (cve, misconfig, exposure, headers) "
            "for known vulnerability scanning, and test IDOR vulnerabilities on "
            "transaction and profile endpoints using identifier variations "
            "(Req. 8, 10)."
        ),
        commands=[
            "nuclei -target <target_url> -tags cve,misconfig,exposure,headers "
            "-json -output nuclei_results.jsonl",
            "toolkit check-idor --endpoint <api_endpoint> "
            "--token <auth_token> --output idor_results.json",
        ],
        collection_instructions=(
            "Provide nuclei_results.jsonl and idor_results.json. "
            "NOTE: This is a MEDIUM-risk phase. Completing the surface "
            "discovery phase first is strongly recommended (Req. 12.5). "
            "Ensure the Nuclei binary is available in PATH before running."
        ),
    ),

    "business_logic": PhaseBriefing(
        phase_name="business_logic",
        objective=(
            "Test business logic vulnerabilities in deposit and withdrawal "
            "flows: parameter manipulation with values {-1, 0, 0.000000001, "
            "9007199254740991, 'abc'} and optional race condition test "
            "(3 simultaneous requests). All requests are logged in the audit "
            "log with ISO 8601 timestamp, method, endpoint, masked payload, "
            "status, and body size (Req. 9)."
        ),
        commands=[
            "toolkit check-business-logic --endpoint <withdrawal_endpoint> "
            "--params amount --token <auth_token> --output biz_results.json",
            "toolkit check-business-logic --endpoint <withdrawal_endpoint> "
            "--params amount --token <auth_token> --race --output race_results.json",
        ],
        collection_instructions=(
            "Provide biz_results.json and (if race condition test was enabled) "
            "race_results.json. "
            "NOTE: This is a HIGH-risk phase. Completing the surface discovery "
            "phase first is strongly recommended (Req. 12.5). "
            "Sensitive payload values are automatically masked before logging."
        ),
    ),

    "report_generation": PhaseBriefing(
        phase_name="report_generation",
        objective=(
            "Compile all accumulated findings into a structured technical "
            "report in Markdown and self-contained HTML formats. The report "
            "includes: Cover Page, Executive Summary, Findings Table, Finding "
            "Details, and Recommended Next Steps. Findings are ordered by "
            "descending severity then descending confidence (Req. 11)."
        ),
        commands=[
            "toolkit generate-report --working-dir <working_dir> "
            "--output-dir <output_dir>",
        ],
        collection_instructions=(
            "The Toolkit generates <output_dir>/report.md and "
            "<output_dir>/report.html automatically. "
            "Review the report and share report.html with the institution — "
            "it is self-contained (inline CSS) and requires no external assets."
        ),
    ),
}
