"""
Property-based tests for PhaseOrchestrator — phase gating by risk level.

# Feature: web-security-audit-toolkit, Property 26: Gating de fases por nível de risco

**Validates: Requirements 12.6**

Property 26: Gating de fases por nível de risco
------------------------------------------------
Para todo ``SessionState`` e fase solicitada, ``can_enter_phase`` exige
confirmação explícita se e somente se a fase é de risco médio ou alto E a
fase de descoberta passiva (Fase 1) não consta como concluída; quando a fase
passiva está concluída, fases de qualquer nível são liberadas sem aviso de
ordem.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.conftest import session_state_strategy
from toolkit.models import SessionState
from toolkit.orchestrator import (
    PASSIVE_DISCOVERY_PHASE,
    PHASES,
    RiskLevel,
    PhaseOrchestrator,
    Phase,
)


# ---------------------------------------------------------------------------
# Strategy helpers
# ---------------------------------------------------------------------------

# All canonical phases as a strategy
_phase_strategy = st.sampled_from(PHASES)


@st.composite
def _state_with_passive_done(draw: st.DrawFn) -> SessionState:
    """Generate a SessionState that includes the passive discovery phase."""
    state = draw(session_state_strategy())
    # Ensure surface_discovery is in completed_phases
    if PASSIVE_DISCOVERY_PHASE not in state.completed_phases:
        state.completed_phases.append(PASSIVE_DISCOVERY_PHASE)
    return state


@st.composite
def _state_without_passive_done(draw: st.DrawFn) -> SessionState:
    """Generate a SessionState that does NOT include the passive discovery phase."""
    state = draw(session_state_strategy())
    # Remove surface_discovery if present
    state.completed_phases = [
        p for p in state.completed_phases if p != PASSIVE_DISCOVERY_PHASE
    ]
    return state


# ---------------------------------------------------------------------------
# Property 26
# ---------------------------------------------------------------------------

class TestProperty26PhaseGating:
    """
    Property 26: Gating de fases por nível de risco

    **Validates: Requirements 12.6**

    Verifies the biconditional:
        requires_confirmation  ↔  (phase is MEDIUM/HIGH)  ∧  (passive NOT done)
    """

    @given(state=_state_without_passive_done(), phase=_phase_strategy)
    @settings(max_examples=200)
    def test_medium_high_risk_requires_confirmation_when_passive_not_done(
        self, state: SessionState, phase: Phase
    ) -> None:
        """
        When passive discovery is NOT complete:
        - MEDIUM or HIGH risk phases MUST require confirmation.
        - LOW or NONE risk phases MUST NOT require confirmation.

        # Feature: web-security-audit-toolkit, Property 26: Gating de fases por nível de risco
        """
        orchestrator = PhaseOrchestrator()
        result = orchestrator.can_enter_phase(phase, state)

        is_high_risk = phase.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

        if is_high_risk:
            assert result.requires_confirmation, (
                f"Phase '{phase.name}' (risk={phase.risk_level.value}) should require "
                f"confirmation when passive discovery is not complete. "
                f"completed_phases={state.completed_phases}"
            )
        else:
            assert not result.requires_confirmation, (
                f"Phase '{phase.name}' (risk={phase.risk_level.value}) should NOT require "
                f"confirmation regardless of passive discovery status. "
                f"completed_phases={state.completed_phases}"
            )

    @given(state=_state_with_passive_done(), phase=_phase_strategy)
    @settings(max_examples=200)
    def test_no_confirmation_required_when_passive_done(
        self, state: SessionState, phase: Phase
    ) -> None:
        """
        When passive discovery IS complete, ALL phases are cleared without
        requiring confirmation — regardless of risk level.

        # Feature: web-security-audit-toolkit, Property 26: Gating de fases por nível de risco
        """
        orchestrator = PhaseOrchestrator()
        result = orchestrator.can_enter_phase(phase, state)

        assert not result.requires_confirmation, (
            f"Phase '{phase.name}' (risk={phase.risk_level.value}) should NOT require "
            f"confirmation when passive discovery is already complete. "
            f"completed_phases={state.completed_phases}"
        )

    @given(state=session_state_strategy(), phase=_phase_strategy)
    @settings(max_examples=200)
    def test_biconditional_requires_confirmation(
        self, state: SessionState, phase: Phase
    ) -> None:
        """
        Full biconditional property across all generated states:
            result.requires_confirmation  ↔
            (phase.risk_level in {MEDIUM, HIGH})  ∧
            (PASSIVE_DISCOVERY_PHASE not in state.completed_phases)

        # Feature: web-security-audit-toolkit, Property 26: Gating de fases por nível de risco
        """
        orchestrator = PhaseOrchestrator()
        result = orchestrator.can_enter_phase(phase, state)

        passive_done = PASSIVE_DISCOVERY_PHASE in state.completed_phases
        is_high_risk = phase.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

        expected_confirmation = is_high_risk and not passive_done

        assert result.requires_confirmation == expected_confirmation, (
            f"Biconditional violated for phase='{phase.name}' "
            f"(risk={phase.risk_level.value}), "
            f"passive_done={passive_done}. "
            f"Expected requires_confirmation={expected_confirmation}, "
            f"got {result.requires_confirmation}. "
            f"completed_phases={state.completed_phases}"
        )

    @given(state=session_state_strategy(), phase=_phase_strategy)
    @settings(max_examples=200)
    def test_can_enter_phase_always_allows_entry(
        self, state: SessionState, phase: Phase
    ) -> None:
        """
        ``can_enter_phase`` never hard-blocks entry; ``allowed`` is always True.
        The gate only sets ``requires_confirmation`` to signal the auditor.

        # Feature: web-security-audit-toolkit, Property 26: Gating de fases por nível de risco
        """
        orchestrator = PhaseOrchestrator()
        result = orchestrator.can_enter_phase(phase, state)

        assert result.allowed, (
            f"can_enter_phase should always set allowed=True; "
            f"phase='{phase.name}', completed_phases={state.completed_phases}"
        )

    @given(state=session_state_strategy(), phase=_phase_strategy)
    @settings(max_examples=200)
    def test_gate_result_has_non_empty_reason(
        self, state: SessionState, phase: Phase
    ) -> None:
        """
        ``GateResult.reason`` is always a non-empty string describing the decision.

        # Feature: web-security-audit-toolkit, Property 26: Gating de fases por nível de risco
        """
        orchestrator = PhaseOrchestrator()
        result = orchestrator.can_enter_phase(phase, state)

        assert isinstance(result.reason, str) and len(result.reason) > 0, (
            f"GateResult.reason must be a non-empty string; "
            f"phase='{phase.name}', got reason={result.reason!r}"
        )
