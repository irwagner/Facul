"""
Property-based tests for SessionManager — round-trip do estado de sessão.

# Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão

**Validates: Requirements 12.3**

Property 25: Round-trip do estado de sessão
-------------------------------------------
Para todo ``SessionState``, salvar em JSON e carregar de volta produz um
objeto equivalente ao original (round-trip), preservando fases concluídas,
findings acumulados, alvos testados e timestamps em formato ISO 8601.
"""

from __future__ import annotations

import re
import tempfile

from hypothesis import given, settings
from hypothesis import HealthCheck

from tests.conftest import session_state_strategy
from toolkit.models import SessionState
from toolkit.session import SessionManager


# ISO 8601 basic pattern (datetime strings produced by datetime.isoformat())
_ISO_8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"          # date part
    r"(T\d{2}:\d{2}:\d{2}"         # optional time part
    r"(\.\d+)?"                     # optional fractional seconds
    r"([+-]\d{2}:\d{2}|Z)?"        # optional timezone offset
    r")?$"
)


def _assert_states_equivalent(original: SessionState, loaded: SessionState) -> None:
    """Helper: assert that two SessionState objects are semantically equivalent."""
    # completed_phases preserved
    assert loaded.completed_phases == original.completed_phases, (
        f"completed_phases mismatch: {loaded.completed_phases!r} != {original.completed_phases!r}"
    )

    # tested_targets preserved
    assert loaded.tested_targets == original.tested_targets, (
        f"tested_targets mismatch: {loaded.tested_targets!r} != {original.tested_targets!r}"
    )

    # findings count preserved
    assert len(loaded.findings) == len(original.findings), (
        f"findings count mismatch: {len(loaded.findings)} != {len(original.findings)}"
    )

    # each finding's key fields preserved
    for i, (orig_f, load_f) in enumerate(zip(original.findings, loaded.findings)):
        assert load_f.id == orig_f.id, f"finding[{i}].id mismatch"
        assert load_f.severity == orig_f.severity, f"finding[{i}].severity mismatch"
        assert load_f.confidence == orig_f.confidence, f"finding[{i}].confidence mismatch"
        assert load_f.status == orig_f.status, f"finding[{i}].status mismatch"
        assert load_f.title == orig_f.title, f"finding[{i}].title mismatch"
        assert load_f.summary == orig_f.summary, f"finding[{i}].summary mismatch"
        assert load_f.evidence == orig_f.evidence, f"finding[{i}].evidence mismatch"
        assert load_f.impact == orig_f.impact, f"finding[{i}].impact mismatch"
        assert load_f.remediation == orig_f.remediation, f"finding[{i}].remediation mismatch"
        assert load_f.next_steps == orig_f.next_steps, f"finding[{i}].next_steps mismatch"
        assert load_f.references == orig_f.references, f"finding[{i}].references mismatch"
        assert load_f.affected_endpoint == orig_f.affected_endpoint, (
            f"finding[{i}].affected_endpoint mismatch"
        )

    # authorization preserved
    assert loaded.authorization.domain == original.authorization.domain
    assert loaded.authorization.institution == original.authorization.institution
    assert loaded.authorization.auth_date == original.authorization.auth_date
    assert loaded.authorization.authorized_domains == original.authorization.authorized_domains
    assert loaded.authorization.authorized_cidrs == original.authorization.authorized_cidrs

    # working_dir preserved
    assert loaded.working_dir == original.working_dir

    # operations_log count and fields preserved
    assert len(loaded.operations_log) == len(original.operations_log), (
        f"operations_log count mismatch: "
        f"{len(loaded.operations_log)} != {len(original.operations_log)}"
    )
    for i, (orig_op, load_op) in enumerate(
        zip(original.operations_log, loaded.operations_log)
    ):
        assert load_op.phase == orig_op.phase, f"operations_log[{i}].phase mismatch"
        assert load_op.action == orig_op.action, f"operations_log[{i}].action mismatch"
        assert load_op.timestamp == orig_op.timestamp, (
            f"operations_log[{i}].timestamp mismatch"
        )


def _collect_timestamps(state: SessionState) -> list[str]:
    """Extract all timestamp strings from a SessionState's operations_log."""
    return [op.timestamp for op in state.operations_log]


class TestProperty25SessionStateRoundTrip:
    """
    Property 25: Round-trip do estado de sessão

    **Validates: Requirements 12.3**

    Saves a SessionState to a temporary directory via SessionManager.save(),
    then loads it back via SessionManager.load() and asserts that:
    1. completed_phases are identical
    2. findings are equivalent (all fields match)
    3. tested_targets are identical
    4. operations_log entries are identical (timestamps preserved as ISO 8601)
    5. authorization fields are identical
    6. working_dir is preserved

    Uses tempfile.TemporaryDirectory() instead of pytest's tmp_path fixture
    to avoid the function-scoped fixture health check from Hypothesis.

    # Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão
    """

    @given(state=session_state_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_save_load_round_trip_preserves_all_fields(
        self, state: SessionState
    ) -> None:
        """
        For every generated SessionState, save() then load() returns an
        equivalent object preserving phases, findings, targets, and authorization.

        # Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão
        """
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as working_dir:
            manager.save(state, working_dir)
            loaded = manager.load(working_dir)
            _assert_states_equivalent(state, loaded)

    @given(state=session_state_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip_preserves_completed_phases(
        self, state: SessionState
    ) -> None:
        """
        completed_phases list is exactly preserved after save+load.

        # Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão
        """
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as working_dir:
            manager.save(state, working_dir)
            loaded = manager.load(working_dir)
            assert loaded.completed_phases == state.completed_phases, (
                f"completed_phases not preserved: "
                f"{loaded.completed_phases!r} != {state.completed_phases!r}"
            )

    @given(state=session_state_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip_preserves_tested_targets(
        self, state: SessionState
    ) -> None:
        """
        tested_targets list is exactly preserved after save+load.

        # Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão
        """
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as working_dir:
            manager.save(state, working_dir)
            loaded = manager.load(working_dir)
            assert loaded.tested_targets == state.tested_targets, (
                f"tested_targets not preserved: "
                f"{loaded.tested_targets!r} != {state.tested_targets!r}"
            )

    @given(state=session_state_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip_preserves_findings_count_and_ids(
        self, state: SessionState
    ) -> None:
        """
        The number of findings and their IDs are exactly preserved after save+load.

        # Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão
        """
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as working_dir:
            manager.save(state, working_dir)
            loaded = manager.load(working_dir)
            assert len(loaded.findings) == len(state.findings), (
                f"findings count not preserved: "
                f"{len(loaded.findings)} != {len(state.findings)}"
            )
            original_ids = [f.id for f in state.findings]
            loaded_ids = [f.id for f in loaded.findings]
            assert loaded_ids == original_ids, (
                f"finding IDs not preserved: {loaded_ids!r} != {original_ids!r}"
            )

    @given(state=session_state_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_round_trip_timestamps_are_iso_8601(
        self, state: SessionState
    ) -> None:
        """
        All timestamps in operations_log are preserved and remain valid ISO 8601
        strings after the round-trip.

        # Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão
        """
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as working_dir:
            manager.save(state, working_dir)
            loaded = manager.load(working_dir)

            original_timestamps = _collect_timestamps(state)
            loaded_timestamps = _collect_timestamps(loaded)

            # Timestamps must be preserved verbatim
            assert loaded_timestamps == original_timestamps, (
                f"timestamps not preserved: {loaded_timestamps!r} != {original_timestamps!r}"
            )

            # Each timestamp must match the ISO 8601 pattern
            for ts in loaded_timestamps:
                assert _ISO_8601_RE.match(ts), (
                    f"Timestamp {ts!r} is not a valid ISO 8601 string after round-trip"
                )

    @given(state=session_state_strategy())
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_double_save_load_is_idempotent(
        self, state: SessionState
    ) -> None:
        """
        Saving and loading twice produces the same result as saving and loading
        once — the operation is idempotent.

        # Feature: web-security-audit-toolkit, Property 25: Round-trip do estado de sessão
        """
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as working_dir:
            # First round-trip
            manager.save(state, working_dir)
            loaded_once = manager.load(working_dir)

            # Second round-trip (save the loaded state, load again)
            manager.save(loaded_once, working_dir)
            loaded_twice = manager.load(working_dir)

            _assert_states_equivalent(loaded_once, loaded_twice)
