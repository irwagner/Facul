"""
Unit tests for SessionManager (Req. 12.3, 12.4).

Covers:
- save() writes valid JSON that round-trips via load()
- load() raises SessionPersistenceError when file is missing
- save() raises SessionPersistenceError on OSError (unwritable dir)
- load() raises SessionPersistenceError when JSON is invalid
- The error carries the correct path and reason attributes
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile

import pytest

from toolkit.exceptions import SessionPersistenceError
from toolkit.models import Authorization, Finding, SessionState
from toolkit.session import SESSION_FILE_NAME, SessionManager

from datetime import date


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_minimal_state(working_dir: str) -> SessionState:
    """Return a SessionState with minimal data for testing."""
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


def _make_state_with_findings(working_dir: str) -> SessionState:
    """Return a SessionState that includes a Finding and a completed phase."""
    auth = Authorization(
        domain="target.io",
        institution="Security Lab",
        auth_date=date(2023, 6, 1),
        authorized_domains=["target.io", "api.target.io"],
        authorized_cidrs=["10.0.0.0/24"],
    )
    finding = Finding(
        id="SRCMAP-001",
        title="Source map exposed",
        summary="A JavaScript source map is publicly accessible.",
        severity="high",
        confidence="high",
        status="confirmed",
        affected_endpoint="https://target.io/app.js.map",
        evidence='{"sources":["src/App.jsx"]}',
        impact="Source code disclosure.",
        remediation="Remove .map files from production builds.",
        next_steps=["Verify removal", "Rotate secrets"],
        references=["CWE-200"],
    )
    return SessionState(
        authorization=auth,
        working_dir=working_dir,
        completed_phases=["authorization", "surface_discovery"],
        findings=[finding],
        tested_targets=["target.io"],
        surface_map=None,
        operations_log=[],
    )


# ---------------------------------------------------------------------------
# Tests: save + load round-trip
# ---------------------------------------------------------------------------

class TestSaveLoad:
    def test_save_creates_json_file(self, tmp_path):
        state = _make_minimal_state(str(tmp_path))
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        session_file = tmp_path / SESSION_FILE_NAME
        assert session_file.exists(), "session.json should be created after save()"

    def test_saved_file_is_valid_json(self, tmp_path):
        state = _make_minimal_state(str(tmp_path))
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        session_file = tmp_path / SESSION_FILE_NAME
        with open(session_file, encoding="utf-8") as fh:
            data = json.load(fh)  # should not raise

        assert isinstance(data, dict)

    def test_load_restores_minimal_state(self, tmp_path):
        state = _make_minimal_state(str(tmp_path))
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        loaded = manager.load(str(tmp_path))

        assert loaded.authorization.domain == state.authorization.domain
        assert loaded.authorization.institution == state.authorization.institution
        assert loaded.authorization.auth_date == state.authorization.auth_date
        assert loaded.completed_phases == state.completed_phases
        assert loaded.findings == state.findings
        assert loaded.tested_targets == state.tested_targets

    def test_load_restores_findings_and_phases(self, tmp_path):
        state = _make_state_with_findings(str(tmp_path))
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        loaded = manager.load(str(tmp_path))

        assert loaded.completed_phases == ["authorization", "surface_discovery"]
        assert len(loaded.findings) == 1
        f = loaded.findings[0]
        assert f.id == "SRCMAP-001"
        assert f.severity == "high"
        assert f.status == "confirmed"
        assert loaded.tested_targets == ["target.io"]

    def test_round_trip_preserves_auth_domains(self, tmp_path):
        state = _make_state_with_findings(str(tmp_path))
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        loaded = manager.load(str(tmp_path))

        assert loaded.authorization.authorized_domains == ["target.io", "api.target.io"]
        assert loaded.authorization.authorized_cidrs == ["10.0.0.0/24"]

    def test_save_overwrites_existing_session_file(self, tmp_path):
        """Calling save() twice should overwrite the previous file."""
        manager = SessionManager()
        state1 = _make_minimal_state(str(tmp_path))
        manager.save(state1, str(tmp_path))

        state2 = _make_state_with_findings(str(tmp_path))
        manager.save(state2, str(tmp_path))

        loaded = manager.load(str(tmp_path))
        # Should reflect the second save
        assert loaded.authorization.domain == "target.io"
        assert len(loaded.findings) == 1

    def test_session_file_uses_correct_filename(self, tmp_path):
        state = _make_minimal_state(str(tmp_path))
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        assert (tmp_path / "session.json").exists()

    def test_saved_json_uses_indentation(self, tmp_path):
        """The JSON file should use indented formatting (indent=2)."""
        state = _make_minimal_state(str(tmp_path))
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        raw = (tmp_path / SESSION_FILE_NAME).read_text(encoding="utf-8")
        # Indented JSON will contain at least one newline and spaces
        assert "\n" in raw

    def test_saved_json_uses_utf8_non_ascii(self, tmp_path):
        """ensure_ascii=False: non-ASCII chars should be stored as-is."""
        auth = Authorization(
            domain="example.com",
            institution="Universidade São Paulo",
            auth_date=date(2024, 3, 10),
            authorized_domains=["example.com"],
            authorized_cidrs=[],
        )
        state = SessionState(
            authorization=auth,
            working_dir=str(tmp_path),
            completed_phases=[],
            findings=[],
            tested_targets=[],
        )
        manager = SessionManager()
        manager.save(state, str(tmp_path))

        raw = (tmp_path / SESSION_FILE_NAME).read_text(encoding="utf-8")
        assert "São Paulo" in raw, "Non-ASCII institution name should be stored as-is"


# ---------------------------------------------------------------------------
# Tests: load() error cases
# ---------------------------------------------------------------------------

class TestLoadErrors:
    def test_load_raises_when_file_missing(self, tmp_path):
        manager = SessionManager()
        with pytest.raises(SessionPersistenceError) as exc_info:
            manager.load(str(tmp_path))

        err = exc_info.value
        assert SESSION_FILE_NAME in err.path
        assert err.reason == "File not found"
        assert "Session file not found" in err.message

    def test_load_error_path_attribute_is_full_path(self, tmp_path):
        manager = SessionManager()
        expected_path = os.path.join(str(tmp_path), SESSION_FILE_NAME)

        with pytest.raises(SessionPersistenceError) as exc_info:
            manager.load(str(tmp_path))

        assert exc_info.value.path == expected_path

    def test_load_raises_on_invalid_json(self, tmp_path):
        session_file = tmp_path / SESSION_FILE_NAME
        session_file.write_text("this is not valid json {{{{", encoding="utf-8")

        manager = SessionManager()
        with pytest.raises(SessionPersistenceError) as exc_info:
            manager.load(str(tmp_path))

        err = exc_info.value
        assert "Failed to load session from" in err.message
        assert SESSION_FILE_NAME in err.path

    def test_load_raises_on_empty_file(self, tmp_path):
        session_file = tmp_path / SESSION_FILE_NAME
        session_file.write_text("", encoding="utf-8")

        manager = SessionManager()
        with pytest.raises(SessionPersistenceError):
            manager.load(str(tmp_path))


# ---------------------------------------------------------------------------
# Tests: save() error cases
# ---------------------------------------------------------------------------

class TestSaveErrors:
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="chmod-based permission tests behave differently on Windows",
    )
    def test_save_raises_on_oserror(self, tmp_path):
        """Writing to a read-only directory should raise SessionPersistenceError."""
        # Make the directory read-only so open() fails
        tmp_path.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            state = _make_minimal_state(str(tmp_path))
            manager = SessionManager()
            with pytest.raises(SessionPersistenceError) as exc_info:
                manager.save(state, str(tmp_path))

            err = exc_info.value
            assert "Failed to save session to" in err.message
            assert SESSION_FILE_NAME in err.path
            assert err.reason is not None
        finally:
            # Restore permissions so pytest can clean up tmp_path
            tmp_path.chmod(stat.S_IRWXU)

    def test_save_raises_on_nonexistent_directory(self):
        """Saving to a directory that doesn't exist should raise SessionPersistenceError."""
        nonexistent = os.path.join(tempfile.gettempdir(), "nonexistent_audit_dir_xyz_12345")
        # Ensure it really doesn't exist
        assert not os.path.exists(nonexistent)

        state = _make_minimal_state(nonexistent)
        manager = SessionManager()
        with pytest.raises(SessionPersistenceError) as exc_info:
            manager.save(state, nonexistent)

        err = exc_info.value
        assert "Failed to save session to" in err.message
        assert err.path is not None
        assert err.reason is not None

    def test_save_error_is_subclass_of_toolkit_error(self, tmp_path):
        """SessionPersistenceError must be a ToolkitError (hierarchy check)."""
        from toolkit.exceptions import ToolkitError

        nonexistent = os.path.join(str(tmp_path), "no_such_dir", SESSION_FILE_NAME)
        state = _make_minimal_state(str(tmp_path))
        manager = SessionManager()

        with pytest.raises(ToolkitError):
            manager.save(state, os.path.join(str(tmp_path), "no_such_subdir"))
