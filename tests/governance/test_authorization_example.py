"""
Example tests for ``AuthorizationManager`` — registro e falha de escrita.

Cobre:
- Req. 1.1: registro com os 3 campos obrigatórios (domain, institution, auth_date)
- Req. 1.3: abortar com mensagem (path + razão) quando a gravação falha

Tests:
1. Successful ``register()`` with domain, institution, auth_date saves a config file.
2. ``register()`` raises ``SessionPersistenceError`` with path + reason when file
   write fails (mock ``open`` to raise IOError).
3. ``load()`` reads the config back correctly.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from toolkit.exceptions import SessionPersistenceError
from toolkit.governance.authorization import AuthorizationManager, _AUTH_FILENAME
from toolkit.models import Authorization


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_manager() -> AuthorizationManager:
    return AuthorizationManager()


# ---------------------------------------------------------------------------
# Test 1 — successful register() saves a config file (Req. 1.1, 1.3)
# ---------------------------------------------------------------------------

class TestRegisterSuccess:
    """``register()`` with valid inputs must persist authorization.json."""

    def test_register_returns_authorization_instance(self, tmp_path):
        """register() must return an Authorization object."""
        manager = _make_manager()
        auth = manager.register(
            domain="example.com",
            institution="Universidade Federal",
            auth_date=date(2024, 6, 1),
            scopes=["example.com"],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        assert isinstance(auth, Authorization)

    def test_register_creates_authorization_json(self, tmp_path):
        """After register(), authorization.json must exist in working_dir."""
        manager = _make_manager()
        manager.register(
            domain="example.com",
            institution="Universidade Federal",
            auth_date=date(2024, 6, 1),
            scopes=["example.com"],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        config_path = tmp_path / _AUTH_FILENAME
        assert config_path.exists(), f"{_AUTH_FILENAME} deve ter sido criado em {tmp_path}"

    def test_register_stores_domain(self, tmp_path):
        """The domain field must be persisted correctly."""
        manager = _make_manager()
        manager.register(
            domain="target.io",
            institution="ACME Corp",
            auth_date=date(2024, 3, 15),
            scopes=["target.io"],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        config_path = tmp_path / _AUTH_FILENAME
        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data["domain"] == "target.io"

    def test_register_stores_institution(self, tmp_path):
        """The institution field must be persisted correctly."""
        manager = _make_manager()
        manager.register(
            domain="example.com",
            institution="Faculdade de Tecnologia",
            auth_date=date(2024, 3, 15),
            scopes=[],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        config_path = tmp_path / _AUTH_FILENAME
        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data["institution"] == "Faculdade de Tecnologia"

    def test_register_stores_auth_date(self, tmp_path):
        """The auth_date must be persisted as an ISO 8601 string."""
        manager = _make_manager()
        auth_date = date(2024, 11, 20)
        manager.register(
            domain="example.com",
            institution="Test Uni",
            auth_date=auth_date,
            scopes=[],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        config_path = tmp_path / _AUTH_FILENAME
        data = json.loads(config_path.read_text(encoding="utf-8"))
        assert data["auth_date"] == auth_date.isoformat()

    def test_register_returned_auth_matches_inputs(self, tmp_path):
        """The returned Authorization object must reflect the registered inputs."""
        manager = _make_manager()
        auth_date = date(2024, 7, 4)
        auth = manager.register(
            domain="secure.org",
            institution="Security Institute",
            auth_date=auth_date,
            scopes=["secure.org", "api.secure.org"],
            cidrs=["10.0.0.0/8"],
            working_dir=str(tmp_path),
        )
        assert auth.domain == "secure.org"
        assert auth.institution == "Security Institute"
        assert auth.auth_date == auth_date
        assert "secure.org" in auth.authorized_domains
        assert "10.0.0.0/8" in auth.authorized_cidrs


# ---------------------------------------------------------------------------
# Test 2 — register() raises with path+reason when file write fails (Req. 1.3)
# ---------------------------------------------------------------------------

class TestRegisterWriteFailure:
    """``register()`` must abort and raise ``SessionPersistenceError`` on IOError."""

    def _make_ioerror(self, strerror: str) -> OSError:
        """Create an OSError with the strerror attribute set correctly."""
        error = OSError(strerror)
        error.strerror = strerror
        return error

    def test_register_raises_session_persistence_error_on_ioerror(self, tmp_path):
        """
        When Path.open() raises OSError during file write, register() must
        raise SessionPersistenceError (Req. 1.3).
        """
        manager = _make_manager()
        error = self._make_ioerror("Permission denied")

        with patch("pathlib.Path.open", side_effect=error):
            with pytest.raises(SessionPersistenceError):
                manager.register(
                    domain="example.com",
                    institution="Test Uni",
                    auth_date=date(2024, 1, 1),
                    scopes=[],
                    cidrs=[],
                    working_dir=str(tmp_path),
                )

    def test_register_error_message_contains_path(self, tmp_path):
        """
        The error message must include the filesystem path where the write
        was attempted (Req. 1.3).
        """
        manager = _make_manager()
        error = self._make_ioerror("No space left on device")

        with patch("pathlib.Path.open", side_effect=error):
            with pytest.raises(SessionPersistenceError) as exc_info:
                manager.register(
                    domain="example.com",
                    institution="Test Uni",
                    auth_date=date(2024, 1, 1),
                    scopes=[],
                    cidrs=[],
                    working_dir=str(tmp_path),
                )

        expected_path = str(tmp_path / _AUTH_FILENAME)
        assert expected_path in exc_info.value.message, (
            f"Error message deve conter o path '{expected_path}', "
            f"mas foi: {exc_info.value.message!r}"
        )

    def test_register_error_message_contains_reason(self, tmp_path):
        """
        The error message must include the failure reason (Req. 1.3).
        """
        manager = _make_manager()
        failure_reason = "Permission denied"
        error = self._make_ioerror(failure_reason)

        with patch("pathlib.Path.open", side_effect=error):
            with pytest.raises(SessionPersistenceError) as exc_info:
                manager.register(
                    domain="example.com",
                    institution="Test Uni",
                    auth_date=date(2024, 1, 1),
                    scopes=[],
                    cidrs=[],
                    working_dir=str(tmp_path),
                )

        assert failure_reason in exc_info.value.message, (
            f"Error message deve conter a razão '{failure_reason}', "
            f"mas foi: {exc_info.value.message!r}"
        )

    def test_register_error_exposes_path_attribute(self, tmp_path):
        """SessionPersistenceError.path must be set to the intended file path."""
        manager = _make_manager()
        error = self._make_ioerror("Disk full")

        with patch("pathlib.Path.open", side_effect=error):
            with pytest.raises(SessionPersistenceError) as exc_info:
                manager.register(
                    domain="example.com",
                    institution="Test Uni",
                    auth_date=date(2024, 1, 1),
                    scopes=[],
                    cidrs=[],
                    working_dir=str(tmp_path),
                )

        expected_path = str(tmp_path / _AUTH_FILENAME)
        assert exc_info.value.path == expected_path

    def test_register_error_exposes_reason_attribute(self, tmp_path):
        """SessionPersistenceError.reason must be set to the OS error string."""
        manager = _make_manager()
        failure_reason = "Read-only file system"
        error = self._make_ioerror(failure_reason)

        with patch("pathlib.Path.open", side_effect=error):
            with pytest.raises(SessionPersistenceError) as exc_info:
                manager.register(
                    domain="example.com",
                    institution="Test Uni",
                    auth_date=date(2024, 1, 1),
                    scopes=[],
                    cidrs=[],
                    working_dir=str(tmp_path),
                )

        assert exc_info.value.reason == failure_reason


# ---------------------------------------------------------------------------
# Test 3 — load() reads the config correctly (Req. 1.1)
# ---------------------------------------------------------------------------

class TestLoad:
    """``load()`` must restore an Authorization from authorization.json."""

    def test_load_returns_none_when_file_absent(self, tmp_path):
        """load() must return None when authorization.json does not exist."""
        manager = _make_manager()
        result = manager.load(str(tmp_path))
        assert result is None

    def test_load_returns_authorization_after_register(self, tmp_path):
        """load() must return an Authorization object after register()."""
        manager = _make_manager()
        manager.register(
            domain="example.com",
            institution="Test Uni",
            auth_date=date(2024, 5, 10),
            scopes=["example.com"],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        loaded = manager.load(str(tmp_path))
        assert isinstance(loaded, Authorization)

    def test_load_restores_domain(self, tmp_path):
        """The domain must be preserved through register→load round-trip."""
        manager = _make_manager()
        manager.register(
            domain="roundtrip.com",
            institution="RT University",
            auth_date=date(2024, 9, 1),
            scopes=[],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        loaded = manager.load(str(tmp_path))
        assert loaded.domain == "roundtrip.com"

    def test_load_restores_institution(self, tmp_path):
        """The institution must be preserved through register→load round-trip."""
        manager = _make_manager()
        manager.register(
            domain="example.com",
            institution="Instituto de Tecnologia",
            auth_date=date(2024, 9, 1),
            scopes=[],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        loaded = manager.load(str(tmp_path))
        assert loaded.institution == "Instituto de Tecnologia"

    def test_load_restores_auth_date(self, tmp_path):
        """The auth_date must be preserved through register→load round-trip."""
        manager = _make_manager()
        auth_date = date(2024, 12, 31)
        manager.register(
            domain="example.com",
            institution="Test Uni",
            auth_date=auth_date,
            scopes=[],
            cidrs=[],
            working_dir=str(tmp_path),
        )
        loaded = manager.load(str(tmp_path))
        assert loaded.auth_date == auth_date

    def test_load_restores_authorized_domains(self, tmp_path):
        """The authorized_domains list must be preserved through register→load."""
        manager = _make_manager()
        scopes = ["example.com", "api.example.com", "admin.example.com"]
        manager.register(
            domain="example.com",
            institution="Test Uni",
            auth_date=date(2024, 1, 1),
            scopes=scopes,
            cidrs=[],
            working_dir=str(tmp_path),
        )
        loaded = manager.load(str(tmp_path))
        assert loaded.authorized_domains == scopes

    def test_load_restores_authorized_cidrs(self, tmp_path):
        """The authorized_cidrs list must be preserved through register→load."""
        manager = _make_manager()
        cidrs = ["192.168.0.0/24", "10.0.0.0/8"]
        manager.register(
            domain="example.com",
            institution="Test Uni",
            auth_date=date(2024, 1, 1),
            scopes=[],
            cidrs=cidrs,
            working_dir=str(tmp_path),
        )
        loaded = manager.load(str(tmp_path))
        assert loaded.authorized_cidrs == cidrs

    def test_load_from_manually_written_json(self, tmp_path):
        """load() must work on a manually written authorization.json file."""
        config_path = tmp_path / _AUTH_FILENAME
        data = {
            "domain": "manual.org",
            "institution": "Manual University",
            "auth_date": "2024-02-14",
            "authorized_domains": ["manual.org"],
            "authorized_cidrs": [],
        }
        config_path.write_text(json.dumps(data), encoding="utf-8")

        manager = _make_manager()
        loaded = manager.load(str(tmp_path))

        assert loaded.domain == "manual.org"
        assert loaded.institution == "Manual University"
        assert loaded.auth_date == date(2024, 2, 14)
