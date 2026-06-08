"""
Smoke and integration tests for NucleiAdapter (Req. 10.1, 10.2, 10.6).

Smoke
-----
  * ``is_available`` queries the system PATH via ``shutil.which``; the test
    patches ``shutil.which`` to confirm the correct binary name is checked and
    that the boolean return value reflects the lookup result.

Integration (subprocess mocked)
---------------------------------
  * Command is assembled with the correct flags for target, tags, and JSON
    output (``-je``).
  * When tags are empty the ``-t`` flag is omitted.
  * stdout and stderr captured from ``subprocess.run`` are forwarded in the
    returned ``NucleiRun``.
  * A non-zero exit code causes ``NucleiError`` to be raised with the captured
    stderr and the exit code attached.

Requirements covered: 10.1, 10.2, 10.6
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from toolkit.exceptions import NucleiError
from toolkit.execution.nuclei_adapter import NucleiAdapter, NucleiRun


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_subprocess_result(
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> MagicMock:
    """Return a minimal ``subprocess.CompletedProcess``-like mock."""
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result


# ---------------------------------------------------------------------------
# Smoke tests — binary availability (Req. 10.1)
# ---------------------------------------------------------------------------

class TestIsAvailableSmoke:
    """
    Smoke tests: ``is_available`` checks whether the ``nuclei`` binary is
    present in the system PATH (Req. 10.1).
    """

    def test_returns_true_when_nuclei_found_in_path(self):
        """
        When ``shutil.which('nuclei')`` returns a non-None path, ``is_available``
        must return ``True``.
        """
        adapter = NucleiAdapter()
        with patch("toolkit.execution.nuclei_adapter.shutil.which", return_value="/usr/local/bin/nuclei") as mock_which:
            result = adapter.is_available()

        assert result is True
        mock_which.assert_called_once_with("nuclei")

    def test_returns_false_when_nuclei_not_in_path(self):
        """
        When ``shutil.which('nuclei')`` returns ``None``, ``is_available``
        must return ``False``.
        """
        adapter = NucleiAdapter()
        with patch("toolkit.execution.nuclei_adapter.shutil.which", return_value=None) as mock_which:
            result = adapter.is_available()

        assert result is False
        mock_which.assert_called_once_with("nuclei")

    def test_checks_exact_binary_name_nuclei(self):
        """
        ``is_available`` must look up exactly the string ``'nuclei'`` — not a
        variant like ``'nuclei.exe'`` or an empty string.
        """
        adapter = NucleiAdapter()
        with patch("toolkit.execution.nuclei_adapter.shutil.which", return_value=None) as mock_which:
            adapter.is_available()

        called_with = mock_which.call_args[0][0]
        assert called_with == "nuclei"


# ---------------------------------------------------------------------------
# Integration tests — command assembly (Req. 10.2)
# ---------------------------------------------------------------------------

class TestRunCommandAssembly:
    """
    Integration tests: ``run`` assembles the correct subprocess command and
    forwards the captured output (Req. 10.2, 10.6).

    ``subprocess.run`` is always mocked so no real process is spawned.
    """

    def test_command_includes_target_flag(self):
        """
        ``run`` must pass ``-u <target>`` to the Nuclei binary.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result) as mock_run:
            adapter.run(target="https://example.com", tags=["cve"])

        cmd = mock_run.call_args[0][0]
        assert "-u" in cmd
        assert "https://example.com" in cmd

    def test_command_includes_tags_flag(self):
        """
        When tags are provided, ``run`` must include ``-t`` followed by a
        comma-joined string of those tags.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result) as mock_run:
            adapter.run(target="https://example.com", tags=["cve", "misconfig", "exposure"])

        cmd = mock_run.call_args[0][0]
        assert "-t" in cmd
        t_index = cmd.index("-t")
        tag_string = cmd[t_index + 1]
        assert "cve" in tag_string
        assert "misconfig" in tag_string
        assert "exposure" in tag_string

    def test_command_omits_tags_flag_when_tags_empty(self):
        """
        When ``tags`` is an empty list, the ``-t`` flag must be omitted from
        the command (all templates are executed).
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result) as mock_run:
            adapter.run(target="https://example.com", tags=[])

        cmd = mock_run.call_args[0][0]
        assert "-t" not in cmd

    def test_command_includes_json_output_flag(self):
        """
        ``run`` must pass the JSON export flag (``-je``) followed by a
        path to the output file (Req. 10.2).
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result) as mock_run:
            adapter.run(target="https://example.com", tags=[])

        cmd = mock_run.call_args[0][0]
        assert "-je" in cmd
        je_index = cmd.index("-je")
        # The argument following -je must be a non-empty string (the output file path)
        assert len(cmd) > je_index + 1
        assert cmd[je_index + 1]  # non-empty path

    def test_command_starts_with_nuclei_binary(self):
        """
        The first element of the command list must be the ``nuclei`` binary.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result) as mock_run:
            adapter.run(target="https://target.io", tags=["headers"])

        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "nuclei"

    def test_subprocess_run_called_with_capture_output_and_text(self):
        """
        ``subprocess.run`` must be called with ``capture_output=True`` and
        ``text=True`` so stdout/stderr are available as strings.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result) as mock_run:
            adapter.run(target="https://example.com", tags=[])

        kwargs = mock_run.call_args[1]
        assert kwargs.get("capture_output") is True
        assert kwargs.get("text") is True


# ---------------------------------------------------------------------------
# Integration tests — stdout/stderr capture (Req. 10.2)
# ---------------------------------------------------------------------------

class TestRunOutputCapture:
    """
    ``run`` must forward stdout, stderr, exit_code and the output file path
    from the subprocess result into the returned ``NucleiRun`` (Req. 10.2).
    """

    def test_stdout_forwarded_to_nuclei_run(self):
        """stdout captured from subprocess is returned in NucleiRun.stdout."""
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0, stdout="scan progress info")

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            run = adapter.run(target="https://example.com", tags=[])

        assert run.stdout == "scan progress info"

    def test_stderr_forwarded_to_nuclei_run(self):
        """stderr captured from subprocess is returned in NucleiRun.stderr."""
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0, stderr="[INF] Loading templates")

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            run = adapter.run(target="https://example.com", tags=[])

        assert run.stderr == "[INF] Loading templates"

    def test_exit_code_zero_forwarded_to_nuclei_run(self):
        """A zero exit code is recorded in NucleiRun.exit_code."""
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            run = adapter.run(target="https://example.com", tags=[])

        assert run.exit_code == 0

    def test_output_file_path_is_set_in_nuclei_run(self):
        """
        The output_file attribute of the returned NucleiRun must be a
        non-empty string (the temporary file path).
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            run = adapter.run(target="https://example.com", tags=[])

        assert isinstance(run.output_file, str)
        assert run.output_file  # non-empty

    def test_run_returns_nuclei_run_instance(self):
        """``run`` returns a ``NucleiRun`` dataclass instance on success."""
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            run = adapter.run(target="https://example.com", tags=["cve"])

        assert isinstance(run, NucleiRun)


# ---------------------------------------------------------------------------
# Integration tests — error handling on non-zero exit (Req. 10.6)
# ---------------------------------------------------------------------------

class TestRunNucleiError:
    """
    When Nuclei exits with a non-zero code, ``run`` must raise ``NucleiError``
    with the captured stderr and exit_code attached (Req. 10.6).
    """

    def test_raises_nuclei_error_on_nonzero_exit(self):
        """
        A non-zero exit code triggers ``NucleiError`` to be raised.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=1, stderr="error: target unreachable")

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            with pytest.raises(NucleiError):
                adapter.run(target="https://example.com", tags=[])

    def test_nuclei_error_carries_stderr(self):
        """
        The raised ``NucleiError`` must expose the stderr output via its
        ``stderr`` attribute so the caller can diagnose the failure.
        """
        adapter = NucleiAdapter()
        error_output = "FATA[0001] Could not create output file: permission denied"
        mock_result = _make_subprocess_result(returncode=2, stderr=error_output)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            with pytest.raises(NucleiError) as exc_info:
                adapter.run(target="https://example.com", tags=[])

        assert exc_info.value.stderr == error_output

    def test_nuclei_error_carries_exit_code(self):
        """
        The raised ``NucleiError`` must expose the original exit code via
        its ``exit_code`` attribute.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=42, stderr="unexpected error")

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            with pytest.raises(NucleiError) as exc_info:
                adapter.run(target="https://example.com", tags=[])

        assert exc_info.value.exit_code == 42

    @pytest.mark.parametrize("exit_code", [1, 2, 127, 255])
    def test_raises_nuclei_error_for_various_nonzero_codes(self, exit_code: int):
        """
        ``NucleiError`` is raised for any non-zero exit code, not only
        specific values.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=exit_code, stderr="some error")

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            with pytest.raises(NucleiError):
                adapter.run(target="https://example.com", tags=[])

    def test_no_error_raised_on_zero_exit(self):
        """
        A zero exit code must not raise ``NucleiError``; the method returns
        normally.
        """
        adapter = NucleiAdapter()
        mock_result = _make_subprocess_result(returncode=0)

        with patch("toolkit.execution.nuclei_adapter.subprocess.run", return_value=mock_result):
            result = adapter.run(target="https://example.com", tags=[])

        # Reaching here means no exception was raised
        assert result is not None
