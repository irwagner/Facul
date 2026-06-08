"""
SessionManager — persists and restores SessionState as a single JSON file.

The session file is stored in the working directory as ``session.json``.
All IO errors and JSON errors are wrapped in ``SessionPersistenceError``
so callers can handle persistence failures uniformly (Req. 12.3, 12.4).
"""

from __future__ import annotations

import json
import os

from toolkit.exceptions import SessionPersistenceError
from toolkit.models import SessionState

SESSION_FILE_NAME = "session.json"


class SessionManager:
    """
    Saves and loads a :class:`~toolkit.models.SessionState` to/from a
    single JSON file inside the working directory.

    The file is always named ``session.json``.  Any :exc:`OSError` raised
    during file I/O, and any :exc:`json.JSONDecodeError` raised during
    parsing, are re-raised as :exc:`~toolkit.exceptions.SessionPersistenceError`
    with ``path`` and ``reason`` attributes populated for diagnostics.
    """

    def save(self, state: SessionState, working_dir: str) -> None:
        """
        Serialise *state* and write it to ``<working_dir>/session.json``.

        Parameters
        ----------
        state:
            The :class:`~toolkit.models.SessionState` to persist.
        working_dir:
            Directory in which ``session.json`` will be written.

        Raises
        ------
        SessionPersistenceError
            If an :exc:`OSError` occurs during file writing.
        """
        path = os.path.join(working_dir, SESSION_FILE_NAME)
        data = state.to_dict()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(data, indent=2, ensure_ascii=False))
        except OSError as e:
            raise SessionPersistenceError(
                f"Failed to save session to {path}: {e}",
                path=path,
                reason=str(e),
            ) from e

    def load(self, working_dir: str) -> SessionState:
        """
        Read ``<working_dir>/session.json`` and deserialise it.

        Parameters
        ----------
        working_dir:
            Directory that contains ``session.json``.

        Returns
        -------
        SessionState
            The restored session state.

        Raises
        ------
        SessionPersistenceError
            If the file does not exist, if an :exc:`OSError` occurs during
            reading, or if the file contains invalid JSON.
        """
        path = os.path.join(working_dir, SESSION_FILE_NAME)

        if not os.path.exists(path):
            raise SessionPersistenceError(
                f"Session file not found: {path}",
                path=path,
                reason="File not found",
            )

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.loads(fh.read())
        except (OSError, json.JSONDecodeError) as e:
            raise SessionPersistenceError(
                f"Failed to load session from {path}: {e}",
                path=path,
                reason=str(e),
            ) from e

        return SessionState.from_dict(data)
