"""
AuditLogger — Log de auditoria append-only com mascaramento de dados sensíveis.

Requisitos cobertos: 1.5, 2.6, 9.6
"""

from __future__ import annotations

import json
from typing import Any

from toolkit.models import AuditEvent

# ---------------------------------------------------------------------------
# Chaves sensíveis a mascarar (case-insensitive)
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "token",
    "secret",
    "key",
    "payload",
    "authorization",
)

_MASK = "***MASKED***"


def _is_sensitive_key(key: str) -> bool:
    """Retorna True se o nome da chave contém algum fragmento sensível."""
    lower = key.lower()
    return any(fragment in lower for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _mask_detail(detail: dict) -> dict:
    """
    Retorna uma cópia de *detail* com valores mascarados para chaves sensíveis.

    Apenas valores do tipo ``str`` são substituídos; outros tipos são mantidos
    intactos para não perder informação estrutural.
    """
    masked: dict[str, Any] = {}
    for k, v in detail.items():
        if _is_sensitive_key(k) and isinstance(v, str):
            masked[k] = _MASK
        else:
            masked[k] = v
    return masked


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------


class AuditLogger:
    """
    Log de auditoria append-only com timestamp ISO 8601.

    Cada evento registrado é mascarado antes de ser armazenado: qualquer chave
    em ``event.detail`` cujo nome contenha um fragmento sensível
    (``password``, ``token``, ``secret``, ``key``, ``payload``,
    ``authorization``) tem seu valor substituído por ``"***MASKED***"``.

    Se um caminho de arquivo for fornecido, cada evento é também serializado
    como uma linha JSON no arquivo (modo append). Falhas de I/O são silenciadas
    para que o logger nunca interrompa o fluxo principal (Req. 1.5, 9.6).

    Parameters
    ----------
    log_file_path:
        Caminho para o arquivo de log. Se ``None``, o logger opera apenas
        em memória.
    """

    def __init__(self, log_file_path: str | None = None) -> None:
        self._log_file_path: str | None = log_file_path
        self._events: list[AuditEvent] = []

    # ------------------------------------------------------------------
    # Interface pública
    # ------------------------------------------------------------------

    def log(self, event: AuditEvent) -> None:
        """
        Registra um evento de auditoria.

        O campo ``detail`` do evento é mascarado (in-place) antes do
        armazenamento. O evento é adicionado à lista em memória e,
        opcionalmente, serializado no arquivo de log.

        Parameters
        ----------
        event:
            Evento de auditoria a registrar.
        """
        # Mascara os payloads sensíveis no detalhe antes de armazenar
        event.detail = _mask_detail(event.detail)

        # Armazenamento em memória (append-only)
        self._events.append(event)

        # Persistência em arquivo (falhas são silenciadas)
        if self._log_file_path is not None:
            try:
                with open(self._log_file_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event.to_dict(), ensure_ascii=False))
                    fh.write("\n")
            except OSError:
                # Logging nunca deve interromper o fluxo do auditor (Req. 1.5)
                pass

    def get_events(self) -> list[AuditEvent]:
        """
        Retorna uma cópia da lista de eventos em memória.

        Returns
        -------
        list[AuditEvent]
            Cópia rasa da lista de eventos registrados.
        """
        return list(self._events)
