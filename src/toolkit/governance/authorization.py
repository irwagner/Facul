"""
AuthorizationManager — Gerencia o ciclo de vida da autorização de auditoria.

Requisitos cobertos: 1.1, 1.2, 1.3, 1.6
"""

from __future__ import annotations

import json
import os
from datetime import date
from pathlib import Path
from typing import Optional

from toolkit.exceptions import AuthorizationError, SessionPersistenceError
from toolkit.models import Authorization

# Nome fixo do arquivo de autorização no diretório de trabalho
_AUTH_FILENAME = "authorization.json"


class AuthorizationManager:
    """
    Gerencia o ciclo de vida da autorização por escrito para auditoria de segurança.

    Persiste e carrega a autorização de ``<working_dir>/authorization.json``.
    Nenhuma requisição de rede deve ser despachada sem que ``require_valid``
    tenha sido chamado com sucesso (Req. 1.2).
    """

    # ------------------------------------------------------------------
    # Registro e persistência
    # ------------------------------------------------------------------

    def register(
        self,
        domain: str,
        institution: str,
        auth_date: date,
        scopes: list[str],
        cidrs: list[str],
        working_dir: str,
    ) -> Authorization:
        """
        Cria e persiste uma nova autorização.

        Parâmetros
        ----------
        domain:
            Domínio principal autorizado (campo obrigatório, Req. 1.1).
        institution:
            Nome da instituição autorizadora (campo obrigatório, Req. 1.1).
        auth_date:
            Data da autorização por escrito (campo obrigatório, Req. 1.1).
        scopes:
            Lista de domínios autorizados para teste de escopo (Req. 1.4).
        cidrs:
            Lista de faixas CIDR autorizadas (Req. 1.4).
        working_dir:
            Diretório de trabalho onde ``authorization.json`` será gravado.

        Retorna
        -------
        Authorization
            O objeto de autorização criado.

        Lança
        -----
        SessionPersistenceError
            Se a gravação do arquivo falhar; o path e a razão são
            propagados (Req. 1.3).
        """
        auth = Authorization(
            domain=domain,
            institution=institution,
            auth_date=auth_date,
            authorized_domains=list(scopes),
            authorized_cidrs=list(cidrs),
        )
        self._persist(auth, working_dir)
        return auth

    def _persist(self, auth: Authorization, working_dir: str) -> None:
        """Grava a autorização em ``<working_dir>/authorization.json``."""
        path = Path(working_dir) / _AUTH_FILENAME
        try:
            # Garante que o diretório existe
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as fh:
                json.dump(auth.to_dict(), fh, ensure_ascii=False, indent=2)
        except OSError as exc:
            raise SessionPersistenceError(
                message=(
                    f"Falha ao persistir a autorização em '{path}': {exc.strerror}"
                ),
                path=str(path),
                reason=exc.strerror,
            ) from exc

    # ------------------------------------------------------------------
    # Carregamento
    # ------------------------------------------------------------------

    def load(self, working_dir: str) -> Optional[Authorization]:
        """
        Carrega a autorização de ``<working_dir>/authorization.json``.

        Retorna ``None`` se o arquivo não existir.

        Parâmetros
        ----------
        working_dir:
            Diretório de trabalho onde o arquivo de autorização está localizado.

        Retorna
        -------
        Authorization | None
            O objeto de autorização carregado, ou ``None`` se o arquivo
            não existir.
        """
        path = Path(working_dir) / _AUTH_FILENAME
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return Authorization.from_dict(data)

    # ------------------------------------------------------------------
    # Validação
    # ------------------------------------------------------------------

    def is_valid(self, auth: Optional[Authorization], now: date) -> bool:
        """
        Retorna ``True`` se e somente se:

        * ``auth`` não é ``None``;
        * os três campos obrigatórios (``domain``, ``institution``,
          ``auth_date``) estão presentes e não são vazios/nulos;
        * ``(now - auth.auth_date).days <= 365`` (Req. 1.2).

        Parâmetros
        ----------
        auth:
            Objeto de autorização a validar (pode ser ``None``).
        now:
            Data de referência para o cálculo de validade.
        """
        if auth is None:
            return False
        if not auth.domain or not auth.institution or auth.auth_date is None:
            return False
        return (now - auth.auth_date).days <= 365

    def is_expired(self, auth: Authorization, now: date) -> bool:
        """
        Retorna ``True`` se ``now - auth.auth_date > 1 ano`` (Req. 1.6).

        Parâmetros
        ----------
        auth:
            Objeto de autorização a verificar.
        now:
            Data de referência para o cálculo de expiração.
        """
        return (now - auth.auth_date).days > 365

    def require_valid(self, auth: Optional[Authorization], now: date) -> None:
        """
        Lança ``AuthorizationError`` se a autorização estiver ausente ou inválida.

        Deve ser chamado antes de qualquer operação que dependa de autorização
        válida (Req. 1.2, 1.3).

        Parâmetros
        ----------
        auth:
            Objeto de autorização a verificar (pode ser ``None``).
        now:
            Data de referência para o cálculo de validade.

        Lança
        -----
        AuthorizationError
            Se ``not is_valid(auth, now)``.
        """
        if not self.is_valid(auth, now):
            domain = auth.domain if auth is not None else None
            if auth is None:
                reason = "Autorização ausente."
            elif not auth.domain or not auth.institution or auth.auth_date is None:
                reason = "Autorização inválida: campos obrigatórios ausentes."
            else:
                reason = (
                    f"Autorização expirada: emitida em {auth.auth_date.isoformat()}, "
                    f"referência em {now.isoformat()}."
                )
            raise AuthorizationError(reason, domain=domain)
