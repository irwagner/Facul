"""
Hierarquia de exceções do Web Security Audit Toolkit.

Todas as exceções do toolkit derivam de ToolkitError, permitindo
captura seletiva tanto por tipo específico quanto pela base comum.
"""


class ToolkitError(Exception):
    """
    Exceção base do Web Security Audit Toolkit.

    Todas as exceções específicas do toolkit herdam desta classe,
    permitindo ao chamador capturar qualquer falha interna com um
    único bloco ``except ToolkitError``.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __repr__(self) -> str:  # pragma: no cover
        return f"{self.__class__.__name__}({self.message!r})"


class AuthorizationError(ToolkitError):
    """
    Lançada quando a autorização está ausente, é inválida ou expirou.

    Gerada pelo ``AuthorizationManager.require_valid`` e pelos módulos
    que verificam a presença de autorização antes de despachar qualquer
    requisição de rede (Req. 1.2, 1.3, 1.6).

    Attributes:
        message: Descrição legível do motivo da falha de autorização.
        domain: Domínio para o qual a autorização foi (ou deveria ter
                sido) emitida, quando disponível.
    """

    def __init__(self, message: str, domain: str | None = None) -> None:
        super().__init__(message)
        self.domain = domain


class ScopeError(ToolkitError):
    """
    Lançada quando um alvo está fora do escopo autorizado.

    Gerada pelo ``ScopeValidator.assert_in_scope`` após registrar um
    ``AuditEvent`` com timestamp, alvo, escopo autorizado e módulo
    solicitante (Req. 1.4, 1.5).

    Attributes:
        message: Descrição legível indicando qual alvo foi rejeitado
                 e por quê.
        target: Alvo (domínio, host ou IP) que foi rejeitado.
        authorized_scope: Representação do escopo autorizado vigente
                          (lista de domínios/CIDRs) para contextualização.
    """

    def __init__(
        self,
        message: str,
        target: str | None = None,
        authorized_scope: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.target = target
        self.authorized_scope: list[str] = authorized_scope or []


class SessionPersistenceError(ToolkitError):
    """
    Lançada quando o arquivo JSON de sessão não pode ser lido ou escrito.

    Gerada pelo ``SessionManager`` ao falhar na leitura ou gravação do
    estado persistente da sessão (Req. 12.3).

    Attributes:
        message: Descrição legível da falha de persistência.
        path: Caminho do arquivo JSON de sessão que causou o erro.
        reason: Descrição técnica da causa raiz (ex.: permissão negada,
                disco cheio, JSON malformado).
    """

    def __init__(
        self,
        message: str,
        path: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.path = path
        self.reason = reason


class NucleiError(ToolkitError):
    """
    Lançada quando o binário Nuclei falha ou retorna código de saída não-zero.

    Gerada pelo ``NucleiAdapter.run`` quando a execução via ``subprocess``
    termina com ``exit_code != 0`` ou o processo não pode ser iniciado
    (Req. 10.6).

    Attributes:
        message: Descrição legível do erro, incluindo contexto de execução.
        stderr: Saída de erro capturada do processo Nuclei, útil para
                diagnóstico.
        exit_code: Código de saída retornado pelo Nuclei (``None`` se o
                   processo não pôde ser iniciado).
    """

    def __init__(
        self,
        message: str,
        stderr: str | None = None,
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.stderr = stderr
        self.exit_code = exit_code
