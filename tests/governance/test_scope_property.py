"""
Property-based tests for ``ScopeValidator`` (task 2.4, Req. 1.4, 1.5).

# Feature: web-security-audit-toolkit, Property 2: Decisão de escopo e bloqueio com log

**Validates: Requirements 1.4, 1.5**

Properties
----------
Property 2a — in_scope bicondicional (domínios):
    Para toda lista de domínios autorizados e qualquer alvo de domínio,
    ``in_scope`` retorna True se e somente se o alvo é correspondência exata
    ou sufixo de subdomínio de algum domínio autorizado (comparação
    case-insensitive).

Property 2b — in_scope bicondicional (CIDRs):
    Para toda lista de CIDRs autorizados e qualquer endereço IP válido,
    ``in_scope`` retorna True se e somente se o IP está contido em algum
    CIDR autorizado.

Property 2c — assert_in_scope lança ScopeError e registra AuditEvent
    para alvos fora de escopo:
    Para qualquer alvo fora de escopo, ``assert_in_scope`` sempre lança
    ``ScopeError`` e registra exatamente um ``AuditEvent`` do tipo
    ``scope_block`` contendo timestamp, alvo, escopo autorizado e módulo.

Property 2d — assert_in_scope não lança nem registra para alvos em escopo:
    Para qualquer alvo em escopo, ``assert_in_scope`` não lança e não
    registra nenhum evento.
"""

from __future__ import annotations

import ipaddress
import string

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from hypothesis.strategies import composite

from toolkit.exceptions import ScopeError
from toolkit.governance.audit_logger import AuditLogger
from toolkit.governance.scope import ScopeValidator

# ---------------------------------------------------------------------------
# Estratégias auxiliares
# ---------------------------------------------------------------------------

_safe_label = st.text(
    alphabet=string.ascii_lowercase + string.digits,
    min_size=1,
    max_size=20,
)

_tld_strategy = st.sampled_from(["com", "org", "net", "edu", "io", "br", "uk"])


@composite
def domain_strategy(draw: st.DrawFn) -> str:
    """Gera um domínio válido como 'label.tld'."""
    label = draw(_safe_label)
    tld = draw(_tld_strategy)
    return f"{label}.{tld}"


@composite
def subdomain_of_strategy(draw: st.DrawFn, parent: str) -> str:
    """Gera um subdomínio de *parent* (ex.: 'sub.parent.tld')."""
    prefix = draw(_safe_label)
    return f"{prefix}.{parent}"


@composite
def deep_subdomain_of_strategy(draw: st.DrawFn, parent: str) -> str:
    """Gera um subdomínio profundo de *parent* (1 ou 2 níveis)."""
    levels = draw(st.integers(min_value=1, max_value=2))
    result = parent
    for _ in range(levels):
        label = draw(_safe_label)
        result = f"{label}.{result}"
    return result


@composite
def ipv4_strategy(draw: st.DrawFn) -> str:
    """Gera um endereço IPv4 válido."""
    octets = draw(
        st.tuples(
            st.integers(min_value=1, max_value=254),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=1, max_value=254),
        )
    )
    return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"


@composite
def cidr_strategy(draw: st.DrawFn) -> str:
    """Gera um CIDR IPv4 com prefixo entre /16 e /30."""
    a = draw(st.integers(min_value=10, max_value=200))
    b = draw(st.integers(min_value=0, max_value=255))
    prefix = draw(st.integers(min_value=16, max_value=30))
    return f"{a}.{b}.0.0/{prefix}"


@composite
def module_name_strategy(draw: st.DrawFn) -> str:
    """Gera um nome de módulo simples."""
    return draw(
        st.text(
            alphabet=string.ascii_lowercase + "_",
            min_size=3,
            max_size=30,
        )
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_real_logger() -> AuditLogger:
    """Instancia um AuditLogger real em memória (sem arquivo)."""
    return AuditLogger(log_file_path=None)


# ---------------------------------------------------------------------------
# Property 2a — in_scope bicondicional (domínios)
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    authorized_domains=st.lists(domain_strategy(), min_size=1, max_size=5),
    use_subdomain=st.booleans(),
    deep=st.booleans(),
)
def test_in_scope_domain_bicondition_in_scope(
    authorized_domains: list[str],
    use_subdomain: bool,
    deep: bool,
) -> None:
    """
    Property 2a (parte em-escopo): in_scope retorna True para correspondência
    exata de domínio e para subdomínio sufixo de qualquer domínio autorizado.

    Validates: Requirements 1.4
    """
    # Escolhe um domínio autorizado como base
    base_domain = authorized_domains[0]

    if use_subdomain:
        if deep:
            # Subdomínio profundo (ex.: 'a.b.example.com')
            target = f"sub1.sub2.{base_domain}"
        else:
            # Subdomínio simples (ex.: 'api.example.com')
            target = f"api.{base_domain}"
    else:
        # Correspondência exata
        target = base_domain

    sv = ScopeValidator(authorized_domains, [])
    assert sv.in_scope(target) is True, (
        f"Esperado in_scope=True para target={target!r} "
        f"com authorized_domains={authorized_domains!r}"
    )


@settings(max_examples=100)
@given(
    authorized_domains=st.lists(domain_strategy(), min_size=1, max_size=5),
    target=domain_strategy(),
)
def test_in_scope_domain_bicondition_out_of_scope(
    authorized_domains: list[str],
    target: str,
) -> None:
    """
    Property 2a (parte fora-de-escopo): in_scope retorna False quando o alvo
    não é correspondência exata nem subdomínio de nenhum domínio autorizado.

    Validates: Requirements 1.4
    """
    # Garante que o target não corresponde a nenhum domínio autorizado
    target_lower = target.lower()
    for d in authorized_domains:
        d_lower = d.lower()
        assume(target_lower != d_lower)
        assume(not target_lower.endswith("." + d_lower))

    sv = ScopeValidator(authorized_domains, [])
    assert sv.in_scope(target) is False, (
        f"Esperado in_scope=False para target={target!r} "
        f"com authorized_domains={authorized_domains!r}"
    )


@settings(max_examples=100)
@given(
    authorized_domains=st.lists(domain_strategy(), min_size=1, max_size=5),
    target=domain_strategy(),
)
def test_in_scope_domain_bicondition_full(
    authorized_domains: list[str],
    target: str,
) -> None:
    """
    Property 2a (bicondicional completo): in_scope retorna True se e somente se
    o alvo satisfaz correspondência exata ou sufixo de subdomínio de algum
    domínio autorizado.

    Validates: Requirements 1.4
    """
    target_lower = target.lower()
    expected = any(
        target_lower == d.lower() or target_lower.endswith("." + d.lower())
        for d in authorized_domains
    )

    sv = ScopeValidator(authorized_domains, [])
    result = sv.in_scope(target)

    assert result == expected, (
        f"in_scope={result!r} mas esperado={expected!r} "
        f"para target={target!r} e authorized_domains={authorized_domains!r}"
    )


# ---------------------------------------------------------------------------
# Property 2b — in_scope bicondicional (CIDRs)
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    cidr=cidr_strategy(),
    offset=st.integers(min_value=1, max_value=10),
)
def test_in_scope_cidr_bicondition_in_scope(cidr: str, offset: int) -> None:
    """
    Property 2b (parte em-escopo): in_scope retorna True para um IP contido
    no CIDR autorizado.

    Validates: Requirements 1.4
    """
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())
    assume(len(hosts) >= offset)

    # Pega um host dentro da rede
    ip_in = str(hosts[offset - 1])

    sv = ScopeValidator([], [cidr])
    assert sv.in_scope(ip_in) is True, (
        f"Esperado in_scope=True para IP={ip_in!r} dentro de CIDR={cidr!r}"
    )


@settings(max_examples=100)
@given(
    cidr=cidr_strategy(),
    ip=ipv4_strategy(),
)
def test_in_scope_cidr_bicondition_out_of_scope(cidr: str, ip: str) -> None:
    """
    Property 2b (parte fora-de-escopo): in_scope retorna False para um IP fora
    do CIDR autorizado.

    Validates: Requirements 1.4
    """
    network = ipaddress.ip_network(cidr, strict=False)
    ip_obj = ipaddress.ip_address(ip)
    assume(ip_obj not in network)

    sv = ScopeValidator([], [cidr])
    assert sv.in_scope(ip) is False, (
        f"Esperado in_scope=False para IP={ip!r} fora de CIDR={cidr!r}"
    )


@settings(max_examples=100)
@given(
    cidrs=st.lists(cidr_strategy(), min_size=1, max_size=3),
    ip=ipv4_strategy(),
)
def test_in_scope_cidr_bicondition_full(cidrs: list[str], ip: str) -> None:
    """
    Property 2b (bicondicional completo para CIDRs): in_scope retorna True se
    e somente se o IP está contido em algum CIDR autorizado.

    Validates: Requirements 1.4
    """
    ip_obj = ipaddress.ip_address(ip)
    expected = any(
        ip_obj in ipaddress.ip_network(cidr, strict=False)
        for cidr in cidrs
    )

    sv = ScopeValidator([], cidrs)
    result = sv.in_scope(ip)

    assert result == expected, (
        f"in_scope={result!r} mas esperado={expected!r} "
        f"para IP={ip!r} e CIDRs={cidrs!r}"
    )


# ---------------------------------------------------------------------------
# Property 2c — assert_in_scope lança ScopeError e registra AuditEvent
#               para alvos fora de escopo
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    authorized_domains=st.lists(domain_strategy(), min_size=1, max_size=5),
    target=domain_strategy(),
    module=module_name_strategy(),
)
def test_assert_in_scope_raises_and_logs_for_out_of_scope_domain(
    authorized_domains: list[str],
    target: str,
    module: str,
) -> None:
    """
    Property 2c (domínio fora de escopo): assert_in_scope sempre lança
    ScopeError e registra exatamente um AuditEvent do tipo 'scope_block'
    contendo timestamp, alvo, escopo autorizado e módulo.

    Validates: Requirements 1.4, 1.5
    """
    # Garante que o target está fora de escopo
    target_lower = target.lower()
    for d in authorized_domains:
        d_lower = d.lower()
        assume(target_lower != d_lower)
        assume(not target_lower.endswith("." + d_lower))

    sv = ScopeValidator(authorized_domains, [])
    logger = make_real_logger()

    with pytest.raises(ScopeError) as exc_info:
        sv.assert_in_scope(target, module, logger)

    # Verifica que ScopeError foi lançado com os atributos corretos
    error = exc_info.value
    assert error.target == target, (
        f"ScopeError.target={error.target!r} esperado={target!r}"
    )

    # Verifica que exatamente um AuditEvent foi registrado
    events = logger.get_events()
    assert len(events) == 1, (
        f"Esperado 1 evento registrado, obtido {len(events)}"
    )

    event = events[0]

    # event_type deve ser 'scope_block'
    assert event.event_type == "scope_block", (
        f"event_type={event.event_type!r} esperado='scope_block'"
    )

    # event.target deve ser o alvo bloqueado
    assert event.target == target, (
        f"event.target={event.target!r} esperado={target!r}"
    )

    # event.module deve ser o módulo solicitante
    assert event.module == module, (
        f"event.module={event.module!r} esperado={module!r}"
    )

    # event.timestamp deve ser uma string ISO 8601 não-vazia com 'T'
    assert isinstance(event.timestamp, str) and len(event.timestamp) > 0, (
        f"timestamp inválido: {event.timestamp!r}"
    )
    assert "T" in event.timestamp, (
        f"timestamp não parece ISO 8601: {event.timestamp!r}"
    )

    # event.detail deve conter authorized_domains e authorized_cidrs
    assert "authorized_domains" in event.detail, (
        "detail não contém 'authorized_domains'"
    )
    assert "authorized_cidrs" in event.detail, (
        "detail não contém 'authorized_cidrs'"
    )


@settings(max_examples=100)
@given(
    cidrs=st.lists(cidr_strategy(), min_size=1, max_size=3),
    ip=ipv4_strategy(),
    module=module_name_strategy(),
)
def test_assert_in_scope_raises_and_logs_for_out_of_scope_ip(
    cidrs: list[str],
    ip: str,
    module: str,
) -> None:
    """
    Property 2c (IP fora de escopo): assert_in_scope sempre lança ScopeError
    e registra exatamente um AuditEvent do tipo 'scope_block' com todos os
    campos obrigatórios.

    Validates: Requirements 1.4, 1.5
    """
    # Garante que o IP está fora de todos os CIDRs
    ip_obj = ipaddress.ip_address(ip)
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        assume(ip_obj not in network)

    sv = ScopeValidator([], cidrs)
    logger = make_real_logger()

    with pytest.raises(ScopeError) as exc_info:
        sv.assert_in_scope(ip, module, logger)

    error = exc_info.value
    assert error.target == ip

    events = logger.get_events()
    assert len(events) == 1

    event = events[0]
    assert event.event_type == "scope_block"
    assert event.target == ip
    assert event.module == module
    assert isinstance(event.timestamp, str) and "T" in event.timestamp
    assert "authorized_domains" in event.detail
    assert "authorized_cidrs" in event.detail


@settings(max_examples=100)
@given(
    authorized_domains=st.lists(domain_strategy(), min_size=0, max_size=4),
    cidrs=st.lists(cidr_strategy(), min_size=0, max_size=3),
    target=domain_strategy(),
    module=module_name_strategy(),
)
def test_assert_in_scope_scope_error_authorized_scope_contains_all_entries(
    authorized_domains: list[str],
    cidrs: list[str],
    target: str,
    module: str,
) -> None:
    """
    Property 2c (authorized_scope no ScopeError): o atributo authorized_scope
    do ScopeError contém todos os domínios e CIDRs autorizados.

    Validates: Requirements 1.5
    """
    # Garante que o alvo está fora de escopo
    target_lower = target.lower()
    for d in authorized_domains:
        assume(target_lower != d.lower())
        assume(not target_lower.endswith("." + d.lower()))

    sv = ScopeValidator(authorized_domains, cidrs)
    logger = make_real_logger()

    with pytest.raises(ScopeError) as exc_info:
        sv.assert_in_scope(target, module, logger)

    error = exc_info.value
    for d in authorized_domains:
        assert d in error.authorized_scope, (
            f"Domínio {d!r} não encontrado em authorized_scope={error.authorized_scope!r}"
        )
    for cidr in cidrs:
        assert cidr in error.authorized_scope, (
            f"CIDR {cidr!r} não encontrado em authorized_scope={error.authorized_scope!r}"
        )


# ---------------------------------------------------------------------------
# Property 2d — assert_in_scope não lança nem registra para alvos em escopo
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    authorized_domains=st.lists(domain_strategy(), min_size=1, max_size=5),
    use_subdomain=st.booleans(),
    module=module_name_strategy(),
)
def test_assert_in_scope_does_not_raise_or_log_for_in_scope_domain(
    authorized_domains: list[str],
    use_subdomain: bool,
    module: str,
) -> None:
    """
    Property 2d (domínio em escopo): assert_in_scope não lança exceção e não
    registra nenhum evento para alvos dentro do escopo autorizado.

    Validates: Requirements 1.4, 1.5
    """
    base_domain = authorized_domains[0]

    if use_subdomain:
        target = f"api.{base_domain}"
    else:
        target = base_domain

    sv = ScopeValidator(authorized_domains, [])
    logger = make_real_logger()

    # Não deve lançar
    sv.assert_in_scope(target, module, logger)

    # Não deve registrar nenhum evento
    events = logger.get_events()
    assert len(events) == 0, (
        f"Esperado 0 eventos para target em escopo {target!r}, "
        f"obtido {len(events)}"
    )


@settings(max_examples=100)
@given(
    cidr=cidr_strategy(),
    offset=st.integers(min_value=1, max_value=5),
    module=module_name_strategy(),
)
def test_assert_in_scope_does_not_raise_or_log_for_in_scope_ip(
    cidr: str,
    offset: int,
    module: str,
) -> None:
    """
    Property 2d (IP em escopo): assert_in_scope não lança exceção e não
    registra nenhum evento para um IP dentro do CIDR autorizado.

    Validates: Requirements 1.4, 1.5
    """
    network = ipaddress.ip_network(cidr, strict=False)
    hosts = list(network.hosts())
    assume(len(hosts) >= offset)

    ip_in = str(hosts[offset - 1])

    sv = ScopeValidator([], [cidr])
    logger = make_real_logger()

    # Não deve lançar
    sv.assert_in_scope(ip_in, module, logger)

    # Não deve registrar nenhum evento
    events = logger.get_events()
    assert len(events) == 0, (
        f"Esperado 0 eventos para IP em escopo {ip_in!r} no CIDR {cidr!r}, "
        f"obtido {len(events)}"
    )
