"""
Property-based tests for SurfaceMapper.build_surface_map.

# Feature: web-security-audit-toolkit, Property 4: Geração do mapa de superfície exclui itens fora de escopo

**Validates: Requirements 2.5, 2.6**

Property under test
-------------------
For every mixed set of hosts (in-scope and out-of-scope) with their ports
and technologies, the resulting AttackSurfaceMap:
  1. Contains exactly the in-scope hosts.
  2. Preserves the ports and technologies of every included host.
  3. Contains no out-of-scope hosts in active_hosts.
  4. Records exactly one Exclusion per excluded host (host name, reason,
     ISO 8601 timestamp).
"""

from __future__ import annotations

import re
import string
from datetime import datetime

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import composite

from toolkit.discovery.surface_mapper import SurfaceMapper
from toolkit.governance.audit_logger import AuditLogger
from toolkit.governance.scope import ScopeValidator
from toolkit.models import Host, Technology


# ---------------------------------------------------------------------------
# Primitive helpers shared by this test module
# ---------------------------------------------------------------------------

_safe_label = st.text(
    alphabet=string.ascii_lowercase + string.digits,
    min_size=1,
    max_size=20,
)

_tld_strategy = st.sampled_from(["com", "org", "net", "edu", "io"])

_domain_strategy = st.builds(
    lambda label, tld: f"{label}.{tld}",
    label=_safe_label,
    tld=_tld_strategy,
)

_ip_strategy = st.builds(
    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
    a=st.integers(min_value=1, max_value=254),
    b=st.integers(min_value=0, max_value=255),
    c=st.integers(min_value=0, max_value=255),
    d=st.integers(min_value=1, max_value=254),
)

_port_strategy = st.integers(min_value=1, max_value=65535)

_tech_category_strategy = st.sampled_from(
    ["web_server", "framework", "cdn", "other"]
)

_technology_strategy = st.builds(
    lambda name, version, category: Technology(
        name=name, version=version, category=category
    ),
    name=st.text(
        alphabet=string.ascii_letters + string.digits + "-.",
        min_size=1,
        max_size=30,
    ),
    version=st.one_of(
        st.none(),
        st.text(
            alphabet=string.digits + ".",
            min_size=1,
            max_size=10,
        ),
    ),
    category=_tech_category_strategy,
)


# ---------------------------------------------------------------------------
# Composite strategy: a Host with optional ports and techs
# ---------------------------------------------------------------------------

@composite
def host_with_data_strategy(draw: st.DrawFn):
    """
    Returns (host, ports_list, techs_list) for use in the test strategy.

    The host's hostname is always a simple label + tld domain string so that
    ScopeValidator can match it deterministically against the auth domain.
    """
    label = draw(_safe_label)
    tld = draw(_tld_strategy)
    hostname = f"{label}.{tld}"
    ip = draw(_ip_strategy)
    is_active = draw(st.booleans())
    open_ports = draw(st.lists(_port_strategy, min_size=0, max_size=5, unique=True))
    technologies = draw(st.lists(_technology_strategy, min_size=0, max_size=4))

    host = Host(
        hostname=hostname,
        ip=ip,
        is_active=is_active,
        open_ports=open_ports,
        technologies=technologies,
    )
    extra_ports = draw(st.lists(_port_strategy, min_size=0, max_size=5, unique=True))
    extra_techs = draw(st.lists(_technology_strategy, min_size=0, max_size=3))
    return host, extra_ports, extra_techs


@composite
def surface_map_input_strategy(draw: st.DrawFn):
    """
    Generates a scenario for build_surface_map:

    Returns
    -------
    (in_scope_host_data, out_of_scope_host_data, authorized_domain)

    * in_scope_host_data  : list of (Host, ports, techs) — all in scope
    * out_of_scope_host_data : list of (Host, ports, techs) — all out of scope

    Strategy guarantees disjoint hostnames between the two groups.
    """
    authorized_domain = draw(_domain_strategy)

    # In-scope hosts: hostnames that are exactly the authorized domain or
    # a subdomain of it.
    in_scope_data = []
    num_in_scope = draw(st.integers(min_value=0, max_value=5))
    used_hostnames: set[str] = set()
    for _ in range(num_in_scope):
        # Build a subdomain of the authorized domain to ensure in-scope match
        sub_label = draw(_safe_label)
        hostname = f"{sub_label}.{authorized_domain}"
        if hostname in used_hostnames:
            continue
        used_hostnames.add(hostname)
        ip = draw(_ip_strategy)
        is_active = draw(st.booleans())
        open_ports = draw(
            st.lists(_port_strategy, min_size=0, max_size=5, unique=True)
        )
        technologies = draw(st.lists(_technology_strategy, min_size=0, max_size=4))
        host = Host(
            hostname=hostname,
            ip=ip,
            is_active=is_active,
            open_ports=open_ports,
            technologies=technologies,
        )
        extra_ports = draw(
            st.lists(_port_strategy, min_size=0, max_size=5, unique=True)
        )
        extra_techs = draw(st.lists(_technology_strategy, min_size=0, max_size=3))
        in_scope_data.append((host, extra_ports, extra_techs))

    # Out-of-scope hosts: use a completely different TLD so they never match.
    # We use the fixed suffix ".invalid" which cannot match any real domain.
    out_scope_data = []
    num_out_scope = draw(st.integers(min_value=0, max_value=5))
    for i in range(num_out_scope):
        hostname = f"external{i}.invalid"
        if hostname in used_hostnames:
            continue
        used_hostnames.add(hostname)
        ip = draw(_ip_strategy)
        is_active = draw(st.booleans())
        open_ports = draw(
            st.lists(_port_strategy, min_size=0, max_size=5, unique=True)
        )
        technologies = draw(st.lists(_technology_strategy, min_size=0, max_size=4))
        host = Host(
            hostname=hostname,
            ip=ip,
            is_active=is_active,
            open_ports=open_ports,
            technologies=technologies,
        )
        extra_ports = draw(
            st.lists(_port_strategy, min_size=0, max_size=5, unique=True)
        )
        extra_techs = draw(st.lists(_technology_strategy, min_size=0, max_size=3))
        out_scope_data.append((host, extra_ports, extra_techs))

    return in_scope_data, out_scope_data, authorized_domain


# ---------------------------------------------------------------------------
# ISO 8601 validation helper
# ---------------------------------------------------------------------------

_ISO_8601_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?$"
)


def _is_iso8601(value: str) -> bool:
    """Return True if value looks like an ISO 8601 datetime string."""
    return bool(_ISO_8601_RE.match(value))


# ---------------------------------------------------------------------------
# Property 4 — main property test
# ---------------------------------------------------------------------------

@given(scenario=surface_map_input_strategy())
@settings(max_examples=100)
def test_property4_surface_map_scope_filtering(scenario):
    """
    Property 4: Geração do mapa de superfície exclui itens fora de escopo.

    **Validates: Requirements 2.5, 2.6**

    For every mixed set of hosts (in-scope and out-of-scope) with their
    ports and technologies:
      - The map contains exactly the in-scope hosts (by hostname).
      - No out-of-scope host appears in active_hosts.
      - Each in-scope host has its ports and technologies preserved from
        the ports/techs dicts passed to build_surface_map.
      - There is exactly one Exclusion per out-of-scope host, with a
        non-empty reason and an ISO 8601 timestamp.
    """
    in_scope_data, out_scope_data, authorized_domain = scenario

    # Build combined host list (order: in-scope first, then out-of-scope)
    all_hosts: list[Host] = []
    ports: dict[str, list[int]] = {}
    techs: dict[str, list[Technology]] = {}

    for host, extra_ports, extra_techs in in_scope_data:
        all_hosts.append(host)
        ports[host.hostname] = extra_ports
        techs[host.hostname] = extra_techs

    for host, extra_ports, extra_techs in out_scope_data:
        all_hosts.append(host)
        ports[host.hostname] = extra_ports
        techs[host.hostname] = extra_techs

    # Configure scope: only authorized_domain and its subdomains are in scope.
    scope = ScopeValidator(
        authorized_domains=[authorized_domain],
        authorized_cidrs=[],
    )
    logger = AuditLogger()
    mapper = SurfaceMapper()

    result = mapper.build_surface_map(
        hosts=all_hosts,
        ports=ports,
        techs=techs,
        scope=scope,
        logger=logger,
    )

    # --- Assertion 1: active_hosts contains exactly the in-scope hostnames ---
    expected_in_scope_names = {
        host.hostname for host, _, _ in in_scope_data
    }
    actual_active_names = {h.hostname for h in result.active_hosts}
    assert actual_active_names == expected_in_scope_names, (
        f"active_hosts hostnames {actual_active_names!r} != "
        f"expected in-scope {expected_in_scope_names!r}"
    )

    # --- Assertion 2: no out-of-scope host appears in active_hosts ---
    out_scope_names = {host.hostname for host, _, _ in out_scope_data}
    for active_host in result.active_hosts:
        assert active_host.hostname not in out_scope_names, (
            f"Out-of-scope host {active_host.hostname!r} found in active_hosts"
        )

    # --- Assertion 3: ports and technologies are preserved for in-scope hosts ---
    active_by_name = {h.hostname: h for h in result.active_hosts}
    for host, extra_ports, extra_techs in in_scope_data:
        name = host.hostname
        assert name in active_by_name, f"In-scope host {name!r} missing from active_hosts"

        included = active_by_name[name]
        # Ports should match what was provided in the ports dict
        assert sorted(included.open_ports) == sorted(extra_ports), (
            f"Ports for {name!r}: expected {sorted(extra_ports)}, "
            f"got {sorted(included.open_ports)}"
        )
        # Technologies should match what was provided in the techs dict
        actual_tech_names = sorted(t.name for t in included.technologies)
        expected_tech_names = sorted(t.name for t in extra_techs)
        assert actual_tech_names == expected_tech_names, (
            f"Tech names for {name!r}: expected {expected_tech_names}, "
            f"got {actual_tech_names}"
        )

    # --- Assertion 4: one Exclusion per out-of-scope host ---
    assert len(result.excluded) == len(out_scope_data), (
        f"Expected {len(out_scope_data)} exclusions, got {len(result.excluded)}"
    )
    excluded_names_in_result = {e.host for e in result.excluded}
    assert excluded_names_in_result == out_scope_names, (
        f"Excluded host names {excluded_names_in_result!r} != "
        f"expected {out_scope_names!r}"
    )

    # --- Assertion 5: each Exclusion has a non-empty reason and ISO 8601 timestamp ---
    for exclusion in result.excluded:
        assert exclusion.reason, (
            f"Exclusion for {exclusion.host!r} has an empty reason"
        )
        assert _is_iso8601(exclusion.timestamp), (
            f"Exclusion timestamp {exclusion.timestamp!r} is not ISO 8601"
        )

    # --- Assertion 6: audit logger received one exclusion event per out-of-scope host ---
    logged_exclusions = [
        e for e in logger.get_events() if e.event_type == "exclusion"
    ]
    assert len(logged_exclusions) == len(out_scope_data), (
        f"Expected {len(out_scope_data)} exclusion events logged, "
        f"got {len(logged_exclusions)}"
    )
    logged_targets = {e.target for e in logged_exclusions}
    assert logged_targets == out_scope_names, (
        f"Logged exclusion targets {logged_targets!r} != out-of-scope names {out_scope_names!r}"
    )


# ---------------------------------------------------------------------------
# Additional edge-case: all hosts in scope → no exclusions
# ---------------------------------------------------------------------------

@given(scenario=surface_map_input_strategy())
@settings(max_examples=50)
def test_property4_all_in_scope_no_exclusions(scenario):
    """
    When every host is in scope, excluded must be empty and active_hosts must
    contain all provided hosts.

    **Validates: Requirements 2.5, 2.6**
    """
    in_scope_data, _, authorized_domain = scenario

    # Only use in-scope hosts
    all_hosts = [host for host, _, _ in in_scope_data]
    ports = {host.hostname: ep for host, ep, _ in in_scope_data}
    techs = {host.hostname: et for host, _, et in in_scope_data}

    scope = ScopeValidator(
        authorized_domains=[authorized_domain],
        authorized_cidrs=[],
    )
    logger = AuditLogger()
    mapper = SurfaceMapper()

    result = mapper.build_surface_map(
        hosts=all_hosts,
        ports=ports,
        techs=techs,
        scope=scope,
        logger=logger,
    )

    # No exclusions expected
    assert result.excluded == [], (
        f"Expected no exclusions, got {result.excluded!r}"
    )
    # All hosts should appear in active_hosts
    expected_names = {h.hostname for h in all_hosts}
    actual_names = {h.hostname for h in result.active_hosts}
    assert actual_names == expected_names


# ---------------------------------------------------------------------------
# Additional edge-case: all hosts out of scope → empty active_hosts
# ---------------------------------------------------------------------------

@given(scenario=surface_map_input_strategy())
@settings(max_examples=50)
def test_property4_all_out_of_scope_empty_active_hosts(scenario):
    """
    When every host is out of scope, active_hosts must be empty and there must
    be one exclusion per host.

    **Validates: Requirements 2.5, 2.6**
    """
    _, out_scope_data, authorized_domain = scenario

    # Only use out-of-scope hosts
    all_hosts = [host for host, _, _ in out_scope_data]
    ports = {host.hostname: ep for host, ep, _ in out_scope_data}
    techs = {host.hostname: et for host, _, et in out_scope_data}

    scope = ScopeValidator(
        authorized_domains=[authorized_domain],
        authorized_cidrs=[],
    )
    logger = AuditLogger()
    mapper = SurfaceMapper()

    result = mapper.build_surface_map(
        hosts=all_hosts,
        ports=ports,
        techs=techs,
        scope=scope,
        logger=logger,
    )

    # No in-scope active hosts
    assert result.active_hosts == [], (
        f"Expected empty active_hosts, got {result.active_hosts!r}"
    )
    # One exclusion per host
    assert len(result.excluded) == len(all_hosts), (
        f"Expected {len(all_hosts)} exclusions, got {len(result.excluded)}"
    )
    excluded_names = {e.host for e in result.excluded}
    input_names = {h.hostname for h in all_hosts}
    assert excluded_names == input_names


# ---------------------------------------------------------------------------
# Additional edge-case: empty host list → empty map, no exclusions
# ---------------------------------------------------------------------------

def test_property4_empty_host_list():
    """
    With an empty host list the resulting map has no active hosts, no
    exclusions, and no technologies.

    **Validates: Requirements 2.5, 2.6**
    """
    scope = ScopeValidator(
        authorized_domains=["example.com"],
        authorized_cidrs=[],
    )
    logger = AuditLogger()
    mapper = SurfaceMapper()

    result = mapper.build_surface_map(
        hosts=[],
        ports={},
        techs={},
        scope=scope,
        logger=logger,
    )

    assert result.active_hosts == []
    assert result.excluded == []
    assert result.technologies_by_host == {}
    assert result.subdomains == []
