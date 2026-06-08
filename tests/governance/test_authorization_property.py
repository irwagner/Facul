"""
Property-based tests for ``AuthorizationManager`` (task 2.2, Req. 1.2, 1.6).

# Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização

**Validates: Requirements 1.2, 1.6**

Properties
----------
1. Bicondicional de ``is_valid``:
   ``is_valid(auth, now)`` é ``True`` se e somente se:
   - ``auth`` não é ``None``;
   - ``domain``, ``institution`` e ``auth_date`` estão presentes e não vazios;
   - ``(now - auth.auth_date).days <= 365``.

2. Bicondicional de ``is_expired``:
   ``is_expired(auth, now)`` é ``True`` se e somente se
   ``(now - auth.auth_date).days > 365``.

3. Complementaridade entre ``is_valid`` e ``is_expired`` para autorizações com
   todos os campos obrigatórios presentes:
   uma autorização válida nunca está expirada, e vice-versa (quando os campos
   estão presentes, as duas propriedades são mutuamente exclusivas e cobrindo
   o critério de 1 ano).

4. ``require_valid`` sempre lança ``AuthorizationError`` quando a autorização
   está ausente (``None``) ou inválida (campos faltando ou data expirada).
"""

from __future__ import annotations

import string
from datetime import date, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import composite

from toolkit.exceptions import AuthorizationError
from toolkit.governance.authorization import AuthorizationManager
from toolkit.models import Authorization

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_today = date.today()

# Dates that cover well before expiry, on the boundary, and after expiry
_any_auth_date = st.dates(
    min_value=_today - timedelta(days=5 * 365),
    max_value=_today + timedelta(days=365),
)

# Dates that are within the valid window (at most 365 days before now)
_valid_auth_date = st.dates(
    min_value=_today - timedelta(days=365),
    max_value=_today,
)

# Dates that are strictly outside the valid window (more than 365 days before now)
_expired_auth_date = st.dates(
    min_value=_today - timedelta(days=5 * 365),
    max_value=_today - timedelta(days=366),
)

_non_empty_text = st.text(
    alphabet=string.ascii_letters + string.digits + " -_.",
    min_size=1,
    max_size=80,
)

_domain_strategy = st.builds(
    lambda label, tld: f"{label}.{tld}",
    label=st.text(
        alphabet=string.ascii_lowercase + string.digits + "-",
        min_size=1,
        max_size=30,
    ),
    tld=st.sampled_from(["com", "org", "net", "edu", "io"]),
)


@composite
def valid_authorization(draw: st.DrawFn) -> Authorization:
    """Authorization with all 3 required fields and a date within 1 year."""
    return Authorization(
        domain=draw(_domain_strategy),
        institution=draw(_non_empty_text),
        auth_date=draw(_valid_auth_date),
        authorized_domains=[],
        authorized_cidrs=[],
    )


@composite
def expired_authorization(draw: st.DrawFn) -> Authorization:
    """Authorization with all 3 required fields but a date older than 1 year."""
    return Authorization(
        domain=draw(_domain_strategy),
        institution=draw(_non_empty_text),
        auth_date=draw(_expired_auth_date),
        authorized_domains=[],
        authorized_cidrs=[],
    )


@composite
def missing_fields_authorization(draw: st.DrawFn) -> Authorization:
    """Authorization where at least one of the 3 required fields is empty."""
    domain = draw(st.one_of(st.just(""), _domain_strategy))
    institution = draw(st.one_of(st.just(""), _non_empty_text))
    # Ensure at least one of domain or institution is empty
    if domain and institution:
        # Force one to be empty
        which = draw(st.sampled_from(["domain", "institution"]))
        if which == "domain":
            domain = ""
        else:
            institution = ""
    auth_date = draw(_any_auth_date)
    return Authorization(
        domain=domain,
        institution=institution,
        auth_date=auth_date,
        authorized_domains=[],
        authorized_cidrs=[],
    )


@composite
def any_authorization(draw: st.DrawFn) -> Authorization:
    """Authorization with any combination of fields and dates."""
    domain = draw(st.one_of(st.just(""), _domain_strategy))
    institution = draw(st.one_of(st.just(""), _non_empty_text))
    auth_date = draw(_any_auth_date)
    return Authorization(
        domain=domain,
        institution=institution,
        auth_date=auth_date,
        authorized_domains=[],
        authorized_cidrs=[],
    )


# ---------------------------------------------------------------------------
# Property 1a: is_valid returns True for fully populated, non-expired auth
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=valid_authorization())
def test_is_valid_true_when_fields_present_and_not_expired(
    auth: Authorization,
) -> None:
    """
    Property 1a: ``is_valid`` returns ``True`` when all 3 required fields are
    present and ``auth_date`` is within 1 year of today.

    Validates: Requirements 1.2
    """
    manager = AuthorizationManager()
    now = _today

    result = manager.is_valid(auth, now)

    assert result is True, (
        f"Expected is_valid=True for domain={auth.domain!r}, "
        f"institution={auth.institution!r}, auth_date={auth.auth_date!r}, "
        f"now={now!r}"
    )


# ---------------------------------------------------------------------------
# Property 1b: is_valid returns False when auth_date is expired
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=expired_authorization())
def test_is_valid_false_when_expired(auth: Authorization) -> None:
    """
    Property 1b: ``is_valid`` returns ``False`` when ``auth_date`` is more than
    365 days before ``now``.

    Validates: Requirements 1.2
    """
    manager = AuthorizationManager()
    now = _today

    result = manager.is_valid(auth, now)

    assert result is False, (
        f"Expected is_valid=False for auth_date={auth.auth_date!r} "
        f"(more than 1 year before now={now!r})"
    )


# ---------------------------------------------------------------------------
# Property 1c: is_valid returns False when required fields are missing
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=missing_fields_authorization())
def test_is_valid_false_when_fields_missing(auth: Authorization) -> None:
    """
    Property 1c: ``is_valid`` returns ``False`` when at least one of the 3
    required fields (domain, institution, auth_date) is empty/missing.

    Validates: Requirements 1.2
    """
    manager = AuthorizationManager()
    now = _today

    result = manager.is_valid(auth, now)

    assert result is False, (
        f"Expected is_valid=False for domain={auth.domain!r}, "
        f"institution={auth.institution!r}"
    )


# ---------------------------------------------------------------------------
# Property 1d: is_valid returns False for None
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(now=st.dates(
    min_value=_today - timedelta(days=365),
    max_value=_today + timedelta(days=365),
))
def test_is_valid_false_for_none(now: date) -> None:
    """
    Property 1d: ``is_valid(None, now)`` always returns ``False``.

    Validates: Requirements 1.2
    """
    manager = AuthorizationManager()

    result = manager.is_valid(None, now)

    assert result is False, f"Expected is_valid=False for auth=None, now={now!r}"


# ---------------------------------------------------------------------------
# Property 2a: is_expired returns True when auth_date is more than 1 year ago
# Validates: Requirements 1.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=expired_authorization())
def test_is_expired_true_when_older_than_one_year(auth: Authorization) -> None:
    """
    Property 2a: ``is_expired`` returns ``True`` when
    ``(now - auth.auth_date).days > 365``.

    Validates: Requirements 1.6
    """
    manager = AuthorizationManager()
    now = _today

    result = manager.is_expired(auth, now)

    assert result is True, (
        f"Expected is_expired=True for auth_date={auth.auth_date!r} "
        f"(days since issue: {(now - auth.auth_date).days})"
    )


# ---------------------------------------------------------------------------
# Property 2b: is_expired returns False when auth_date is within 1 year
# Validates: Requirements 1.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=valid_authorization())
def test_is_expired_false_when_within_one_year(auth: Authorization) -> None:
    """
    Property 2b: ``is_expired`` returns ``False`` when
    ``(now - auth.auth_date).days <= 365``.

    Validates: Requirements 1.6
    """
    manager = AuthorizationManager()
    now = _today

    result = manager.is_expired(auth, now)

    assert result is False, (
        f"Expected is_expired=False for auth_date={auth.auth_date!r} "
        f"(days since issue: {(now - auth.auth_date).days})"
    )


# ---------------------------------------------------------------------------
# Property 3: Complementarity — valid ↔ not expired (for complete auths)
# Validates: Requirements 1.2, 1.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=any_authorization(), now=_any_auth_date)
def test_valid_and_expired_are_mutually_exclusive_for_complete_auth(
    auth: Authorization,
    now: date,
) -> None:
    """
    Property 3: For an authorization whose required fields are all present,
    ``is_valid`` and ``is_expired`` are mutually exclusive with respect to the
    1-year threshold: an authorization cannot be both valid and expired
    simultaneously.

    Specifically: if domain, institution, and auth_date are all present,
    then ``is_valid(auth, now) == (not is_expired(auth, now))``.

    Validates: Requirements 1.2, 1.6
    """
    if not auth.domain or not auth.institution or auth.auth_date is None:
        return  # only applies when all 3 fields are present

    manager = AuthorizationManager()

    valid = manager.is_valid(auth, now)
    expired = manager.is_expired(auth, now)

    assert valid != expired, (
        f"is_valid={valid!r} and is_expired={expired!r} must be opposites "
        f"when all fields are present. "
        f"auth_date={auth.auth_date!r}, now={now!r}, "
        f"days={(now - auth.auth_date).days}"
    )


# ---------------------------------------------------------------------------
# Property 4a: require_valid raises AuthorizationError for None
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(now=st.dates(
    min_value=_today - timedelta(days=365),
    max_value=_today + timedelta(days=365),
))
def test_require_valid_raises_for_none(now: date) -> None:
    """
    Property 4a: ``require_valid(None, now)`` always raises ``AuthorizationError``.

    Validates: Requirements 1.2
    """
    manager = AuthorizationManager()

    with pytest.raises(AuthorizationError):
        manager.require_valid(None, now)


# ---------------------------------------------------------------------------
# Property 4b: require_valid raises AuthorizationError for expired auth
# Validates: Requirements 1.2, 1.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=expired_authorization())
def test_require_valid_raises_for_expired_auth(auth: Authorization) -> None:
    """
    Property 4b: ``require_valid`` raises ``AuthorizationError`` when the
    authorization has expired (``auth_date`` more than 365 days before now).

    Validates: Requirements 1.2, 1.6
    """
    manager = AuthorizationManager()
    now = _today

    with pytest.raises(AuthorizationError):
        manager.require_valid(auth, now)


# ---------------------------------------------------------------------------
# Property 4c: require_valid raises AuthorizationError for missing fields
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=missing_fields_authorization())
def test_require_valid_raises_for_missing_fields(auth: Authorization) -> None:
    """
    Property 4c: ``require_valid`` raises ``AuthorizationError`` when at least
    one required field (domain or institution) is empty, regardless of the date.

    Validates: Requirements 1.2
    """
    manager = AuthorizationManager()
    now = _today

    with pytest.raises(AuthorizationError):
        manager.require_valid(auth, now)


# ---------------------------------------------------------------------------
# Property 4d: require_valid does NOT raise for a fully valid authorization
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=valid_authorization())
def test_require_valid_does_not_raise_for_valid_auth(auth: Authorization) -> None:
    """
    Property 4d: ``require_valid`` does NOT raise when the authorization is
    fully valid (all 3 fields present, date within 1 year).

    Validates: Requirements 1.2
    """
    manager = AuthorizationManager()
    now = _today

    # Should complete without raising
    manager.require_valid(auth, now)
