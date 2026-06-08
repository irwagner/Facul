"""
Property-based tests for ``AuthorizationManager`` — validade/expiração da autorização.

# Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização

**Validates: Requirements 1.2, 1.6**

Properties tested
-----------------
1. Bicondicional de ``is_valid``:
   ``is_valid(auth, now)`` retorna ``True`` se e somente se:
   - ``auth`` não é ``None``;
   - ``domain``, ``institution`` e ``auth_date`` estão presentes e não são vazios;
   - ``(now - auth.auth_date).days <= 365``.

2. Bicondicional de ``is_expired``:
   ``is_expired(auth, now)`` retorna ``True`` se e somente se
   ``(now - auth.auth_date).days > 365``.

3. Complementaridade (mutual exclusivity):
   Para toda autorização com os 3 campos obrigatórios presentes,
   ``is_valid(auth, now) == (not is_expired(auth, now))``.

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
# Reference date and date strategies
# ---------------------------------------------------------------------------

_today = date.today()

# Wide window: covers well before, at the boundary, and after expiry
_any_date = st.dates(
    min_value=_today - timedelta(days=5 * 365),
    max_value=_today + timedelta(days=365),
)

# Within the valid window (at most 365 days before now)
_valid_auth_date = st.dates(
    min_value=_today - timedelta(days=365),
    max_value=_today,
)

# Strictly outside the valid window (more than 365 days before now)
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


# ---------------------------------------------------------------------------
# Composite strategies
# ---------------------------------------------------------------------------

@composite
def valid_authorization(draw: st.DrawFn) -> Authorization:
    """Authorization with all 3 required fields and auth_date within 1 year."""
    return Authorization(
        domain=draw(_domain_strategy),
        institution=draw(_non_empty_text),
        auth_date=draw(_valid_auth_date),
        authorized_domains=[],
        authorized_cidrs=[],
    )


@composite
def expired_authorization(draw: st.DrawFn) -> Authorization:
    """Authorization with all 3 required fields but auth_date older than 1 year."""
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
    # Guarantee at least one required field is empty
    if domain and institution:
        which = draw(st.sampled_from(["domain", "institution"]))
        if which == "domain":
            domain = ""
        else:
            institution = ""
    auth_date = draw(_any_date)
    return Authorization(
        domain=domain,
        institution=institution,
        auth_date=auth_date,
        authorized_domains=[],
        authorized_cidrs=[],
    )


@composite
def any_complete_authorization(draw: st.DrawFn) -> Authorization:
    """Authorization with all 3 required fields (non-empty) and any date."""
    return Authorization(
        domain=draw(_domain_strategy),
        institution=draw(_non_empty_text),
        auth_date=draw(_any_date),
        authorized_domains=[],
        authorized_cidrs=[],
    )


# ---------------------------------------------------------------------------
# Property 1a — is_valid returns True iff all fields present AND date <= 1 year
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=valid_authorization())
def test_is_valid_true_for_complete_non_expired_auth(auth: Authorization) -> None:
    """
    **Property 1 (positive arm)**: ``is_valid`` returns ``True`` when all 3
    required fields are present and ``auth_date`` is within 1 year of today.

    Validates: Requirements 1.2
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()
    result = manager.is_valid(auth, _today)

    assert result is True, (
        f"Expected is_valid=True but got False. "
        f"domain={auth.domain!r}, institution={auth.institution!r}, "
        f"auth_date={auth.auth_date!r}, now={_today!r}, "
        f"days={((_today - auth.auth_date).days)}"
    )


@settings(max_examples=100)
@given(auth=expired_authorization())
def test_is_valid_false_for_expired_auth(auth: Authorization) -> None:
    """
    **Property 1 (expired arm)**: ``is_valid`` returns ``False`` when
    ``auth_date`` is more than 365 days before ``now``.

    Validates: Requirements 1.2
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()
    result = manager.is_valid(auth, _today)

    assert result is False, (
        f"Expected is_valid=False for expired auth_date={auth.auth_date!r} "
        f"(days since issue: {(_today - auth.auth_date).days})"
    )


@settings(max_examples=100)
@given(auth=missing_fields_authorization())
def test_is_valid_false_for_missing_required_fields(auth: Authorization) -> None:
    """
    **Property 1 (missing-fields arm)**: ``is_valid`` returns ``False`` when at
    least one of the 3 required fields (domain, institution) is empty.

    Validates: Requirements 1.2
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()
    result = manager.is_valid(auth, _today)

    assert result is False, (
        f"Expected is_valid=False for domain={auth.domain!r}, "
        f"institution={auth.institution!r}"
    )


@settings(max_examples=100)
@given(now=_any_date)
def test_is_valid_false_for_none(now: date) -> None:
    """
    **Property 1 (None arm)**: ``is_valid(None, now)`` always returns ``False``.

    Validates: Requirements 1.2
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()
    result = manager.is_valid(None, now)

    assert result is False, f"Expected is_valid=False for auth=None, now={now!r}"


# ---------------------------------------------------------------------------
# Property 2a — is_expired returns True iff now - auth_date > 1 year
# Validates: Requirements 1.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=expired_authorization())
def test_is_expired_true_when_date_exceeds_one_year(auth: Authorization) -> None:
    """
    **Property 2 (positive arm)**: ``is_expired`` returns ``True`` when
    ``(now - auth.auth_date).days > 365``.

    Validates: Requirements 1.6
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()
    result = manager.is_expired(auth, _today)

    assert result is True, (
        f"Expected is_expired=True for auth_date={auth.auth_date!r} "
        f"(days since issue: {(_today - auth.auth_date).days})"
    )


@settings(max_examples=100)
@given(auth=valid_authorization())
def test_is_expired_false_when_date_within_one_year(auth: Authorization) -> None:
    """
    **Property 2 (negative arm)**: ``is_expired`` returns ``False`` when
    ``(now - auth.auth_date).days <= 365``.

    Validates: Requirements 1.6
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()
    result = manager.is_expired(auth, _today)

    assert result is False, (
        f"Expected is_expired=False for auth_date={auth.auth_date!r} "
        f"(days since issue: {(_today - auth.auth_date).days})"
    )


# ---------------------------------------------------------------------------
# Property 3 — is_valid and is_expired are mutually exclusive (biconditional)
# Validates: Requirements 1.2, 1.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=any_complete_authorization(), now=_any_date)
def test_is_valid_and_is_expired_biconditional(
    auth: Authorization,
    now: date,
) -> None:
    """
    **Property 3 (biconditional / complementarity)**:
    For an authorization whose 3 required fields are all present,
    ``is_valid(auth, now) == (not is_expired(auth, now))``.

    The two predicates are determined solely by whether
    ``(now - auth.auth_date).days`` is ≤ 365 or > 365, so they are
    always mutually exclusive and exhaustive.

    Validates: Requirements 1.2, 1.6
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()

    valid = manager.is_valid(auth, now)
    expired = manager.is_expired(auth, now)

    # is_valid is True  ↔  is_expired is False
    # is_valid is False ↔  is_expired is True
    assert valid != expired, (
        f"is_valid={valid!r} and is_expired={expired!r} must always differ "
        f"for authorizations with all fields present. "
        f"auth_date={auth.auth_date!r}, now={now!r}, "
        f"days={(now - auth.auth_date).days}"
    )


# ---------------------------------------------------------------------------
# Property 4a — require_valid raises AuthorizationError for None
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(now=_any_date)
def test_require_valid_raises_for_none_auth(now: date) -> None:
    """
    **Property 4 (None arm)**: ``require_valid(None, now)`` always raises
    ``AuthorizationError``, regardless of the reference date.

    Validates: Requirements 1.2
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()

    with pytest.raises(AuthorizationError):
        manager.require_valid(None, now)


# ---------------------------------------------------------------------------
# Property 4b — require_valid raises AuthorizationError for expired auth
# Validates: Requirements 1.2, 1.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=expired_authorization())
def test_require_valid_raises_for_expired_auth(auth: Authorization) -> None:
    """
    **Property 4 (expired arm)**: ``require_valid`` raises ``AuthorizationError``
    for any authorization whose ``auth_date`` is more than 365 days before now.

    Validates: Requirements 1.2, 1.6
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()

    with pytest.raises(AuthorizationError):
        manager.require_valid(auth, _today)


# ---------------------------------------------------------------------------
# Property 4c — require_valid raises AuthorizationError for missing fields
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=missing_fields_authorization())
def test_require_valid_raises_for_missing_required_fields(auth: Authorization) -> None:
    """
    **Property 4 (missing-fields arm)**: ``require_valid`` raises
    ``AuthorizationError`` when at least one required field is empty,
    regardless of the date.

    Validates: Requirements 1.2
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()

    with pytest.raises(AuthorizationError):
        manager.require_valid(auth, _today)


# ---------------------------------------------------------------------------
# Property 4d — require_valid does NOT raise for a fully valid authorization
# Validates: Requirements 1.2
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(auth=valid_authorization())
def test_require_valid_does_not_raise_for_valid_auth(auth: Authorization) -> None:
    """
    **Property 4 (valid arm)**: ``require_valid`` does NOT raise when the
    authorization has all 3 required fields and ``auth_date`` is within 1 year.

    Validates: Requirements 1.2
    """
    # Feature: web-security-audit-toolkit, Property 1: Validade e expiração da autorização
    manager = AuthorizationManager()

    # Must complete without raising any exception
    manager.require_valid(auth, _today)
