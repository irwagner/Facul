"""Tests for the open-redirect check and classifier."""

from __future__ import annotations

from dataclasses import dataclass

from hypothesis import given, settings, strategies as st

from toolkit.execution.checks import open_redirect as orc
from toolkit.analysis.classifiers import open_redirect as orcls


@dataclass
class FakeResp:
    status: int
    location: str | None = None
    url: str | None = None


def _fake_transport(map_url_to_resp):
    def transport(url):
        return map_url_to_resp.get(url, FakeResp(status=200))
    return transport


def test_check_open_redirect_injects_payloads_into_query():
    """Each (parameter, payload) pair must produce one HTTP attempt."""
    seen: list[str] = []

    def transport(url):
        seen.append(url)
        return FakeResp(status=302, location=f"https://{orc.CANARY_HOST}/")

    target = "https://target.test/login?next=/home"
    result = orc.check_open_redirect(target, transport=transport)

    expected = len(orc.DEFAULT_REDIRECT_PARAMS) * len(orc.PAYLOADS)
    assert len(result.attempts) == expected
    assert len(seen) == expected


# Feature: web-security-audit-toolkit, Property 29: classifier confirms vulnerable
# only when Location header (or final URL) resolves to the canary host.
@given(
    canary=st.booleans(),
    via_location=st.booleans(),
    payload=st.sampled_from(orc.PAYLOADS),
    parameter=st.sampled_from(orc.DEFAULT_REDIRECT_PARAMS),
)
@settings(max_examples=100, deadline=None)
def test_classifier_decision(canary, via_location, payload, parameter):
    location = f"https://{orc.CANARY_HOST}/" if canary and via_location else "https://target.test/safe"
    final_url = f"https://{orc.CANARY_HOST}/" if canary and not via_location else "https://target.test/safe"

    attempt = orc.RedirectAttempt(
        parameter=parameter,
        payload=payload,
        final_url=final_url,
        status=302,
        location=location,
    )
    result = orc.OpenRedirectResult(target_url="https://target.test/login", attempts=[attempt])

    classification = orcls.analyze_open_redirect(result)
    assert classification.is_vulnerable is canary
    if canary:
        assert classification.findings[0].confirmed_via in {"location_header", "final_url"}


def test_classifier_ignores_errored_attempts():
    attempt = orc.RedirectAttempt(
        parameter="next",
        payload=orc.PAYLOADS[0],
        final_url=None,
        status=None,
        location=None,
        error="ConnectionError",
    )
    result = orc.OpenRedirectResult(target_url="https://target.test", attempts=[attempt])
    assert orcls.analyze_open_redirect(result).is_vulnerable is False


def test_protocol_relative_canary_is_detected():
    attempt = orc.RedirectAttempt(
        parameter="next",
        payload="//evil",
        final_url=None,
        status=302,
        location=f"//{orc.CANARY_HOST}/",
    )
    result = orc.OpenRedirectResult(target_url="x", attempts=[attempt])
    assert orcls.analyze_open_redirect(result).is_vulnerable is True
