"""
Property-based tests for Enumerator response classification.

# Feature: web-security-audit-toolkit, Property 6: Classificação de resposta registra os campos corretos por classe de status

**Validates: Requirements 3.3, 3.4**

Property under test
-------------------
For every HTTP response, ``Enumerator.classify_response`` produces an
``Endpoint`` that:

* **Status 200** — records ``status_code``, ``body_size``, and the page
  title extracted from the HTML ``<title>`` tag when present (``None`` when
  absent).  ``kind`` is set to ``"page"``.

* **Status 301/302** — records the original ``path``, ``status_code``, and
  the ``Location`` header value.  ``kind`` is set to ``"redirect"``.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.discovery.enumerator import Enumerator
from toolkit.models import Endpoint


# ---------------------------------------------------------------------------
# Minimal fake response object
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Minimal HTTP response stub accepted by ``classify_response``."""

    def __init__(
        self,
        status_code: int,
        body_size: int,
        text: str = "",
        location: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.body_size = body_size
        self.text = text
        self.location = location


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Valid URL path segment
_path_char_alphabet = string.ascii_lowercase + string.digits + "-_."

_path_strategy = st.builds(
    lambda segment: f"/{segment}",
    segment=st.text(
        alphabet=_path_char_alphabet,
        min_size=1,
        max_size=60,
    ),
)

# Non-empty title text (may contain any printable characters except </>)
_title_text_strategy = st.text(
    alphabet=string.printable.replace("<", "").replace(">", "").replace("/", ""),
    min_size=1,
    max_size=120,
)

# HTML body strategy: optionally embeds a <title> tag
@st.composite
def _html_body_strategy(draw: st.DrawFn) -> tuple[str, str | None]:
    """
    Returns ``(html_body, expected_title)`` where ``expected_title`` is
    ``None`` when the body contains no ``<title>`` tag.
    """
    has_title = draw(st.booleans())
    if has_title:
        title = draw(_title_text_strategy)
        # The title can be nested in a realistic HTML skeleton or be bare
        use_skeleton = draw(st.booleans())
        if use_skeleton:
            html = (
                f"<!DOCTYPE html><html><head>"
                f"<title>{title}</title>"
                f"</head><body></body></html>"
            )
        else:
            html = f"<title>{title}</title>"
        return html, title.strip() or None
    else:
        # Body without any <title>
        plain = draw(
            st.text(
                alphabet=string.printable,
                min_size=0,
                max_size=200,
            ).filter(lambda s: "<title" not in s.lower())
        )
        return plain, None


# Positive body size (bytes)
_body_size_strategy = st.integers(min_value=0, max_value=1_000_000)

# Location header value strategy (absolute or relative URL)
_location_strategy = st.builds(
    lambda host, path: f"https://{host}/{path}",
    host=st.builds(
        lambda label: f"{label}.example.com",
        label=st.text(
            alphabet=string.ascii_lowercase + string.digits,
            min_size=1,
            max_size=30,
        ),
    ),
    path=st.text(
        alphabet=string.ascii_lowercase + string.digits + "/-_",
        min_size=0,
        max_size=60,
    ),
)


# ---------------------------------------------------------------------------
# Property 6a — Status 200: correct fields recorded
# ---------------------------------------------------------------------------

@given(
    path=_path_strategy,
    body_size=_body_size_strategy,
    html_and_title=_html_body_strategy(),
)
@settings(max_examples=100)
def test_property6_status_200_records_status_body_size_and_title(
    path: str,
    body_size: int,
    html_and_title: tuple[str, str | None],
):
    """
    Property 6 (status 200): Classificação de resposta registra os campos corretos.

    **Validates: Requirements 3.3**

    For every HTTP 200 response, ``classify_response`` MUST:
      1. Record ``status_code == 200``.
      2. Record ``body_size`` equal to the response body size.
      3. Extract and record ``title`` from the ``<title>`` tag when present,
         or ``None`` when absent.
      4. Set ``kind == "page"``.
      5. Record the original ``path``.
    """
    html_body, expected_title = html_and_title
    resp = _FakeResponse(
        status_code=200,
        body_size=body_size,
        text=html_body,
        location=None,
    )

    enumerator = Enumerator()
    endpoint = enumerator.classify_response(path, resp)

    # Sub-property 1: path is preserved
    assert endpoint.path == path, (
        f"Expected path={path!r}, got {endpoint.path!r}"
    )

    # Sub-property 2: status_code is 200
    assert endpoint.status_code == 200, (
        f"Expected status_code=200, got {endpoint.status_code!r}"
    )

    # Sub-property 3: body_size matches
    assert endpoint.body_size == body_size, (
        f"Expected body_size={body_size}, got {endpoint.body_size!r}"
    )

    # Sub-property 4: title extracted correctly
    assert endpoint.title == expected_title, (
        f"Expected title={expected_title!r}, got {endpoint.title!r}\n"
        f"HTML body: {html_body!r}"
    )

    # Sub-property 5: kind is "page"
    assert endpoint.kind == "page", (
        f"Expected kind='page', got {endpoint.kind!r}"
    )

    # Sub-property 6: location is None for 200 responses
    assert endpoint.location is None, (
        f"Expected location=None for 200, got {endpoint.location!r}"
    )


# ---------------------------------------------------------------------------
# Property 6b — Status 301/302: correct fields recorded
# ---------------------------------------------------------------------------

@given(
    path=_path_strategy,
    body_size=_body_size_strategy,
    location=st.one_of(st.none(), _location_strategy),
    status_code=st.sampled_from([301, 302]),
)
@settings(max_examples=100)
def test_property6_status_301_302_records_path_status_and_location(
    path: str,
    body_size: int,
    location: str | None,
    status_code: int,
):
    """
    Property 6 (status 301/302): Classificação de resposta registra os campos corretos.

    **Validates: Requirements 3.4**

    For every HTTP 301 or 302 response, ``classify_response`` MUST:
      1. Record the original ``path``.
      2. Record ``status_code`` as 301 or 302 (the actual redirect code).
      3. Record the ``Location`` header value (may be ``None`` if absent).
      4. Set ``kind == "redirect"``.
    """
    resp = _FakeResponse(
        status_code=status_code,
        body_size=body_size,
        text="",
        location=location,
    )

    enumerator = Enumerator()
    endpoint = enumerator.classify_response(path, resp)

    # Sub-property 1: original path is preserved
    assert endpoint.path == path, (
        f"Expected path={path!r}, got {endpoint.path!r}"
    )

    # Sub-property 2: status_code matches the redirect code
    assert endpoint.status_code == status_code, (
        f"Expected status_code={status_code}, got {endpoint.status_code!r}"
    )

    # Sub-property 3: Location header value is recorded as-is
    assert endpoint.location == location, (
        f"Expected location={location!r}, got {endpoint.location!r}"
    )

    # Sub-property 4: kind is "redirect"
    assert endpoint.kind == "redirect", (
        f"Expected kind='redirect', got {endpoint.kind!r}"
    )

    # Sub-property 5: title is None for redirects
    assert endpoint.title is None, (
        f"Expected title=None for redirect, got {endpoint.title!r}"
    )


# ---------------------------------------------------------------------------
# Property 6c — Status 200 with title case-insensitive tag matching
# ---------------------------------------------------------------------------

@given(
    path=_path_strategy,
    body_size=_body_size_strategy,
    title=_title_text_strategy,
    tag_case=st.sampled_from(["<title>", "<TITLE>", "<Title>", "<TiTlE>"]),
)
@settings(max_examples=100)
def test_property6_status_200_title_extracted_case_insensitively(
    path: str,
    body_size: int,
    title: str,
    tag_case: str,
):
    """
    Property 6 (case-insensitive title): title is extracted regardless of
    ``<title>`` tag capitalisation.

    **Validates: Requirements 3.3**

    The ``<title>`` tag can appear in any mix of upper/lower case and the
    title text must still be extracted correctly.
    """
    closing_tag = tag_case.replace("<", "</")
    html_body = f"{tag_case}{title}{closing_tag}"

    resp = _FakeResponse(
        status_code=200,
        body_size=body_size,
        text=html_body,
        location=None,
    )

    enumerator = Enumerator()
    endpoint = enumerator.classify_response(path, resp)

    expected_title = title.strip() or None
    assert endpoint.title == expected_title, (
        f"Expected title={expected_title!r}, got {endpoint.title!r}\n"
        f"HTML: {html_body!r}"
    )


# ---------------------------------------------------------------------------
# Edge case: status 200, body has no <title> tag → title is None
# ---------------------------------------------------------------------------

def test_property6_status_200_no_title_tag_returns_none():
    """
    When the HTTP 200 response body contains no ``<title>`` tag,
    ``classify_response`` must record ``title=None``.

    **Validates: Requirements 3.3**
    """
    enumerator = Enumerator()
    resp = _FakeResponse(
        status_code=200,
        body_size=512,
        text="<html><head></head><body>Hello</body></html>",
        location=None,
    )
    endpoint = enumerator.classify_response("/hello", resp)

    assert endpoint.title is None
    assert endpoint.status_code == 200
    assert endpoint.body_size == 512
    assert endpoint.kind == "page"
    assert endpoint.path == "/hello"


# ---------------------------------------------------------------------------
# Edge case: status 200, empty <title> tag → title is None
# ---------------------------------------------------------------------------

def test_property6_status_200_empty_title_tag_returns_none():
    """
    An empty ``<title></title>`` tag must result in ``title=None``.

    **Validates: Requirements 3.3**
    """
    enumerator = Enumerator()
    resp = _FakeResponse(
        status_code=200,
        body_size=100,
        text="<html><head><title></title></head></html>",
        location=None,
    )
    endpoint = enumerator.classify_response("/empty-title", resp)

    assert endpoint.title is None
    assert endpoint.kind == "page"


# ---------------------------------------------------------------------------
# Edge case: status 301 with Location header
# ---------------------------------------------------------------------------

def test_property6_status_301_records_location():
    """
    A 301 redirect must record the Location header exactly as given.

    **Validates: Requirements 3.4**
    """
    enumerator = Enumerator()
    resp = _FakeResponse(
        status_code=301,
        body_size=0,
        text="",
        location="https://example.com/new-path",
    )
    endpoint = enumerator.classify_response("/old-path", resp)

    assert endpoint.path == "/old-path"
    assert endpoint.status_code == 301
    assert endpoint.location == "https://example.com/new-path"
    assert endpoint.kind == "redirect"
    assert endpoint.title is None


# ---------------------------------------------------------------------------
# Edge case: status 302 without Location header → location is None
# ---------------------------------------------------------------------------

def test_property6_status_302_no_location_records_none():
    """
    A 302 redirect with no Location header must record ``location=None``.

    **Validates: Requirements 3.4**
    """
    enumerator = Enumerator()
    resp = _FakeResponse(
        status_code=302,
        body_size=0,
        text="",
        location=None,
    )
    endpoint = enumerator.classify_response("/redirect-path", resp)

    assert endpoint.path == "/redirect-path"
    assert endpoint.status_code == 302
    assert endpoint.location is None
    assert endpoint.kind == "redirect"
