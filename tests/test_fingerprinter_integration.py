"""
Integration tests for Fingerprinter (Req. 2.4).

HTTP requests are fully mocked via unittest.mock so the tests never touch
the network. Each test class covers a distinct detection category:

  * Web server identification   (``Server`` header)
  * CDN identification          (various CDN-specific headers)
  * Framework identification    (``X-Powered-By`` / ``<meta name="generator">``)
  * Deduplication               (same technology across multiple ports)
  * Error handling              (connection failures are skipped gracefully)
  * Mixed stacks                (multiple technologies detected per host)

Requirements covered: 2.4
"""

from __future__ import annotations

from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest
import requests

from toolkit.discovery.fingerprinter import Fingerprinter
from toolkit.models import Host, Technology


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_host(hostname: str = "example.com", ip: str = "1.2.3.4") -> Host:
    return Host(hostname=hostname, ip=ip, is_active=True)


def _make_response(
    headers: dict[str, str],
    body: str = "",
    status_code: int = 200,
) -> MagicMock:
    """Build a minimal requests.Response mock."""
    resp = MagicMock()
    resp.headers = headers
    resp.text = body
    resp.status_code = status_code
    return resp


def _patch_requests_get(response: MagicMock):
    """Return a context manager that patches requests.get."""
    return patch("toolkit.discovery.fingerprinter.requests.get", return_value=response)


def _tech_by_category(techs: list[Technology], category: str) -> list[Technology]:
    """Filter technologies by category."""
    return [t for t in techs if t.category == category]


# ---------------------------------------------------------------------------
# Web server detection
# ---------------------------------------------------------------------------

class TestWebServerDetection:
    """Fingerprinter correctly identifies web servers from the Server header (Req. 2.4)."""

    def test_detects_nginx(self):
        """Server: nginx/1.24.0 → Technology(name='nginx', category='web_server')."""
        resp = _make_response({"Server": "nginx/1.24.0"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "nginx"
        assert servers[0].version == "1.24.0"

    def test_detects_apache(self):
        """Server: Apache/2.4.57 → Technology(name='Apache', category='web_server')."""
        resp = _make_response({"Server": "Apache/2.4.57 (Debian)"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "Apache"

    def test_detects_microsoft_iis(self):
        """Server: Microsoft-IIS/10.0 → Technology(name='IIS', category='web_server')."""
        resp = _make_response({"Server": "Microsoft-IIS/10.0"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "IIS"
        assert servers[0].version == "10.0"

    def test_detects_caddy(self):
        """Server: Caddy → Technology(name='Caddy', category='web_server')."""
        resp = _make_response({"Server": "Caddy"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "Caddy"

    def test_detects_gunicorn(self):
        """Server: gunicorn/21.2.0 → Technology(name='Gunicorn', category='web_server')."""
        resp = _make_response({"Server": "gunicorn/21.2.0"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [8000])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "Gunicorn"

    def test_unknown_server_recorded_as_web_server(self):
        """
        An unrecognised Server token is still recorded under category
        'web_server' with the token name, preserving auditability.
        """
        resp = _make_response({"Server": "MyCustomServer/3.0"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "MyCustomServer"
        assert servers[0].category == "web_server"

    def test_no_server_header_returns_no_web_server(self):
        """When the Server header is absent, no web_server technology is returned."""
        resp = _make_response({})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        servers = _tech_by_category(techs, "web_server")
        assert servers == []

    def test_detects_openresty(self):
        """Server: openresty/1.25.3.1 → Technology(name='OpenResty', category='web_server')."""
        resp = _make_response({"Server": "openresty/1.25.3.1"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "OpenResty"


# ---------------------------------------------------------------------------
# CDN detection
# ---------------------------------------------------------------------------

class TestCDNDetection:
    """Fingerprinter correctly identifies CDNs from response headers (Req. 2.4)."""

    def test_detects_cloudflare_via_cf_ray(self):
        """CF-Ray header → Technology(name='Cloudflare', category='cdn')."""
        resp = _make_response({"CF-RAY": "7e1a2b3c4d5e6f78-GRU"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [443])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "Cloudflare" for t in cdns)

    def test_detects_cloudfront_via_x_amz_cf_id(self):
        """X-Amz-Cf-Id header → Technology(name='CloudFront', category='cdn')."""
        resp = _make_response({"X-Amz-Cf-Id": "AbcDef123456"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [443])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "CloudFront" for t in cdns)

    def test_detects_cloudfront_via_x_cache_value(self):
        """X-Cache: Hit from cloudfront → Technology(name='CloudFront', category='cdn')."""
        resp = _make_response({"X-Cache": "Hit from cloudfront"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "CloudFront" for t in cdns)

    def test_detects_varnish_via_x_varnish(self):
        """X-Varnish header → Technology(name='Varnish', category='cdn')."""
        resp = _make_response({"X-Varnish": "12345678"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "Varnish" for t in cdns)

    def test_detects_fastly_via_x_fastly_request_id(self):
        """X-Fastly-Request-Id header → Technology(name='Fastly', category='cdn')."""
        resp = _make_response({"X-Fastly-Request-Id": "abcd1234"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "Fastly" for t in cdns)

    def test_detects_akamai_via_x_akamai_transformed(self):
        """X-Akamai-Transformed header → Technology(name='Akamai', category='cdn')."""
        resp = _make_response({"X-Akamai-Transformed": "9 -"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "Akamai" for t in cdns)

    def test_detects_sucuri_via_x_sucuri_id(self):
        """X-Sucuri-Id header → Technology(name='Sucuri', category='cdn')."""
        resp = _make_response({"X-Sucuri-Id": "abc123"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "Sucuri" for t in cdns)

    def test_detects_azure_cdn_via_x_azure_ref(self):
        """X-Azure-Ref header → Technology(name='Azure CDN', category='cdn')."""
        resp = _make_response({"X-Azure-Ref": "0abc1234"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [443])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "Azure CDN" for t in cdns)

    def test_no_cdn_headers_returns_no_cdn(self):
        """When no CDN headers are present, no cdn technology is returned."""
        resp = _make_response({"Server": "nginx"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        cdns = _tech_by_category(techs, "cdn")
        assert cdns == []

    def test_detects_cloudflare_via_via_header(self):
        """Via: 1.1 cloudflare → Technology(name='Cloudflare', category='cdn')."""
        resp = _make_response({"Via": "1.1 cloudflare (CloudFlare)"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        cdns = _tech_by_category(techs, "cdn")
        assert any(t.name == "Cloudflare" for t in cdns)


# ---------------------------------------------------------------------------
# Framework detection
# ---------------------------------------------------------------------------

class TestFrameworkDetection:
    """Fingerprinter correctly identifies frameworks (Req. 2.4)."""

    def test_detects_php_via_x_powered_by(self):
        """X-Powered-By: PHP/8.2.0 → Technology(name='PHP', category='framework')."""
        resp = _make_response({"X-Powered-By": "PHP/8.2.0"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        frameworks = _tech_by_category(techs, "framework")
        assert len(frameworks) == 1
        assert frameworks[0].name == "PHP"
        assert frameworks[0].version == "8.2.0"

    def test_detects_aspnet_via_x_powered_by(self):
        """X-Powered-By: ASP.NET → Technology(name='ASP.NET', category='framework')."""
        resp = _make_response({"X-Powered-By": "ASP.NET"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        frameworks = _tech_by_category(techs, "framework")
        assert len(frameworks) == 1
        assert frameworks[0].name == "ASP.NET"

    def test_detects_express_via_x_powered_by(self):
        """X-Powered-By: Express → Technology(name='Express', category='framework')."""
        resp = _make_response({"X-Powered-By": "Express"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [3000])

        frameworks = _tech_by_category(techs, "framework")
        assert len(frameworks) == 1
        assert frameworks[0].name == "Express"

    def test_detects_django_via_x_powered_by(self):
        """X-Powered-By: Django/4.2 → Technology(name='Django', category='framework')."""
        resp = _make_response({"X-Powered-By": "Django/4.2"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [8000])

        frameworks = _tech_by_category(techs, "framework")
        assert len(frameworks) == 1
        assert frameworks[0].name == "Django"

    def test_detects_nextjs_via_x_powered_by(self):
        """X-Powered-By: Next.js → Technology(name='Next.js', category='framework')."""
        resp = _make_response({"X-Powered-By": "Next.js"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [3000])

        frameworks = _tech_by_category(techs, "framework")
        assert len(frameworks) == 1
        assert frameworks[0].name == "Next.js"

    def test_detects_wordpress_via_meta_generator(self):
        """
        <meta name="generator" content="WordPress 6.5"> in body →
        Technology(name='WordPress', category='framework').
        """
        body = '<html><head><meta name="generator" content="WordPress 6.5"></head></html>'
        resp = _make_response({}, body=body)
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        frameworks = _tech_by_category(techs, "framework")
        assert any(t.name == "WordPress" for t in frameworks)

    def test_detects_drupal_via_meta_generator(self):
        """<meta name="generator" content="Drupal 10"> → Technology(name='Drupal')."""
        body = '<html><head><meta name="generator" content="Drupal 10 (https://www.drupal.org)"></head></html>'
        resp = _make_response({}, body=body)
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        frameworks = _tech_by_category(techs, "framework")
        assert any(t.name == "Drupal" for t in frameworks)

    def test_detects_joomla_via_meta_generator(self):
        """<meta name="generator" content="Joomla! 4.4"> → Technology(name='Joomla')."""
        body = '<html><head><meta name="generator" content="Joomla! 4.4"></head></html>'
        resp = _make_response({}, body=body)
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        frameworks = _tech_by_category(techs, "framework")
        assert any(t.name == "Joomla" for t in frameworks)

    def test_unknown_x_powered_by_recorded_as_other(self):
        """
        An X-Powered-By value that doesn't match any pattern is kept as
        category 'other' so no information is lost.
        """
        resp = _make_response({"X-Powered-By": "MyCustomFramework"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        other = [t for t in techs if t.category == "other"]
        assert any(t.name == "MyCustomFramework" for t in other)

    def test_no_framework_headers_or_body_returns_no_framework(self):
        """Without X-Powered-By or meta generator, no framework is detected."""
        resp = _make_response({"Server": "nginx"}, body="<html><body>Hello</body></html>")
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        frameworks = _tech_by_category(techs, "framework")
        assert frameworks == []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    """Same technology detected across multiple ports appears only once (Req. 2.4)."""

    def test_same_server_on_two_ports_deduplicated(self):
        """
        nginx detected on port 80 and on port 8080 yields a single
        web_server Technology in the result.
        """
        resp = _make_response({"Server": "nginx/1.24.0"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80, 8080])

        servers = _tech_by_category(techs, "web_server")
        nginx_entries = [t for t in servers if t.name == "nginx"]
        assert len(nginx_entries) == 1, (
            f"Expected exactly 1 nginx entry after dedup, got {len(nginx_entries)}"
        )

    def test_same_cdn_on_two_ports_deduplicated(self):
        """
        Cloudflare detected on port 80 and on port 443 yields one CDN entry.
        """
        resp = _make_response({"CF-RAY": "abc123-GRU"})
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80, 443])

        cdns = _tech_by_category(techs, "cdn")
        cloudflare_entries = [t for t in cdns if t.name == "Cloudflare"]
        assert len(cloudflare_entries) == 1

    def test_different_technologies_on_different_ports_both_returned(self):
        """
        nginx on port 80 and Express on port 3000 → both appear in results.
        """
        nginx_resp = _make_response({"Server": "nginx"})
        express_resp = _make_response({"X-Powered-By": "Express"})
        fp = Fingerprinter()

        call_count = {"n": 0}
        responses = [nginx_resp, express_resp]

        def side_effect(*args, **kwargs):
            r = responses[call_count["n"] % len(responses)]
            call_count["n"] += 1
            return r

        with patch("toolkit.discovery.fingerprinter.requests.get", side_effect=side_effect):
            techs = fp.fingerprint(_make_host(), [80, 3000])

        names = [t.name for t in techs]
        assert "nginx" in names
        assert "Express" in names


# ---------------------------------------------------------------------------
# Error handling — connection failures are skipped
# ---------------------------------------------------------------------------

class TestConnectionErrorHandling:
    """Connection errors on a port are silently skipped (Req. 2.4)."""

    def test_connection_refused_port_is_skipped(self):
        """
        When requests.get raises a RequestException, that port is skipped
        and the method still returns results from other ports.
        """
        good_resp = _make_response({"Server": "nginx/1.24.0"})
        fp = Fingerprinter()

        call_count = {"n": 0}

        def side_effect(*args, **kwargs):
            if call_count["n"] == 0:
                call_count["n"] += 1
                raise requests.exceptions.ConnectionError("refused")
            return good_resp

        with patch("toolkit.discovery.fingerprinter.requests.get", side_effect=side_effect):
            techs = fp.fingerprint(_make_host(), [8080, 80])

        servers = _tech_by_category(techs, "web_server")
        assert len(servers) == 1
        assert servers[0].name == "nginx"

    def test_all_ports_fail_returns_empty_list(self):
        """
        When all ports raise a RequestException, fingerprint returns an
        empty list (no crash).
        """
        fp = Fingerprinter()

        with patch(
            "toolkit.discovery.fingerprinter.requests.get",
            side_effect=requests.exceptions.Timeout("timeout"),
        ):
            techs = fp.fingerprint(_make_host(), [80, 443, 8080])

        assert techs == []

    def test_empty_port_list_returns_empty_list(self):
        """Fingerprinting a host with no open ports returns an empty list."""
        fp = Fingerprinter()
        techs = fp.fingerprint(_make_host(), [])
        assert techs == []


# ---------------------------------------------------------------------------
# HTTPS port selection
# ---------------------------------------------------------------------------

class TestHTTPSPortSelection:
    """HTTPS scheme is chosen for known HTTPS ports (443, 8443, 9443)."""

    @pytest.mark.parametrize("port", [443, 8443, 9443])
    def test_https_ports_use_https_scheme(self, port: int):
        """Fingerprinter constructs an https:// URL for HTTPS ports."""
        resp = _make_response({"Server": "nginx"})
        fp = Fingerprinter()
        captured_urls: list[str] = []

        def side_effect(url, **kwargs):
            captured_urls.append(url)
            return resp

        with patch("toolkit.discovery.fingerprinter.requests.get", side_effect=side_effect):
            fp.fingerprint(_make_host(hostname="example.com"), [port])

        assert captured_urls, "Expected at least one URL to be captured"
        assert captured_urls[0].startswith("https://"), (
            f"Expected https:// URL for port {port}, got: {captured_urls[0]}"
        )

    @pytest.mark.parametrize("port", [80, 8080, 8000, 3000, 5000])
    def test_non_https_ports_use_http_scheme(self, port: int):
        """Fingerprinter constructs an http:// URL for non-HTTPS ports."""
        resp = _make_response({"Server": "nginx"})
        fp = Fingerprinter()
        captured_urls: list[str] = []

        def side_effect(url, **kwargs):
            captured_urls.append(url)
            return resp

        with patch("toolkit.discovery.fingerprinter.requests.get", side_effect=side_effect):
            fp.fingerprint(_make_host(hostname="example.com"), [port])

        assert captured_urls
        assert captured_urls[0].startswith("http://"), (
            f"Expected http:// URL for port {port}, got: {captured_urls[0]}"
        )


# ---------------------------------------------------------------------------
# Mixed technology stacks
# ---------------------------------------------------------------------------

class TestMixedTechnologyStacks:
    """Multiple technologies (server + CDN + framework) are all detected."""

    def test_nginx_cloudflare_php_stack(self):
        """
        A response with Server: nginx, CF-RAY header, and X-Powered-By: PHP
        yields three distinct Technology objects: nginx (web_server),
        Cloudflare (cdn), PHP (framework).
        """
        resp = _make_response(
            {
                "Server": "nginx/1.24.0",
                "CF-RAY": "7e1a2b3c4d5e6f78-GRU",
                "X-Powered-By": "PHP/8.2.0",
            }
        )
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [443])

        categories = {t.category for t in techs}
        assert "web_server" in categories
        assert "cdn" in categories
        assert "framework" in categories

        names = {t.name for t in techs}
        assert "nginx" in names
        assert "Cloudflare" in names
        assert "PHP" in names

    def test_iis_aspnet_azure_cdn_stack(self):
        """
        A Windows/Azure stack: IIS + ASP.NET + Azure CDN all detected.
        """
        resp = _make_response(
            {
                "Server": "Microsoft-IIS/10.0",
                "X-Powered-By": "ASP.NET",
                "X-Azure-Ref": "0abc1234efgh",
            }
        )
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [443])

        names = {t.name for t in techs}
        assert "IIS" in names
        assert "ASP.NET" in names
        assert "Azure CDN" in names

    def test_cloudfront_wordpress_stack_from_headers_and_body(self):
        """
        CloudFront CDN detected from X-Amz-Cf-Id, WordPress detected
        from meta generator in the HTML body.
        """
        body = (
            '<html><head>'
            '<meta name="generator" content="WordPress 6.5">'
            '</head><body>Hello</body></html>'
        )
        resp = _make_response(
            {"X-Amz-Cf-Id": "SomeId123"},
            body=body,
        )
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [443])

        names = {t.name for t in techs}
        assert "CloudFront" in names
        assert "WordPress" in names

    def test_all_categories_present_returns_correct_count(self):
        """
        When web_server, cdn, and framework are all found on a single port,
        the result contains at least one Technology per category.
        """
        resp = _make_response(
            {
                "Server": "Apache/2.4.57",
                "X-Varnish": "123456",
                "X-Powered-By": "PHP/8.1",
            }
        )
        fp = Fingerprinter()

        with _patch_requests_get(resp):
            techs = fp.fingerprint(_make_host(), [80])

        categories = [t.category for t in techs]
        assert "web_server" in categories
        assert "cdn" in categories
        assert "framework" in categories


# ---------------------------------------------------------------------------
# SSL verification is disabled for audit targets
# ---------------------------------------------------------------------------

class TestSSLVerificationDisabled:
    """
    Fingerprinter must pass verify=False to requests.get so self-signed
    certificates on audit targets don't abort the probe (Req. 2.4).
    """

    def test_ssl_verify_false_is_passed(self):
        """requests.get is always called with verify=False."""
        resp = _make_response({"Server": "nginx"})
        fp = Fingerprinter()
        captured_kwargs: list[dict] = []

        def side_effect(url, **kwargs):
            captured_kwargs.append(kwargs)
            return resp

        with patch("toolkit.discovery.fingerprinter.requests.get", side_effect=side_effect):
            fp.fingerprint(_make_host(), [443])

        assert captured_kwargs, "Expected requests.get to be called"
        assert captured_kwargs[0].get("verify") is False, (
            "Expected verify=False for all fingerprint requests"
        )

    def test_timeout_is_respected(self):
        """requests.get is called with the timeout configured on the Fingerprinter."""
        resp = _make_response({"Server": "nginx"})
        fp = Fingerprinter(timeout=3)
        captured_kwargs: list[dict] = []

        def side_effect(url, **kwargs):
            captured_kwargs.append(kwargs)
            return resp

        with patch("toolkit.discovery.fingerprinter.requests.get", side_effect=side_effect):
            fp.fingerprint(_make_host(), [80])

        assert captured_kwargs[0].get("timeout") == 3
