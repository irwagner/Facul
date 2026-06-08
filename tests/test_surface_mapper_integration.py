"""
Integration tests for SurfaceMapper.enumerate_subdomains and
SurfaceMapper.identify_active_hosts.

DNS / Certificate Transparency queries and TCP probing are fully mocked so
these tests never touch the network.

Requirements covered: 2.1, 2.2, 2.7
"""

from __future__ import annotations

import json
import socket
import warnings
from unittest.mock import MagicMock, patch

import pytest

from toolkit.discovery.surface_mapper import SurfaceMapper, _PROBE_TIMEOUT_S
from toolkit.models import Host


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_ct_entry(name_value: str) -> dict:
    """Build a minimal crt.sh JSON entry."""
    return {"name_value": name_value, "id": 1234}


def _ct_response_bytes(entries: list[dict]) -> bytes:
    """Serialise a list of crt.sh entries to UTF-8 JSON bytes."""
    return json.dumps(entries).encode("utf-8")


class _FakeHTTPResponse:
    """Minimal urllib response stub usable as a context manager."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# enumerate_subdomains — happy path
# ---------------------------------------------------------------------------

class TestEnumerateSubdomains:
    """Tests for SurfaceMapper.enumerate_subdomains (Req. 2.1)."""

    def test_returns_subdomains_from_ct_log(self):
        """
        Given a crt.sh response with several subdomain entries the method
        returns a deduplicated list of those subdomains.

        Req. 2.1 — passive DNS + Certificate Transparency enumeration.
        """
        domain = "example.com"
        ct_entries = [
            _make_ct_entry("www.example.com"),
            _make_ct_entry("api.example.com"),
            _make_ct_entry("mail.example.com"),
        ]
        fake_resp = _FakeHTTPResponse(_ct_response_bytes(ct_entries))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            result = mapper.enumerate_subdomains(domain)

        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "mail.example.com" in result

    def test_deduplicated_results(self):
        """
        Duplicate entries in the CT response appear only once in the result.
        """
        domain = "example.com"
        ct_entries = [
            _make_ct_entry("www.example.com"),
            _make_ct_entry("www.example.com"),  # duplicate
            _make_ct_entry("api.example.com"),
        ]
        fake_resp = _FakeHTTPResponse(_ct_response_bytes(ct_entries))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            result = mapper.enumerate_subdomains(domain)

        assert result.count("www.example.com") == 1
        assert "api.example.com" in result

    def test_wildcard_entries_stripped(self):
        """
        Wildcard prefixes (``*.``) in crt.sh name_value fields are stripped
        before inclusion so the result contains bare hostnames.
        """
        domain = "example.com"
        ct_entries = [
            _make_ct_entry("*.example.com"),       # wildcard — stripped to example.com
            _make_ct_entry("*.api.example.com"),   # wildcard subdomain
        ]
        fake_resp = _FakeHTTPResponse(_ct_response_bytes(ct_entries))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            result = mapper.enumerate_subdomains(domain)

        # After stripping "*." the remaining string "api.example.com" is valid
        assert "api.example.com" in result
        # No wildcard entries in the result
        assert not any("*" in name for name in result)

    def test_out_of_domain_entries_excluded(self):
        """
        CT entries whose name_value does not match the queried domain are
        not included in the result.
        """
        domain = "example.com"
        ct_entries = [
            _make_ct_entry("www.example.com"),
            _make_ct_entry("unrelated.org"),
            _make_ct_entry("sub.otherdomain.com"),
        ]
        fake_resp = _FakeHTTPResponse(_ct_response_bytes(ct_entries))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            result = mapper.enumerate_subdomains(domain)

        assert "www.example.com" in result
        assert "unrelated.org" not in result
        assert "sub.otherdomain.com" not in result

    def test_multi_name_entry_newline_separated(self):
        """
        A single crt.sh entry may list several SANs separated by newlines;
        each valid subdomain should appear in the result.
        """
        domain = "example.com"
        multi_name = "www.example.com\nstatic.example.com\ncdn.example.com"
        ct_entries = [_make_ct_entry(multi_name)]
        fake_resp = _FakeHTTPResponse(_ct_response_bytes(ct_entries))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            result = mapper.enumerate_subdomains(domain)

        assert "www.example.com" in result
        assert "static.example.com" in result
        assert "cdn.example.com" in result

    # ------------------------------------------------------------------
    # CT log failure handling
    # ------------------------------------------------------------------

    def test_ct_log_network_error_returns_empty_with_warning(self):
        """
        When the CT log request raises an exception (e.g. network error),
        the method returns an empty list and emits a UserWarning (Req. 2.7).
        """
        domain = "example.com"
        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                result = mapper.enumerate_subdomains(domain)

        assert result == []
        warning_messages = [str(w.message) for w in recorded]
        assert any("no subdomains found" in msg.lower() for msg in warning_messages), (
            f"Expected a 'no subdomains found' warning; got: {warning_messages}"
        )

    def test_ct_log_invalid_json_returns_empty_with_warning(self):
        """
        When the CT log returns malformed JSON, the method returns an empty
        list and emits a UserWarning (Req. 2.7).
        """
        domain = "example.com"
        mapper = SurfaceMapper()
        bad_resp = _FakeHTTPResponse(b"not-json-at-all")

        with patch("urllib.request.urlopen", return_value=bad_resp):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                result = mapper.enumerate_subdomains(domain)

        assert result == []
        warning_messages = [str(w.message) for w in recorded]
        assert any("no subdomains found" in msg.lower() for msg in warning_messages)


# ---------------------------------------------------------------------------
# enumerate_subdomains — zero results / Req. 2.7
# ---------------------------------------------------------------------------

class TestEnumerateSubdomainsZeroResults:
    """
    Tests for the zero-subdomain case (Req. 2.7).

    When no subdomains are found the method MUST:
      * return an empty list
      * emit a UserWarning telling the auditor to verify the target domain
        and DNS resolution.
    """

    def test_empty_ct_response_emits_warning(self):
        """
        An empty JSON array from crt.sh triggers the Req. 2.7 warning.
        """
        domain = "noresults.example.com"
        fake_resp = _FakeHTTPResponse(_ct_response_bytes([]))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                result = mapper.enumerate_subdomains(domain)

        # Must return empty list
        assert result == [], f"Expected empty list, got {result!r}"

        # Must emit at least one UserWarning about "no subdomains found"
        user_warnings = [
            w for w in recorded
            if issubclass(w.category, UserWarning)
        ]
        assert user_warnings, "Expected at least one UserWarning for zero subdomains"
        warning_text = " ".join(str(w.message) for w in user_warnings).lower()
        assert "no subdomains found" in warning_text, (
            f"Warning text does not mention 'no subdomains found': {warning_text!r}"
        )

    def test_warning_mentions_domain_name(self):
        """
        The zero-results warning should reference the domain name so the
        auditor knows which domain was queried.
        """
        domain = "myspecialdomain.org"
        fake_resp = _FakeHTTPResponse(_ct_response_bytes([]))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                mapper.enumerate_subdomains(domain)

        warning_text = " ".join(str(w.message) for w in recorded)
        assert domain in warning_text, (
            f"Warning does not mention domain {domain!r}: {warning_text!r}"
        )

    def test_warning_instructs_to_verify_dns(self):
        """
        The zero-results warning MUST tell the auditor to verify DNS
        resolution (Req. 2.7 explicit requirement).
        """
        domain = "example.com"
        fake_resp = _FakeHTTPResponse(_ct_response_bytes([]))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                mapper.enumerate_subdomains(domain)

        warning_text = " ".join(str(w.message) for w in recorded).lower()
        assert "dns" in warning_text or "verify" in warning_text, (
            f"Warning does not mention DNS/verify: {warning_text!r}"
        )


# ---------------------------------------------------------------------------
# identify_active_hosts — happy path
# ---------------------------------------------------------------------------

class TestIdentifyActiveHosts:
    """Tests for SurfaceMapper.identify_active_hosts (Req. 2.2)."""

    def test_active_host_when_tcp_connection_succeeds(self):
        """
        A subdomain whose TCP connection on any probe port succeeds within
        the timeout is returned as an active Host (is_active=True).

        Req. 2.2 — host active if it responds to TCP SYN within 5 s.
        """
        mapper = SurfaceMapper()
        subdomains = ["www.example.com"]

        with patch("socket.gethostbyname", return_value="93.184.216.34"), \
             patch("socket.create_connection") as mock_conn:
            # Simulate successful TCP connection (context manager)
            mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            result = mapper.identify_active_hosts(subdomains)

        assert len(result) == 1
        host = result[0]
        assert host.hostname == "www.example.com"
        assert host.ip == "93.184.216.34"
        assert host.is_active is True

    def test_inactive_host_when_all_ports_refused(self):
        """
        A subdomain whose TCP connections are refused on all probe ports
        is returned with is_active=False.
        """
        mapper = SurfaceMapper()
        subdomains = ["closed.example.com"]

        with patch("socket.gethostbyname", return_value="10.0.0.1"), \
             patch("socket.create_connection", side_effect=OSError("refused")):

            result = mapper.identify_active_hosts(subdomains)

        assert len(result) == 1
        host = result[0]
        assert host.hostname == "closed.example.com"
        assert host.is_active is False

    def test_host_skipped_when_dns_resolution_fails(self):
        """
        Subdomains that cannot be resolved to an IP are silently skipped;
        they do not appear in the returned list.
        """
        mapper = SurfaceMapper()
        subdomains = ["nonexistent.example.com"]

        with patch("socket.gethostbyname", side_effect=OSError("NXDOMAIN")):
            result = mapper.identify_active_hosts(subdomains)

        assert result == [], (
            "Expected empty list when DNS resolution fails for all subdomains"
        )

    def test_multiple_subdomains_mixed_liveness(self):
        """
        With multiple subdomains, active and inactive hosts are correctly
        separated: hosts that respond are marked active, others inactive.
        """
        mapper = SurfaceMapper()
        subdomains = [
            "active1.example.com",
            "inactive1.example.com",
            "active2.example.com",
        ]
        ip_map = {
            "active1.example.com": "1.1.1.1",
            "inactive1.example.com": "2.2.2.2",
            "active2.example.com": "3.3.3.3",
        }

        def fake_gethostbyname(name):
            return ip_map[name]

        call_count = {"n": 0}

        def fake_create_connection(address, timeout):
            host, _port = address
            if host in ("1.1.1.1", "3.3.3.3"):
                mock = MagicMock()
                mock.__enter__ = MagicMock(return_value=mock)
                mock.__exit__ = MagicMock(return_value=False)
                return mock
            raise OSError("refused")

        with patch("socket.gethostbyname", side_effect=fake_gethostbyname), \
             patch("socket.create_connection", side_effect=fake_create_connection):
            result = mapper.identify_active_hosts(subdomains)

        assert len(result) == 3
        by_name = {h.hostname: h for h in result}

        assert by_name["active1.example.com"].is_active is True
        assert by_name["inactive1.example.com"].is_active is False
        assert by_name["active2.example.com"].is_active is True

    def test_empty_subdomain_list_returns_empty(self):
        """
        An empty input list produces an empty output list.
        """
        mapper = SurfaceMapper()
        result = mapper.identify_active_hosts([])
        assert result == []

    def test_tcp_probe_uses_five_second_timeout(self):
        """
        TCP connections must be attempted with the 5-second timeout
        specified in Req. 2.2.
        """
        mapper = SurfaceMapper()
        subdomains = ["www.example.com"]
        captured_timeouts: list[float] = []

        def fake_create_connection(address, timeout):
            captured_timeouts.append(timeout)
            raise OSError("refused")

        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch("socket.create_connection", side_effect=fake_create_connection):
            mapper.identify_active_hosts(subdomains)

        # Every captured timeout must be exactly _PROBE_TIMEOUT_S (5.0)
        assert captured_timeouts, "Expected at least one TCP connection attempt"
        assert all(t == _PROBE_TIMEOUT_S for t in captured_timeouts), (
            f"Not all TCP attempts used {_PROBE_TIMEOUT_S}s timeout: {captured_timeouts}"
        )

    def test_host_active_on_first_responsive_port(self):
        """
        As soon as one port responds, the host is marked active and no
        further probe ports need to be attempted.
        """
        mapper = SurfaceMapper()
        subdomains = ["www.example.com"]
        connection_attempts: list[tuple] = []

        def fake_create_connection(address, timeout):
            connection_attempts.append(address)
            # Succeed on the first attempt
            mock = MagicMock()
            mock.__enter__ = MagicMock(return_value=mock)
            mock.__exit__ = MagicMock(return_value=False)
            return mock

        with patch("socket.gethostbyname", return_value="1.2.3.4"), \
             patch("socket.create_connection", side_effect=fake_create_connection):
            result = mapper.identify_active_hosts(subdomains)

        assert result[0].is_active is True
        # Should stop after the first successful connection
        assert len(connection_attempts) == 1

    def test_ip_correctly_stored_on_host(self):
        """
        The IP address resolved by gethostbyname is stored verbatim in the
        returned Host object.
        """
        mapper = SurfaceMapper()
        subdomains = ["api.example.com"]
        resolved_ip = "192.0.2.1"

        with patch("socket.gethostbyname", return_value=resolved_ip), \
             patch("socket.create_connection", side_effect=OSError("refused")):
            result = mapper.identify_active_hosts(subdomains)

        assert len(result) == 1
        assert result[0].ip == resolved_ip

    def test_some_dns_fail_others_succeed(self):
        """
        When some subdomains fail DNS resolution and others succeed, only the
        successfully resolved ones appear in the result.
        """
        mapper = SurfaceMapper()
        subdomains = [
            "resolvable.example.com",
            "nxdomain.example.com",
        ]

        def fake_gethostbyname(name):
            if name == "resolvable.example.com":
                return "5.5.5.5"
            raise OSError("NXDOMAIN")

        with patch("socket.gethostbyname", side_effect=fake_gethostbyname), \
             patch("socket.create_connection", side_effect=OSError("refused")):
            result = mapper.identify_active_hosts(subdomains)

        hostnames = [h.hostname for h in result]
        assert "resolvable.example.com" in hostnames
        assert "nxdomain.example.com" not in hostnames


# ---------------------------------------------------------------------------
# Integration scenario: enumerate → probe pipeline
# ---------------------------------------------------------------------------

class TestEnumerateAndProbePipeline:
    """
    End-to-end mocked integration: enumerate_subdomains feeds
    identify_active_hosts in a realistic pipeline (Req. 2.1, 2.2).
    """

    def test_full_pipeline_happy_path(self):
        """
        Discovered subdomains are handed to identify_active_hosts;
        active hosts are returned with correct liveness flags.
        """
        domain = "example.com"
        ct_entries = [
            _make_ct_entry("www.example.com"),
            _make_ct_entry("api.example.com"),
        ]
        fake_resp = _FakeHTTPResponse(_ct_response_bytes(ct_entries))

        ip_map = {
            "www.example.com": "93.184.216.34",
            "api.example.com": "93.184.216.35",
        }

        def fake_gethostbyname(name):
            return ip_map[name]

        def fake_create_connection(address, timeout):
            host, _port = address
            # www is active, api is not
            if host == "93.184.216.34":
                mock = MagicMock()
                mock.__enter__ = MagicMock(return_value=mock)
                mock.__exit__ = MagicMock(return_value=False)
                return mock
            raise OSError("refused")

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            subdomains = mapper.enumerate_subdomains(domain)

        assert set(subdomains) == {"www.example.com", "api.example.com"}

        with patch("socket.gethostbyname", side_effect=fake_gethostbyname), \
             patch("socket.create_connection", side_effect=fake_create_connection):
            hosts = mapper.identify_active_hosts(subdomains)

        assert len(hosts) == 2
        by_name = {h.hostname: h for h in hosts}
        assert by_name["www.example.com"].is_active is True
        assert by_name["api.example.com"].is_active is False

    def test_pipeline_zero_subdomains_emits_warning(self):
        """
        When enumeration yields zero subdomains, a warning is emitted and
        the subsequent identify_active_hosts call returns an empty list
        (Req. 2.7).
        """
        domain = "empty-domain.com"
        fake_resp = _FakeHTTPResponse(_ct_response_bytes([]))

        mapper = SurfaceMapper()

        with patch("urllib.request.urlopen", return_value=fake_resp):
            with warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always")
                subdomains = mapper.enumerate_subdomains(domain)

        # Zero subdomains → warning must have been raised
        assert subdomains == []
        assert any(
            "no subdomains found" in str(w.message).lower()
            for w in recorded
            if issubclass(w.category, UserWarning)
        ), "Expected UserWarning about no subdomains found"

        # Passing empty list to identify_active_hosts is safe
        hosts = mapper.identify_active_hosts(subdomains)
        assert hosts == []
