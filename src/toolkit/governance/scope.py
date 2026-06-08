"""
ScopeValidator — centralised target scope enforcement (Req. 1.4, 1.5, 2.6).

Any module that dispatches a network request must call ``assert_in_scope``
before doing so. The validator is intentionally pure (no I/O) so that it can
be tested without side effects; logging is injected via the ``AuditLogger``
argument.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import TYPE_CHECKING

from toolkit.exceptions import ScopeError
from toolkit.models import AuditEvent

if TYPE_CHECKING:
    from toolkit.governance.audit_logger import AuditLogger


class ScopeValidator:
    """
    Decides whether a target (domain or IP) is within the authorised scope.

    Parameters
    ----------
    authorized_domains:
        List of authorised domain names.  Each entry is matched both as an
        exact host and as a suffix for sub-domain checks (Req. 1.4).
    authorized_cidrs:
        List of CIDR notations (e.g. ``"192.168.1.0/24"``) against which IP
        targets are checked (Req. 1.4).
    """

    def __init__(
        self,
        authorized_domains: list[str],
        authorized_cidrs: list[str],
    ) -> None:
        self.authorized_domains: list[str] = list(authorized_domains)
        self.authorized_cidrs: list[str] = list(authorized_cidrs)

        # Pre-parse CIDR networks for efficient membership tests.
        # Invalid entries are silently ignored so that construction never
        # raises — callers validate the authorisation before building the
        # validator.
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in self.authorized_cidrs:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass  # malformed CIDR — ignored

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def in_scope(self, target: str) -> bool:
        """
        Return ``True`` if *target* is within the authorised scope.

        Matching rules (all comparisons are case-insensitive):

        1. **Exact domain match** – ``target == authorized_domain``
        2. **Sub-domain suffix match** – ``target.endswith("." + authorized_domain)``
        3. **IP in CIDR** – if *target* is a valid IP address, check whether it
           falls within any of the authorised CIDR ranges.

        Parameters
        ----------
        target:
            The hostname or IP address to check.

        Returns
        -------
        bool
            ``True`` if in scope, ``False`` otherwise.
        """
        target_lower = target.lower()

        # --- Domain checks ---
        for domain in self.authorized_domains:
            domain_lower = domain.lower()
            # Rule 1: exact match
            if target_lower == domain_lower:
                return True
            # Rule 2: subdomain suffix match
            if target_lower.endswith("." + domain_lower):
                return True

        # --- IP / CIDR check ---
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            # Not a valid IP address — already handled by domain rules above.
            return False

        for network in self._networks:
            if ip in network:
                return True

        return False

    def assert_in_scope(
        self,
        target: str,
        module: str,
        logger: "AuditLogger",
    ) -> None:
        """
        Raise :class:`~toolkit.exceptions.ScopeError` if *target* is out of scope.

        Before raising, an :class:`~toolkit.models.AuditEvent` with
        ``event_type="scope_block"`` is appended to *logger* so that every
        scope violation is permanently recorded (Req. 1.5).

        Parameters
        ----------
        target:
            The hostname or IP address being requested.
        module:
            Name of the calling module (used in the audit event).
        logger:
            The :class:`~toolkit.governance.audit_logger.AuditLogger` instance
            to receive the audit event.

        Raises
        ------
        ScopeError
            When *target* is not within the authorised scope.
        """
        if not self.in_scope(target):
            event = AuditEvent(
                timestamp=datetime.now().isoformat(),
                event_type="scope_block",
                target=target,
                module=module,
                detail={
                    "authorized_domains": self.authorized_domains,
                    "authorized_cidrs": self.authorized_cidrs,
                },
            )
            logger.log(event)
            raise ScopeError(
                f"Target {target!r} is outside the authorized scope",
                target=target,
                authorized_scope=self.authorized_domains + self.authorized_cidrs,
            )
