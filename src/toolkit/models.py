"""
Data models for the Web Security Audit Toolkit.

All models are Python dataclasses serialisable to/from JSON.
Dates are represented as ``datetime.date`` in memory and serialised to
ISO 8601 strings (``YYYY-MM-DD``).
Datetimes (timestamps) are kept as ISO 8601 strings throughout the models.

Serialisation contract
----------------------
* Every model exposes ``to_dict() -> dict`` (instance method) and
  ``from_dict(cls, d: dict)`` (classmethod).
* ``NucleiFinding.to_dict()`` merges the ``extra`` dict at the top level
  so that round-tripping Nuclei JSONL is lossless.
* Unknown fields passed to ``from_dict`` that don't map to known fields
  are silently ignored for all models except ``NucleiFinding``, where they
  are collected into ``extra``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

@dataclass
class Authorization:
    """Represents a written authorisation for a security audit (Req. 1.1)."""

    domain: str                   # primary authorised domain
    institution: str              # name of the authorising institution
    auth_date: date               # date of the written authorisation
    authorized_domains: list[str]  # domains in scope (Req. 1.4)
    authorized_cidrs: list[str]   # CIDR ranges in scope (Req. 1.4)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "institution": self.institution,
            "auth_date": self.auth_date.isoformat(),
            "authorized_domains": list(self.authorized_domains),
            "authorized_cidrs": list(self.authorized_cidrs),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Authorization":
        return cls(
            domain=d["domain"],
            institution=d["institution"],
            auth_date=date.fromisoformat(d["auth_date"]),
            authorized_domains=list(d.get("authorized_domains", [])),
            authorized_cidrs=list(d.get("authorized_cidrs", [])),
        )


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------

@dataclass
class Target:
    """A raw audit target resolved to a kind (Req. 1.4)."""

    raw: str                         # auditor-supplied string (domain, host or IP)
    kind: Literal["domain", "host", "ip"]
    resolved_ips: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "kind": self.kind,
            "resolved_ips": list(self.resolved_ips),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Target":
        return cls(
            raw=d["raw"],
            kind=d["kind"],
            resolved_ips=list(d.get("resolved_ips", [])),
        )


# ---------------------------------------------------------------------------
# Technology
# ---------------------------------------------------------------------------

@dataclass
class Technology:
    """A technology identified during fingerprinting (Req. 2.4)."""

    name: str
    version: str | None
    category: Literal["web_server", "framework", "cdn", "other"]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Technology":
        return cls(
            name=d["name"],
            version=d.get("version"),
            category=d["category"],
        )


# ---------------------------------------------------------------------------
# Host
# ---------------------------------------------------------------------------

@dataclass
class Host:
    """An active host discovered during surface mapping (Req. 2.2)."""

    hostname: str
    ip: str
    is_active: bool               # responded to SYN/ICMP within 5 s
    open_ports: list[int] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "is_active": self.is_active,
            "open_ports": list(self.open_ports),
            "technologies": [t.to_dict() for t in self.technologies],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Host":
        return cls(
            hostname=d["hostname"],
            ip=d["ip"],
            is_active=d["is_active"],
            open_ports=list(d.get("open_ports", [])),
            technologies=[Technology.from_dict(t) for t in d.get("technologies", [])],
        )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    """A discovered endpoint returned by ``Enumerator.classify_response`` (Req. 3.3, 3.4)."""

    path: str
    status_code: int
    body_size: int                # response body size in bytes
    title: str | None = None      # extracted from <title> when status 200
    location: str | None = None   # Location header value for 301/302
    kind: Literal["page", "redirect", "error", "other"] = "other"

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "status_code": self.status_code,
            "body_size": self.body_size,
            "title": self.title,
            "location": self.location,
            "kind": self.kind,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Endpoint":
        return cls(
            path=d["path"],
            status_code=d["status_code"],
            body_size=d["body_size"],
            title=d.get("title"),
            location=d.get("location"),
            kind=d.get("kind", "other"),
        )


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Standardised finding format, common to all checks (Req. 11.3)."""

    id: str                       # stable identifier, e.g. SRCMAP-001
    title: str
    summary: str                  # (Req. 12.2)
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    status: Literal["confirmed", "not_vulnerable", "inconclusive", "check_failed"]
    affected_endpoint: str | None
    evidence: str                 # truncated/masked per check
    impact: str
    remediation: str              # exact commands/configs (Req. 11.3)
    next_steps: list[str]         # (Req. 12.2)
    references: list[str] = field(default_factory=list)  # CWE/OWASP (Req. 11.3)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "affected_endpoint": self.affected_endpoint,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "next_steps": list(self.next_steps),
            "references": list(self.references),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            id=d["id"],
            title=d["title"],
            summary=d["summary"],
            severity=d["severity"],
            confidence=d["confidence"],
            status=d["status"],
            affected_endpoint=d.get("affected_endpoint"),
            evidence=d["evidence"],
            impact=d["impact"],
            remediation=d["remediation"],
            next_steps=list(d.get("next_steps", [])),
            references=list(d.get("references", [])),
        )


# ---------------------------------------------------------------------------
# NucleiFinding
# ---------------------------------------------------------------------------

# Known first-class fields that are stored as explicit attributes.
_NUCLEI_KNOWN_FIELDS = frozenset(
    {
        "template-id",
        "template_id",
        "host",
        "matched-at",
        "matched_at",
        "severity",
        "name",
        "tags",
        "info",
        "timestamp",
    }
)


@dataclass
class NucleiFinding:
    """
    Faithful representation of a raw Nuclei finding (Req. 10.3, 10.5).

    Unknown fields that arrive in the JSONL output are stored in ``extra``
    so that re-serialisation is lossless (round-trip guarantee).
    """

    template_id: str              # "template-id" in Nuclei JSON
    host: str
    matched_at: str | None        # "matched-at"
    severity: str                 # info.severity
    name: str | None              # info.name
    tags: list[str]               # info.tags
    info: dict                    # full info block
    timestamp: str | None
    extra: dict = field(default_factory=dict)  # unmodelled fields (round-trip)

    def to_dict(self) -> dict:
        """
        Serialise to a dict that mirrors the Nuclei JSONL structure.

        ``extra`` fields are merged at the top level so that the output is
        equivalent to the original Nuclei record.
        """
        d: dict[str, Any] = {
            "template-id": self.template_id,
            "host": self.host,
            "matched-at": self.matched_at,
            "severity": self.severity,
            "name": self.name,
            "tags": list(self.tags),
            "info": dict(self.info),
            "timestamp": self.timestamp,
        }
        # Merge extra fields at the top level (Nuclei round-trip)
        d.update(self.extra)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "NucleiFinding":
        """
        Parse a Nuclei JSONL record.

        Fields not recognised as first-class attributes are collected into
        ``extra`` to preserve them for round-trip serialisation.
        """
        # Support both hyphenated (Nuclei native) and underscore variants
        template_id: str = d.get("template-id") or d.get("template_id", "")
        matched_at: str | None = d.get("matched-at") or d.get("matched_at")

        # Collect unrecognised fields into extra
        extra: dict = {
            k: v
            for k, v in d.items()
            if k not in _NUCLEI_KNOWN_FIELDS
        }

        return cls(
            template_id=template_id,
            host=d.get("host", ""),
            matched_at=matched_at,
            severity=d.get("severity", ""),
            name=d.get("name"),
            tags=list(d.get("tags", [])),
            info=dict(d.get("info", {})),
            timestamp=d.get("timestamp"),
            extra=extra,
        )


# ---------------------------------------------------------------------------
# Exclusion
# ---------------------------------------------------------------------------

@dataclass
class Exclusion:
    """Records a host excluded from the attack surface (Req. 2.6)."""

    host: str
    reason: str
    timestamp: str               # ISO 8601

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Exclusion":
        return cls(
            host=d["host"],
            reason=d["reason"],
            timestamp=d["timestamp"],
        )


# ---------------------------------------------------------------------------
# AttackSurfaceMap
# ---------------------------------------------------------------------------

@dataclass
class AttackSurfaceMap:
    """The aggregated attack surface discovered for an authorised target (Req. 2.5)."""

    subdomains: list[str]
    active_hosts: list[Host]
    technologies_by_host: dict[str, list[Technology]]
    excluded: list[Exclusion] = field(default_factory=list)  # out-of-scope (Req. 2.6)

    def to_dict(self) -> dict:
        return {
            "subdomains": list(self.subdomains),
            "active_hosts": [h.to_dict() for h in self.active_hosts],
            "technologies_by_host": {
                hostname: [t.to_dict() for t in techs]
                for hostname, techs in self.technologies_by_host.items()
            },
            "excluded": [e.to_dict() for e in self.excluded],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttackSurfaceMap":
        return cls(
            subdomains=list(d.get("subdomains", [])),
            active_hosts=[Host.from_dict(h) for h in d.get("active_hosts", [])],
            technologies_by_host={
                hostname: [Technology.from_dict(t) for t in techs]
                for hostname, techs in d.get("technologies_by_host", {}).items()
            },
            excluded=[Exclusion.from_dict(e) for e in d.get("excluded", [])],
        )


# ---------------------------------------------------------------------------
# OperationRecord
# ---------------------------------------------------------------------------

@dataclass
class OperationRecord:
    """A single operation recorded in the session log (Req. 12.3)."""

    phase: str
    action: str
    timestamp: str               # ISO 8601

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "action": self.action,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "OperationRecord":
        return cls(
            phase=d["phase"],
            action=d["action"],
            timestamp=d["timestamp"],
        )


# ---------------------------------------------------------------------------
# PhaseAnalysis
# ---------------------------------------------------------------------------

@dataclass
class PhaseAnalysis:
    """
    Result of interpreting the raw output of a phase (Req. 12.2).

    Produced by ``Analyzer.summarize_phase`` and returned by
    ``PhaseOrchestrator.ingest_phase_results``.  It presents to the auditor:
    a finding summary, the overall confidence level, the estimated severity,
    the recommended next steps, and the exact commands for the following phase.

    Attributes
    ----------
    summary:
        Plain-language summary of the findings produced in this phase.
    confidence:
        Overall confidence level across the phase findings.
    estimated_severity:
        Highest estimated severity across the phase findings.
    next_steps:
        Recommended next actions for the auditor.
    next_phase_commands:
        Exact commands to run in the following phase (empty for the last phase).
    findings:
        The classified findings produced from the raw results.
    """

    summary: str
    confidence: Literal["low", "medium", "high"]
    estimated_severity: Literal["none", "low", "medium", "high", "critical"]
    next_steps: list[str] = field(default_factory=list)
    next_phase_commands: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "confidence": self.confidence,
            "estimated_severity": self.estimated_severity,
            "next_steps": list(self.next_steps),
            "next_phase_commands": list(self.next_phase_commands),
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PhaseAnalysis":
        return cls(
            summary=d["summary"],
            confidence=d["confidence"],
            estimated_severity=d["estimated_severity"],
            next_steps=list(d.get("next_steps", [])),
            next_phase_commands=list(d.get("next_phase_commands", [])),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
        )


# ---------------------------------------------------------------------------
# SessionState
# ---------------------------------------------------------------------------

@dataclass
class SessionState:
    """Persistent state of an iterative audit session (Req. 12.3)."""

    authorization: Authorization
    working_dir: str
    completed_phases: list[str]               # phase names completed so far
    findings: list[Finding]                   # accumulated findings
    tested_targets: list[str]                 # targets already tested
    surface_map: AttackSurfaceMap | None = None
    operations_log: list[OperationRecord] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "authorization": self.authorization.to_dict(),
            "working_dir": self.working_dir,
            "completed_phases": list(self.completed_phases),
            "findings": [f.to_dict() for f in self.findings],
            "tested_targets": list(self.tested_targets),
            "surface_map": self.surface_map.to_dict() if self.surface_map is not None else None,
            "operations_log": [op.to_dict() for op in self.operations_log],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SessionState":
        surface_map_data = d.get("surface_map")
        return cls(
            authorization=Authorization.from_dict(d["authorization"]),
            working_dir=d["working_dir"],
            completed_phases=list(d.get("completed_phases", [])),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            tested_targets=list(d.get("tested_targets", [])),
            surface_map=(
                AttackSurfaceMap.from_dict(surface_map_data)
                if surface_map_data is not None
                else None
            ),
            operations_log=[
                OperationRecord.from_dict(op) for op in d.get("operations_log", [])
            ],
        )


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    """An append-only audit log entry (Req. 1.5, 9.6)."""

    timestamp: str               # ISO 8601
    event_type: Literal["scope_block", "exclusion", "biz_request", "error", "info"]
    target: str | None
    module: str | None
    detail: dict                 # payloads masked when sensitive (Req. 9.6)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "target": self.target,
            "module": self.module,
            "detail": dict(self.detail),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AuditEvent":
        return cls(
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            target=d.get("target"),
            module=d.get("module"),
            detail=dict(d.get("detail", {})),
        )
