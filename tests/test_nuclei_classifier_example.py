"""
Example-based unit tests for the Nuclei findings classifier (Req. 10.3).

Tests cover:
* summary uses finding.name when set, template_id as fallback
* severity mapping for all recognised Nuclei severity values
* confidence is always "medium"
* evidence is matched_at or empty string
* next_steps contains the expected template review string
* references equals tags from the finding
* empty input returns empty list
* id is prefixed with "NUCLEI-"
* status is always "confirmed"
* affected_endpoint equals matched_at
"""

from __future__ import annotations

import pytest

from toolkit.analysis.classifiers.nuclei import map_nuclei_findings
from toolkit.models import Finding, NucleiFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_nuclei_finding(
    template_id: str = "cve-2021-1234",
    host: str = "https://example.com",
    matched_at: str | None = "https://example.com/vuln",
    severity: str = "high",
    name: str | None = "CVE-2021-1234 Example",
    tags: list[str] | None = None,
) -> NucleiFinding:
    return NucleiFinding(
        template_id=template_id,
        host=host,
        matched_at=matched_at,
        severity=severity,
        name=name,
        tags=tags or [],
        info={},
        timestamp=None,
    )


# ---------------------------------------------------------------------------
# 1. Empty input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_list_returns_empty_list(self):
        result = map_nuclei_findings([])
        assert result == []


# ---------------------------------------------------------------------------
# 2. Summary field
# ---------------------------------------------------------------------------

class TestSummary:
    def test_summary_uses_name_when_set(self):
        nf = _make_nuclei_finding(name="My Finding Name", template_id="tmpl-001")
        findings = map_nuclei_findings([nf])
        assert findings[0].summary == "My Finding Name"

    def test_summary_falls_back_to_template_id_when_name_is_none(self):
        nf = _make_nuclei_finding(name=None, template_id="tmpl-fallback")
        findings = map_nuclei_findings([nf])
        assert findings[0].summary == "tmpl-fallback"

    def test_title_equals_summary(self):
        nf = _make_nuclei_finding(name="Title Finding", template_id="tmpl-002")
        findings = map_nuclei_findings([nf])
        assert findings[0].title == findings[0].summary


# ---------------------------------------------------------------------------
# 3. Severity mapping
# ---------------------------------------------------------------------------

class TestSeverityMapping:
    @pytest.mark.parametrize("nuclei_severity,expected", [
        ("info", "low"),
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("critical", "critical"),
    ])
    def test_severity_mapped_correctly(self, nuclei_severity: str, expected: str):
        nf = _make_nuclei_finding(severity=nuclei_severity)
        findings = map_nuclei_findings([nf])
        assert findings[0].severity == expected

    def test_unknown_severity_defaults_to_low(self):
        nf = _make_nuclei_finding(severity="unknown_severity")
        findings = map_nuclei_findings([nf])
        assert findings[0].severity == "low"

    def test_severity_comparison_is_case_insensitive(self):
        nf = _make_nuclei_finding(severity="HIGH")
        findings = map_nuclei_findings([nf])
        assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# 4. Confidence
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_confidence_is_always_medium(self):
        for severity in ("info", "low", "medium", "high", "critical"):
            nf = _make_nuclei_finding(severity=severity)
            findings = map_nuclei_findings([nf])
            assert findings[0].confidence == "medium"


# ---------------------------------------------------------------------------
# 5. Evidence
# ---------------------------------------------------------------------------

class TestEvidence:
    def test_evidence_is_matched_at_when_set(self):
        nf = _make_nuclei_finding(matched_at="https://example.com/path")
        findings = map_nuclei_findings([nf])
        assert findings[0].evidence == "https://example.com/path"

    def test_evidence_is_empty_string_when_matched_at_is_none(self):
        nf = _make_nuclei_finding(matched_at=None)
        findings = map_nuclei_findings([nf])
        assert findings[0].evidence == ""


# ---------------------------------------------------------------------------
# 6. Next steps
# ---------------------------------------------------------------------------

class TestNextSteps:
    def test_next_steps_contains_template_review(self):
        nf = _make_nuclei_finding(template_id="cve-2023-9999")
        findings = map_nuclei_findings([nf])
        assert findings[0].next_steps == ["Review Nuclei template: cve-2023-9999"]

    def test_next_steps_is_single_item_list(self):
        nf = _make_nuclei_finding(template_id="some-template")
        findings = map_nuclei_findings([nf])
        assert len(findings[0].next_steps) == 1


# ---------------------------------------------------------------------------
# 7. References
# ---------------------------------------------------------------------------

class TestReferences:
    def test_references_equals_tags(self):
        nf = _make_nuclei_finding(tags=["cve", "sqli", "owasp"])
        findings = map_nuclei_findings([nf])
        assert findings[0].references == ["cve", "sqli", "owasp"]

    def test_references_empty_when_tags_empty(self):
        nf = _make_nuclei_finding(tags=[])
        findings = map_nuclei_findings([nf])
        assert findings[0].references == []

    def test_references_are_a_copy_of_tags(self):
        """Mutating the original tags should not affect the Finding's references."""
        tags = ["cve", "misconfig"]
        nf = _make_nuclei_finding(tags=tags)
        findings = map_nuclei_findings([nf])
        tags.append("extra")
        assert "extra" not in findings[0].references


# ---------------------------------------------------------------------------
# 8. ID prefix
# ---------------------------------------------------------------------------

class TestId:
    def test_id_has_nuclei_prefix(self):
        nf = _make_nuclei_finding(template_id="headers-missing-hsts")
        findings = map_nuclei_findings([nf])
        assert findings[0].id == "NUCLEI-headers-missing-hsts"


# ---------------------------------------------------------------------------
# 9. Status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_status_is_confirmed(self):
        nf = _make_nuclei_finding()
        findings = map_nuclei_findings([nf])
        assert findings[0].status == "confirmed"


# ---------------------------------------------------------------------------
# 10. Affected endpoint
# ---------------------------------------------------------------------------

class TestAffectedEndpoint:
    def test_affected_endpoint_equals_matched_at(self):
        nf = _make_nuclei_finding(matched_at="https://target.com/admin")
        findings = map_nuclei_findings([nf])
        assert findings[0].affected_endpoint == "https://target.com/admin"

    def test_affected_endpoint_none_when_matched_at_none(self):
        nf = _make_nuclei_finding(matched_at=None)
        findings = map_nuclei_findings([nf])
        assert findings[0].affected_endpoint is None


# ---------------------------------------------------------------------------
# 11. Multiple findings
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    def test_one_output_finding_per_input_finding(self):
        nf_list = [
            _make_nuclei_finding(template_id=f"tmpl-{i}", name=f"Finding {i}")
            for i in range(5)
        ]
        findings = map_nuclei_findings(nf_list)
        assert len(findings) == 5

    def test_output_order_matches_input_order(self):
        template_ids = ["alpha", "beta", "gamma"]
        nf_list = [_make_nuclei_finding(template_id=tid) for tid in template_ids]
        findings = map_nuclei_findings(nf_list)
        for i, tid in enumerate(template_ids):
            assert findings[i].id == f"NUCLEI-{tid}"

    def test_all_output_are_finding_instances(self):
        nf_list = [_make_nuclei_finding() for _ in range(3)]
        findings = map_nuclei_findings(nf_list)
        for f in findings:
            assert isinstance(f, Finding)
