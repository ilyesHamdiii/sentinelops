import pytest

from sentinelops.risk import calculate_risk_score, correlate_findings, evaluate_risk_for_findings


@pytest.fixture
def canonical_findings():
    return [
        {
            "schema_version": "1.0",
            "finding_id": "f-001",
            "source": "securityhub",
            "source_finding_id": "sh-001",
            "account_id": "960577828312",
            "region": "eu-west-1",
            "resource": {
                "type": "AWS::S3::Bucket",
                "id": "arn:aws:s3:::sentinelops-evidence-960577828312",
                "arn": "arn:aws:s3:::sentinelops-evidence-960577828312",
                "tags": {"Project": "sentinelops"},
            },
            "title": "Public bucket policy",
            "description": "Bucket policy allows anonymous read access.",
            "severity_source": "HIGH",
            "risk_score": 82,
            "risk_policy_version": "1.0",
            "status": "OPEN",
            "first_seen": "2026-11-12T12:00:00Z",
            "last_seen": "2026-11-12T12:00:00Z",
            "evidence_refs": ["evt-001"],
            "scenario_id": "S1",
            "confidence": "HIGH",
            "remediation_state": "PROPOSED",
            "asset_criticality": "critical",
            "platform_risk": "high",
        },
        {
            "schema_version": "1.0",
            "finding_id": "f-002",
            "source": "guardduty",
            "source_finding_id": "gd-001",
            "account_id": "960577828312",
            "region": "eu-west-1",
            "resource": {
                "type": "AWS::IAM::Role",
                "id": "arn:aws:iam::960577828312:role/sentinelops-test-role",
                "arn": "arn:aws:iam::960577828312:role/sentinelops-test-role",
                "tags": {"Project": "sentinelops"},
            },
            "title": "Excessive IAM privilege",
            "description": "Role includes wildcard permissions.",
            "severity_source": "MEDIUM",
            "risk_score": 64,
            "risk_policy_version": "1.0",
            "status": "OPEN",
            "first_seen": "2026-11-12T12:00:00Z",
            "last_seen": "2026-11-12T12:00:00Z",
            "evidence_refs": ["evt-002"],
            "scenario_id": "S2",
            "confidence": "MEDIUM",
            "remediation_state": "PROPOSED",
            "asset_criticality": "high",
            "platform_risk": "medium",
        },
    ]


def test_risk_score_is_deterministic_and_policy_versioned(canonical_findings):
    score_a = calculate_risk_score(canonical_findings[0])
    score_b = calculate_risk_score(canonical_findings[0])

    assert score_a == score_b == 100
    assert canonical_findings[0]["risk_policy_version"] == "1.0"


def test_risk_evaluation_stores_rationale_and_correlation(canonical_findings):
    evaluated = evaluate_risk_for_findings(canonical_findings)

    assert len(evaluated) == 2
    assert all(item.get("rationale") for item in evaluated)
    assert all(item.get("policy_version") == "1.0" for item in evaluated)


def test_correlate_findings_groups_by_resource_and_handles_missing_data():
    findings = [
        {
            "resource": {"id": "arn:aws:s3:::example-bucket"},
            "severity_source": "HIGH",
            "risk_score": 75,
            "confidence": "HIGH",
            "asset_criticality": "critical",
            "platform_risk": "high",
            "risk_policy_version": "1.0",
        },
        {
            "resource": {"id": "arn:aws:s3:::example-bucket"},
            "severity_source": "HIGH",
            "risk_score": 60,
            "confidence": "MEDIUM",
            "asset_criticality": "critical",
            "platform_risk": "medium",
            "risk_policy_version": "1.0",
        },
        {
            "resource": {},
            "severity_source": "LOW",
            "risk_score": 20,
            "confidence": "LOW",
            "asset_criticality": "standard",
            "platform_risk": "low",
            "risk_policy_version": "1.0",
        },
    ]

    summaries = correlate_findings(findings)

    assert len(summaries) == 1
    assert summaries[0]["resource_id"] == "arn:aws:s3:::example-bucket"
    assert summaries[0]["finding_count"] == 2
    assert summaries[0]["max_risk_score"] >= 0
