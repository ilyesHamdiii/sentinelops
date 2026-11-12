from sentinelops.validation.risk import (
    RISK_POLICY_VERSION,
    calculate_risk_score,
    correlate_findings,
)


def test_risk_policy_is_versioned_and_deterministic():
    assert RISK_POLICY_VERSION == "1.0"
    assert calculate_risk_score("HIGH", 80, "HIGH", "critical") == 85
    assert calculate_risk_score("HIGH", 80, "HIGH", "critical") == 85


def test_criticality_increases_score_for_same_finding():
    standard = calculate_risk_score("MEDIUM", 60, "MEDIUM", "standard")
    critical = calculate_risk_score("MEDIUM", 60, "MEDIUM", "critical")

    assert standard < critical
    assert critical == 70


def test_correlate_findings_groups_related_assets():
    findings = [
        {
            "resource": {"id": "arn:aws:s3:::example-bucket"},
            "severity_source": "HIGH",
            "risk_score": 80,
            "confidence": "HIGH",
            "asset_criticality": "critical",
        },
        {
            "resource": {"id": "arn:aws:s3:::example-bucket"},
            "severity_source": "MEDIUM",
            "risk_score": 55,
            "confidence": "MEDIUM",
            "asset_criticality": "critical",
        },
        {
            "resource": {"id": "arn:aws:ec2:eu-east-1:123456789012:security-group/sg-1"},
            "severity_source": "LOW",
            "risk_score": 25,
            "confidence": "LOW",
            "asset_criticality": "standard",
        },
    ]

    correlated = correlate_findings(findings)

    assert len(correlated) == 2
    assert correlated[0]["resource_id"] == "arn:aws:s3:::example-bucket"
    assert correlated[0]["finding_count"] == 2
    assert correlated[0]["max_risk_score"] == 85
