"""Local synthetic fixtures used before AWS integration testing."""

from __future__ import annotations

from typing import Any


def synthetic_finding() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "finding_id": "finding-local-001",
        "source": "securityhub",
        "source_finding_id": "source-local-001",
        "account_id": "test-account",
        "region": "us-east-1",
        "resource": {
            "type": "AWS::S3::Bucket",
            "id": "sentinelops-local-bucket",
            "arn": "arn:aws:s3:::sentinelops-local-bucket",
            "tags": {"env": "local", "project": "sentinelops"},
        },
        "title": "Unsafe storage access configuration",
        "description": "Synthetic evidence for local validation.",
        "severity_source": "HIGH",
        "risk_score": 78,
        "risk_policy_version": "1.0",
        "status": "OPEN",
        "first_seen": "2026-11-12T00:00:00Z",
        "last_seen": "2026-11-12T00:05:00Z",
        "evidence_refs": ["synthetic://bucket-policy"],
        "scenario_id": "S1-001",
        "confidence": "HIGH",
        "remediation_state": "PROPOSED",
    }


def synthetic_event() -> dict[str, Any]:
    return {
        "event_id": "evt-local-001",
        "event_type": "finding.ingested",
        "schema_version": "1.0",
        "occurred_at": "2026-11-12T00:00:00Z",
        "received_at": "2026-11-12T00:00:05Z",
        "source": "securityhub",
        "correlation_id": "corr-local-001",
        "account_id": "test-account",
        "region": "us-east-1",
        "payload": {"finding_id": "finding-local-001"},
    }
