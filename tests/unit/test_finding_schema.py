import pytest
from pydantic import ValidationError

from sentinelops.common.schema import EventEnvelope, FindingRecord


def test_finding_record_accepts_valid_payload():
    finding = FindingRecord(
        schema_version="1.0",
        finding_id="finding-001",
        source="securityhub",
        source_finding_id="source-123",
        account_id="test-account",
        region="us-east-1",
        resource={
            "type": "AWS::S3::Bucket",
            "id": "bucket-123",
            "arn": "arn:aws:s3:::bucket-123",
            "tags": {"env": "test"},
        },
        title="Unsafe storage access configuration",
        description="Evidence-based description",
        severity_source="HIGH",
        risk_score=78,
        risk_policy_version="1.0",
        status="OPEN",
        first_seen="2026-11-12T00:00:00Z",
        last_seen="2026-11-12T00:05:00Z",
        evidence_refs=["evidence:1"],
        scenario_id="S1-001",
        confidence="HIGH",
        remediation_state="PROPOSED",
    )

    assert finding.finding_id == "finding-001"
    assert finding.risk_score == 78
    assert finding.resource.type == "AWS::S3::Bucket"


def test_finding_record_rejects_out_of_bounds_risk_score():
    with pytest.raises(ValidationError):
        FindingRecord(
            schema_version="1.0",
            finding_id="finding-002",
            source="securityhub",
            source_finding_id="source-456",
            account_id="test-account",
            region="us-east-1",
            resource={
                "type": "AWS::S3::Bucket",
                "id": "bucket-456",
                "arn": "arn:aws:s3:::bucket-456",
                "tags": {},
            },
            title="Unsafe storage access configuration",
            description="Evidence-based description",
            severity_source="HIGH",
            risk_score=120,
            risk_policy_version="1.0",
            status="OPEN",
            first_seen="2026-11-12T00:00:00Z",
            last_seen="2026-11-12T00:05:00Z",
            evidence_refs=[],
            scenario_id="S1-001",
            confidence="HIGH",
            remediation_state="PROPOSED",
        )


def test_event_envelope_validates_required_fields():
    event = EventEnvelope(
        event_id="event-1",
        event_type="finding.ingested",
        schema_version="1.0",
        occurred_at="2026-11-12T00:00:00Z",
        received_at="2026-11-12T00:00:02Z",
        source="securityhub",
        correlation_id="corr-1",
        account_id="test-account",
        region="us-east-1",
        payload={"finding_id": "finding-001"},
    )

    assert event.event_type == "finding.ingested"
    assert event.payload["finding_id"] == "finding-001"


def test_event_envelope_rejects_missing_required_field():
    with pytest.raises(ValidationError):
        EventEnvelope(
            event_id="event-2",
            event_type="finding.ingested",
            schema_version="1.0",
            occurred_at="2026-11-12T00:00:00Z",
            received_at="2026-11-12T00:00:02Z",
            source="securityhub",
            correlation_id="corr-2",
            account_id="test-account",
            payload={"finding_id": "finding-002"},
        )
