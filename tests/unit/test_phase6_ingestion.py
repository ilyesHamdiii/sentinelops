import pytest

from sentinelops.normalization import normalize_event_payload, validate_event_envelope
from sentinelops.validation.integrations import ingest_event


@pytest.fixture
def valid_event():
    return {
        "event_id": "evt-001",
        "event_type": "securityhub-finding",
        "schema_version": "1.0",
        "occurred_at": "2026-11-12T12:00:00Z",
        "received_at": "2026-11-12T12:00:00Z",
        "source": "securityhub",
        "correlation_id": "corr-001",
        "account_id": "960577828312",
        "region": "eu-west-1",
        "payload": {
            "resource": {
                "type": "AWS::S3::Bucket",
                "id": "sentinelops-evidence-960577828312",
                "arn": "arn:aws:s3:::sentinelops-evidence-960577828312",
                "tags": {"Project": "sentinelops"},
            },
            "title": "Public S3 bucket access policy",
            "description": "Bucket policy allows public access.",
            "severity": "HIGH",
            "risk_score": 82,
            "finding_id": "sh-finding-001",
            "scenario_id": "S1",
            "confidence": "HIGH",
        },
    }


def test_validate_event_envelope_accepts_valid_securityhub_payload(valid_event):
    envelope = validate_event_envelope(valid_event)

    assert envelope.source == "securityhub"
    assert envelope.account_id == "960577828312"
    assert envelope.region == "eu-west-1"


def test_normalize_event_payload_builds_canonical_finding(valid_event):
    normalized = normalize_event_payload(valid_event)

    assert normalized["schema_version"] == "1.0"
    assert normalized["source"] == "securityhub"
    assert normalized["source_finding_id"] == "evt-001"
    assert normalized["resource"]["type"] == "AWS::S3::Bucket"
    assert normalized["status"] == "OPEN"
    assert normalized["severity_source"] == "HIGH"


def test_malformed_event_is_rejected():
    malformed = {"event_id": "evt-002", "source": "not-supported"}

    with pytest.raises(ValueError):
        validate_event_envelope(malformed)


def test_duplicate_event_is_skipped_for_idempotency(valid_event):
    seen_keys = set()

    first = ingest_event(valid_event, seen_keys=seen_keys)
    second = ingest_event(valid_event, seen_keys=seen_keys)

    assert first["status"] == "accepted"
    assert second["status"] == "duplicate"
    assert len(seen_keys) == 1
