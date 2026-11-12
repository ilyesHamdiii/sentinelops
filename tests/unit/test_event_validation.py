import pytest

from sentinelops.common.schema import EventEnvelope


def test_event_envelope_accepts_local_synthetic_values():
    event = EventEnvelope(
        event_id="evt-local-001",
        event_type="finding.ingested",
        schema_version="1.0",
        occurred_at="2026-11-12T00:00:00Z",
        received_at="2026-11-12T00:00:05Z",
        source="securityhub",
        correlation_id="corr-local-001",
        account_id="test-account",
        region="us-east-1",
        payload={"finding_id": "finding-local-001"},
    )

    assert event.payload["finding_id"] == "finding-local-001"


def test_event_envelope_rejects_unsupported_source():
    with pytest.raises(ValueError):
        EventEnvelope(
            event_id="evt-local-002",
            event_type="finding.ingested",
            schema_version="1.0",
            occurred_at="2026-11-12T00:00:00Z",
            received_at="2026-11-12T00:00:05Z",
            source="unsupported-source",
            correlation_id="corr-local-002",
            account_id="test-account",
            region="us-east-1",
            payload={"finding_id": "finding-local-002"},
        )
