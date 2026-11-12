import logging

from sentinelops.common.fixtures import synthetic_event, synthetic_finding
from sentinelops.common.logging import get_logger


def test_synthetic_finding_fixture_has_expected_shape():
    finding = synthetic_finding()

    assert finding["schema_version"] == "1.0"
    assert finding["source"] in {"securityhub", "guardduty", "aws_config", "sentinelops"}
    assert 0 <= finding["risk_score"] <= 100
    assert finding["resource"]["type"]


def test_synthetic_event_fixture_has_expected_event_metadata():
    event = synthetic_event()

    assert event["event_type"] == "finding.ingested"
    assert event["schema_version"] == "1.0"
    assert event["payload"]["finding_id"]
    assert event["correlation_id"]


def test_logger_emits_structured_output(caplog):
    logger = get_logger("phase2.test")

    with caplog.at_level(logging.INFO):
        logger.info("phase-2-local-foundation", extra={"event_id": "evt-123", "component": "test"})

    assert "phase-2-local-foundation" in caplog.text
    assert "evt-123" in caplog.text
