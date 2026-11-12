"""Managed security integration support and deduplication helpers."""

from __future__ import annotations

from collections.abc import MutableSet
from typing import Any

from sentinelops.normalization import normalize_event_payload, validate_event_envelope

SUPPORTED_FINDING_SOURCES = {"securityhub", "guardduty", "aws_config", "sentinelops"}


def is_supported_finding_source(source: str | None) -> bool:
    return bool(source) and source in SUPPORTED_FINDING_SOURCES


def dedupe_key(finding: dict) -> str:
    source = str(finding.get("source", "")).strip()
    source_finding_id = str(finding.get("source_finding_id", "")).strip()
    account_id = str(finding.get("account_id", "")).strip()
    region = str(finding.get("region", "")).strip()
    return f"{source}:{account_id}:{region}:{source_finding_id}"


def validate_supported_finding(finding: dict) -> bool:
    if not isinstance(finding, dict):
        return False

    if not is_supported_finding_source(finding.get("source")):
        return False

    if not finding.get("source_finding_id"):
        return False

    if not finding.get("account_id"):
        return False

    if not finding.get("region"):
        return False

    return True


def event_idempotency_key(event: dict[str, Any]) -> str:
    envelope = validate_event_envelope(event)
    return f"{envelope.source}:{envelope.account_id}:{envelope.region}:{envelope.event_id}"


def ingest_event(event: dict[str, Any], seen_keys: MutableSet[str] | None = None) -> dict[str, Any]:
    if seen_keys is None:
        seen_keys = set()

    key = event_idempotency_key(event)
    if key in seen_keys:
        return {"status": "duplicate", "idempotency_key": key}

    validate_event_envelope(event)
    normalized = normalize_event_payload(event)
    seen_keys.add(key)
    return {"status": "accepted", "idempotency_key": key, "finding": normalized}
