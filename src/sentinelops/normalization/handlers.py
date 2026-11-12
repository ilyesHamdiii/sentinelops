"""Canonical event validation and normalization for the Phase 6 ingestion layer."""

from __future__ import annotations

from typing import Any

from sentinelops.common.schema import EventEnvelope, FindingRecord


def _normalize_severity(raw_value: Any) -> str:
    value = str(raw_value or "MEDIUM").upper()
    return value if value in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} else "MEDIUM"


def _normalize_confidence(raw_value: Any) -> str:
    value = str(raw_value or "MEDIUM").upper()
    return value if value in {"LOW", "MEDIUM", "HIGH"} else "MEDIUM"


def validate_event_envelope(event: dict[str, Any]) -> EventEnvelope:
    if not isinstance(event, dict):
        raise ValueError("Event payload must be a dictionary.")

    for field in ("event_id", "event_type", "source", "account_id", "region", "payload"):
        if not event.get(field):
            raise ValueError(f"{field} is required for an event envelope.")

    if not isinstance(event["payload"], dict):
        raise ValueError("payload must be a dictionary.")

    try:
        return EventEnvelope.model_validate(event)
    except Exception as exc:  # pragma: no cover - rewrap for deterministic validation message
        raise ValueError(f"Malformed event envelope: {exc}") from exc


def normalize_event_payload(event: dict[str, Any]) -> dict[str, Any]:
    envelope = validate_event_envelope(event)
    payload = envelope.payload or {}

    resource = payload.get("resource") if isinstance(payload.get("resource"), dict) else {}
    resource_type = (
        resource.get("type")
        or payload.get("resource_type")
        or "AWS::Unknown::Resource"
    )
    resource_id = (
        resource.get("id")
        or payload.get("resource_id")
        or resource.get("arn")
        or payload.get("arn")
        or f"{envelope.source}:{envelope.account_id}:{envelope.region}"
    )
    resource_arn = (
        resource.get("arn")
        or payload.get("arn")
        or f"arn:aws:resource:{envelope.region}:{envelope.account_id}:{resource_id}"
    )
    resource_tags = resource.get("tags") if isinstance(resource.get("tags"), dict) else {}

    normalized = {
        "schema_version": "1.0",
        "finding_id": f"{envelope.source}:{envelope.account_id}:{envelope.region}:{envelope.event_id}",
        "source": envelope.source,
        "source_finding_id": envelope.event_id,
        "account_id": envelope.account_id,
        "region": envelope.region,
        "resource": {
            "type": str(resource_type),
            "id": str(resource_id),
            "arn": str(resource_arn),
            "tags": {str(key): str(value) for key, value in resource_tags.items()},
        },
        "title": str(payload.get("title") or payload.get("finding_type") or "Security finding"),
        "description": str(
            payload.get("description")
            or payload.get("summary")
            or "Normalized security finding captured by SentinelOps."
        ),
        "severity_source": _normalize_severity(payload.get("severity") or payload.get("severity_source")),
        "risk_score": max(0, min(100, int(payload.get("risk_score", 50)))),
        "risk_policy_version": "1.0",
        "status": "OPEN",
        "first_seen": envelope.occurred_at,
        "last_seen": envelope.occurred_at,
        "evidence_refs": [
            str(entry) for entry in (payload.get("evidence_refs") or [envelope.event_id])
        ],
        "scenario_id": str(payload.get("scenario_id") or "PHASE6-INGESTION"),
        "confidence": _normalize_confidence(payload.get("confidence") or "MEDIUM"),
        "remediation_state": "PROPOSED",
    }

    return normalized


def normalize_finding_record(finding: dict[str, Any]) -> FindingRecord:
    if not isinstance(finding, dict):
        raise ValueError("Finding payload must be a dictionary.")

    try:
        return FindingRecord.model_validate(finding)
    except Exception as exc:  # pragma: no cover - wrapper for deterministic validation failure
        raise ValueError(f"Malformed finding record: {exc}") from exc
