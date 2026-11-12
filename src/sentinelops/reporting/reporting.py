"""Sanitized report generation and summary helpers."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone

_SECRET_KEYWORDS = (
    "secret",
    "token",
    "password",
    "passwd",
    "session",
    "key",
    "private",
    "credential",
    "aws_access",
    "api_key",
)


def sanitize_payload(value):
    """Recursively strip secret-bearing fields while preserving evidence metadata."""
    if isinstance(value, Mapping):
        sanitized = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(keyword in lowered for keyword in _SECRET_KEYWORDS):
                continue
            sanitized[key] = sanitize_payload(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_payload(item) for item in value)
    return value


def summarize_findings(findings: list[dict]) -> dict:
    """Build a deterministic summary for the current finding set."""
    total = len(findings)
    open_count = sum(1 for item in findings if item.get("status") == "OPEN")
    resolved_count = sum(1 for item in findings if item.get("status") == "RESOLVED")
    max_risk = max((int(item.get("risk_score", 0)) for item in findings), default=0)
    asset_count = len({item.get("resource_id") for item in findings if item.get("resource_id")})

    return {
        "total_findings": total,
        "open_findings": open_count,
        "resolved_findings": resolved_count,
        "max_risk_score": max_risk,
        "asset_count": asset_count,
    }


def build_report(report_id: str, findings: list[dict]) -> dict:
    """Create a report with traceable ids and sanitized payloads."""
    summary = summarize_findings(findings)
    items = [
        sanitize_payload(
            {
                "id": item.get("id"),
                "title": item.get("title"),
                "severity": item.get("severity"),
                "status": item.get("status"),
                "resource_id": item.get("resource_id"),
                "evidence_refs": item.get("evidence_refs", []),
            }
        )
        for item in findings
    ]

    return {
        "report_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": items,
    }
