"""Deterministic risk scoring and correlation for SentinelOps findings."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

RISK_POLICY_VERSION = "1.0"

SEVERITY_WEIGHTS = {
    "LOW": 10,
    "MEDIUM": 20,
    "HIGH": 35,
    "CRITICAL": 50,
}

CONFIDENCE_WEIGHTS = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 20,
}

ASSET_CRITICALITY_WEIGHTS = {
    "standard": 0,
    "high": 10,
    "critical": 20,
}

PLATFORM_RISK_WEIGHTS = {
    "low": 0,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


def _coerce_text(value: Any, default: str) -> str:
    text = str(value or default).strip()
    return text if text else default


def _normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(finding)
    resource = normalized.get("resource") if isinstance(normalized.get("resource"), dict) else {}
    normalized["severity_source"] = _coerce_text(normalized.get("severity_source"), "LOW").upper()
    normalized["confidence"] = _coerce_text(normalized.get("confidence"), "LOW").upper()
    normalized["asset_criticality"] = _coerce_text(normalized.get("asset_criticality"), "standard").lower()
    normalized["platform_risk"] = _coerce_text(normalized.get("platform_risk"), "low").lower()
    normalized["risk_policy_version"] = normalized.get("risk_policy_version") or RISK_POLICY_VERSION
    normalized["risk_score"] = int(normalized.get("risk_score", 0))
    normalized["resource"] = resource
    return normalized


def calculate_risk_score(finding: dict[str, Any]) -> int:
    """Compute a deterministic 0-100 score for a single finding."""
    normalized = _normalize_finding(finding)

    severity_part = SEVERITY_WEIGHTS.get(normalized["severity_source"], 0)
    confidence_part = CONFIDENCE_WEIGHTS.get(normalized["confidence"], 0)
    criticality_part = ASSET_CRITICALITY_WEIGHTS.get(normalized["asset_criticality"], 0)
    platform_part = PLATFORM_RISK_WEIGHTS.get(normalized["platform_risk"], 0)

    score = (
        int(normalized["risk_score"]) * 0.55
        + severity_part
        + confidence_part
        + criticality_part
        + platform_part
    )
    return max(0, min(100, int(round(score))))


def _build_rationale(finding: dict[str, Any], score: int) -> str:
    severity = _coerce_text(finding.get("severity_source"), "LOW").upper()
    confidence = _coerce_text(finding.get("confidence"), "LOW").upper()
    criticality = _coerce_text(finding.get("asset_criticality"), "standard").lower()
    platform = _coerce_text(finding.get("platform_risk"), "low").lower()
    source = _coerce_text(finding.get("source"), "unknown")
    resource = (finding.get("resource") or {}).get("id") or "unknown-resource"

    return (
        f"Source={source}; severity={severity}; confidence={confidence}; "
        f"asset_criticality={criticality}; platform_risk={platform}; "
        f"resource={resource}; score={score}; policy_version={RISK_POLICY_VERSION}."
    )


def evaluate_risk_for_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach deterministic score, rationale, and policy version to each finding."""
    evaluated: list[dict[str, Any]] = []
    for finding in findings:
        normalized = _normalize_finding(finding)
        score = calculate_risk_score(normalized)
        rationale = _build_rationale(normalized, score)

        entry = dict(normalized)
        entry["risk_score"] = score
        entry["risk_policy_version"] = normalized["risk_policy_version"]
        entry["rationale"] = rationale
        entry["policy_version"] = normalized["risk_policy_version"]
        evaluated.append(entry)
    return evaluated


def correlate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group findings by resource identity and summarize the highest risk signal."""
    grouped: dict[str, dict[str, Any]] = defaultdict(lambda: {
        "resource_id": None,
        "finding_count": 0,
        "max_risk_score": 0,
        "rationale": "",
    })

    for finding in findings:
        resource = finding.get("resource") if isinstance(finding.get("resource"), dict) else {}
        resource_id = resource.get("id") or resource.get("arn")
        if not resource_id:
            continue

        entry = grouped[resource_id]
        entry["resource_id"] = resource_id
        entry["finding_count"] += 1

        score = calculate_risk_score(finding)
        entry["max_risk_score"] = max(entry["max_risk_score"], score)
        if not entry["rationale"]:
            entry["rationale"] = f"Asset {resource_id} shows {entry['finding_count']} related finding(s)."

    correlated = sorted(
        grouped.values(),
        key=lambda item: (-item["finding_count"], -item["max_risk_score"], str(item["resource_id"])),
    )
    return correlated
