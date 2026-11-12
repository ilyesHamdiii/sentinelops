"""Backward-compatible risk helpers that bridge the legacy API to the canonical Phase 7 engine."""

from __future__ import annotations

from collections.abc import Sequence

from sentinelops.risk import (
    correlate_findings as _correlate_findings,
    evaluate_risk_for_findings as _evaluate_risk_for_findings,
)

RISK_POLICY_VERSION = "1.0"

SEVERITY_WEIGHTS = {
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 15,
    "CRITICAL": 20,
}

CONFIDENCE_WEIGHTS = {
    "LOW": 5,
    "MEDIUM": 10,
    "HIGH": 15,
}

ASSET_CRITICALITY_WEIGHTS = {
    "standard": 0,
    "high": 5,
    "critical": 15,
}


def calculate_risk_score(
    severity_source: str | dict,
    risk_score: int | None = None,
    confidence: str | None = None,
    asset_criticality: str = "standard",
    platform_risk: str = "low",
) -> int:
    """Compatibility wrapper for both legacy and canonical risk score inputs."""
    if isinstance(severity_source, dict):
        from sentinelops.risk import calculate_risk_score as canonical_calculate

        return canonical_calculate(severity_source)

    source_severity = str(severity_source or "LOW").upper()
    confidence_level = str(confidence or "LOW").upper()
    criticality = str(asset_criticality or "standard").lower()

    severity_component = SEVERITY_WEIGHTS.get(source_severity, 0)
    confidence_component = CONFIDENCE_WEIGHTS.get(confidence_level, 0)
    criticality_component = ASSET_CRITICALITY_WEIGHTS.get(criticality, 0)

    normalized_score = (
        (int(risk_score or 0) * 0.5)
        + severity_component
        + confidence_component
        + criticality_component
    )
    return max(0, min(100, int(normalized_score)))


def correlate_findings(findings: Sequence[dict]) -> list[dict]:
    """Group findings by resource identity and summarize the highest risk signal."""
    legacy_findings = []
    for finding in findings:
        if isinstance(finding, dict) and ("severity_source" in finding or "resource" in finding):
            legacy_findings.append(finding)

    if not legacy_findings:
        return _correlate_findings(list(findings))

    grouped: dict[str, dict] = {}
    for finding in legacy_findings:
        resource = finding.get("resource") or {}
        resource_id = resource.get("id") or resource.get("arn")
        if not resource_id:
            continue

        if resource_id not in grouped:
            grouped[resource_id] = {
                "resource_id": resource_id,
                "finding_count": 0,
                "max_risk_score": 0,
            }

        grouped[resource_id]["finding_count"] += 1
        grouped[resource_id]["max_risk_score"] = max(
            grouped[resource_id]["max_risk_score"],
            calculate_risk_score(
                finding.get("severity_source", "LOW"),
                finding.get("risk_score", 0),
                finding.get("confidence", "LOW"),
                finding.get("asset_criticality", "standard"),
            ),
        )

    return sorted(
        grouped.values(),
        key=lambda item: (-item["finding_count"], -item["max_risk_score"], item["resource_id"]),
    )


def evaluate_risk_for_findings(findings: Sequence[dict]) -> list[dict]:
    """Canonical evaluation hook for the current Phase 7 contract."""
    return _evaluate_risk_for_findings(list(findings))
