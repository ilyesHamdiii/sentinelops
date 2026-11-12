"""Canonical schema validation models for SentinelOps findings and events."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ResourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    id: str
    arn: str
    tags: dict[str, str] = Field(default_factory=dict)


class FindingRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    finding_id: str
    source: Literal["securityhub", "guardduty", "aws_config", "sentinelops"]
    source_finding_id: str
    account_id: str
    region: str
    resource: ResourceRef
    title: str
    description: str
    severity_source: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: int = Field(ge=0, le=100)
    risk_policy_version: str
    status: Literal["OPEN", "RESOLVED", "SUPPRESSED", "UNKNOWN"]
    first_seen: str
    last_seen: str
    evidence_refs: list[str] = Field(default_factory=list)
    scenario_id: str
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    remediation_state: Literal[
        "PROPOSED",
        "APPROVED",
        "REJECTED",
        "EXECUTING",
        "VERIFYING",
        "RESOLVED",
        "FAILED",
    ]


class EventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    event_type: str
    schema_version: Literal["1.0"]
    occurred_at: str
    received_at: str
    source: Literal["securityhub", "guardduty", "aws_config", "sentinelops"]
    correlation_id: str
    account_id: str
    region: str
    payload: dict[str, Any]
    trace_context: dict[str, Any] | None = None
