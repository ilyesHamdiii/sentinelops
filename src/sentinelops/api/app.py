"""FastAPI service for SentinelOps findings, scenarios, and remediation workflows."""

from __future__ import annotations

from typing import Any, cast

from fastapi import Body, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from sentinelops.reporting.reporting import build_report, sanitize_payload, summarize_findings

FINDINGS = [
    {
        "id": "fg-001",
        "title": "Public S3 bucket exposure",
        "description": "Bucket is publicly readable.",
        "severity": "HIGH",
        "status": "OPEN",
        "risk_score": 96,
        "resource_id": "arn:aws:s3:::public-bucket",
        "evidence_refs": ["s3://public-bucket/acl"],
        "scenario_id": "s3-public-access",
    },
    {
        "id": "fg-002",
        "title": "Bucket policy permits anonymous access",
        "description": "Policy allows unauthenticated access to objects.",
        "severity": "CRITICAL",
        "status": "OPEN",
        "risk_score": 92,
        "resource_id": "arn:aws:s3:::example-bucket",
        "evidence_refs": ["s3://example-bucket/policy"],
        "scenario_id": "s3-public-access",
    },
    {
        "id": "fg-003",
        "title": "IAM wildcard access",
        "description": "Policy grants broad access to all actions.",
        "severity": "MEDIUM",
        "status": "RESOLVED",
        "risk_score": 62,
        "resource_id": "arn:aws:iam::123456789012:policy/example-policy",
        "evidence_refs": ["iam://example-policy"],
        "scenario_id": "iam-overprivilege",
    },
]

SCENARIOS = [
    {"id": "s3-public-access", "name": "Public S3 exposure"},
    {"id": "iam-overprivilege", "name": "IAM overprivilege"},
    {"id": "security-group-exposure", "name": "Security group exposure"},
]

REMEDIATIONS = [
    {
        "id": "rm-001",
        "action": "s3_block_public_access",
        "target": "arn:aws:s3:::public-bucket",
        "status": "PROPOSED",
        "approved": False,
        "state": "PENDING_APPROVAL",
        "reason": "Restrict public access to the S3 bucket.",
        "actor": None,
    }
]


class ApprovalRequest(BaseModel):
    actor: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, min_length=1, max_length=512)
    decision: str = Field(default="approve")

    @field_validator("decision")
    @classmethod
    def validate_decision(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"approve", "reject"}:
            raise ValueError("decision must be 'approve' or 'reject'")
        return normalized


class ExecutionRequest(BaseModel):
    status: str = Field(default="SUCCESS")
    verification_passed: bool = True
    details: str | None = Field(default=None, max_length=512)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"SUCCESS", "FAILED"}:
            raise ValueError("status must be 'SUCCESS' or 'FAILED'")
        return normalized


app = FastAPI(
    title="SentinelOps API",
    version="0.1.0",
    description="FastAPI service for findings, reporting, and approved remediation workflows.",
)


def _require_role(x_sentinelops_role: str | None, required: str = "reader") -> None:
    if x_sentinelops_role is None:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Unauthorized: this operation requires the '{required}' role "
                "for approval or execution."
            ),
        )
    if x_sentinelops_role.lower() != required.lower():
        raise HTTPException(
            status_code=403,
            detail=(
                f"Unauthorized: this operation requires the '{required}' role "
                "for approval or execution."
            ),
        )


def _list_findings(status: str | None = None) -> list[dict[str, Any]]:
    if not status:
        return list(FINDINGS)
    normalized = status.strip().upper()
    return [item for item in FINDINGS if item.get("status", "").upper() == normalized]


def _sanitize_finding(item: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], sanitize_payload(item))


@app.get("/")
def root() -> None:
    raise HTTPException(
        status_code=404,
        detail="SentinelOps API is headless; browser UI routes are intentionally disabled.",
    )


@app.get("/dashboard")
def dashboard_view() -> None:
    raise HTTPException(
        status_code=404,
        detail="SentinelOps API is headless; browser UI routes are intentionally disabled.",
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinelops"}


@app.get("/findings")
def list_findings(
    status_filter: str | None = Query(
        default=None,
        description="Optional status filter: OPEN or RESOLVED",
    ),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=10, ge=1, le=100),
) -> dict[str, Any]:
    filtered = _list_findings(status=status_filter)
    start = (page - 1) * limit
    end = start + limit
    items = filtered[start:end]
    return {
        "items": [_sanitize_finding(item) for item in items],
        "count": len(items),
        "page": page,
        "limit": limit,
        "total": len(filtered),
    }


@app.get("/findings/{finding_id}")
def get_finding(finding_id: str) -> dict[str, Any]:
    for item in FINDINGS:
        if item["id"] == finding_id:
            return _sanitize_finding(item)
    raise HTTPException(status_code=404, detail="Finding not found")


@app.get("/assets")
def list_assets() -> dict[str, Any]:
    assets = sorted(
        {str(item.get("resource_id")) for item in FINDINGS if item.get("resource_id")}
    )
    return {"items": assets, "count": len(assets)}


@app.get("/metrics/summary")
def metrics_summary() -> dict[str, Any]:
    return summarize_findings(FINDINGS)


@app.get("/scenarios")
def list_scenarios() -> dict[str, Any]:
    return {"items": SCENARIOS, "count": len(SCENARIOS)}


@app.get("/remediations")
def list_remediations() -> dict[str, Any]:
    return {"items": REMEDIATIONS, "count": len(REMEDIATIONS)}


@app.get("/remediations/{remediation_id}")
def get_remediation(remediation_id: str) -> dict[str, Any]:
    for remediation in REMEDIATIONS:
        if remediation["id"] == remediation_id:
            return remediation
    raise HTTPException(status_code=404, detail="Remediation not found")


@app.post("/remediations")
def create_remediation(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    item = {
        "id": payload.get("id", f"rm-{len(REMEDIATIONS) + 1:03d}"),
        "action": payload["action"],
        "target": payload["target"],
        "status": "PROPOSED",
        "approved": False,
        "state": "PENDING_APPROVAL",
        "reason": payload.get("reason", "No reason provided."),
        "actor": payload.get("actor"),
    }
    REMEDIATIONS.append(item)
    return item


@app.post("/remediations/{remediation_id}/approve")
def approve_remediation(
    remediation_id: str,
    payload: ApprovalRequest = Body(default_factory=ApprovalRequest),
    x_sentinelops_role: str | None = Header(default=None, alias="x-sentinelops-role"),
) -> dict[str, Any]:
    _require_role(x_sentinelops_role, required="approver")
    for remediation in REMEDIATIONS:
        if remediation["id"] == remediation_id:
            remediation["approved"] = True
            remediation["status"] = "APPROVED"
            remediation["state"] = "APPROVED"
            remediation["actor"] = payload.actor or remediation.get("actor")
            if payload.reason:
                remediation["reason"] = payload.reason
            return remediation
    raise HTTPException(status_code=404, detail="Remediation not found")


@app.post("/remediations/{remediation_id}/reject")
def reject_remediation(
    remediation_id: str,
    payload: ApprovalRequest = Body(default_factory=ApprovalRequest),
    x_sentinelops_role: str | None = Header(default=None, alias="x-sentinelops-role"),
) -> dict[str, Any]:
    _require_role(x_sentinelops_role, required="approver")
    for remediation in REMEDIATIONS:
        if remediation["id"] == remediation_id:
            remediation["approved"] = False
            remediation["status"] = "REJECTED"
            remediation["state"] = "REJECTED"
            remediation["actor"] = payload.actor or remediation.get("actor")
            if payload.reason:
                remediation["reason"] = payload.reason
            return remediation
    raise HTTPException(status_code=404, detail="Remediation not found")


@app.post("/remediations/{remediation_id}/execute")
def execute_remediation(
    remediation_id: str,
    payload: ExecutionRequest = Body(default_factory=ExecutionRequest),
    x_sentinelops_role: str | None = Header(default=None, alias="x-sentinelops-role"),
) -> dict[str, Any]:
    _require_role(x_sentinelops_role, required="approver")
    for remediation in REMEDIATIONS:
        if remediation["id"] == remediation_id:
            verification_passed = bool(payload.verification_passed)
            if payload.status == "SUCCESS" and verification_passed:
                remediation["status"] = "VERIFIED"
                remediation["state"] = "RESOLVED"
                remediation["approved"] = True
                return {
                    "id": remediation["id"],
                    "status": "VERIFIED",
                    "state": "RESOLVED",
                    "verification": {
                        "passed": True,
                        "details": payload.details,
                    },
                    "remediation": remediation,
                }
            remediation["status"] = "FAILED"
            remediation["state"] = "OPEN"
            return {
                "id": remediation["id"],
                "status": "FAILED",
                "state": "OPEN",
                "verification": {
                    "passed": False,
                    "details": payload.details,
                },
                "remediation": remediation,
            }
    raise HTTPException(status_code=404, detail="Remediation not found")


@app.get("/reports/{report_id}")
def get_report(report_id: str) -> dict[str, Any]:
    if report_id != "rpt-001":
        raise HTTPException(status_code=404, detail="Report not found")
    return build_report(report_id, FINDINGS)
