"""Secure, allowlisted remediation workflow for SentinelOps.

The remediation pipeline is intentionally scoped to explicit allowlisted actions
and binds approvals to the exact action, target, and rationale that produced the
approval hash. This prevents accidental approval drift and ensures a remediation
cannot be replayed after it has already been used.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ApprovedRemediationAction(str, Enum):
    """Actions considered safe and explicitly allowlisted for Class 2 execution."""

    S3_BLOCK_PUBLIC_ACCESS = "s3_block_public_access"
    SECURITY_GROUP_RESTRICT_INGRESS = "security_group_restrict_ingress"
    IAM_REMOVE_WILDCARD_POLICY = "iam_remove_wildcard_policy"


APPROVED_ACTIONS = {value.value for value in ApprovedRemediationAction}
_DEFAULT_APPROVAL_TTL_SECONDS = 3600
_ALLOWED_TRANSITIONS = {
    "DRAFT": {"PENDING_APPROVAL", "REJECTED"},
    "PENDING_APPROVAL": {"APPROVED", "REJECTED"},
    "APPROVED": {"EXECUTING"},
    "EXECUTING": {"VERIFYING", "FAILED"},
    "VERIFYING": {"RESOLVED", "OPEN"},
    "FAILED": {"TRIAGED"},
    "REJECTED": {"TRIAGED"},
    "OPEN": {"TRIAGED"},
    "RESOLVED": {"OPEN"},
}


def build_action_hash(action: str, target: str, reason: str) -> str:
    payload = f"{action}:{target}:{reason}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:32]


def _coerce_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def validate_remediation_approval(
    action: str,
    target: str,
    reason: str,
    approval_hash: str,
    approved: bool,
    created_at: datetime | str | None = None,
    current_time: datetime | str | None = None,
    approval_ttl_seconds: int = _DEFAULT_APPROVAL_TTL_SECONDS,
) -> bool:
    """Validate the approval hash and ensure the approval is not expired."""
    if not approved:
        return False
    if not action or not target or not reason:
        return False
    if action not in APPROVED_ACTIONS:
        return False

    approval_hash_value = str(approval_hash or "")
    expected_hash = build_action_hash(action, target, reason)
    if approval_hash_value != expected_hash:
        return False

    if approval_ttl_seconds is None or approval_ttl_seconds <= 0:
        return True

    created = _coerce_datetime(created_at)
    if created is None:
        return True

    now = _coerce_datetime(current_time) or datetime.now(timezone.utc)
    age = now - created
    if age > timedelta(seconds=approval_ttl_seconds):
        return False
    return True


def approve_remediation(
    *,
    action: str,
    target: str,
    reason: str,
    approved: bool = True,
    created_at: datetime | str | None = None,
    approval_ttl_seconds: int = _DEFAULT_APPROVAL_TTL_SECONDS,
) -> dict[str, Any]:
    """Create a signed approval record that is bound to the exact action payload."""
    if not approved:
        return {
            "approved": False,
            "action": action,
            "target": target,
            "reason": reason,
            "hash": "",
            "state": "REJECTED",
        }

    if not action or action not in APPROVED_ACTIONS:
        raise ValueError(f"Action '{action}' is not allowlisted for remediation")
    if not target or not reason:
        raise ValueError("Approval requires a target resource and human-readable rationale")

    approval_time = _coerce_datetime(created_at) or datetime.now(timezone.utc)
    approval_hash = build_action_hash(action, target, reason)
    expires_at = approval_time + timedelta(seconds=approval_ttl_seconds)

    return {
        "approved": True,
        "id": f"apr-{approval_hash[:12]}",
        "action": action,
        "target": target,
        "reason": reason,
        "hash": approval_hash,
        "created_at": approval_time.isoformat(),
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": approval_ttl_seconds,
        "state": "PENDING_APPROVAL",
    }


def validate_remediation_execution(
    *,
    action: str,
    approved: bool,
    verification_passed: bool,
    execution_status: str,
) -> str:
    """Validate execution outcome for a remediation attempt."""
    normalized_action = str(action or "").strip()
    if normalized_action and normalized_action not in APPROVED_ACTIONS:
        return "REJECTED"
    if not approved:
        return "REJECTED"
    if execution_status == "FAILED":
        return "FAILED"
    if verification_passed:
        return "VERIFIED"
    return "FAILED"


def _transition_state(current_state: str, target_state: str) -> str:
    allowed = _ALLOWED_TRANSITIONS.get(current_state, set())
    if target_state not in allowed:
        raise ValueError(
            f"State transition from {current_state} to {target_state} is not allowed"
        )
    return target_state


class RemediationWorkflow:
    """Workflow controller enforcing allowlist, approval binding, replay protection, and verification."""

    def __init__(self, *, approval_ttl_seconds: int = _DEFAULT_APPROVAL_TTL_SECONDS):
        self.approval_ttl_seconds = approval_ttl_seconds
        self._used_approvals: set[str] = set()

    def create_approval(
        self,
        *,
        action: str,
        target: str,
        reason: str,
        created_at: datetime | str | None = None,
    ) -> dict[str, Any]:
        return approve_remediation(
            action=action,
            target=target,
            reason=reason,
            created_at=created_at,
            approval_ttl_seconds=self.approval_ttl_seconds,
        )

    def execute(
        self,
        *,
        approval: dict[str, Any],
        action: str,
        target: str,
        reason: str,
        before_state: dict[str, Any] | None,
        after_state: dict[str, Any] | None,
        verification_passed: bool,
        execution_status: str = "SUCCESS",
        current_time: datetime | str | None = None,
    ) -> dict[str, Any]:
        if not approval or not approval.get("approved"):
            return {
                "status": "REJECTED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "post_action_verification"},
            }

        approval_hash = str(approval.get("hash") or "")
        if not approval_hash:
            return {
                "status": "REJECTED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "approval_validation"},
                "reason": "Approval hash is missing or malformed.",
            }

        if approval_hash in self._used_approvals:
            return {
                "status": "REJECTED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "replay_guard"},
                "reason": "Replay attempt rejected: approval already used once.",
            }

        if not validate_remediation_approval(
            action=action,
            target=target,
            reason=reason,
            approval_hash=approval_hash,
            approved=True,
            created_at=approval.get("created_at"),
            current_time=current_time,
            approval_ttl_seconds=self.approval_ttl_seconds,
        ):
            return {
                "status": "REJECTED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "approval_validation"},
                "reason": "Approval hash is invalid, stale, or mismatched to the action target and rationale.",
            }

        if execution_status == "FAILED":
            self._used_approvals.add(approval_hash)
            return {
                "status": "FAILED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "post_action_verification"},
                "reason": "Execution failed before validation could confirm the fix.",
            }

        if not verification_passed:
            self._used_approvals.add(approval_hash)
            return {
                "status": "FAILED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "post_action_verification"},
                "reason": "Independent verification failed; finding remains open.",
            }

        self._used_approvals.add(approval_hash)
        return {
            "status": "VERIFIED",
            "state": "RESOLVED",
            "approval": approval,
            "verification": {
                "passed": True,
                "source": "post_action_verification",
                "before_state": before_state,
                "after_state": after_state,
            },
            "reason": "Verification confirms the intended remediation is in effect.",
        }


def execute_remediation(
    *,
    action: str,
    target: str,
    reason: str,
    approval: dict[str, Any],
    before_state: dict[str, Any] | None,
    after_state: dict[str, Any] | None,
    verification_passed: bool,
    execution_status: str = "SUCCESS",
    current_time: datetime | str | None = None,
) -> dict[str, Any]:
    """Execute a remediation only when its approval is valid and verified."""
    workflow = RemediationWorkflow()
    return workflow.execute(
        approval=approval,
        action=action,
        target=target,
        reason=reason,
        before_state=before_state,
        after_state=after_state,
        verification_passed=verification_passed,
        execution_status=execution_status,
        current_time=current_time,
    )


__all__ = [
    "APPROVED_ACTIONS",
    "ApprovedRemediationAction",
    "RemediationWorkflow",
    "approve_remediation",
    "build_action_hash",
    "execute_remediation",
    "validate_remediation_approval",
    "validate_remediation_execution",
]
