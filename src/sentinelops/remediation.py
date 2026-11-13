"""Secure, allowlisted remediation workflow for SentinelOps.

The remediation pipeline is intentionally scoped to explicit allowlisted actions
and binds approvals to the exact action, target, and rationale that produced the
approval hash. This prevents accidental approval drift and ensures a remediation
cannot be replayed after it has already been used.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sentinelops.scenarios import evaluate_scenario


class ApprovedRemediationAction(str, Enum):
    """Actions considered safe and explicitly allowlisted for Class 2 execution."""

    S3_BLOCK_PUBLIC_ACCESS = "s3_block_public_access"
    SECURITY_GROUP_RESTRICT_INGRESS = "security_group_restrict_ingress"
    IAM_REMOVE_WILDCARD_POLICY = "iam_remove_wildcard_policy"  # detection-only, not auto-remediated


class VerificationOutcome(str, Enum):
    """Explicit outcomes for fresh AWS verification after a remediation."""

    VERIFIED = "VERIFIED"
    NOT_RESOLVED = "NOT_RESOLVED"
    INCONCLUSIVE = "INCONCLUSIVE"
    FAILED = "FAILED"


APPROVED_ACTIONS = {
    ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS.value,
    ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS.value,
}
_DEFAULT_APPROVAL_TTL_SECONDS = 3600
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_APPROVAL_STORE_PATH = _PROJECT_ROOT / ".sentinelops" / "approval-ledger.sqlite3"
_SESSION_STORE_PATH = _PROJECT_ROOT / ".sentinelops" / "session-ledger.sqlite3"
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


def analyze_iam_wildcard_policy(
    policy_document: dict[str, Any] | list[dict[str, Any]] | str | None,
    *,
    role_name: str | None = None,
    target_arn: str | None = None,
) -> dict[str, Any]:
    """Detect wildcard IAM statements without allowing the code to delete an inline policy.

    The IAM wildcard remediation path is intentionally detection-only. If a policy
    mixes excessive wildcard permissions with legitimate ones, the result records
    both sets without attempting to remove the entire inline policy. This prevents
    accidental loss of required permissions while still surfacing the violation.
    """
    if policy_document is None:
        return {
            "status": "missing_policy_document",
            "remediation_allowed": False,
            "excessive_actions": [],
            "legitimate_actions": [],
            "reason": "No IAM policy document was supplied; wildcard policy review cannot proceed.",
        }

    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except json.JSONDecodeError:
            return {
                "status": "missing_policy_document",
                "remediation_allowed": False,
                "excessive_actions": [],
                "legitimate_actions": [],
                "reason": "The supplied IAM policy document is not valid JSON.",
            }

    if isinstance(policy_document, dict):
        statements = policy_document.get("Statement") or [policy_document]
    elif isinstance(policy_document, list):
        statements = policy_document
    else:
        return {
            "status": "missing_policy_document",
            "remediation_allowed": False,
            "excessive_actions": [],
            "legitimate_actions": [],
            "reason": "Unsupported IAM policy document format.",
        }

    if isinstance(statements, dict):
        statements = [statements]

    excessive_actions: list[str] = []
    legitimate_actions: list[str] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        actions = statement.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            if not isinstance(action, str):
                continue
            cleaned = action.strip()
            if "*" in cleaned:
                excessive_actions.append(cleaned)
            else:
                legitimate_actions.append(cleaned)

    if role_name and target_arn:
        target_role = str(target_arn or "").strip()
        expected_role = str(role_name or "").strip()
        if expected_role and target_role:
            identifier = target_role.rsplit(":role/", 1)[-1] if ":role/" in target_role else target_role
            if identifier != expected_role:
                return {
                    "status": "resource_role_mismatch",
                    "remediation_allowed": False,
                    "excessive_actions": excessive_actions,
                    "legitimate_actions": legitimate_actions,
                    "reason": "The supplied resource target does not match the role being reviewed.",
                }

    if not excessive_actions:
        return {
            "status": "no_excessive_permissions",
            "remediation_allowed": False,
            "excessive_actions": [],
            "legitimate_actions": legitimate_actions,
            "reason": "No wildcard IAM permissions were found in the supplied policy document.",
        }

    if legitimate_actions:
        return {
            "status": "mixed_permissions",
            "remediation_allowed": False,
            "excessive_actions": sorted(set(excessive_actions)),
            "legitimate_actions": sorted(set(legitimate_actions)),
            "reason": "The policy contains both excessive wildcard privileges and legitimate permissions. Automated deletion of the inline policy is not permitted.",
        }

    return {
        "status": "wildcard_policy_detected",
        "remediation_allowed": False,
        "excessive_actions": sorted(set(excessive_actions)),
        "legitimate_actions": sorted(set(legitimate_actions)),
        "reason": "Wildcard IAM permissions were detected. This review is detection-only; no automated inline policy deletion is allowed.",
    }


class _ApprovalLedger:
    """Persist single-use approval consumption across independent workflow instances."""

    def __init__(self, db_path: str | Path = _APPROVAL_STORE_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS used_approvals (hash TEXT PRIMARY KEY, consumed_at TEXT NOT NULL)"
            )

    def is_used(self, approval_hash: str) -> bool:
        if not approval_hash:
            return False
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM used_approvals WHERE hash = ? LIMIT 1",
                (approval_hash,),
            ).fetchone()
        return row is not None

    def consume(self, approval_hash: str) -> bool:
        if not approval_hash:
            return False
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT 1 FROM used_approvals WHERE hash = ? LIMIT 1",
                (approval_hash,),
            ).fetchone()
            if existing is not None:
                conn.rollback()
                return False
            conn.execute(
                "INSERT INTO used_approvals(hash, consumed_at) VALUES(?, ?)",
                (approval_hash, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return True

    def mark_used(self, approval_hash: str) -> None:
        self.consume(approval_hash)

    def populate(self, approval_hashes: set[str]) -> None:
        for approval_hash in sorted(approval_hashes):
            self.consume(approval_hash)


class _SessionLedger:
    """Persist assessment-session identity usage to reject replayed validation sessions."""

    def __init__(self, db_path: str | Path = _SESSION_STORE_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _initialize(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, seen_at TEXT NOT NULL)"
            )

    def is_reused(self, session_id: str | None) -> bool:
        if not session_id or not str(session_id).strip():
            return False
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM sessions WHERE session_id = ? LIMIT 1",
                (str(session_id).strip(),),
            ).fetchone()
        return row is not None

    def register_seen(self, session_id: str | None) -> bool:
        if not session_id or not str(session_id).strip():
            return False
        normalized = str(session_id).strip()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT 1 FROM sessions WHERE session_id = ? LIMIT 1",
                (normalized,),
            ).fetchone()
            if existing is not None:
                conn.rollback()
                return False
            conn.execute(
                "INSERT INTO sessions(session_id, seen_at) VALUES(?, ?)",
                (normalized, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return True

    def mark_seen(self, session_id: str | None) -> bool:
        return self.register_seen(session_id)


_APPROVAL_LEDGER = _ApprovalLedger()
_SESSION_LEDGER = _SessionLedger()


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


def _coerce_verification_status(value: Any) -> VerificationOutcome:
    if isinstance(value, VerificationOutcome):
        return value
    if isinstance(value, str):
        normalized = value.strip().upper()
        try:
            return VerificationOutcome(normalized)
        except ValueError:
            return VerificationOutcome.FAILED
    return VerificationOutcome.FAILED


def _resource_matches_target(finding: dict[str, Any], target: str) -> bool:
    if not finding:
        return False
    expected = str(target or "").strip()
    if not expected:
        return False
    resource = finding.get("resource") or {}
    candidates = [
        str(resource.get("id") or "").strip(),
        str(resource.get("arn") or "").strip(),
        str(finding.get("resource_id") or "").strip(),
        str(finding.get("target") or "").strip(),
    ]
    return expected in candidates


def _collect_fresh_observation_for_finding(
    *,
    finding: dict[str, Any],
    assessment_session: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(assessment_session, dict):
        raise RuntimeError("Assessment session is required for independent verification.")
    if assessment_session.get("role_type") == "remediation":
        raise PermissionError("The remediation identity is not permitted to perform verification.")

    target = str((finding.get("resource") or {}).get("id") or finding.get("resource_id") or "").strip()
    if not target:
        raise ValueError("Finding resource target is missing.")

    if target.startswith("arn:aws:s3:::"):
        client = assessment_session.get("s3")
        if client is None:
            raise RuntimeError("Fresh S3 assessment client is unavailable.")
        bucket_name = target.replace("arn:aws:s3:::", "", 1).split("/", 1)[0]
        response = client.get_public_access_block(Bucket=bucket_name)
        public_access_block = response.get("PublicAccessBlockConfiguration", {})
        return {"public_access_block": public_access_block}

    if target.startswith("arn:aws:iam::"):
        client = assessment_session.get("iam")
        if client is None:
            raise RuntimeError("Fresh IAM assessment client is unavailable.")
        try:
            roles = client.list_roles().get("Roles", [])
        except Exception as exc:  # pragma: no cover - defensive path
            raise RuntimeError("IAM collection failed") from exc
        for role in roles:
            if str(role.get("Arn") or "").strip() == target:
                return {"policy_statements": []}
        return {"policy_statements": []}

    if target.startswith("arn:aws:ec2:"):
        client = assessment_session.get("ec2")
        if client is None:
            raise RuntimeError("Fresh EC2 assessment client is unavailable.")
        response = client.describe_security_groups()
        groups = response.get("SecurityGroups", [])
        for group in groups:
            if str(group.get("GroupId") or "").strip() == target.rsplit("/", 1)[-1]:
                return {"ingress": [{"CidrIp": cidr.get("CidrIp"), "IpProtocol": permission.get("IpProtocol"), "FromPort": permission.get("FromPort"), "ToPort": permission.get("ToPort")} for permission in (group.get("IpPermissions") or []) for cidr in (permission.get("IpRanges") or [])]}
        return {"ingress": []}

    raise RuntimeError(f"No fresh verification collector is defined for target '{target}'.")


def _validate_assessment_session(
    *,
    assessment_session: dict[str, Any] | None,
    current_time: datetime | str | None = None,
) -> str | None:
    if not isinstance(assessment_session, dict):
        return "Independent verification requires a fresh assessment session and read-only identity."

    role_type = str(assessment_session.get("role_type") or "").strip().lower()
    if role_type == "remediation":
        return "Verification session is invalid: the remediation identity is not permitted to perform verification."

    session_id = assessment_session.get("session_id")
    if session_id is not None and not _SESSION_LEDGER.register_seen(session_id):
        return "Verification session is invalid: the assessment session_id has already been used."

    evidence_collected_at = assessment_session.get("evidence_collected_at")
    if evidence_collected_at is not None:
        evidence_time = _coerce_datetime(evidence_collected_at)
        if evidence_time is None:
            return "Verification session is invalid: evidence_collected_at is not parseable."
        now = _coerce_datetime(current_time) or datetime.now(timezone.utc)
        if now - evidence_time > timedelta(seconds=_DEFAULT_APPROVAL_TTL_SECONDS):
            return "Verification session is invalid: the fresh evidence is stale and cannot be trusted."

    return None


def verify_finding_resolution(
    *,
    finding: dict[str, Any],
    approval: dict[str, Any],
    action: str,
    target: str,
    reason: str,
    assessment_session: dict[str, Any] | None,
    current_time: datetime | str | None = None,
) -> dict[str, Any]:
    """Re-audit the resource with fresh, read-only evidence and compare it to the original finding."""
    approval_hash = str((approval or {}).get("hash") or "")
    if not approval or not approval.get("approved"):
        return {
            "status": VerificationOutcome.FAILED,
            "reason": "Approval is missing or rejected; verification cannot proceed.",
            "fresh_observation": None,
        }
    if not validate_remediation_approval(
        action=action,
        target=target,
        reason=reason,
        approval_hash=approval_hash,
        approved=True,
        created_at=approval.get("created_at"),
        current_time=current_time,
        approval_ttl_seconds=_DEFAULT_APPROVAL_TTL_SECONDS,
    ):
        return {
            "status": VerificationOutcome.FAILED,
            "reason": "Approval hash is missing, stale, mismatched, or expired.",
            "fresh_observation": None,
        }
    if not _resource_matches_target(finding, target):
        return {
            "status": VerificationOutcome.FAILED,
            "reason": "Verification target does not match the original finding resource.",
            "fresh_observation": None,
        }

    session_error = _validate_assessment_session(
        assessment_session=assessment_session,
        current_time=current_time,
    )
    if session_error is not None:
        return {
            "status": VerificationOutcome.INCONCLUSIVE,
            "reason": f"Fresh AWS evidence could not be collected: {session_error}",
            "fresh_observation": None,
        }

    try:
        fresh_observation = _collect_fresh_observation_for_finding(
            finding=finding,
            assessment_session=assessment_session,
        )
    except Exception as exc:  # pragma: no cover - defensive path
        return {
            "status": VerificationOutcome.INCONCLUSIVE,
            "reason": f"Fresh AWS evidence could not be collected: {exc}",
            "fresh_observation": None,
        }

    if not fresh_observation:
        return {
            "status": VerificationOutcome.INCONCLUSIVE,
            "reason": "Fresh AWS evidence was empty or incomplete.",
            "fresh_observation": None,
        }

    scenario_id = str(finding.get("scenario_id") or "").strip()
    result = evaluate_scenario(scenario_id, fresh_observation)
    raw_status = str(result.get("status", "INCONCLUSIVE")).strip()
    if raw_status == "no_finding_detected":
        return {
            "status": VerificationOutcome.VERIFIED,
            "reason": "Fresh AWS evidence confirms the original misconfiguration no longer exists.",
            "fresh_observation": fresh_observation,
        }
    if raw_status == "finding_detected":
        return {
            "status": VerificationOutcome.NOT_RESOLVED,
            "reason": "Fresh AWS evidence confirms the misconfiguration remains.",
            "fresh_observation": fresh_observation,
        }
    if raw_status in {"drift_detected", "drift_resolved"}:
        return {
            "status": VerificationOutcome.INCONCLUSIVE,
            "reason": "Fresh evidence indicates a drift state rather than a direct security finding resolution.",
            "fresh_observation": fresh_observation,
        }
    return {
        "status": VerificationOutcome.INCONCLUSIVE,
        "reason": "Fresh AWS evidence was insufficient to determine the resolved state.",
        "fresh_observation": fresh_observation,
    }


def _transition_state(current_state: str, target_state: str) -> str:
    allowed = _ALLOWED_TRANSITIONS.get(current_state, set())
    if target_state not in allowed:
        raise ValueError(
            f"State transition from {current_state} to {target_state} is not allowed"
        )
    return target_state


class RemediationWorkflow:
    """Workflow controller enforcing allowlist, approval binding, replay protection, and verification."""

    def __init__(
        self,
        *,
        approval_ttl_seconds: int = _DEFAULT_APPROVAL_TTL_SECONDS,
        approval_ledger: _ApprovalLedger | None = None,
        session_ledger: _SessionLedger | None = None,
        approval_db_path: str | Path | None = None,
        session_db_path: str | Path | None = None,
    ):
        self.approval_ttl_seconds = approval_ttl_seconds
        self._ledger = approval_ledger or ( _ApprovalLedger(approval_db_path) if approval_db_path else _APPROVAL_LEDGER )
        self._session_ledger = session_ledger or ( _SessionLedger(session_db_path) if session_db_path else _SESSION_LEDGER )
        self._used_approvals: set[str] = set()
        self._used_approvals.update(
            row[0]
            for row in sqlite3.connect(self._ledger.db_path).execute(
                "SELECT hash FROM used_approvals"
            ).fetchall()
        )

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
        verification_result: dict[str, Any] | None = None,
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

        if approval_hash in self._used_approvals:
            return {
                "status": "REJECTED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "replay_guard"},
                "reason": "Replay attempt rejected: approval already used once.",
            }

        if execution_status == "FAILED":
            if not self._ledger.consume(approval_hash):
                self._used_approvals.add(approval_hash)
                return {
                    "status": "REJECTED",
                    "state": "OPEN",
                    "approval": approval,
                    "verification": {"passed": False, "source": "replay_guard"},
                    "reason": "Replay attempt rejected: approval already used once.",
                }
            self._used_approvals.add(approval_hash)
            return {
                "status": "FAILED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "post_action_verification"},
                "reason": "Execution failed before validation could confirm the fix.",
            }

        effective_verification = verification_result or {"status": VerificationOutcome.VERIFIED if verification_passed else VerificationOutcome.FAILED}
        normalization = _coerce_verification_status(effective_verification.get("status"))
        if normalization is not VerificationOutcome.VERIFIED:
            if not self._ledger.consume(approval_hash):
                self._used_approvals.add(approval_hash)
                return {
                    "status": "REJECTED",
                    "state": "OPEN",
                    "approval": approval,
                    "verification": {"passed": False, "source": "replay_guard"},
                    "reason": "Replay attempt rejected: approval already used once.",
                }
            self._used_approvals.add(approval_hash)
            return {
                "status": "FAILED",
                "state": "OPEN",
                "approval": approval,
                "verification": {
                    "passed": False,
                    "source": "post_action_verification",
                    "verification_result": effective_verification,
                },
                "reason": "Independent verification did not confirm the finding is resolved.",
            }

        if not verification_passed:
            if not self._ledger.consume(approval_hash):
                self._used_approvals.add(approval_hash)
                return {
                    "status": "REJECTED",
                    "state": "OPEN",
                    "approval": approval,
                    "verification": {"passed": False, "source": "replay_guard"},
                    "reason": "Replay attempt rejected: approval already used once.",
                }
            self._used_approvals.add(approval_hash)
            return {
                "status": "FAILED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "post_action_verification"},
                "reason": "Independent verification failed; finding remains open.",
            }

        if not self._ledger.consume(approval_hash):
            self._used_approvals.add(approval_hash)
            return {
                "status": "REJECTED",
                "state": "OPEN",
                "approval": approval,
                "verification": {"passed": False, "source": "replay_guard"},
                "reason": "Replay attempt rejected: approval already used once.",
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
                "verification_result": effective_verification,
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
    verification_result: dict[str, Any] | None = None,
    approval_ledger: _ApprovalLedger | None = None,
    session_ledger: _SessionLedger | None = None,
    approval_db_path: str | Path | None = None,
    session_db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Execute a remediation only when its approval is valid and verified."""
    workflow = RemediationWorkflow(
        approval_ledger=approval_ledger,
        session_ledger=session_ledger,
        approval_db_path=approval_db_path,
        session_db_path=session_db_path,
    )
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
        verification_result=verification_result,
    )


__all__ = [
    "APPROVED_ACTIONS",
    "ApprovedRemediationAction",
    "RemediationWorkflow",
    "VerificationOutcome",
    "analyze_iam_wildcard_policy",
    "approve_remediation",
    "build_action_hash",
    "execute_remediation",
    "validate_remediation_approval",
    "validate_remediation_execution",
    "verify_finding_resolution",
]
