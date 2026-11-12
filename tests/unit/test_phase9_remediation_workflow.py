from datetime import datetime, timedelta, timezone

from sentinelops.remediation import (
    ApprovedRemediationAction,
    RemediationWorkflow,
    approve_remediation,
    build_action_hash,
    execute_remediation,
    validate_remediation_approval,
    validate_remediation_execution,
)


def test_allowlisted_execution_succeeds_with_exact_hash_and_verification():
    action = ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS
    target = "arn:aws:s3:::example-bucket"
    reason = "Close public access block to remove anonymous reads."
    approval = approve_remediation(action=action, target=target, reason=reason)

    result = execute_remediation(
        action=action,
        target=target,
        reason=reason,
        approval=approval,
        before_state={"public_access_block": "off"},
        after_state={"public_access_block": "on"},
        verification_passed=True,
    )

    assert result["status"] == "VERIFIED"
    assert result["approval"]["hash"] == approval["hash"]
    assert result["verification"]["passed"] is True
    assert result["state"] == "RESOLVED"


def test_approval_hash_mismatch_is_rejected():
    approval = approve_remediation(
        action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
        target="sg-123456",
        reason="Restrict inbound 0.0.0.0/0 access.",
    )

    assert (
        validate_remediation_approval(
            action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
            target="sg-123456",
            reason="Restrict inbound 0.0.0.0/0 access.",
            approval_hash="bad-hash",
            approved=True,
        )
        is False
    )
    assert (
        validate_remediation_approval(
            action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
            target="sg-123456",
            reason="Restrict inbound 0.0.0.0/0 access.",
            approval_hash=approval["hash"],
            approved=False,
        )
        is False
    )


def test_stale_approval_is_rejected():
    stale_time = datetime.now(timezone.utc) - timedelta(hours=2)
    approval = approve_remediation(
        action=ApprovedRemediationAction.IAM_REMOVE_WILDCARD_POLICY,
        target="arn:aws:iam::123456789012:policy/example-policy",
        reason="Remove wildcard access from the test policy.",
        created_at=stale_time,
        approval_ttl_seconds=60,
    )

    assert (
        validate_remediation_approval(
            action=ApprovedRemediationAction.IAM_REMOVE_WILDCARD_POLICY,
            target="arn:aws:iam::123456789012:policy/example-policy",
            reason="Remove wildcard access from the test policy.",
            approval_hash=approval["hash"],
            approved=True,
            created_at=approval["created_at"],
            current_time=datetime.now(timezone.utc),
            approval_ttl_seconds=60,
        )
        is False
    )


def test_post_verification_failure_prevents_marking_finding_resolved():
    action = ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS
    target = "arn:aws:s3:::example-bucket"
    reason = "Close public access block to remove anonymous reads."
    approval = approve_remediation(action=action, target=target, reason=reason)

    result = execute_remediation(
        action=action,
        target=target,
        reason=reason,
        approval=approval,
        before_state={"public_access_block": "off"},
        after_state={"public_access_block": "off"},
        verification_passed=False,
    )

    assert result["status"] == "FAILED"
    assert result["state"] == "OPEN"
    assert result["verification"]["passed"] is False


def test_workflow_rejects_replay_when_same_action_is_approved_twice():
    workflow = RemediationWorkflow()
    approval = workflow.create_approval(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::replay-bucket",
        reason="Remove public access.",
    )

    first = workflow.execute(
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::replay-bucket",
        reason="Remove public access.",
        before_state={"public_access_block": "on"},
        after_state={"public_access_block": "on"},
        verification_passed=True,
    )
    second = workflow.execute(
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::replay-bucket",
        reason="Remove public access.",
        before_state={"public_access_block": "on"},
        after_state={"public_access_block": "on"},
        verification_passed=True,
    )

    assert first["status"] == "VERIFIED"
    assert second["status"] == "REJECTED"
    assert second["state"] == "OPEN"


def test_hash_binding_uses_action_target_and_reason_exactly():
    approval_a = approve_remediation(
        action="s3_block_public_access",
        target="arn:aws:s3:::a",
        reason="Close public access.",
    )
    approval_b = approve_remediation(
        action="s3_block_public_access",
        target="arn:aws:s3:::a",
        reason="Close public access.",
    )

    assert approval_a["hash"] == approval_b["hash"]
    assert build_action_hash("s3_block_public_access", "arn:aws:s3:::a", "Close public access.") == approval_a["hash"]
    assert validate_remediation_execution(
        action="s3_block_public_access",
        approved=True,
        verification_passed=True,
        execution_status="SUCCESS",
    ) == "VERIFIED"
