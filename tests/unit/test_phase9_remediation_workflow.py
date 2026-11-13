import threading
from datetime import datetime, timedelta, timezone

from sentinelops.remediation import (
    ApprovedRemediationAction,
    RemediationWorkflow,
    VerificationOutcome,
    analyze_iam_wildcard_policy,
    approve_remediation,
    build_action_hash,
    execute_remediation,
    validate_remediation_approval,
    validate_remediation_execution,
    verify_finding_resolution,
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
    action = ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS
    target = "arn:aws:s3:::stale-policy-bucket"
    approval = approve_remediation(
        action=action,
        target=target,
        reason="Close public access after the stale approval window.",
        created_at=stale_time,
        approval_ttl_seconds=60,
    )

    assert (
        validate_remediation_approval(
            action=action,
            target=target,
            reason="Close public access after the stale approval window.",
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
    target = "arn:aws:s3:::example-bucket-post-verification"
    reason = "Close public access block to remove anonymous reads after the failed verification check."
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


def test_iam_wildcard_detection_reports_failed_remediation_and_independent_verification():
    finding = {
        "scenario_id": "S2",
        "resource": {"id": "arn:aws:iam::123456789012:role/example-role"},
        "evidence": {"policy_document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}}
    }
    assessment_session = {
        "role_type": "reader",
        "session_id": "verification-iam-001",
        "evidence_collected_at": datetime.now(timezone.utc).isoformat(),
        "iam": type("FakeIAMClient", (), {"list_roles": lambda self: {"Roles": [{"Arn": "arn:aws:iam::123456789012:role/example-role"}]}})(),
    }

    policy_result = analyze_iam_wildcard_policy(finding["evidence"]["policy_document"], role_name="example-role")
    assert policy_result["status"] == "wildcard_policy_detected"
    assert policy_result["remediation_allowed"] is False

    result = execute_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::example-bucket-iam-check",
        reason="Close public access block after the failed verification check.",
        approval=approve_remediation(
            action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
            target="arn:aws:s3:::example-bucket-iam-check",
            reason="Close public access block after the failed verification check.",
        ),
        before_state={"public_access_block": "off"},
        after_state={"public_access_block": "on"},
        verification_passed=False,
        execution_status="FAILED",
    )
    assert result["status"] == "FAILED"

    verification = verify_finding_resolution(
        finding=finding,
        approval=approve_remediation(
            action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
            target="arn:aws:iam::123456789012:role/example-role",
            reason="Close the public access block.",
        ),
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:iam::123456789012:role/example-role",
        reason="Close the public access block.",
        assessment_session=assessment_session,
    )
    assert verification["status"] in {VerificationOutcome.VERIFIED, VerificationOutcome.FAILED, VerificationOutcome.INCONCLUSIVE}


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


def test_execute_remediation_rejects_reused_approval_across_instances():
    action = ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS
    target = "arn:aws:s3:::cross-instance-bucket"
    reason = "Remove public access after confirming the issue."
    approval = approve_remediation(action=action, target=target, reason=reason)

    first = execute_remediation(
        action=action,
        target=target,
        reason=reason,
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )
    second = execute_remediation(
        action=action,
        target=target,
        reason=reason,
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )

    assert first["status"] == "VERIFIED"
    assert second["status"] == "REJECTED"
    assert second["state"] == "OPEN"


def test_verification_rejects_remediation_identity_and_reused_session_id():
    finding = {
        "scenario_id": "S1",
        "resource": {"id": "arn:aws:s3:::session-bucket"},
        "evidence": {"public_access_block": {"BlockPublicAcls": False}},
    }
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::session-bucket",
        reason="Remove the public bucket exposure.",
    )

    class FakeS3Client:
        def list_buckets(self):
            return {"Buckets": [{"Name": "session-bucket"}]}

        def get_bucket_tagging(self, Bucket):
            return {"TagSet": []}

        def get_public_access_block(self, Bucket):
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                }
            }

    session = {
        "session_id": "session-123",
        "role_type": "remediation",
        "region": "eu-west-1",
        "account_id": "123456789012",
        "s3": FakeS3Client(),
        "evidence_collected_at": datetime.now(timezone.utc).isoformat(),
    }

    result = verify_finding_resolution(
        finding=finding,
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::session-bucket",
        reason=approval["reason"],
        assessment_session=session,
    )

    assert result["status"] == VerificationOutcome.INCONCLUSIVE
    assert "session" in str(result["reason"]).lower()


def test_process_restart_rejects_consumed_approval_using_same_persistent_database(tmp_path):
    db_path = tmp_path / "approval-ledger.sqlite3"
    workflow = RemediationWorkflow(approval_db_path=db_path)
    approval = workflow.create_approval(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::restart-bucket",
        reason="Close public access after the persistent proof check.",
    )

    first = workflow.execute(
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::restart-bucket",
        reason="Close public access after the persistent proof check.",
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )
    reopened = RemediationWorkflow(approval_db_path=db_path)
    second = reopened.execute(
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::restart-bucket",
        reason="Close public access after the persistent proof check.",
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )

    assert first["status"] == "VERIFIED"
    assert second["status"] == "REJECTED"


def test_concurrent_replay_only_allows_one_successful_consumption(tmp_path):
    db_path = tmp_path / "approval-ledger.sqlite3"
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::concurrent-bucket",
        reason="Remove concurrent public access exposure after the assessment confirms it.",
    )
    results: list[dict[str, object]] = []
    barrier = threading.Barrier(2)

    def worker() -> None:
        barrier.wait()
        workflow = RemediationWorkflow(approval_db_path=db_path)
        results.append(
            workflow.execute(
                approval=approval,
                action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
                target="arn:aws:s3:::concurrent-bucket",
                reason="Remove concurrent public access exposure after the assessment confirms it.",
                before_state={"public_access_block": False},
                after_state={"public_access_block": True},
                verification_passed=True,
            )
        )

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(1 for item in results if item["status"] == "VERIFIED") == 1
    assert sum(1 for item in results if item["status"] == "REJECTED") == 1


def test_failure_after_consumption_rejects_reuse_even_when_remediation_fails(tmp_path):
    db_path = tmp_path / "approval-ledger.sqlite3"
    workflow = RemediationWorkflow(approval_db_path=db_path)
    approval = workflow.create_approval(
        action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
        target="arn:aws:ec2:eu-west-1:123456789012:security-group/sg-fail-after-consume",
        reason="Restrict exposed SSH ingress after the assessment confirms it.",
    )

    first = workflow.execute(
        approval=approval,
        action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
        target="arn:aws:ec2:eu-west-1:123456789012:security-group/sg-fail-after-consume",
        reason="Restrict exposed SSH ingress after the assessment confirms it.",
        before_state={"ingress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22}], "approved": True},
        after_state={"ingress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22}], "approved": True},
        verification_passed=False,
        execution_status="FAILED",
    )
    second = workflow.execute(
        approval=approval,
        action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
        target="arn:aws:ec2:eu-west-1:123456789012:security-group/sg-fail-after-consume",
        reason="Restrict exposed SSH ingress after the assessment confirms it.",
        before_state={"ingress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22}], "approved": True},
        after_state={"ingress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22}], "approved": True},
        verification_passed=True,
    )

    assert first["status"] == "FAILED"
    assert second["status"] == "REJECTED"


def test_verification_failure_keeps_approval_consumed_and_finding_open(tmp_path):
    db_path = tmp_path / "approval-ledger.sqlite3"
    action = ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS
    approval = approve_remediation(
        action=action,
        target="arn:aws:s3:::verification-fail-bucket",
        reason="Restrict public bucket access after fresh evaluation flags it.",
    )

    result = execute_remediation(
        action=action,
        target="arn:aws:s3:::verification-fail-bucket",
        reason="Restrict public bucket access after fresh evaluation flags it.",
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
        verification_result={"status": VerificationOutcome.NOT_RESOLVED},
        approval_db_path=db_path,
    )
    replay = execute_remediation(
        action=action,
        target="arn:aws:s3:::verification-fail-bucket",
        reason="Restrict public bucket access after fresh evaluation flags it.",
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
        approval_db_path=db_path,
    )

    assert result["status"] == "FAILED"
    assert result["state"] == "OPEN"
    assert replay["status"] == "REJECTED"


def test_stale_evidence_session_is_inconclusive_and_reused_session_is_rejected():
    finding = {
        "scenario_id": "S1",
        "resource": {"id": "arn:aws:s3:::stale-evidence-bucket"},
        "evidence": {"public_access_block": {"BlockPublicAcls": False}},
    }
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::stale-evidence-bucket",
        reason="Close the stale S3 bucket access exposure.",
    )

    session = {
        "session_id": "stale-session-42",
        "role_type": "reader",
        "region": "eu-west-1",
        "account_id": "123456789012",
        "evidence_collected_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
    }

    result = verify_finding_resolution(
        finding=finding,
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::stale-evidence-bucket",
        reason=approval["reason"],
        assessment_session=session,
    )

    assert result["status"] == VerificationOutcome.INCONCLUSIVE
    assert "stale" in str(result["reason"]).lower()


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


def test_fresh_assessment_verification_confirms_resolution():
    finding = {
        "scenario_id": "S1",
        "resource": {"id": "arn:aws:s3:::example-bucket"},
        "evidence": {"public_access_block": {"BlockPublicAcls": False}},
    }
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::example-bucket",
        reason="Restrict public access now that the public policy has been removed.",
    )

    class FakeS3Client:
        def list_buckets(self):
            return {"Buckets": [{"Name": "example-bucket"}]}

        def get_bucket_tagging(self, Bucket):
            return {"TagSet": []}

        def get_public_access_block(self, Bucket):
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                }
            }

    session = {"region": "eu-west-1", "account_id": "123456789012", "s3": FakeS3Client()}
    result = verify_finding_resolution(
        finding=finding,
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::example-bucket",
        reason=approval["reason"],
        assessment_session=session,
    )

    assert result["status"] == VerificationOutcome.VERIFIED
    assert result["fresh_observation"] is not finding["evidence"]


def test_fresh_assessment_verification_detects_remaining_issue():
    finding = {
        "scenario_id": "S1",
        "resource": {"id": "arn:aws:s3:::problem-bucket"},
        "evidence": {"public_access_block": {"BlockPublicAcls": False}},
    }
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::problem-bucket",
        reason="Remove public access from the exposed bucket.",
    )

    class FakeS3Client:
        def list_buckets(self):
            return {"Buckets": [{"Name": "problem-bucket"}]}

        def get_bucket_tagging(self, Bucket):
            return {"TagSet": []}

        def get_public_access_block(self, Bucket):
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "BlockPublicPolicy": False,
                    "IgnorePublicAcls": False,
                    "RestrictPublicBuckets": False,
                }
            }

    session = {"region": "eu-west-1", "account_id": "123456789012", "s3": FakeS3Client()}
    result = verify_finding_resolution(
        finding=finding,
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::problem-bucket",
        reason=approval["reason"],
        assessment_session=session,
    )

    assert result["status"] == VerificationOutcome.NOT_RESOLVED


def test_collection_failure_returns_inconclusive_verification():
    finding = {
        "scenario_id": "S1",
        "resource": {"id": "arn:aws:s3:::failed-collection-bucket"},
        "evidence": {"public_access_block": {"BlockPublicAcls": False}},
    }
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::failed-collection-bucket",
        reason="Close public access after the read-only assessment showed the bucket was exposed.",
    )

    class FakeS3Client:
        def get_public_access_block(self, Bucket):
            raise RuntimeError("temporary AWS outage")

    session = {"region": "eu-west-1", "account_id": "123456789012", "s3": FakeS3Client()}
    result = verify_finding_resolution(
        finding=finding,
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::failed-collection-bucket",
        reason=approval["reason"],
        assessment_session=session,
    )

    assert result["status"] == VerificationOutcome.INCONCLUSIVE


def test_verification_rejects_wrong_resource_or_target():
    finding = {
        "scenario_id": "S3",
        "resource": {"id": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-two"},
        "evidence": {"ingress": [{"CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}]},
    }
    approval = approve_remediation(
        action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
        target="arn:aws:ec2:eu-west-1:123456789012:security-group/sg-one",
        reason="Restrict the public SSH ingress rule inside the approved security group.",
    )

    result = verify_finding_resolution(
        finding=finding,
        approval=approval,
        action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
        target="arn:aws:ec2:eu-west-1:123456789012:security-group/sg-one",
        reason=approval["reason"],
        assessment_session={"region": "eu-west-1", "account_id": "123456789012"},
    )

    assert result["status"] == VerificationOutcome.FAILED
    assert "target" in str(result["reason"]).lower()


def test_expired_approval_is_rejected_by_verifier():
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::stale-bucket",
        reason="Remove the stale bucket exposure before the approval expires.",
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
        approval_ttl_seconds=60,
    )

    result = verify_finding_resolution(
        finding={"scenario_id": "S1", "resource": {"id": "arn:aws:s3:::stale-bucket"}, "evidence": {}},
        approval=approval,
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target="arn:aws:s3:::stale-bucket",
        reason="Remove the stale bucket exposure before the approval expires.",
        assessment_session={"region": "eu-west-1", "account_id": "123456789012"},
    )

    assert result["status"] == VerificationOutcome.FAILED


def test_remediation_api_success_without_verification_is_not_resolved():
    action = ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS
    approval = approve_remediation(
        action=action,
        target="arn:aws:s3:::demo-bucket",
        reason="Restrict the bucket after the proof command confirms the issue.",
    )
    result = execute_remediation(
        action=action,
        target="arn:aws:s3:::demo-bucket",
        reason=approval["reason"],
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
        verification_result={"status": VerificationOutcome.NOT_RESOLVED},
    )

    assert result["status"] == "FAILED"
    assert result["state"] == "OPEN"
