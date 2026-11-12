from sentinelops.validation.remediation import (
    APPROVED_ACTIONS,
    build_action_hash,
    validate_remediation_approval,
    validate_remediation_execution,
)


def test_allowlisted_actions_cover_safely_scoped_changes():
    assert "s3_block_public_access" in APPROVED_ACTIONS
    assert "security_group_restrict_ingress" in APPROVED_ACTIONS
    assert "iam_remove_wildcard_policy" in APPROVED_ACTIONS
    assert "delete_resource" not in APPROVED_ACTIONS


def test_approval_hash_must_match_for_executing_class_2_change():
    action = "s3_block_public_access"
    target = "arn:aws:s3:::example-bucket"
    reason = "close public access block"
    expected_hash = build_action_hash(action, target, reason)

    assert validate_remediation_approval(action, target, reason, expected_hash, True) is True
    assert validate_remediation_approval(action, target, reason, "bad-hash", True) is False
    assert validate_remediation_approval(action, target, reason, expected_hash, False) is False


def test_execution_validation_requires_approval_and_post_check():
    approved = validate_remediation_execution(
        action="security_group_restrict_ingress",
        approved=True,
        verification_passed=True,
        execution_status="SUCCESS",
    )
    rejected = validate_remediation_execution(
        action="security_group_restrict_ingress",
        approved=False,
        verification_passed=True,
        execution_status="SUCCESS",
    )
    failed = validate_remediation_execution(
        action="security_group_restrict_ingress",
        approved=True,
        verification_passed=False,
        execution_status="FAILED",
    )

    assert approved == "VERIFIED"
    assert rejected == "REJECTED"
    assert failed == "FAILED"
