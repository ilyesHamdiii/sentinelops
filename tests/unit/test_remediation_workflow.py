import pytest

from sentinelops.remediation import analyze_iam_wildcard_policy
from sentinelops.validation.remediation import (
    APPROVED_ACTIONS,
    build_action_hash,
    validate_remediation_approval,
    validate_remediation_execution,
)


def test_allowlisted_actions_cover_safely_scoped_changes():
    assert "s3_block_public_access" in APPROVED_ACTIONS
    assert "security_group_restrict_ingress" in APPROVED_ACTIONS
    assert "iam_remove_wildcard_policy" not in APPROVED_ACTIONS
    assert "delete_resource" not in APPROVED_ACTIONS


def test_iam_wildcard_policy_detection_is_detection_only():
    mixed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "iam:*"],
                "Resource": "arn:aws:s3:::example-bucket/*",
            }
        ],
    }
    result = analyze_iam_wildcard_policy(mixed_policy, role_name="example-role")
    assert result["status"] == "mixed_permissions"
    assert result["remediation_allowed"] is False
    assert "iam:*" in result["excessive_actions"]

    with pytest.raises(ValueError):
        import sentinelops.remediation as remediation

        remediation.approve_remediation(
            action="iam_remove_wildcard_policy",
            target="arn:aws:iam::123456789012:role/example-role",
            reason="This path is detection-only and not auto-remediated.",
        )


def test_iam_wildcard_policy_analysis_handles_excessive_only_and_missing_documents():
    excessive = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    result = analyze_iam_wildcard_policy(excessive, role_name="example-role")
    assert result["status"] == "wildcard_policy_detected"
    assert result["remediation_allowed"] is False

    missing = analyze_iam_wildcard_policy(None, role_name="example-role")
    assert missing["status"] == "missing_policy_document"

    mismatch = analyze_iam_wildcard_policy(
        {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]},
        role_name="different-role",
        target_arn="arn:aws:iam::123456789012:role/example-role",
    )
    assert mismatch["status"] == "resource_role_mismatch"


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
