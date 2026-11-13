"""Verify the real Terraform IAM and OIDC trust definitions used by SentinelOps."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
TERRAFORM_FILE = ROOT / "infra" / "terraform" / "baseline.tf"
WORKFLOW_FILE = ROOT / ".github" / "workflows" / "deploy-oidc.yml"

BANNED_WRITE_ACTIONS = (
    "iam:AttachRolePolicy",
    "iam:CreatePolicy",
    "iam:CreatePolicyVersion",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "s3:DeleteObject",
    "s3:PutObject",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:RevokeSecurityGroupIngress",
)


def _extract_hcl_block(block_type: str, block_name: str) -> str:
    text = TERRAFORM_FILE.read_text(encoding="utf-8")
    start_marker = f'{block_type} "{block_name}" {{'
    start = text.index(start_marker)
    cursor = start + len(start_marker)
    depth = 1
    chars: list[str] = []

    while cursor < len(text) and depth > 0:
        ch = text[cursor]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
        if depth > 0:
            chars.append(ch)
        cursor += 1

    return "".join(chars)


def _contains_any(text: str, values: tuple[str, ...]) -> bool:
    return any(value in text for value in values)


def test_assessment_policy_in_terraform_is_read_only() -> None:
    block = _extract_hcl_block('data "aws_iam_policy_document"', "assessment_policy")
    assert "s3:GetObject" in block
    assert "cloudtrail:DescribeTrails" in block
    assert "iam:ListRoles" in block
    assert "sts:GetCallerIdentity" in block
    assert not _contains_any(block, ("s3:PutObject", "s3:DeleteObject", "iam:PutRolePolicy", "iam:AttachRolePolicy", "sts:AssumeRole"))
    assert not _contains_any(block, ("iam:*", "s3:*", "ec2:*", "logs:*"))


def test_remediation_policy_in_terraform_is_scoped() -> None:
    block = _extract_hcl_block('data "aws_iam_policy_document"', "remediation_policy")
    assert "s3:PutPublicAccessBlock" in block
    assert "ec2:AuthorizeSecurityGroupIngress" in block
    assert "ec2:RevokeSecurityGroupIngress" in block
    assert "iam:GetRolePolicy" in block
    assert "iam:ListRolePolicies" in block
    assert "iam:DeleteRolePolicy" not in block
    assert 'effect = "Deny"' in block
    assert "iam:AttachRolePolicy" in block
    assert "iam:PutRolePolicy" in block
    assert "sts:AssumeRole" in block
    assert "arn:aws:iam::${local.account_id}:role/sentinelops-*" in block
    assert not _contains_any(block, ("iam:*", "s3:*", "ec2:*", "logs:*"))


def test_bootstrap_is_separate_and_write_scoped() -> None:
    block = _extract_hcl_block('data "aws_iam_policy_document"', "bootstrap_policy")
    assert "cloudtrail:CreateTrail" in block
    assert "s3:PutObject" in block
    assert "logs:CreateLogGroup" in block
    assert "kms:GenerateDataKey*" in block
    assert "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}" in block
    assert "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" not in block


def test_github_oidc_trust_uses_repository_and_environment() -> None:
    plan_trust = _extract_hcl_block('data "aws_iam_policy_document"', "github_oidc_plan_role")
    apply_trust = _extract_hcl_block('data "aws_iam_policy_document"', "github_oidc_apply_role")
    for trust in (plan_trust, apply_trust):
        assert 'token.actions.githubusercontent.com:aud' in trust
        assert 'sts.amazonaws.com' in trust
        assert 'token.actions.githubusercontent.com:sub' in trust
        assert 'repo:${var.github_repository}:environment:${var.github_environment}' in trust
        assert 'repo:*' not in trust
        assert 'environment:*' not in trust


def test_workflow_requires_oidc_permission_and_environment_gate() -> None:
    workflow = WORKFLOW_FILE.read_text(encoding="utf-8")
    assert "id-token: write" in workflow
    assert "role-to-assume: arn:aws:iam::960577828312:role/sentinelops-github-oidc-deploy" in workflow
    assert "environment: sandbox" in workflow
    assert "inputs.environment == 'sandbox'" in workflow
    assert "confirm_deploy" in workflow
    assert "terraform plan -lock=false -input=false -no-color" in workflow
    assert "terraform apply" not in workflow
    assert "terraform destroy" not in workflow


def test_terraform_oidc_provider_uses_stable_github_thumbprint() -> None:
    provider = TERRAFORM_FILE.read_text(encoding="utf-8")
    assert 'thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]' in provider
    assert "token.actions.githubusercontent.com" in provider
    assert not re.search(r'thumbprint_list\s*=\s*\[\s*"[0-9a-fA-F]{39}"\s*\]', provider)


def test_no_unrestricted_service_wildcards_are_present_in_terraform_source() -> None:
    terraform_text = TERRAFORM_FILE.read_text(encoding="utf-8")
    for wildcard in ("iam:*", "s3:*", "ec2:*", "logs:*", "cloudtrail:*", "budgets:*"):
        assert wildcard not in terraform_text

    apply_policy = _extract_hcl_block('data "aws_iam_policy_document"', "github_apply_policy")
    for forbidden in ("iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy", "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "logs:CreateLogGroup", "s3:PutObject"):
        assert forbidden not in apply_policy


def _flatten_actions(statement: dict[str, object]) -> set[str]:
    value = statement.get("Action", [])
    if isinstance(value, str):
        return {value}
    return set(value)


def test_assessment_policy_covers_actual_collector_api_calls() -> None:
    assessment_block = _extract_hcl_block('data "aws_iam_policy_document"', "assessment_policy")
    collector_source = (ROOT / "src" / "sentinelops" / "collectors" / "aws.py").read_text(encoding="utf-8")
    required_actions = (
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "s3:GetBucketAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketTagging",
        "s3:GetObject",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeVpcs",
        "cloudtrail:DescribeTrails",
        "logs:DescribeLogGroups",
        "kms:DescribeKey",
        "budgets:DescribeBudget",
        "sts:GetCallerIdentity",
    )
    assert "list_buckets" in collector_source
    assert "describe_security_groups" in collector_source
    assert "list_roles" in collector_source
    for action in required_actions:
        assert action in assessment_block, f"assessment policy missing {action}"


def test_remediation_policy_covers_actual_live_proof_calls() -> None:
    remediation_block = _extract_hcl_block('data "aws_iam_policy_document"', "remediation_policy")
    proof_source = (ROOT / "scripts" / "phase8_live_aws_proof.py").read_text(encoding="utf-8")
    assert "put_public_access_block" in proof_source
    assert "authorize_security_group_ingress" in proof_source
    assert "iam:DeleteRolePolicy" not in remediation_block
    assert "s3:PutPublicAccessBlock" in remediation_block
    assert "ec2:AuthorizeSecurityGroupIngress" in remediation_block
    assert "ec2:RevokeSecurityGroupIngress" in remediation_block


def test_bootstrap_policy_covers_provisioning_and_cleanup_calls() -> None:
    bootstrap_block = _extract_hcl_block('data "aws_iam_policy_document"', "bootstrap_policy")
    proof_source = (ROOT / "scripts" / "phase8_live_aws_proof.py").read_text(encoding="utf-8")
    required_actions = (
        "s3:GetBucketLocation",
        "s3:PutObject",
        "s3:DeleteObject",
        "kms:GenerateDataKey*",
        "cloudtrail:CreateTrail",
        "cloudtrail:DeleteTrail",
        "logs:CreateLogGroup",
        "logs:PutLogEvents",
    )
    assert "_cleanup_s3_bucket" in proof_source
    assert "_cleanup_iam" in proof_source
    assert "_cleanup_security_group" in proof_source
    for action in required_actions:
        assert action in bootstrap_block, f"bootstrap policy missing {action}"


def test_remediation_requires_independent_verification_after_execution() -> None:
    approval = __import__("sentinelops.remediation", fromlist=["approve_remediation"]).approve_remediation(
        action="s3_block_public_access",
        target="arn:aws:s3:::demo-bucket",
        reason="Restrict anonymous reads after evidence shows the public policy.",
    )
    result = __import__("sentinelops.remediation", fromlist=["execute_remediation"]).execute_remediation(
        action="s3_block_public_access",
        target="arn:aws:s3:::demo-bucket",
        reason="Restrict anonymous reads after evidence shows the public policy.",
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=False,
    )
    assert result["status"] == "FAILED"
    assert result["verification"]["passed"] is False
