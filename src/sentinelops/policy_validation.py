"""Policy validation helpers for SentinelOps IAM and OIDC trust boundaries."""

from __future__ import annotations

from typing import Any

ASSESSMENT_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowReadOnlyS3Assessment",
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:GetBucketAcl",
                "s3:GetPublicAccessBlock",
                "s3:GetBucketTagging",
                "s3:GetObject",
                "s3:GetObjectVersion",
            ],
            "Resource": [
                "arn:aws:s3:::sentinelops-*",
                "arn:aws:s3:::sentinelops-*/*",
            ],
        },
        {
            "Sid": "AllowReadOnlyIamMetadata",
            "Effect": "Allow",
            "Action": [
                "iam:ListRoles",
                "iam:GetRole",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:ListPolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetAccountSummary",
            ],
            "Resource": "*",
        },
        {
            "Sid": "AllowReadOnlySecurityGroups",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSecurityGroupRules",
                "ec2:DescribeVpcs",
            ],
            "Resource": "*",
        },
        {
            "Sid": "AllowReadOnlyTrailMetadata",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:ListTags",
            ],
            "Resource": ["arn:aws:cloudtrail:eu-west-1:123456789012:trail/*"],
        },
        {
            "Sid": "AllowReadOnlyLogs",
            "Effect": "Allow",
            "Action": [
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:GetLogEvents",
            ],
            "Resource": ["arn:aws:logs:eu-west-1:123456789012:log-group:*"],
        },
        {
            "Sid": "AllowReadOnlyKms",
            "Effect": "Allow",
            "Action": [
                "kms:DescribeKey",
                "kms:ListAliases",
                "kms:ListKeys",
            ],
            "Resource": ["arn:aws:kms:eu-west-1:123456789012:key/*"],
        },
        {
            "Sid": "AllowReadOnlyBudgets",
            "Effect": "Allow",
            "Action": [
                "budgets:DescribeBudget",
                "budgets:DescribeBudgets",
            ],
            "Resource": "*",
        },
        {
            "Sid": "AllowGetCallerIdentity",
            "Effect": "Allow",
            "Action": ["sts:GetCallerIdentity"],
            "Resource": "*",
        },
    ],
}

REMEDIATION_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowScopedS3PublicAccessRemediation",
            "Effect": "Allow",
            "Action": ["s3:PutPublicAccessBlock"],
            "Resource": ["arn:aws:s3:::sentinelops-*"],
        },
        {
            "Sid": "AllowScopedSecurityGroupIngressRemediation",
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:RevokeSecurityGroupIngress",
            ],
            "Resource": ["arn:aws:ec2:eu-west-1:123456789012:security-group/*"],
        },
        {
            "Sid": "DenyPrivilegeEscalation",
            "Effect": "Deny",
            "Action": [
                "iam:AttachRolePolicy",
                "iam:PutRolePolicy",
                "iam:CreatePolicy",
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "iam:PassRole",
                "iam:UpdateAssumeRolePolicy",
                "sts:AssumeRole",
                "sts:AssumeRoleWithWebIdentity",
                "sts:AssumeRoleWithSAML",
                "iam:DeleteRolePolicy",
            ],
            "Resource": "*",
        },
    ],
}

BOOTSTRAP_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3BucketGateway",
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListBucket",
                "s3:GetBucketAcl",
                "s3:PutBucketAcl",
                "s3:PutPublicAccessBlock",
                "s3:PutBucketVersioning",
                "s3:PutEncryptionConfiguration",
            ],
            "Resource": [
                "arn:aws:s3:::sentinelops-evidence-*",
                "arn:aws:s3:::sentinelops-cloudtrail-*",
            ],
        },
        {
            "Sid": "S3ArtifactWrite",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:ListBucketMultipartUploads",
                "s3:AbortMultipartUpload",
            ],
            "Resource": [
                "arn:aws:s3:::sentinelops-evidence-*/*",
                "arn:aws:s3:::sentinelops-cloudtrail-*/*",
            ],
        },
        {
            "Sid": "UseEvidenceKms",
            "Effect": "Allow",
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:DescribeKey",
                "kms:GenerateDataKey*",
                "kms:ListAliases",
                "kms:ListKeys",
            ],
            "Resource": ["arn:aws:kms:eu-west-1:123456789012:key/*"],
        },
        {
            "Sid": "CloudTrailBucketWrite",
            "Effect": "Allow",
            "Action": [
                "cloudtrail:CreateTrail",
                "cloudtrail:UpdateTrail",
                "cloudtrail:DeleteTrail",
                "cloudtrail:StartLogging",
                "cloudtrail:StopLogging",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "cloudtrail:ListTags",
            ],
            "Resource": ["arn:aws:cloudtrail:eu-west-1:123456789012:trail/*"],
        },
        {
            "Sid": "BudgetReadWrite",
            "Effect": "Allow",
            "Action": [
                "budgets:CreateBudget",
                "budgets:UpdateBudget",
                "budgets:DeleteBudget",
                "budgets:DescribeBudget",
                "budgets:DescribeBudgets",
            ],
            "Resource": "*",
        },
        {
            "Sid": "CloudWatchLogging",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
            ],
            "Resource": ["arn:aws:logs:eu-west-1:123456789012:log-group:*"],
        },
    ],
}

GITHUB_OIDC_TRUST: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "GithubActionsRepoEnvironment",
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": "repo:OWNER/REPO:environment:sandbox",
                }
            },
        }
    ],
}


def _flatten_actions(statement: dict[str, Any]) -> list[str]:
    value = statement.get("Action", [])
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _flatten_resources(statement: dict[str, Any]) -> list[str]:
    value = statement.get("Resource", [])
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def assert_no_privilege_escalation(policy: dict[str, Any]) -> None:
    denied = {
        "iam:AttachRolePolicy",
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:PassRole",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole",
        "sts:AssumeRoleWithSAML",
        "sts:AssumeRoleWithWebIdentity",
    }
    for statement in policy.get("Statement", []):
        if statement.get("Effect") == "Deny":
            continue
        for action in _flatten_actions(statement):
            if action in denied:
                raise AssertionError(f"Privilege escalation action present: {action}")


def assert_no_broad_service_wildcards(policy: dict[str, Any]) -> None:
    for statement in policy.get("Statement", []):
        if statement.get("Effect") == "Deny":
            continue
        for action in _flatten_actions(statement):
            normalized = str(action).strip()
            if normalized in {"*", "iam:*", "s3:*", "ec2:*", "logs:*", "cloudtrail:*", "budgets:*"}:
                raise AssertionError(f"Broad wildcard action is not permitted: {action}")
            if normalized.endswith(":*"):
                raise AssertionError(f"Service wildcard action is not permitted: {action}")


def assert_policy_is_read_only(policy: dict[str, Any]) -> None:
    write_actions = {
        "Put",
        "Create",
        "Delete",
        "Update",
        "Attach",
        "Detach",
        "Modify",
        "Write",
        "Remove",
        "TagResource",
        "UntagResource",
        "PassRole",
        "Revoke",
        "Authorize",
        "Stop",
        "Start",
    }
    for statement in policy.get("Statement", []):
        for action in _flatten_actions(statement):
            service_action = str(action).split(":", 1)[1] if ":" in action else str(action)
            if any(marker in service_action for marker in write_actions):
                raise AssertionError(f"Read-only policy contains write action: {action}")


def assert_policy_restricts_trust(policy: dict[str, Any]) -> None:
    for statement in policy.get("Statement", []):
        principal = statement.get("Principal", {})
        federated = principal.get("Federated") if isinstance(principal, dict) else None
        if not federated:
            raise AssertionError("OIDC trust policy must use a federated principal.")
        if "token.actions.githubusercontent.com" not in str(federated):
            raise AssertionError("OIDC trust must identify the GitHub Actions provider.")
        condition = statement.get("Condition", {})
        string_equals = condition.get("StringEquals", {}) if isinstance(condition, dict) else {}
        aud = string_equals.get("token.actions.githubusercontent.com:aud") if isinstance(string_equals, dict) else None
        repo_subject = string_equals.get("token.actions.githubusercontent.com:sub") if isinstance(string_equals, dict) else None
        if aud != "sts.amazonaws.com":
            raise AssertionError("OIDC audience must be set to sts.amazonaws.com.")
        if not isinstance(repo_subject, str) or "repo:" not in repo_subject or ":environment:" not in repo_subject:
            raise AssertionError("OIDC subject must restrict to a specific repository and environment.")


def _normalize_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return policy
