"""Local-only baseline control checks for AWS resource posture."""

from __future__ import annotations

from typing import Any


def _is_open_to_world(rule: dict[str, Any]) -> bool:
    if not isinstance(rule, dict):
        return False

    if rule.get("CidrIp") not in {"0.0.0.0/0", "::/0"}:
        return False

    protocol = str(rule.get("IpProtocol", "-1")).lower()
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    if protocol in {"-1", "all"}:
        return True

    if isinstance(from_port, int) and isinstance(to_port, int):
        if from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
            return True

    return False


def _evaluate_s3_bucket(asset: dict[str, Any]) -> tuple[str, list[str], str]:
    public_block = asset.get("public_access_block") or {}
    if not isinstance(public_block, dict):
        public_block = {}

    required_flags = (
        "BlockPublicAcls",
        "BlockPublicPolicy",
        "IgnorePublicAcls",
        "RestrictPublicBuckets",
    )

    failing = [
        flag for flag in required_flags if public_block.get(flag) is not True
    ]
    if failing:
        return (
            "FAIL",
            [
                "S3 bucket public access block is not fully enabled: "
                + ", ".join(failing)
            ],
            "S3 bucket baseline failed because the public access block is incomplete.",
        )

    return (
        "PASS",
        [],
        "S3 bucket passed the baseline public access block checks.",
    )


def _evaluate_security_group(asset: dict[str, Any]) -> tuple[str, list[str], str]:
    ingress = asset.get("ingress") or []
    if not isinstance(ingress, list):
        ingress = []

    open_rules = [
        rule for rule in ingress if isinstance(rule, dict) and _is_open_to_world(rule)
    ]

    if open_rules:
        descriptions = [
            f"Ingress rule {idx + 1} exposes port {rule.get('FromPort')} to the internet"
            for idx, rule in enumerate(open_rules)
        ]
        return (
            "FAIL",
            descriptions,
            "Security group baseline failed because a dangerous ingress rule allows public access.",
        )

    return (
        "PASS",
        [],
        "Security group passed the baseline ingress checks.",
    )


def _evaluate_iam_policy(asset: dict[str, Any]) -> tuple[str, list[str], str]:
    statements = asset.get("policy_statements") or asset.get("statements") or []
    if not isinstance(statements, list):
        statements = []

    wildcard = False
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        action = statement.get("Action")
        resource = statement.get("Resource")
        if action in {"*", "iam:*", "AdministratorAccess"} or resource == "*":
            wildcard = True
            break

    if wildcard:
        return (
            "FAIL",
            ["IAM policy grants wildcard access that exceeds the baseline least-privilege model."],
            "IAM baseline failed because a policy contains wildcard administrative access.",
        )

    return (
        "PASS",
        [],
        "IAM policy passed the baseline least-privilege checks.",
    )


def evaluate_baseline(asset: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a single AWS resource against the local baseline rules.

    The baseline is intentionally local-only and cannot replace a real AWS
    configuration review; it is used to enforce a minimal guardrail set before any
    real AWS deployment or remediation executes.
    """

    resource_type = asset.get("resource_type") or asset.get("type")
    if not resource_type:
        return {
            "resource_type": None,
            "name": asset.get("name"),
            "status": "UNKNOWN",
            "summary": "Resource type is missing; baseline not yet evaluated.",
            "findings": ["Resource type missing from the asset metadata."],
        }

    evaluator_map = {
        "AWS::S3::Bucket": _evaluate_s3_bucket,
        "AWS::EC2::SecurityGroup": _evaluate_security_group,
        "AWS::IAM::Role": _evaluate_iam_policy,
        "AWS::IAM::ManagedPolicy": _evaluate_iam_policy,
    }

    evaluator = evaluator_map.get(resource_type)
    if evaluator is None:
        return {
            "resource_type": resource_type,
            "name": asset.get("name"),
            "status": "UNKNOWN",
            "summary": f"{resource_type} is not yet evaluated by the local baseline controls.",
            "findings": ["Resource type not yet evaluated by the baseline policy."],
        }

    status, findings, summary = evaluator(asset)
    return {
        "resource_type": resource_type,
        "name": asset.get("name"),
        "status": status,
        "summary": summary,
        "findings": findings,
    }
