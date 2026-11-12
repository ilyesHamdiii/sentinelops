"""Read-only AWS resource collectors for SentinelOps baseline assessment."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterable, Mapping
from typing import Any

from botocore.exceptions import ClientError

from sentinelops.validation.baseline import evaluate_baseline


def _safe_tags(raw_tags: Any) -> dict[str, str]:
    if not isinstance(raw_tags, list):
        return {}

    tags: dict[str, str] = {}
    for item in raw_tags:
        if not isinstance(item, dict):
            continue
        key = item.get("Key")
        value = item.get("Value")
        if isinstance(key, str):
            tags[key] = str(value) if value is not None else ""
    return tags


def _policy_doc_to_statements(document: Any) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []

    normalized: list[dict[str, Any]] = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        normalized.append(
            {
                "Effect": statement.get("Effect", "Deny"),
                "Action": statement.get("Action"),
                "Resource": statement.get("Resource"),
            }
        )
    return normalized


def _flatten_ingress_rules(ip_permissions: Any) -> list[dict[str, Any]]:
    if not isinstance(ip_permissions, list):
        return []

    flattened: list[dict[str, Any]] = []
    for permission in ip_permissions:
        if not isinstance(permission, dict):
            continue

        base_rule = {
            "IpProtocol": permission.get("IpProtocol", "-1"),
            "FromPort": permission.get("FromPort"),
            "ToPort": permission.get("ToPort"),
        }

        for cidr in permission.get("IpRanges", []) or []:
            if isinstance(cidr, dict):
                rule = dict(base_rule)
                rule["CidrIp"] = cidr.get("CidrIp")
                flattened.append(rule)

        for cidr in permission.get("Ipv6Ranges", []) or []:
            if isinstance(cidr, dict):
                rule = dict(base_rule)
                rule["CidrIp"] = cidr.get("CidrIpv6")
                flattened.append(rule)

    return flattened


def collect_s3_assets(
    s3_client: Any,
    region: str | None = None,
    account_id: str | None = None,
) -> list[dict[str, Any]]:
    """Collect read-only S3 metadata and public access block information."""
    buckets = s3_client.list_buckets().get("Buckets", [])
    assets: list[dict[str, Any]] = []

    for bucket in buckets:
        name = bucket.get("Name")
        if not isinstance(name, str):
            continue

        tags = {}
        try:
            tags_response = s3_client.get_bucket_tagging(Bucket=name)
            tags = _safe_tags(tags_response.get("TagSet", []))
        except (AttributeError, ClientError):
            tags = {}

        public_access_block = {}
        try:
            response = s3_client.get_public_access_block(Bucket=name)
            public_access_block = response.get("PublicAccessBlockConfiguration", {})
        except (AttributeError, ClientError):
            public_access_block = {}

        assets.append(
            {
                "resource_type": "AWS::S3::Bucket",
                "name": name,
                "arn": f"arn:aws:s3:::{name}",
                "account_id": account_id,
                "region": region,
                "tags": tags,
                "public_access_block": public_access_block,
            }
        )

    return assets


def collect_iam_assets(
    iam_client: Any,
    region: str | None = None,
    account_id: str | None = None,
) -> list[dict[str, Any]]:
    """Collect read-only IAM role and managed policy metadata."""
    assets: list[dict[str, Any]] = []

    roles = iam_client.list_roles().get("Roles", [])
    for role in roles:
        role_name = role.get("RoleName")
        if not isinstance(role_name, str):
            continue

        statements: list[dict[str, Any]] = []
        inline_policy_names: list[str] = []
        try:
            inline_policy_names = iam_client.list_role_policies(RoleName=role_name).get("PolicyNames", [])
        except (AttributeError, ClientError):
            inline_policy_names = []

        if not inline_policy_names:
            inline_policy_names = [role_name, f"{role_name}-policy"]

        for policy_name in inline_policy_names:
            try:
                policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                statements.extend(_policy_doc_to_statements(policy.get("PolicyDocument", {})))
            except (AttributeError, ClientError):
                continue

        assets.append(
            {
                "resource_type": "AWS::IAM::Role",
                "name": role_name,
                "arn": role.get("Arn", f"arn:aws:iam::{account_id or 'unknown'}:role/{role_name}"),
                "account_id": account_id,
                "region": region,
                "tags": _safe_tags(role.get("Tags", [])),
                "policy_statements": statements,
            }
        )

    policies = iam_client.list_policies().get("Policies", [])
    for policy in policies:
        policy_name = policy.get("PolicyName")
        if not isinstance(policy_name, str):
            continue

        statement_list: list[dict[str, Any]] = []
        policy_arn = policy.get("Arn")
        version_id = policy.get("DefaultVersionId") or "v1"
        try:
            if isinstance(policy_arn, str):
                response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
                document = response.get("PolicyVersion", {}).get("Document", {})
                statement_list = _policy_doc_to_statements(document)
        except (AttributeError, ClientError):
            statement_list = []

        assets.append(
            {
                "resource_type": "AWS::IAM::ManagedPolicy",
                "name": policy_name,
                "arn": policy.get("Arn", f"arn:aws:iam::{account_id or 'unknown'}:policy/{policy_name}"),
                "account_id": account_id,
                "region": region,
                "tags": _safe_tags(policy.get("Tags", [])),
                "policy_statements": statement_list,
            }
        )

    return assets


def collect_security_group_assets(
    ec2_client: Any,
    region: str | None = None,
    account_id: str | None = None,
) -> list[dict[str, Any]]:
    """Collect read-only EC2 security group metadata and ingress rules."""
    security_groups = ec2_client.describe_security_groups().get("SecurityGroups", [])
    assets: list[dict[str, Any]] = []

    for group in security_groups:
        group_id = group.get("GroupId")
        group_name = group.get("GroupName")
        if not isinstance(group_id, str):
            continue

        name = group_name or group_id
        assets.append(
            {
                "resource_type": "AWS::EC2::SecurityGroup",
                "name": name,
                "arn": f"arn:aws:ec2:{region}:{account_id or 'unknown'}:security-group/{group_id}",
                "account_id": account_id,
                "region": region,
                "tags": _safe_tags(group.get("Tags", [])),
                "ingress": _flatten_ingress_rules(group.get("IpPermissions", [])),
            }
        )

    return assets


def evaluate_live_assets(
    assets_by_type: Mapping[str, Iterable[dict[str, Any]]],
) -> dict[str, Any]:
    """Evaluate a live or synthetic asset set against the baseline policy."""
    all_assets: list[dict[str, Any]] = []
    for asset_list in assets_by_type.values():
        all_assets.extend(asset_list)

    results = [evaluate_baseline(asset) for asset in all_assets]
    summary = {
        "total_assets": len(results),
        "pass": sum(1 for item in results if item["status"] == "PASS"),
        "fail": sum(1 for item in results if item["status"] == "FAIL"),
        "unknown": sum(1 for item in results if item["status"] == "UNKNOWN"),
    }
    summary["failures"] = summary["fail"]
    summary["passes"] = summary["pass"]

    return {"summary": summary, "results": results}


def persist_live_evidence(
    assets: Iterable[dict[str, Any]],
    *,
    account_id: str | None = None,
    region: str | None = None,
    evidence_dir: str | Path | None = None,
) -> Path:
    """Persist a JSON evidence snapshot of the observed assets."""
    payload: dict[str, Any] = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "region": region,
        "asset_count": 0,
        "assets": [],
    }

    asset_list = list(assets)
    payload["asset_count"] = len(asset_list)
    payload["assets"] = asset_list

    root = Path(evidence_dir) if evidence_dir is not None else Path.cwd() / "evidence"
    root.mkdir(parents=True, exist_ok=True)

    file_name = f"live-baseline-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    output_path = root / file_name
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return output_path


def collect_live_assets(
    *,
    region: str | None = None,
    account_id: str | None = None,
    session: Any | None = None,
    evidence_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Collect AWS resources and baseline results in read-only mode."""
    boto_session = session or __import__("boto3").Session()

    s3_client = boto_session.client("s3", region_name=region)
    iam_client = boto_session.client("iam")
    ec2_client = boto_session.client("ec2", region_name=region)

    assets_by_type = {
        "s3": collect_s3_assets(s3_client, region=region, account_id=account_id),
        "iam": collect_iam_assets(iam_client, region=region, account_id=account_id),
        "security_groups": collect_security_group_assets(ec2_client, region=region, account_id=account_id),
    }

    results = evaluate_live_assets(assets_by_type)
    persist_live_evidence(
        (asset for group in assets_by_type.values() for asset in group),
        account_id=account_id,
        region=region,
        evidence_dir=evidence_dir,
    )
    return results
