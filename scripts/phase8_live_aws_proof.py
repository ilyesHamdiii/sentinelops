"""Phase 8 live AWS validation for SentinelOps in a dedicated sandbox.

This script is intentionally non-executing by default. It refuses to create
insecure resources unless a human operator has explicitly enabled the live-demo
flow and the execution context matches the approved AWS sandbox account and
region. This preserves the repository's no-deploy constraint while making the
proof script safe by construction.
"""

from __future__ import annotations

import json
import os
import random
import string
import sys
from typing import Any

import boto3

from sentinelops.scenarios import evaluate_scenario

REGION = "eu-west-1"
PROJECT_TAG = {"Project": "sentinelops", "Environment": "sandbox", "Purpose": "phase8-live-proof"}
BOOTSTRAP_ROLE_NAME = "sentinelops-bootstrap"


def _random_suffix(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _read_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _parse_allowed_account_ids(value: str | None) -> set[str]:
    if not value:
        return set()
    ids = {item.strip() for item in value.split(",") if item.strip()}
    valid = {item for item in ids if len(item) == 12 and item.isdigit()}
    return valid


def _require_live_demo_guardrails() -> dict[str, str]:
    allow_demo = _read_bool(os.environ.get("SENTINELOPS_ENABLE_LIVE_DEMO"))
    approve_demo = _read_bool(os.environ.get("SENTINELOPS_APPROVE_LIVE_DEMO"))
    allowed_accounts = _parse_allowed_account_ids(os.environ.get("SENTINELOPS_ALLOWED_ACCOUNT_IDS"))
    region = (os.environ.get("SENTINELOPS_TEST_REGION") or REGION).strip()
    environment = (os.environ.get("SENTINELOPS_TEST_ENVIRONMENT") or "").strip()
    vpc_id = (os.environ.get("SENTINELOPS_TEST_VPC_ID") or "").strip()
    bootstrap_name = (os.environ.get("SENTINELOPS_BOOTSTRAP_ROLE_NAME") or BOOTSTRAP_ROLE_NAME).strip()

    if not allow_demo:
        raise RuntimeError("Live AWS demo is disabled by default; set SENTINELOPS_ENABLE_LIVE_DEMO=true.")
    if not approve_demo:
        raise RuntimeError("Explicit operator approval is required; set SENTINELOPS_APPROVE_LIVE_DEMO=true.")
    if not allowed_accounts:
        raise RuntimeError("No allowed AWS account IDs were provided; set SENTINELOPS_ALLOWED_ACCOUNT_IDS.")
    if region not in {"eu-west-1"}:
        raise RuntimeError("Only the eu-west-1 sandbox region is permitted for this script.")
    if not environment:
        raise RuntimeError("SENTINELOPS_TEST_ENVIRONMENT is required; the default VPC is not acceptable as an implicit boundary.")
    if environment.lower() == "default":
        raise RuntimeError("The default VPC is not an allowed test boundary; provide an explicitly identified test environment or VPC.")
    if not vpc_id:
        raise RuntimeError("SENTINELOPS_TEST_VPC_ID is required. Do not use the default VPC implicitly.")
    if not bootstrap_name:
        raise RuntimeError("The dedicated bootstrap role name is required for provisioning.")

    return {
        "region": region,
        "environment": environment,
        "vpc_id": vpc_id,
        "bootstrap_role_name": bootstrap_name,
    }


def _ensure_tagged(resource: dict[str, Any]) -> dict[str, Any]:
    tags = resource.get("Tags", [])
    existing = {tag.get("Key"): tag.get("Value") for tag in tags if isinstance(tag, dict)}
    merged = {**existing, **PROJECT_TAG}
    return [{"Key": key, "Value": value} for key, value in merged.items()]


def _validate_bootstrap_identity(session: Any, allowed_accounts: set[str], expected_role_name: str) -> dict[str, str]:
    identity = session.client("sts").get_caller_identity()
    account_id = str(identity.get("Account") or "").strip()
    arn = str(identity.get("Arn") or "").strip()
    if not account_id or not arn:
        raise RuntimeError("AWS identity could not be verified; refusing to execute the live proof script.")
    if account_id not in allowed_accounts:
        raise RuntimeError(f"Account '{account_id}' is not in the explicit allowlist: {sorted(allowed_accounts)}")
    lower_arn = arn.lower()
    if expected_role_name.lower() not in lower_arn and f"role/{expected_role_name}" not in lower_arn:
        raise RuntimeError(
            f"Caller '{arn}' is not using the dedicated bootstrap identity '{expected_role_name}'. "
            "Refusing to create vulnerable resources."
        )
    return {"account_id": account_id, "arn": arn}


def _create_s3_public_bucket(client: Any, bucket_name: str) -> dict[str, Any]:
    create_bucket_kwargs = {"Bucket": bucket_name}
    if REGION != "us-east-1":
        create_bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": REGION}
    client.create_bucket(**create_bucket_kwargs)

    client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/*"],
            }],
        }),
    )
    return {"bucket_name": bucket_name, "public_access_block": {"BlockPublicAcls": False, "BlockPublicPolicy": False, "IgnorePublicAcls": False, "RestrictPublicBuckets": False}}


def _cleanup_s3_bucket(client: Any, bucket_name: str) -> None:
    try:
        paginator = client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            versions = page.get("Versions", [])
            for version in versions:
                client.delete_object(Bucket=bucket_name, Key=version["Key"], VersionId=version["VersionId"])
            delete_markers = page.get("DeleteMarkers", [])
            for marker in delete_markers:
                client.delete_object(Bucket=bucket_name, Key=marker["Key"], VersionId=marker["VersionId"])
        client.delete_bucket(Bucket=bucket_name)
    except Exception:
        pass


def _create_iam_wildcard_role(iam: Any, role_name: str, policy_name: str) -> dict[str, Any]:
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    iam.tag_role(RoleName=role_name, Tags=[{"Key": key, "Value": value} for key, value in PROJECT_TAG.items()])

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    }
    policy = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy["Policy"]["Arn"])
    return {
        "role_name": role_name,
        "policy_name": policy_name,
        "policy_arn": policy["Policy"]["Arn"],
        "policy_doc": policy_doc,
    }


def _cleanup_iam(iam: Any, role_name: str, policy_name: str) -> None:
    try:
        policies = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
        for policy in policies:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy["PolicyArn"])
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                if policy["PolicyName"] == policy_name:
                    iam.delete_policy(PolicyArn=policy["Arn"])
        iam.delete_role(RoleName=role_name)
    except Exception:
        pass


def _create_insecure_security_group(ec2: Any, vpc_id: str, group_name: str) -> dict[str, Any]:
    response = ec2.create_security_group(
        GroupName=group_name,
        Description="Phase 8 public ingress validation group",
        VpcId=vpc_id,
    )
    group_id = response["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    return {"group_id": group_id, "ingress": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}]}


def _cleanup_security_group(ec2: Any, group_id: str) -> None:
    try:
        ec2.delete_security_group(GroupId=group_id)
    except Exception:
        pass


def _get_default_vpc_id(ec2: Any) -> str:
    raise RuntimeError("The default VPC is not allowed for live validation. Use SENTINELOPS_TEST_VPC_ID to specify an explicit test environment.")


def main() -> int:
    try:
        guardrails = _require_live_demo_guardrails()
        allowed_accounts = _parse_allowed_account_ids(os.environ.get("SENTINELOPS_ALLOWED_ACCOUNT_IDS"))
        if not allowed_accounts:
            raise RuntimeError("No account IDs were allowlisted.")

        session = boto3.Session(region_name=guardrails["region"])
        identity = _validate_bootstrap_identity(session, allowed_accounts, guardrails["bootstrap_role_name"])
        account_id = identity["account_id"]
        print(f"Bootstrap account: {account_id} | role: {identity['arn']} | region: {guardrails['region']} | environment: {guardrails['environment']} | vpc: {guardrails['vpc_id']}")

        suffix = _random_suffix()
        bucket_name = f"sentinelops-phase8-{guardrails['environment']}-{suffix}"
        role_name = f"sentinelops-phase8-role-{suffix}"
        policy_name = f"sentinelops-phase8-policy-{suffix}"
        sg_name = f"sentinelops-phase8-sg-{suffix}"

        s3 = session.client("s3", region_name=guardrails["region"])
        iam = session.client("iam", region_name=guardrails["region"])
        ec2 = session.client("ec2", region_name=guardrails["region"])

        created: list[dict[str, Any]] = []
        try:
            bucket = _create_s3_public_bucket(s3, bucket_name)
            created.append({"kind": "s3", "name": bucket_name, "payload": bucket})
            print("[S1] Created public S3 bucket:", bucket_name)

            role = _create_iam_wildcard_role(iam, role_name, policy_name)
            created.append({"kind": "iam", "name": role_name, "payload": role})
            print("[S2] Created wildcard IAM policy and role:", role_name)

            security_group = _create_insecure_security_group(ec2, guardrails["vpc_id"], sg_name)
            created.append({"kind": "sg", "name": sg_name, "payload": security_group})
            print("[S3] Created public security group:", sg_name)

            s1 = evaluate_scenario("S1", {
                "bucket_name": bucket_name,
                "public_access_block": bucket["public_access_block"],
                "bucket_policy": {"Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                }]},
            })
            s2 = evaluate_scenario("S2", {"policy_statements": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }]})
            s3_result = evaluate_scenario("S3", {"ingress": [{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "CidrIp": "0.0.0.0/0",
            }]})

            print("[S1] Result:", s1)
            print("[S2] Result:", s2)
            print("[S3] Result:", s3_result)

            assert s1["status"] == "finding_detected"
            assert s2["status"] == "finding_detected"
            assert s3_result["status"] == "finding_detected"

            print("Live Phase 8 validation succeeded in the explicit sandbox environment.")
            return 0
        finally:
            print("Beginning teardown...")
            cleanup_errors: list[str] = []
            for item in reversed(created):
                kind = item["kind"]
                name = item["name"]
                try:
                    if kind == "s3":
                        _cleanup_s3_bucket(s3, name)
                        print(f"[teardown] S3 bucket deleted: {name}")
                    elif kind == "iam":
                        _cleanup_iam(iam, name, item["payload"]["policy_name"])
                        print(f"[teardown] IAM role and policy deleted: {name}")
                    elif kind == "sg":
                        _cleanup_security_group(ec2, item["payload"]["group_id"])
                        print(f"[teardown] Security group deleted: {name}")
                except Exception as exc:  # pragma: no cover - defensive path in live execution only
                    cleanup_errors.append(f"{kind}:{name}:{exc}")

            if cleanup_errors:
                raise RuntimeError("Cleanup did not complete for all script-created resources: " + "; ".join(cleanup_errors))
    except RuntimeError as exc:
        print(f"Live AWS proof refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    os.environ.setdefault("AWS_REGION", REGION)
    raise SystemExit(main())
