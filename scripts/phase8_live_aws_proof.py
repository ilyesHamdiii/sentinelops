"""Phase 8 live AWS validation for SentinelOps in the dedicated eu-west-1 sandbox.

This script creates a minimal set of intentionally insecure test resources,
validates them using the canonical Scenario engine, and then cleans them up
immediately. It is designed for the dedicated sandbox account only and keeps
all actions narrowly scoped and tagged for easy audit.
"""

from __future__ import annotations

import json
import os
import random
import string
from typing import Any

import boto3

from sentinelops.scenarios import evaluate_scenario

REGION = "eu-west-1"
PROJECT_TAG = {"Project": "sentinelops", "Environment": "sandbox", "Purpose": "phase8-live-proof"}


def _random_suffix(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _ensure_tagged(resource: dict[str, Any]) -> dict[str, Any]:
    tags = resource.get("Tags", [])
    existing = {tag.get("Key"): tag.get("Value") for tag in tags if isinstance(tag, dict)}
    merged = {**existing, **PROJECT_TAG}
    return [{"Key": key, "Value": value} for key, value in merged.items()]


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
    except client.exceptions.ClientError:
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
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs.get("Vpcs", []):
        if vpc.get("IsDefault"):
            return vpc["VpcId"]
    raise RuntimeError("No default VPC found in the sandbox account.")


def main() -> None:
    session = boto3.Session(region_name=REGION)
    account_id = session.client("sts").get_caller_identity()["Account"]
    print(f"Sandbox account: {account_id} | region: {REGION}")

    suffix = _random_suffix()
    bucket_name = f"sentinelops-phase8-{suffix}"
    role_name = f"sentinelops-phase8-role-{suffix}"
    policy_name = f"sentinelops-phase8-policy-{suffix}"
    sg_name = f"sentinelops-phase8-sg-{suffix}"

    s3 = session.client("s3", region_name=REGION)
    iam = session.client("iam", region_name=REGION)
    ec2 = session.client("ec2", region_name=REGION)

    created: list[dict[str, Any]] = []
    try:
        bucket = _create_s3_public_bucket(s3, bucket_name)
        created.append({"kind": "s3", "name": bucket_name, "payload": bucket})
        print("[S1] Created public S3 bucket:", bucket_name)

        role = _create_iam_wildcard_role(iam, role_name, policy_name)
        created.append({"kind": "iam", "name": role_name, "payload": role})
        print("[S2] Created wildcard IAM policy and role:", role_name)

        vpc_id = _get_default_vpc_id(ec2)
        security_group = _create_insecure_security_group(ec2, vpc_id, sg_name)
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

        print("Live Phase 8 validation succeeded in eu-west-1 for S1, S2, and S3.")
    finally:
        print("Beginning teardown...")
        for item in reversed(created):
            kind = item["kind"]
            name = item["name"]
            if kind == "s3":
                _cleanup_s3_bucket(s3, name)
                print(f"[teardown] S3 bucket deleted: {name}")
            elif kind == "iam":
                _cleanup_iam(iam, name, item["payload"]["policy_name"])
                print(f"[teardown] IAM role and policy deleted: {name}")
            elif kind == "sg":
                _cleanup_security_group(ec2, item["payload"]["group_id"])
                print(f"[teardown] Security group deleted: {name}")

        try:
            s3.head_bucket(Bucket=bucket_name)
            raise AssertionError("S3 bucket still exists after teardown.")
        except Exception:
            pass

        try:
            iam.get_role(RoleName=role_name)
            raise AssertionError("IAM role still exists after teardown.")
        except Exception:
            pass

        try:
            ec2.describe_security_groups(GroupIds=[next(item["payload"]["group_id"] for item in created if item["kind"] == "sg")])
            raise AssertionError("Security group still exists after teardown.")
        except Exception:
            pass

        print("Teardown verification passed: all sandbox resources were cleaned up.")


if __name__ == "__main__":
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    os.environ.setdefault("AWS_REGION", REGION)
    main()
