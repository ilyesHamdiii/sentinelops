"""Synthetic local demonstration of the SentinelOps workflow.

This script intentionally exercises the mock-based assessment and remediation
pipeline without contacting AWS. It is designed to show the operator the exact
local workflow and evidence trails used by SentinelOps during validation only.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from sentinelops.api.app import app, FINDINGS
from sentinelops.aws_identity import AWSIdentityContext, assume_role_session, validate_session_permissions
from sentinelops.collectors.aws import (
    collect_iam_assets,
    collect_s3_assets,
    collect_security_group_assets,
)
from sentinelops.remediation import ApprovedRemediationAction, approve_remediation, execute_remediation
from sentinelops.risk import evaluate_risk_for_findings
from sentinelops.scenarios import evaluate_scenario


class FakeSTSClient:
    def assume_role(self, RoleArn, RoleSessionName, DurationSeconds=None):
        return {
            "Credentials": {
                "AccessKeyId": "ASIAFAKEKEY",
                "SecretAccessKey": "fake-secret",
                "SessionToken": "fake-session-token",
                "Expiration": datetime.now(timezone.utc).replace(microsecond=0),
            },
            "AssumedRoleUser": {
                "Arn": RoleArn,
                "AssumedRoleId": "AROAFAKE",
            },
        }

    def get_caller_identity(self):
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/sentinelops-reader/demo",
            "UserId": "AIDAXXX",
        }


class FakeS3Client:
    def list_buckets(self):
        return {"Buckets": [{"Name": "public-bucket"}]}

    def get_bucket_tagging(self, Bucket):
        return {"TagSet": [{"Key": "Name", "Value": Bucket}]}

    def get_public_access_block(self, Bucket):
        return {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "BlockPublicPolicy": False,
                "IgnorePublicAcls": False,
                "RestrictPublicBuckets": False,
            }
        }


class FakeIAMClient:
    def list_roles(self):
        return {"Roles": [{"RoleName": "demo-role", "Arn": "arn:aws:iam::123456789012:role/demo-role"}]}

    def list_role_policies(self, RoleName):
        return {"PolicyNames": ["demo-policy"]}

    def get_role_policy(self, RoleName, PolicyName):
        return {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}

    def list_policies(self):
        return {"Policies": [{"PolicyName": "demo-policy", "Arn": "arn:aws:iam::123456789012:policy/demo-policy"}]}

    def get_policy_version(self, PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}}}


class FakeEC2Client:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-demo-01",
                    "GroupName": "public-admin-sg",
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }],
                }
            ]
        }


def build_findings():
    identity = AWSIdentityContext(
        account_id="123456789012",
        region="eu-west-1",
        role_arn="arn:aws:iam::123456789012:role/sentinelops-reader",
        role_type="read_only",
        session_name="synthetic-demo",
    )
    assume_role_session(
        sts_client=FakeSTSClient(),
        role_arn=identity.role_arn,
        session_name=identity.session_name,
        region=identity.region,
        account_id=identity.account_id,
    )
    validate_session_permissions(FakeSTSClient())

    s3_assets = collect_s3_assets(FakeS3Client(), region=identity.region, account_id=identity.account_id)
    iam_assets = collect_iam_assets(FakeIAMClient(), region=identity.region, account_id=identity.account_id)
    sg_assets = collect_security_group_assets(FakeEC2Client(), region=identity.region, account_id=identity.account_id)

    findings = [
        {
            "id": "fg-01",
            "title": "Public S3 bucket exposure",
            "description": "Bucket exposes public read access.",
            "severity_source": "HIGH",
            "confidence": "HIGH",
            "asset_criticality": "critical",
            "platform_risk": "high",
            "source": "synthetic-demo",
            "resource": {"id": "arn:aws:s3:::public-bucket", "type": "AWS::S3::Bucket"},
            "evidence": {
                "public_access_block": s3_assets[0]["public_access_block"],
                "bucket_policy": {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-bucket/*"}]},
            },
            "scenario_id": "S1",
            "risk_score": 0,
        },
        {
            "id": "fg-02",
            "title": "IAM wildcard access",
            "description": "Policy grants unrestricted administrative access.",
            "severity_source": "CRITICAL",
            "confidence": "HIGH",
            "asset_criticality": "critical",
            "platform_risk": "high",
            "source": "synthetic-demo",
            "resource": {"id": "arn:aws:iam::123456789012:policy/demo-policy", "type": "AWS::IAM::ManagedPolicy"},
            "evidence": {"policy_statements": iam_assets[0]["policy_statements"]},
            "scenario_id": "S2",
            "risk_score": 0,
        },
        {
            "id": "fg-03",
            "title": "Public ingress to administrative port",
            "description": "Security group exposes SSH to the internet.",
            "severity_source": "HIGH",
            "confidence": "HIGH",
            "asset_criticality": "high",
            "platform_risk": "high",
            "source": "synthetic-demo",
            "resource": {"id": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-demo-01", "type": "AWS::EC2::SecurityGroup"},
            "evidence": {"ingress": sg_assets[0]["ingress"]},
            "scenario_id": "S3",
            "risk_score": 0,
        },
    ]

    for index, finding in enumerate(findings):
        result = evaluate_scenario(finding["scenario_id"], finding["evidence"])
        finding["scenario_result"] = result
        finding["risk_score"] = evaluate_risk_for_findings([finding])[0]["risk_score"]
        finding["status"] = "OPEN"
        finding["severity"] = finding["severity_source"]
        finding["evidence_refs"] = [f"demo://evidence/{index + 1}"]
        finding["finding_id"] = finding["id"]

    return findings


if __name__ == "__main__":
    print("Synthetic/mock SentinelOps demonstration (not live AWS validation)")
    findings = build_findings()
    for finding in findings:
        print(f"- {finding['title']} | scenario={finding['scenario_id']} | score={finding['risk_score']} | status={finding['status']}")

    target = findings[0]["resource"]["id"]
    approval = approve_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target=target,
        reason="Restrict public access on the demo bucket after confirming anonymous reads.",
    )
    remediation_result = execute_remediation(
        action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
        target=target,
        reason=approval["reason"],
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )
    print(f"Approval: {approval['approved']} | hash={approval['hash'][:12]}")
    print(f"Remediation result: {remediation_result['status']} | state={remediation_result['state']}")

    original = list(FINDINGS)
    FINDINGS[:] = [
        {
            "id": item["id"],
            "title": item["title"],
            "description": item["description"],
            "severity": item["severity_source"],
            "status": item["status"],
            "risk_score": item["risk_score"],
            "resource_id": item["resource"]["id"],
            "evidence_refs": item["evidence_refs"],
            "scenario_id": item["scenario_id"],
        }
        for item in findings
    ]
    try:
        client = TestClient(app)
        response = client.get("/findings")
        payload = response.json()
        print(f"API finding count: {payload['count']} | total: {payload['total']}")
    finally:
        FINDINGS[:] = original
