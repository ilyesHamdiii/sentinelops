from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from sentinelops.api.app import app
from sentinelops.aws_identity import AWSIdentityContext, assume_role_session, validate_session_permissions
from sentinelops.collectors.aws import (
    collect_iam_assets,
    collect_s3_assets,
    collect_security_group_assets,
)
from sentinelops.remediation import (
    ApprovedRemediationAction,
    RemediationWorkflow,
    approve_remediation,
    execute_remediation,
    validate_remediation_approval,
)
from sentinelops.reporting.reporting import sanitize_payload
from sentinelops.risk import evaluate_risk_for_findings
from sentinelops.scenarios import evaluate_scenario

api_module = importlib.import_module("sentinelops.api.app")


class FakeSTSClient:
    def __init__(self, *, caller_identity=None, assume_result=None, error=None):
        self.caller_identity = caller_identity or {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/sentinelops-reader/assessment",
            "UserId": "AIDAXXXXXXXXXXXXX",
        }
        self.assume_result = assume_result or {
            "Credentials": {
                "AccessKeyId": "ASIAFAKEKEY",
                "SecretAccessKey": "fake-secret",
                "SessionToken": "fake-session-token",
                "Expiration": datetime.now(timezone.utc).replace(microsecond=0) + timedelta(hours=1),
            },
            "AssumedRoleUser": {
                "Arn": "arn:aws:sts::123456789012:assumed-role/sentinelops-reader/assessment",
                "AssumedRoleId": "AROAFake",
            },
        }
        self.error = error

    def assume_role(self, RoleArn, RoleSessionName, DurationSeconds=None):
        if self.error is not None:
            raise self.error
        return self.assume_result

    def get_caller_identity(self):
        if self.error is not None:
            raise self.error
        return self.caller_identity


class FakeS3Client:
    def __init__(self, *, public_access_block=None):
        self.bucket_state = {
            "public-bucket": {
                "public_access_block": public_access_block or {
                    "BlockPublicAcls": False,
                    "BlockPublicPolicy": False,
                    "IgnorePublicAcls": False,
                    "RestrictPublicBuckets": False,
                },
                "bucket_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::public-bucket/*",
                        }
                    ]
                },
            }
        }

    def list_buckets(self):
        return {
            "Buckets": [{"Name": name} for name in self.bucket_state],
        }

    def get_bucket_tagging(self, Bucket):
        return {"TagSet": [{"Key": "Name", "Value": Bucket}]}

    def get_public_access_block(self, Bucket):
        state = self.bucket_state[Bucket]
        return {"PublicAccessBlockConfiguration": state["public_access_block"]}


class FakeIAMClient:
    def list_roles(self):
        return {
            "Roles": [
                {
                    "RoleName": "sentinelops-reader",
                    "Arn": "arn:aws:iam::123456789012:role/sentinelops-reader",
                }
            ]
        }

    def list_role_policies(self, RoleName):
        return {"PolicyNames": ["inline-policy"]}

    def get_role_policy(self, RoleName, PolicyName):
        return {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    }
                ]
            }
        }

    def list_policies(self):
        return {
            "Policies": [
                {
                    "PolicyName": "overprivileged-policy",
                    "Arn": "arn:aws:iam::123456789012:policy/overprivileged-policy",
                }
            ]
        }

    def get_policy_version(self, PolicyArn, VersionId):
        return {
            "PolicyVersion": {
                "Document": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:*",
                            "Resource": "*",
                        }
                    ]
                }
            }
        }


class FakeEC2Client:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1234567890",
                    "GroupName": "public-admin-sg",
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }


def _synthetic_assessment_bundle():
    identity = AWSIdentityContext(
        account_id="123456789012",
        region="eu-west-1",
        role_arn="arn:aws:iam::123456789012:role/sentinelops-reader",
        role_type="read_only",
        session_name="synthetic-evidence",
    )
    sts_client = FakeSTSClient()
    assumed = assume_role_session(
        sts_client=sts_client,
        role_arn=identity.role_arn,
        session_name=identity.session_name,
        region=identity.region,
        account_id=identity.account_id,
    )
    assert assumed["account_id"] == identity.account_id
    validate_session_permissions(sts_client)

    s3_assets = collect_s3_assets(FakeS3Client(), region=identity.region, account_id=identity.account_id)
    iam_assets = collect_iam_assets(FakeIAMClient(), region=identity.region, account_id=identity.account_id)
    sg_assets = collect_security_group_assets(FakeEC2Client(), region=identity.region, account_id=identity.account_id)

    normalized = [sanitize_payload(item) for group in (s3_assets, iam_assets, sg_assets) for item in group]
    bucket_evidence = {
        "public_access_block": s3_assets[0]["public_access_block"],
        "bucket_policy": {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-bucket/*",
                }
            ]
        },
    }
    iam_evidence = {"policy_statements": iam_assets[0]["policy_statements"]}
    sg_evidence = {"ingress": sg_assets[0]["ingress"]}

    findings = [
        {
            "id": "fg-s3-001",
            "resource": {"id": "arn:aws:s3:::public-bucket", "type": "AWS::S3::Bucket"},
            "scenario_id": "S1",
            "title": "Public S3 bucket exposure",
            "description": "The bucket allows public access and unauthenticated reads.",
            "severity_source": "HIGH",
            "confidence": "HIGH",
            "asset_criticality": "critical",
            "platform_risk": "high",
            "source": "synthetic-evidence",
            "risk_score": 0,
            "evidence": bucket_evidence,
            "action_required": "s3_block_public_access",
        },
        {
            "id": "fg-iam-001",
            "resource": {"id": "arn:aws:iam::123456789012:policy/overprivileged-policy", "type": "AWS::IAM::ManagedPolicy"},
            "scenario_id": "S2",
            "title": "IAM wildcard access",
            "description": "The managed policy grants wildcard administrative access in the mock environment.",
            "severity_source": "CRITICAL",
            "confidence": "HIGH",
            "asset_criticality": "critical",
            "platform_risk": "high",
            "source": "synthetic-evidence",
            "risk_score": 0,
            "evidence": iam_evidence,
            "action_required": "iam_remove_wildcard_policy",
        },
        {
            "id": "fg-sg-001",
            "resource": {"id": "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-1234567890", "type": "AWS::EC2::SecurityGroup"},
            "scenario_id": "S3",
            "title": "Public ingress to administrative port",
            "description": "The security group exposes SSH to 0.0.0.0/0.",
            "severity_source": "HIGH",
            "confidence": "HIGH",
            "asset_criticality": "high",
            "platform_risk": "high",
            "source": "synthetic-evidence",
            "risk_score": 0,
            "evidence": sg_evidence,
            "action_required": "security_group_restrict_ingress",
        },
    ]

    for finding in findings:
        finding["scenario_result"] = evaluate_scenario(finding["scenario_id"], finding["evidence"])
        finding["risk_score"] = max(0, evaluate_risk_for_findings([finding])[0]["risk_score"])
        finding["status"] = "OPEN"
        finding["severity"] = finding["severity_source"]
        finding["evidence_refs"] = [
            f"{finding['resource']['id']}/{finding['scenario_id']}",
        ]

    return {
        "identity": identity,
        "assumed": assumed,
        "assets": normalized,
        "scenario_findings": findings,
    }


def test_assessment_pipeline_integrates_identity_collection_scenarios_and_api_reporting():
    bundle = _synthetic_assessment_bundle()
    assert bundle["assumed"]["account_id"] == "123456789012"
    assert bundle["assumed"]["region"] == "eu-west-1"

    assert evaluate_scenario("S1", bundle["scenario_findings"][0]["evidence"])["status"] == "finding_detected"
    assert evaluate_scenario("S2", bundle["scenario_findings"][1]["evidence"])["status"] == "finding_detected"
    assert evaluate_scenario("S3", bundle["scenario_findings"][2]["evidence"])["status"] == "finding_detected"

    original_findings = list(api_module.FINDINGS)
    api_module.FINDINGS[:] = [
        {
            "id": item["id"],
            "title": item["title"],
            "description": item["description"],
            "severity": item["severity"],
            "status": item["status"],
            "risk_score": item["risk_score"],
            "resource_id": item["resource"]["id"],
            "evidence_refs": item["evidence_refs"],
            "scenario_id": item["scenario_id"],
        }
        for item in bundle["scenario_findings"]
    ]

    try:
        client = TestClient(app)
        response = client.get("/findings")
        assert response.status_code == 200
        payload = response.json()
        assert payload["total"] >= 3
        assert payload["items"][0]["resource_id"]
        assert any(item["scenario_id"] == "S1" for item in payload["items"])
        assert any(item["scenario_id"] == "S2" for item in payload["items"])
        assert any(item["scenario_id"] == "S3" for item in payload["items"])
    finally:
        api_module.FINDINGS[:] = original_findings


def test_remediation_pipeline_enforces_approval_and_verifies_post_change_state():
    bundle = _synthetic_assessment_bundle()
    target = bundle["scenario_findings"][0]["resource"]["id"]
    action = ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS
    reason = "Restrict public bucket access after confirming anonymous reads."
    approval = approve_remediation(action=action, target=target, reason=reason)

    assert validate_remediation_approval(
        action=action,
        target=target,
        reason=reason,
        approval_hash=approval["hash"],
        approved=True,
        created_at=approval["created_at"],
    ) is True

    rejected = execute_remediation(
        action=action,
        target=target,
        reason=reason,
        approval={"approved": False},
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )
    assert rejected["status"] == "REJECTED"

    mock_public_bucket = {
        "public_access_block": {"BlockPublicAcls": False, "BlockPublicPolicy": False},
        "bucket_policy": {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-bucket/*"}]
        },
    }

    remediation_result = execute_remediation(
        action=action,
        target=target,
        reason=reason,
        approval=approval,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )
    assert remediation_result["status"] == "VERIFIED"
    assert remediation_result["state"] == "RESOLVED"

    mock_public_bucket["public_access_block"] = {
        "BlockPublicAcls": True,
        "BlockPublicPolicy": True,
        "IgnorePublicAcls": True,
        "RestrictPublicBuckets": True,
    }
    mock_public_bucket["bucket_policy"] = {"Statement": []}

    post_fix = evaluate_scenario(
        "S1",
        {
            "public_access_block": mock_public_bucket["public_access_block"],
            "bucket_policy": mock_public_bucket["bucket_policy"],
        },
    )
    assert post_fix["status"] == "no_finding_detected"

    workflow = RemediationWorkflow()
    approval_again = workflow.create_approval(
        action=action,
        target=target,
        reason=reason,
    )
    first = workflow.execute(
        approval=approval_again,
        action=action,
        target=target,
        reason=reason,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )
    second = workflow.execute(
        approval=approval_again,
        action=action,
        target=target,
        reason=reason,
        before_state={"public_access_block": False},
        after_state={"public_access_block": True},
        verification_passed=True,
    )
    assert first["status"] == "VERIFIED"
    assert second["status"] == "REJECTED"


@pytest.mark.parametrize(
    ("operation", "expected_state"),
    [
        (lambda: validate_session_permissions(FakeSTSClient(error=RuntimeError("missing credentials"))), "ERROR"),
        (lambda: assume_role_session(
            sts_client=FakeSTSClient(error=RuntimeError("expired credentials")),
            role_arn="arn:aws:iam::123456789012:role/sentinelops-reader",
            session_name="expired",
            region="eu-west-1",
            account_id="123456789012",
        ), "ERROR"),
        (lambda: validate_remediation_approval(
            action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
            target="arn:aws:s3:::example-bucket",
            reason="Test approval expiry",
            approval_hash="bad-hash",
            approved=True,
            created_at=datetime.now(timezone.utc) - timedelta(hours=2),
            current_time=datetime.now(timezone.utc),
            approval_ttl_seconds=60,
        ), "REJECTED"),
        (lambda: execute_remediation(
            action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
            target="arn:aws:s3:::example-bucket",
            reason="Test mismatched resource",
            approval=approve_remediation(
                action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
                target="arn:aws:s3:::other-bucket",
                reason="Different resource",
            ),
            before_state={"public_access_block": False},
            after_state={"public_access_block": True},
            verification_passed=True,
        ), "REJECTED"),
        (lambda: execute_remediation(
            action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
            target="arn:aws:ec2:eu-west-1:123456789012:security-group/sg-123",
            reason="Restrict SSH access.",
            approval=approve_remediation(
                action=ApprovedRemediationAction.SECURITY_GROUP_RESTRICT_INGRESS,
                target="arn:aws:ec2:eu-west-1:123456789012:security-group/sg-123",
                reason="Restrict SSH access.",
            ),
            before_state={"ingress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22}], "approved": True},
            after_state={"ingress": [{"CidrIp": "0.0.0.0/0", "FromPort": 22}], "approved": True},
            verification_passed=False,
        ), "FAILED"),
        (lambda: execute_remediation(
            action="unsupported_action",
            target="arn:aws:s3:::example-bucket",
            reason="Attempt unsupported action",
            approval=approve_remediation(
                action=ApprovedRemediationAction.S3_BLOCK_PUBLIC_ACCESS,
                target="arn:aws:s3:::example-bucket",
                reason="Allowlisted request",
            ),
            before_state={"public_access_block": False},
            after_state={"public_access_block": True},
            verification_passed=True,
        ), "REJECTED"),
    ],
)
def test_security_failure_conditions_are_rejected_without_successful_remediation(operation, expected_state):
    try:
        result = operation()
        if expected_state == "ERROR":
            pytest.fail("Expected an exception to be raised for invalid AWS state")
        if expected_state in {"FAILED", "REJECTED"}:
            if isinstance(result, dict):
                assert result["status"] == expected_state
                assert result["state"] in {"OPEN", "FAILED"}
            else:
                assert result is False
        else:
            raise AssertionError(f"Unexpected state: {expected_state}")
    except PermissionError:
        assert expected_state == "ERROR"
    except ValueError:
        assert expected_state == "REJECTED"
    except Exception as exc:  # pragma: no cover - sanity guard for unexpected behavior
        pytest.fail(f"Unexpected exception: {type(exc).__name__}: {exc}")
