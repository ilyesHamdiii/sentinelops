from sentinelops.collectors.aws import (
    collect_iam_assets,
    collect_s3_assets,
    collect_security_group_assets,
    evaluate_live_assets,
)


class FakeS3Client:
    def __init__(self):
        self._buckets = ["alpha-bucket", "beta-bucket"]

    def list_buckets(self):
        return {"Buckets": [{"Name": name} for name in self._buckets]}

    def get_bucket_tagging(self, Bucket):
        return {"TagSet": [{"Key": "Project", "Value": "sentinelops"}]}

    def get_public_access_block(self, Bucket):
        if Bucket == "alpha-bucket":
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "BlockPublicPolicy": True,
                    "IgnorePublicAcls": True,
                    "RestrictPublicBuckets": True,
                }
            }
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
        return {"Roles": [{"RoleName": "ops-role", "Arn": "arn:aws:iam::123:role/ops-role"}]}

    def list_policies(self):
        return {"Policies": [{"PolicyName": "admin-policy", "Arn": "arn:aws:iam::123:policy/admin-policy"}]}

    def get_role_policy(self, RoleName, PolicyName):
        return {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example/*"}]
            }
        }

    def get_policy_version(self, PolicyArn, VersionId):
        return {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }
            }
        }


class FakeEC2Client:
    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-123",
                    "GroupName": "safe-sg",
                    "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
                },
                {
                    "GroupId": "sg-456",
                    "GroupName": "unsafe-sg",
                    "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                },
            ]
        }


def test_collect_s3_assets_normalizes_bucket_state():
    assets = collect_s3_assets(FakeS3Client(), region="eu-west-1", account_id="123456789012")

    assert len(assets) == 2
    assert assets[0]["resource_type"] == "AWS::S3::Bucket"
    assert assets[0]["name"] in {"alpha-bucket", "beta-bucket"}
    assert "public_access_block" in assets[0]


def test_collect_iam_assets_normalizes_policy_statement_data():
    assets = collect_iam_assets(FakeIAMClient(), account_id="123456789012", region="eu-west-1")

    assert any(item["resource_type"] == "AWS::IAM::ManagedPolicy" for item in assets)
    assert any(item["resource_type"] == "AWS::IAM::Role" for item in assets)
    assert any(item.get("policy_statements") for item in assets)


def test_collect_security_group_assets_flags_public_ingress():
    assets = collect_security_group_assets(FakeEC2Client(), region="eu-west-1", account_id="123456789012")

    assert len(assets) == 2
    assert assets[0]["resource_type"] == "AWS::EC2::SecurityGroup"
    assert assets[1]["ingress"]


def test_evaluate_live_assets_returns_baseline_results():
    results = evaluate_live_assets(
        {
            "s3": collect_s3_assets(FakeS3Client(), region="eu-west-1", account_id="123456789012"),
            "iam": collect_iam_assets(FakeIAMClient(), account_id="123456789012", region="eu-west-1"),
            "security_groups": collect_security_group_assets(FakeEC2Client(), region="eu-west-1", account_id="123456789012"),
        }
    )

    assert results["summary"]["total_assets"] == 6
    assert results["summary"]["failures"] >= 2
    assert results["summary"]["unknown"] >= 0
