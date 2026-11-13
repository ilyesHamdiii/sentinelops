import json
from pathlib import Path

import boto3

from sentinelops.scenarios import evaluate_scenario

cache_dir = Path.home() / ".aws" / "login" / "cache"
cache_file = next(cache_dir.glob("*.json"))
obj = json.loads(cache_file.read_text())
creds = obj["accessToken"]

session = boto3.Session(
    aws_access_key_id=creds["accessKeyId"],
    aws_secret_access_key=creds["secretAccessKey"],
    aws_session_token=creds["sessionToken"],
    region_name="eu-west-1",
)

s3 = session.client("s3", region_name="eu-west-1")
iam = session.client("iam", region_name="eu-west-1")
ec2 = session.client("ec2", region_name="eu-west-1")

bucket_name = "sentinelops-demo-public-bucket-001"
sg_id = "sg-080bf854cd7fbc613"

public_block = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
bucket_policy = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
s1 = evaluate_scenario("S1", {"public_access_block": public_block, "bucket_policy": bucket_policy})

role_name = "sentinelops-demo-iam-wildcard-role"
policy_name = iam.list_role_policies(RoleName=role_name)["PolicyNames"][0]
policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)["PolicyDocument"]
s2 = evaluate_scenario("S2", {"policy_statements": policy_doc.get("Statement", [])})

def make_ingress_entries(group):
    entries = []
    for permission in group.get("IpPermissions", []):
        for cidr in permission.get("IpRanges", []):
            entries.append(
                {
                    "CidrIp": cidr.get("CidrIp"),
                    "IpProtocol": permission.get("IpProtocol"),
                    "FromPort": permission.get("FromPort"),
                    "ToPort": permission.get("ToPort"),
                }
            )
    return entries

group = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]

s3_result = evaluate_scenario("S3", {"ingress": make_ingress_entries(group)})
result = {"S1": s1, "S2": s2, "S3": s3_result}

out = Path("evidence/live-discovery-2026-11-13.json")
out.write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
