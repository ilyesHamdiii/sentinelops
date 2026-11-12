from sentinelops.validation.baseline import evaluate_baseline


def test_secure_s3_bucket_passes_baseline_check():
    asset = {
        "resource_type": "AWS::S3::Bucket",
        "name": "sentinelops-secure-bucket",
        "public_access_block": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
    }

    result = evaluate_baseline(asset)

    assert result["status"] == "PASS"
    assert result["resource_type"] == "AWS::S3::Bucket"
    assert not result["findings"]


def test_insecure_s3_bucket_fails_baseline_check():
    asset = {
        "resource_type": "AWS::S3::Bucket",
        "name": "sentinelops-public-bucket",
        "public_access_block": {
            "BlockPublicAcls": False,
            "BlockPublicPolicy": False,
            "IgnorePublicAcls": False,
            "RestrictPublicBuckets": False,
        },
    }

    result = evaluate_baseline(asset)

    assert result["status"] == "FAIL"
    assert any("public access block" in finding.lower() for finding in result["findings"])


def test_security_group_with_open_ssh_fails_baseline_check():
    asset = {
        "resource_type": "AWS::EC2::SecurityGroup",
        "name": "public-web-sg",
        "ingress": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"},
        ],
    }

    result = evaluate_baseline(asset)

    assert result["status"] == "FAIL"
    assert "22" in " ".join(result["findings"])


def test_unknown_resource_is_marked_unknown():
    asset = {"resource_type": "AWS::Lambda::Function", "name": "sample"}

    result = evaluate_baseline(asset)

    assert result["status"] == "UNKNOWN"
    assert "not yet evaluated" in result["summary"].lower()
