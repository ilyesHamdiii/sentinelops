from sentinelops.scenarios import (
    SCENARIO_DEFINITIONS,
    evaluate_scenario,
    validate_scenario_definition,
    validate_scenario_result,
)


def test_six_scenarios_are_defined_and_named():
    assert sorted(SCENARIO_DEFINITIONS) == ["S1", "S2", "S3", "S4", "S5", "S6"]
    assert SCENARIO_DEFINITIONS["S1"]["title"] == "Public or unsafe S3 access"
    assert SCENARIO_DEFINITIONS["S6"]["expected_outcome"] == "drift_detected"


def test_scenario_definitions_require_valid_id_and_expected_outcome():
    valid = {"scenario_id": "S3", "title": "Network exposure", "expected_outcome": "finding_detected"}
    invalid = {"scenario_id": "S9", "title": "Unknown scenario"}

    assert validate_scenario_definition(valid) is True
    assert validate_scenario_definition(invalid) is False


def test_s1_s3_public_access_detects_and_rejects_safe_bucket():
    public_bucket = {
        "bucket_name": "sentinelops-public-demo",
        "public_access_block": {"BlockPublicAcls": False, "BlockPublicPolicy": False},
        "bucket_policy": {
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::sentinelops-public-demo/*",
            }]
        },
    }
    secure_bucket = {
        "bucket_name": "sentinelops-private-demo",
        "public_access_block": {
            "BlockPublicAcls": True,
            "BlockPublicPolicy": True,
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
        "bucket_policy": {"Statement": []},
    }

    assert evaluate_scenario("S1", public_bucket)["status"] == "finding_detected"
    assert evaluate_scenario("S1", secure_bucket)["status"] == "no_finding_detected"


def test_s2_s3_and_iam_case_detection_and_negative_regression():
    risky_policy = {
        "policy_statements": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    }
    safe_policy = {
        "policy_statements": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::demo-bucket/*",
        }],
    }

    assert evaluate_scenario("S2", risky_policy)["status"] == "finding_detected"
    assert evaluate_scenario("S2", safe_policy)["status"] == "no_finding_detected"


def test_s3_security_group_detection_and_safe_regression():
    exposed = {
        "ingress": [{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIp": "0.0.0.0/0",
        }],
    }
    safe = {
        "ingress": [{
            "IpProtocol": "tcp",
            "FromPort": 443,
            "ToPort": 443,
            "CidrIp": "10.0.0.0/8",
        }],
    }

    assert evaluate_scenario("S3", exposed)["status"] == "finding_detected"
    assert evaluate_scenario("S3", safe)["status"] == "no_finding_detected"


def test_s4_cloudtrail_tampering_detection_and_safe_regression():
    tampered = {
        "trail": {"is_multi_region_trail": False, "log_file_validation_enabled": False},
        "recent_events": [{"eventName": "DeleteTrail"}],
    }
    secure = {
        "trail": {"is_multi_region_trail": True, "log_file_validation_enabled": True},
        "recent_events": [{"eventName": "ListBuckets"}],
    }

    assert evaluate_scenario("S4", tampered)["status"] == "finding_detected"
    assert evaluate_scenario("S4", secure)["status"] == "no_finding_detected"


def test_s5_encryption_and_secret_weakness_detection():
    weak = {
        "sse_enabled": False,
        "kms_key_id": None,
        "secret_rotation_enabled": False,
    }
    strong = {
        "sse_enabled": True,
        "kms_key_id": "alias/sentinelops-key",
        "secret_rotation_enabled": True,
    }

    assert evaluate_scenario("S5", weak)["status"] == "finding_detected"
    assert evaluate_scenario("S5", strong)["status"] == "no_finding_detected"


def test_s6_configuration_drift_detection_and_resolution():
    drifted = {
        "expected_state": {"public_access_block": True},
        "actual_state": {"public_access_block": False},
    }
    stable = {
        "expected_state": {"public_access_block": True},
        "actual_state": {"public_access_block": True},
    }

    assert evaluate_scenario("S6", drifted)["status"] == "drift_detected"
    assert evaluate_scenario("S6", stable)["status"] == "drift_resolved"


def test_unknown_scenario_and_result_validation_are_conservative():
    assert validate_scenario_result("S1", "finding_detected", "finding_detected") == "PASS"
    assert validate_scenario_result("S1", "finding_detected", "no_finding_detected") == "FAIL"
    assert validate_scenario_result("S9", "finding_detected", "finding_detected") == "UNKNOWN"
    assert evaluate_scenario("S9", {})["status"] == "unknown"
