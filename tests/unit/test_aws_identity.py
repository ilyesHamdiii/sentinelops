from sentinelops.aws_identity import (
    AWSIdentityContext,
    assume_role_session,
    validate_account_id,
    validate_aws_region,
    validate_session_permissions,
)


def test_validate_account_id_accepts_twelve_digit_ids():
    assert validate_account_id("123456789012") == "123456789012"


def test_validate_account_id_rejects_invalid_ids():
    try:
        validate_account_id("not-an-account")
    except ValueError as exc:
        assert "12-digit" in str(exc)
    else:
        raise AssertionError("Expected ValueError for invalid account ID")


def test_validate_aws_region_accepts_supported_region():
    assert validate_aws_region("eu-west-1") == "eu-west-1"


def test_validate_aws_region_rejects_unsupported_region():
    try:
        validate_aws_region("us-east-1")
    except ValueError as exc:
        assert "eu-west-1" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unsupported region")


def test_aws_identity_context_tracks_role_and_provenance():
    context = AWSIdentityContext(
        account_id="123456789012",
        region="eu-west-1",
        role_arn="arn:aws:iam::123456789012:role/sentinelops-reader",
        role_type="read_only",
        session_name="sentinelops-assessment",
    )

    assert context.account_id == "123456789012"
    assert context.region == "eu-west-1"
    assert context.role_type == "read_only"
    assert context.provenance == "aws_assume_role"
    assert context.session_name == "sentinelops-assessment"


def test_assume_role_session_generates_context_from_sts_response():
    class FakeSTSClient:
        def assume_role(self, RoleArn, RoleSessionName, DurationSeconds=None):
            return {
                "Credentials": {
                    "AccessKeyId": "AKIAFAKE",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                    "Expiration": "2026-01-01T00:00:00Z",
                },
                "AssumedRoleUser": {"Arn": RoleArn, "AssumedRoleId": "AROAFAKE"},
            }

    result = assume_role_session(
        sts_client=FakeSTSClient(),
        role_arn="arn:aws:iam::123456789012:role/sentinelops-reader",
        session_name="sentinelops-assessment",
        region="eu-west-1",
        account_id="123456789012",
    )

    assert result["account_id"] == "123456789012"
    assert result["region"] == "eu-west-1"
    assert result["role_arn"] == "arn:aws:iam::123456789012:role/sentinelops-reader"
    assert result["session_name"] == "sentinelops-assessment"
    assert result["provenance"] == "aws_assume_role"


def test_validate_session_permissions_rejects_missing_credentials():
    class FakeSTSClient:
        def get_caller_identity(self):
            raise RuntimeError("No credentials available")

    try:
        validate_session_permissions(FakeSTSClient())
    except PermissionError as exc:
        assert "credentials" in str(exc).lower()
    else:
        raise AssertionError("Expected PermissionError when AWS credentials are missing")
