from sentinelops.validation.integrations import (
    SUPPORTED_FINDING_SOURCES,
    dedupe_key,
    is_supported_finding_source,
    validate_supported_finding,
)


def test_supported_sources_include_expected_aws_integrations():
    assert SUPPORTED_FINDING_SOURCES == {
        "securityhub",
        "guardduty",
        "aws_config",
        "sentinelops",
    }


def test_supported_sources_reject_unsupported_well_known_value():
    assert not is_supported_finding_source("cloudtrail")
    assert is_supported_finding_source("guardduty")


def test_dedupe_key_is_stable_for_same_source_finding_id():
    first = {
        "source": "securityhub",
        "source_finding_id": "finding-abc",
        "account_id": "123456789012",
        "region": "eu-east-1",
    }
    second = {
        "source": "securityhub",
        "source_finding_id": "finding-abc",
        "account_id": "123456789012",
        "region": "eu-east-1",
    }

    assert dedupe_key(first) == dedupe_key(second)


def test_validate_supported_finding_rejects_missing_or_unsupported_metadata():
    unsupported = {"source": "cloudtrail", "account_id": "123456789012"}
    valid = {
        "source": "guardduty",
        "source_finding_id": "finding-1",
        "account_id": "123456789012",
        "region": "eu-east-1",
    }

    assert validate_supported_finding(unsupported) is False
    assert validate_supported_finding(valid) is True
