from sentinelops.validation.scenarios import (
    SCENARIO_DEFINITIONS,
    validate_scenario_definition,
    validate_scenario_result,
)


def test_six_scenarios_are_defined_and_named():
    assert sorted(SCENARIO_DEFINITIONS) == [
        "S1",
        "S2",
        "S3",
        "S4",
        "S5",
        "S6",
    ]
    assert SCENARIO_DEFINITIONS["S1"]["title"] == "Public or unsafe S3 access"


def test_scenario_definitions_require_expected_outcome_and_id():
    valid = {
        "scenario_id": "S3",
        "title": "Network exposure",
        "expected_outcome": "finding_detected",
    }
    invalid = {"scenario_id": "S9", "title": "Unknown scenario"}

    assert validate_scenario_definition(valid) is True
    assert validate_scenario_definition(invalid) is False


def test_expected_outcome_is_checked_without_live_aws_access():
    assert validate_scenario_result("S1", "finding_detected", "finding_detected") == "PASS"
    assert validate_scenario_result("S1", "finding_detected", "no_finding_detected") == "FAIL"
    assert validate_scenario_result("S9", "finding_detected", "finding_detected") == "UNKNOWN"
