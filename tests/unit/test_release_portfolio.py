from sentinelops.validation.release import validate_release_package


def test_release_package_is_ready_when_docs_and_costs_are_complete():
    result = validate_release_package(
        version="0.1.0",
        demo_minutes=7,
        required_docs=[
            "README.md",
            "docs/progress.md",
            "docs/architecture/overview.md",
            "docs/adr/README.md",
            "docs/cost/cost-review.md",
        ],
        sanitized_evidence=True,
        teardown_documented=True,
        cost_reviewed=True,
        no_secrets_exposed=True,
    )

    assert result["status"] == "PASS"
    assert result["checks"]["demo_minutes_ok"] is True
    assert result["checks"]["cost_reviewed"] is True


def test_release_package_fails_when_demo_or_evidence_is_not_ready():
    result = validate_release_package(
        version="0.1.0",
        demo_minutes=10,
        required_docs=["README.md", "docs/progress.md"],
        sanitized_evidence=False,
        teardown_documented=False,
        cost_reviewed=False,
        no_secrets_exposed=False,
    )

    assert result["status"] == "FAIL"
    assert any(issue["code"] == "sanitized-evidence" for issue in result["issues"])
    assert any(issue["code"] == "demo-length" for issue in result["issues"])
