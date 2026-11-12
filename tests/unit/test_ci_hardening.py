from sentinelops.validation.hardening import validate_pipeline_hardening


def test_secure_pr_pipeline_is_accepted():
    result = validate_pipeline_hardening(
        workflow_name="sentinelops-pr",
        commands=["python -m ruff check src tests", "python -m pytest -q"],
        environment_vars=["AWS_REGION=eu-east-1"],
        uses_oidc=True,
        static_secrets=[],
    )

    assert result["status"] == "PASS"
    assert result["checks"]["oidc_required"] is True
    assert "python -m pytest -q" in result["checks"]["commands"]


def test_static_credentials_and_missing_oidc_fail_the_pipeline():
    result = validate_pipeline_hardening(
        workflow_name="sentinelops-deploy",
        commands=["python -m pytest -q"],
        environment_vars=["AWS_ACCESS_KEY_ID=AKIA1234567890EXAMPLE"],
        uses_oidc=False,
        static_secrets=["AWS_ACCESS_KEY_ID=AKIA1234567890EXAMPLE"],
    )

    assert result["status"] == "FAIL"
    assert any(issue["code"] == "static-credentials" for issue in result["issues"])
    assert any(issue["code"] == "oidc-required" for issue in result["issues"])
