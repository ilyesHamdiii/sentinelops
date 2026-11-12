"""Local CI hardening and pipeline safety checks for SentinelOps."""

from __future__ import annotations

import re

_STATIC_KEY_RE = re.compile(
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|aws_secret_access_key|aws_session_token|aws_access_key_id",
    re.IGNORECASE,
)


def detect_static_secret(value: str | None) -> bool:
    if not value:
        return False
    return bool(_STATIC_KEY_RE.search(value))


def validate_pipeline_hardening(
    *,
    workflow_name: str,
    commands: list[str],
    environment_vars: list[str] | None = None,
    uses_oidc: bool,
    static_secrets: list[str] | None = None,
) -> dict:
    """Validate a CI workflow against the SentinelOps local hardening policy."""
    issues: list[dict] = []
    environment_vars = environment_vars or []
    static_secrets = static_secrets or []

    if "deploy" in workflow_name.lower() and not uses_oidc:
        issues.append(
            {
                "code": "oidc-required",
                "message": "Deploy workflows must use OIDC instead of static AWS credentials.",
            }
        )

    for secret in static_secrets + environment_vars:
        if detect_static_secret(secret):
            issues.append(
                {
                    "code": "static-credentials",
                    "message": f"Static secret-like value detected in CI configuration: {secret}",
                }
            )

    if not any("pytest" in command.lower() for command in commands):
        issues.append(
            {
                "code": "pytest-missing",
                "message": "CI pipeline must include the project test suite.",
            }
        )

    if not any("ruff" in command.lower() for command in commands):
        issues.append(
            {
                "code": "lint-missing",
                "message": "CI pipeline must include linting checks before merge.",
            }
        )

    result = {
        "workflow_name": workflow_name,
        "status": "PASS" if not issues else "FAIL",
        "checks": {
            "oidc_required": uses_oidc or "deploy" not in workflow_name.lower(),
            "commands": commands,
        },
        "issues": issues,
    }
    return result
