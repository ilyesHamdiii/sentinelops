"""Local release-readiness checks for SentinelOps portfolio delivery."""

from __future__ import annotations


def validate_release_package(
    *,
    version: str,
    demo_minutes: int,
    required_docs: list[str],
    sanitized_evidence: bool,
    teardown_documented: bool,
    cost_reviewed: bool,
    no_secrets_exposed: bool,
) -> dict:
    """Validate the local release package before any portfolio handoff."""
    checks = {
        "demo_minutes_ok": 5 <= demo_minutes <= 8,
        "cost_reviewed": cost_reviewed,
        "teardown_documented": teardown_documented,
        "sanitized_evidence": sanitized_evidence,
        "no_secrets_exposed": no_secrets_exposed,
        "required_docs_present": all(doc in required_docs for doc in [
            "README.md",
            "docs/progress.md",
        ]),
    }

    issues: list[dict] = []

    if not checks["demo_minutes_ok"]:
        issues.append({
            "code": "demo-length",
            "message": (
                "Release demo must be between 5 and 8 minutes for the "
                "planned portfolio demo."
            ),
        })

    if not sanitized_evidence:
        issues.append({
            "code": "sanitized-evidence",
            "message": "Evidence must be sanitized before release package handoff.",
        })

    if not teardown_documented:
        issues.append({
            "code": "teardown-missing",
            "message": "Teardown instructions must be documented for the release package.",
        })

    if not cost_reviewed:
        issues.append({
            "code": "cost-review",
            "message": "Cost review and cleanup expectations must be documented for release.",
        })

    if not no_secrets_exposed:
        issues.append({
            "code": "secrets-exposed",
            "message": "No secrets or credential identifiers may be exposed in release evidence.",
        })

    if not checks["required_docs_present"]:
        issues.append({
            "code": "missing-docs",
            "message": "README and progress log are required for release readiness.",
        })

    return {
        "version": version,
        "status": "PASS" if not issues else "FAIL",
        "checks": checks,
        "issues": issues,
    }
