# SentinelOps release and portfolio runbook

## Purpose

This runbook documents how to prepare and present the SentinelOps release package in a safe, reproducible, no-secret posture. It is intentionally local-first and does not assume any live AWS provisioning or account access.

## Prerequisites

- Local clone of the SentinelOps repository.
- Python 3.11+ installed.
- Project dependencies installed via `python -m pip install -e ".[dev]"`.
- A clean repo state with the latest approved docs and test results.
- No active AWS credentials or deployment secrets in the environment.

## Required readiness checks

1. Confirm the repository is green:
   - `python -m pytest -q`
   - `python -m ruff check src tests`
2. Confirm the project tracker is current:
   - `docs/progress.md`
3. Confirm architecture and cost evidence exists:
   - `docs/architecture/overview.md`
   - `docs/cost/cost-review.md`
4. Confirm ADR and governance references are present:
   - `docs/adr/README.md`
5. Confirm no sensitive identifiers are included in logs, screenshots, or evidence.

## Portfolio demo flow

1. Open the project overview in the README.
2. Explain the problem statement and the no-deploy guardrail.
3. Show the architecture overview and trust boundaries.
4. Summarize the risk engine and scenario validation model.
5. Walk through a sample finding and the approval-gated remediation flow.
6. Show the sanitized report output and evidence trail.
7. Close on the cost, cleanup, and operating-limitations summary.

## Demo configuration

- Target duration: 5-8 minutes.
- Keep the narrative on architecture, evidence, and controls rather than live infrastructure.
- If a screenshot is included, ensure it contains no AWS account IDs, credentials, or raw logs.

## Rollback and cleanup

- No live AWS rollout is required for this runbook.
- If a local environment is created for validation, remove temporary virtual environments, caches, or generated artifacts before handoff.
- Record any cleanup steps in the project progress log.

## Failure handling

If tests or lint fail, fix the root cause and rerun the same checks before demonstrating the release package. Do not proceed with live AWS phases until the repository checks are green and the review assumptions are documented.

## Exit criteria

The release package is ready for handoff when all of the following are true:

- tests pass
- lint passes
- architecture docs are current
- risk and evidence story is documented
- cost and cleanup review is recorded
- no secrets or credentials are exposed
