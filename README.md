# SentinelOps

SentinelOps is a headless AWS cloud security assessment and controlled-remediation platform. It validates AWS posture in a single sandbox region, scores findings, enforces approval-gated remediation, and verifies post-change state before a finding is marked resolved.

## Current status

This repository is in a verified local-only validation state. The codebase has passed the local quality gates and synthetic end-to-end checks, and it is now being prepared for a controlled AWS sandbox validation only after explicit approval.

## Safety rules

- No live AWS deployment without explicit user approval.
- This sandbox remains pinned to eu-west-1.
- No AdministratorAccess or broad AWS privileges are permitted for either assessment or remediation roles.
- Remediation requires an allowlisted action, approval binding, and independent verification.
- Terraform validation is allowed; Terraform apply remains blocked until an approval gate is cleared.

## Local validation commands

The following commands are the project’s actual validation flow and match the implementation currently in the repo:

```bash
python -m pytest --cov=src/sentinelops --cov-report=term-missing -q
ruff check src tests
mypy src
bandit -r src -q
python -m pip_audit --desc --progress-spinner off
python scripts/local_end_to_end_demo.py
terraform -chdir=infra/terraform validate
```

## Repository structure

- src/sentinelops: Python assessment, identity, scenarios, risk, remediation, and API code.
- tests/unit: local validation and end-to-end synthetic workflows.
- infra/terraform: baseline sandbox and local validation components.
- docs: architecture, cost, progress, runbooks, and readiness records.
- scripts: local demonstration and operational utilities.

## Sandbox readiness

SentinelOps is ready for a controlled sandbox review only if the following conditions are met:

1. a dedicated non-production AWS account is available,
2. the account and region are confirmed as eu-west-1,
3. GitHub OIDC is scoped to the repo and environment,
4. the assessment role is read-only by policy, not by naming convention,
5. the remediation role is allowlisted and not broad-admin,
6. budget alerts are configured at $7.50, $12.00, and $15.00,
7. all temporary test resources are tagged and teardown is documented.

## Project scope

The platform follows the master specification and focuses on a disciplined, evidence-driven workflow:

- collect AWS asset and configuration evidence
- normalize findings from multiple AWS sources
- score risk with explainable rules
- validate security controls with synthetic scenarios
- generate approval-gated remediation proposals
- verify actual AWS state before declaring a finding resolved
