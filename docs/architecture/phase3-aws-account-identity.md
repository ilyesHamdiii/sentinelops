# Phase 3 — AWS account and identity readiness

## Objective

Prepare the project for a future, explicit AWS bootstrap in a dedicated account while keeping all work inside the local-first, approval-gated policy established for SentinelOps.

## Why this is necessary

SentinelOps depends on a clean, auditable AWS identity and account model before any configuration or remediation logic is executed. The project cannot safely operate without:

- a dedicated workload account rather than a shared or production account,
- Multi-Factor Authentication on the root user,
- least-privilege human and automation access,
- a tracked budget and region plan,
- and a clear distinction between read-only validation and disruptive change actions.

## Decision

Use a dedicated AWS account for SentinelOps testing and validation, with no root-level routine access, federated access for human operators, and a minimal bootstrap role for Terraform or CLI operations. All future AWS execution is blocked until the user explicitly approves the account, services, cost, and region plan.

## Approved operating constraints

- Account purpose: shared sandbox account for SentinelOps development and future cloud security/engineering projects; no production data.
- Resource isolation: all SentinelOps resources must be tagged with `Project = "sentinelops"` and `Environment = "sandbox"`.
- Region: `eu-east-1` for single-region deployment only.
- Budget ceiling: `$15/month` hard ceiling, with AWS Budget alerts at 50% ($7.50), 80% ($12.00), and 100% ($15.00).

## Account model

### Recommended model

- Account type: dedicated non-production security validation account.
- Ownership: single accountable operator with security review and billing visibility.
- Region policy: fixed primary region `eu-east-1`; no multi-region expansion during MVP.
- Environment boundaries: sandbox-only workload; no production data or workloads on the same account.

### Identity principles

- Root user: enabled only for account bootstrap and emergency recovery.
- Root MFA: required before any other work.
- Human access: via IAM Identity Center, SSO, or federated access with least privilege.
- Automation access: short-lived credentials or IAM roles tied to GitHub OIDC or an explicit bootstrap role.
- Long-lived access keys: prohibited for routine use.

## Security guardrails

- Never use broad wildcard permissions.
- Do not create or reuse long-lived AWS keys for automation.
- Store configuration in encrypted local files only; never commit credentials or secrets to the repo.
- Only use AWS actions after explicit user approval and documented cleanup.
- Require approval for any remediation that modifies production-like resources.

## Budget and cost control

Before any real deployment, document:

- target AWS services and expected usage profile,
- anticipated monthly cost range,
- alert thresholds and monthly budget, and
- a cleanup plan for every provisioned resource.

Approved budget policy:

- Hard ceiling: `$15/month`.
- Preserve the user's `$200` AWS credit balance for multiple projects.
- Configure AWS Budget alerts at 50% ($7.50), 80% ($12.00), and 100% ($15.00).
- Use the sandbox tag set `Project = "sentinelops"` and `Environment = "sandbox"` to isolate spend and cleanup.

Budget controls should be configured before the first non-trivial application deployment.

## CLI and local readiness

A future local setup should include:

- AWS CLI v2 installed and configured,
- a named profile for the target account,
- `aws sts get-caller-identity` validation before workflow execution,
- `aws configure list` verification for account, region, and ARN,
- and a documented `--profile` workflow for all commands.

## Example future commands

These commands are intentionally stored as a future-use bootstrap plan and not run in this local workspace unless the user explicitly approves live AWS actions.

```bash
aws configure --profile sentinelops-dev
aws sts get-caller-identity --profile sentinelops-dev
aws iam list-account-aliases --profile sentinelops-dev
aws budgets create-budget --account-id <id> --budget ...
```

## Future implementation dependencies

The following are required before a live bootstrap can proceed:

1. Explicit user approval for the target AWS account and budget.
2. Confirmation of the primary AWS region.
3. A clear list of services to be enabled and their expected lifetime.
4. Documented teardown instructions for all temporary IaC and test resources.
5. Review of IAM trust policies and minimal bootstrap roles.

## Acceptance criteria

Phase 3 is considered ready when all of the following are true:

- Dedicated test account and role model are documented.
- Root MFA and least-privilege access policy are captured in project docs.
- A no-long-lived-keys rule is in place and enforced in runbooks.
- Budget alert thresholds and cost guardrails are recorded.
- Local project policy reflects the pending AWS bootstrap requirement.

## Risk posture

This phase remains controlled because no live AWS account changes are made in the repository or local environment. The main risk is delay or unapproved execution, which is mitigated by the project’s documented approval gate.
