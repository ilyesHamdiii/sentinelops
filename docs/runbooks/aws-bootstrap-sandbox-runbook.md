# AWS bootstrap sandbox runbook

## Objective

Prepare the SentinelOps sandbox account for future AWS validation work while staying within the approved guardrails:

- account purpose: shared sandbox for SentinelOps and future cloud security/engineering work
- no production data
- region: `eu-east-1`
- budget hard ceiling: `$15/month`
- resource tags: `Project = "sentinelops"`, `Environment = "sandbox"`

This document is a planning and execution checklist, not a live action without explicit user approval.

## Preconditions

1. The user has approved the sandbox account purpose, region, and budget.
2. The target AWS account exists and is dedicated to non-production work.
3. The operator has a secure federated login path and is not using long-lived AWS access keys.
4. Billing alerts and cancellation/cleanup permissions are understood.
5. The resource lifecycle and tagging policy are documented before any service is created.

## Security baseline

- Root user: emergency-only; MFA required before use.
- Daily work: use an IAM role or federated identity, not the root user.
- No long-lived AWS keys in local files or Git history.
- All resources must include the tags:
  - `Project = "sentinelops"`
  - `Environment = "sandbox"`
- No production data or workloads may be created in this account.

## Region and account constraints

- Primary region: `eu-east-1`.
- Single-region scope only during MVP.
- Do not enable unrelated regions or services without documented cost review and user approval.

## Budget controls

Set a monthly budget at `$15` and configure alerts at:

- 50%: `$7.50`
- 80%: `$12.00`
- 100%: `$15.00`

Guardrail rules:

- Treat the budget as a hard stop, not a suggestion.
- Review Cost Explorer after every significant change.
- Destroy temporary resources immediately after validation.
- Keep all resources in the sandbox tag set to simplify cost review.

## Required setup steps

### 1. Confirm account identity

Run after login and before any AWS service action:

```bash
aws sts get-caller-identity --profile sentinelops-sandbox
aws configure list --profile sentinelops-sandbox
```

Verify:

- account ID is the correct shared sandbox account,
- region is `eu-east-1`,
- the effective identity is not the root user.

### 2. Validate account metadata

```bash
aws iam list-account-aliases --profile sentinelops-sandbox
aws account list-regions --profile sentinelops-sandbox --query "Regions[?RegionName=='eu-east-1']"
```

Check whether the account is still consistent with the sandbox-only scope.

### 3. Configure budget

Use the AWS Budget console or CLI to create a monthly budget with the approved thresholds.

Example CLI pattern (future use only):

```bash
aws budgets create-budget \
  --account-id <sandbox-account-id> \
  --budget file://budget.json \
  --notifications-with-subscribers file://budget-notifications.json
```

### 4. Create bootstrap roles and trust policies

Bootstrap roles must be minimal and explicitly scoped for:

- Terraform plan/apply operations,
- read-only inventory validation,
- and deployment/verification tasks.

Avoid broad permissions such as `AdministratorAccess`.

### 5. Ensure tagging standards

Every future resource should be tagged with:

- `Project = "sentinelops"`
- `Environment = "sandbox"`

This is required for cost tracing and teardown review.

## Service selection policy

Only enable services necessary for SentinelOps validation. Prefer:

- read-only validation first,
- minimal AWS Config/CloudTrail footprint,
- no always-on NAT or purposely public endpoints,
- no production-like infrastructure that could exceed the hard budget.

Do not enable:

- broad managed security services without an explicit cost model,
- multi-region deployments,
- paid data services outside the minimal required validation path.

## Teardown and cleanup

Before shutdown, verify and terminate:

- temporary S3 evidence buckets used for testing,
- CloudTrail resources or event integrations no longer needed,
- IAM roles that were only for setup,
- any test EC2, VPC, or network components,
- any log storage or monitoring resources created for the sandbox.

Cleanup rule:

- if a resource does not carry the required tags, treat it as unapproved pending review.

## Failure handling

If AWS service creation triggers spending beyond plan:

1. Stop all nonessential work immediately.
2. Review current spend in Cost Explorer.
3. Remove the newest unapproved resources first.
4. Update the budget and cost narrative before proceeding.
5. Re-validate the account is still sandbox-only and tagged correctly.

## Acceptance gates before any live bootstrap

This runbook is considered complete only when all of the following are true:

- the user has approved the sandbox account purpose and budget,
- the region is confirmed as `eu-east-1`,
- budget alarms are configured and documented,
- the bootstrap roles are least-privilege and not root-based,
- and the tag policy is in place before any Terraform or AWS resource creation.

## Risk posture

This remains a controlled local-first workflow. The risk is not that the repo lacks a plan; the risk is moving to live AWS without explicit approvals or spend constraints. The sandbox guardrails above are the stop condition for that risk.
