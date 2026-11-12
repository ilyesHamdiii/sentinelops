# ADR-0002: Dedicated AWS account and least-privilege identity model

- Status: Proposed
- Date: 2026-11-12

## Context

SentinelOps requires a clean, auditable AWS execution environment to validate controls, run minimal test scenarios, and verify remediation outcomes. Shared accounts, long-lived credentials, and broad role permissions would increase blast radius and violate the project’s security requirements.

## Decision

Use a dedicated AWS account for SentinelOps validation work, require MFA for the root account, and grant human and automation access through federated or role-based mechanisms with least privilege. Do not use long-lived access keys for routine operations.

## Rationale

A dedicated account isolates project activity from unrelated production or shared workloads. Least-privilege roles and short-lived credentials reduce the risk of accidental broad access while preserving the ability to run controlled validation scenarios.

## Alternatives considered

- Shared AWS account: rejected because it mixes project activity with unrelated workloads and increases privilege and cost risk.
- Long-lived access keys: rejected because they are easier to leak and harder to rotate.
- Broad administrator access: rejected because it violates the project guardrail against over-scoped IAM and unsafe automation.

## Consequences

Benefits:

- better isolation and auditability,
- clear ownership and billing boundaries,
- reduced exposure from accidental broad permissions.

Trade-offs:

- additional setup and approval overhead,
- temporary operational friction for federated access,
- stronger governance before any live AWS validation.

## Cost and operational impact

This phase does not create AWS spend or live resources. The future implementation will require budget alerts, explicit approval, and documented teardown steps for any temporary resources.

## Follow-up actions

- Define a bootstrap IAM role and trust policy before deployment.
- Document budget alert thresholds and cleanup instructions.
- Prepare the CLI profile and identity verification workflow in project documentation.
- Reassess before any Terraform or AWS service activation.
