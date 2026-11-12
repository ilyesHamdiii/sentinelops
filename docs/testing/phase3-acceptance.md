# Phase 3 acceptance checks

## Goal

Validate that the SentinelOps project is ready to bootstrap a dedicated AWS account and identity model without violating the project’s safety and least-privilege constraints.

## Required acceptance checks

### 1. Dedicated account model

- A dedicated AWS account is documented as the target environment.
- Shared or production accounts are explicitly excluded from the planned bootstrap path.
- The user has reviewed the account purpose, cost scope, and cleanup expectations.

### 2. Root access controls

- The root user is treated as emergency-only and not used for routine work.
- Root MFA is documented as a mandatory prerequisite before runtime access.
- The account is not considered ready until root access is restricted and auditable.

### 3. Least-privilege identity

- Human access is federated or SSO-based rather than permanent user credentials.
- Temporary or role-based access is preferred over static keys.
- IAM bootstrap roles are scoped to the minimum permissions required for setup.

### 4. Budget and cost guardrails

- Monthly cost thresholds are documented before deployment.
- Budget alerts are explicitly planned before any non-trivial AWS usage.
- Cleanup and destruction steps are recorded for every temporary resource.

### 5. CLI and workflow readiness

- AWS CLI profile is named and documented.
- `aws sts get-caller-identity` is a required verification step before any task is run.
- The project includes a standard profile-based workflow with no secrets in repo files.

### 6. No silent drift

- Every AWS activity must be tied to a documented approval record.
- Any future action involving remediation must be verified by a second read after execution.
- The project must reject acts that do not preserve evidence or cleanup intent.

## Pass/fail outcome

The phase passes only when the team can explain the account purpose, cost limits, identity model, and fallback cleanup path in plain language and has no unapproved live AWS actions underway.
