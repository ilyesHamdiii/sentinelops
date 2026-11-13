# IAM security review

## Scope

This review is source-based and local-only. It does not claim live AWS validation, role assumption, or account-level policy enforcement in a real AWS environment.

## Status summary

### Implemented

- Separate bootstrap, assessment, and remediation identities are modeled in Terraform.
- Assessment role is restricted to read-only AWS APIs.
- Remediation role is limited to a narrow allowlist.
- GitHub OIDC workflow is configured to request an ID token and assume a role only through the sanctioned workflow.

### Locally validated

- Terraform source is locally validated.
- Python IAM boundary tests pass locally.
- The local repo validation suite passes without AWS access.

### Not validated against AWS

- Actual role assumption in a real AWS account.
- Real trust-policy evaluation by AWS STS.
- Real OIDC exchange with a target AWS account.

### Requires live verification

- Final role trust behavior in a production or sandbox AWS account.
- Runtime permission dry-runs and actual account-level policy checks.

## Identity separation

The design deliberately separates the responsibilities:

1. Assessment identity
   - Read-only.
   - Gather evidence and findings.
   - No resource modification or creation.

2. Remediation identity
   - Allowlisted to the supported actions only.
   - No broad admin permissions.
   - No general bootstrap or provisioning rights.

3. Bootstrap identity
   - Setup and cleanup of the sandbox foundation.
   - Separate from runtime assessment and remediation.

## Review findings

- The assessment policy is narrowly read-only and includes metadata collection and no write operations.
- The remediation policy is allowlisted and denies a set of privilege-escalation paths.
- The bootstrap role is separate and scoped to the sandbox evidence, CloudTrail, KMS, and log resources needed for local operational setup.
- GitHub OIDC is configured to trust the repository/environment in a difficult-to-guess binding, not to arbitrary repos or branches.

## Residual risk

This remains a source-level security review, not a live AWS assurance package. Any future AWS activation must be tracked under explicit user authorization and validated in a dedicated sandbox account.
