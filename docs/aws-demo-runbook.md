# AWS demo runbook

## Status

This document describes the intended future AWS sandbox demonstration path. It is not operational guidance for live execution in the current workspace.

## Precondition

Before any live AWS action, obtain explicit authorization for:

- target AWS account ID,
- region `eu-west-1`,
- GitHub environment and repo trust,
- budget ceiling,
- sandbox cleanup plan.

## Controlled sequence

1. Confirm account and region.
2. Validate OIDC trust configuration.
3. Provision the secure baseline.
4. Deploy three intentionally vulnerable test resources.
5. Run the assessment identity and collect fresh evidence.
6. Produce findings for S3, IAM, and public ingress.
7. Approve two remediation actions explicitly.
8. Remediate only the approved findings with the remediation identity.
9. Re-run assessment with a new session ID and fresh evidence.
10. Verify the final state and record audit output.
11. Execute cleanup via the bootstrap identity.

## Safety checks

- No apply operations without approval.
- No static AWS keys in GitHub Actions.
- No destructive action without explicit confirmation.
- All test resources must be tagged for tracking and cleanup.

## Execution status

Not executed in this workspace.
