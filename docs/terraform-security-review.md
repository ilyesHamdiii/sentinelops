# Terraform security review

## Scope

The Terraform review is limited to local source inspection and local validation. No Terraform apply or destroy has been run against AWS.

## Reviewed files

- infra/terraform/baseline.tf
- infra/terraform/versions.tf
- infra/terraform/providers.tf
- infra/terraform/locals.tf
- infra/terraform/variables.tf
- infra/terraform/outputs.tf
- .github/workflows/deploy-oidc.yml

## Implemented controls

- Separate bootstrap, assessment, remediation, and OIDC-related identity definitions.
- Read-only assessment policy for S3, IAM, EC2, CloudTrail, Logs, and budgets.
- Narrow remediation policy with allowlisted actions.
- KMS-backed evidence bucket encryption and public access blocking.
- region restriction to `eu-west-1` in source validation.
- OIDC provider and GitHub role trust definitions kept separate from the application runtime.

## Locally validated

- Terraform init succeeded with the lock file.
- Terraform validation succeeded.
- Terraform formatting check succeeded.
- Source-level IAM boundary tests passed locally.

## Not validated against AWS

- Actual role assumption.
- Real trust-policy enforcement.
- Sandbox deployment or cleanup.

## Security posture

The source is broadly aligned with least-privilege patterns and with the project’s security requirement to keep runtime roles separate. The main limitation is that this is still a static review and not a live AWS assurance result.

## Final conclusion

The Terraform baseline is both secure-by-design and safe-to-review locally. However, it remains a pre-deployment, source-only trust model until an authorized AWS sandbox demonstration is approved.
