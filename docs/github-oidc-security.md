# GitHub OIDC security review

## Scope

The GitHub OIDC workflow is reviewed at the source level only. This does not validate live AWS trust behavior.

## Implemented configuration

The repository includes a GitHub Actions workflow that requires:

- `id-token: write`
- `workflow_dispatch`
- explicit environment input
- explicit confirmation input before AWS access is granted
- Terraform validation in plan-only mode

The workflow is controlled by `confirm_deploy` and does not auto-assume a role unless a human-triggered approval value is provided.

## Security review

### Implemented

- OIDC is used in lieu of static AWS keys.
- Role assumption is handled through `aws-actions/configure-aws-credentials` with `role-to-assume`.
- The workflow is not allowed to assume a role without explicit operator approval.
- Region is pinned to `eu-west-1` in the workflow.

### Locally validated

- Workflow file presence and trust gating are validated by unit tests.
- The source is aligned with the repository’s OIDC-first deployment approach.

### Not validated against AWS

- Actual GitHub-to-AWS OIDC federation exchange.
- Real trust policy evaluation in AWS STS.
- `aud` and `sub` values in a live execution context.

### Requires live verification

- The repo and environment subject claim must be confirmed in the target AWS account.
- The role trust policy in AWS must map exactly to the GitHub workflow and environment.

## Final assessment

The source configuration is sound and conservative: the deployment path expects explicit authorization and avoids long-lived credentials. It remains a preflight design until an authorized sandbox run is executed.
