# GitHub OIDC security review

## Scope

The GitHub OIDC workflow is reviewed at the source level only. This does not validate live AWS trust behavior.

## Implemented configuration

The repository includes a GitHub Actions workflow that requires:

- `id-token: write`
- `workflow_dispatch`
- explicit `sandbox` environment gate
- explicit confirmation input before AWS access is granted
- Terraform validation in plan-only mode
- exact AWS role assumption to `arn:aws:iam::960577828312:role/sentinelops-github-oidc-deploy`

The workflow is controlled by `confirm_deploy`, and the job only executes when the GitHub repository is `ilyesHamdiii/sentinelops`, the environment is `sandbox`, and approval is explicitly set to `yes`.

## Exact trust requirements

The AWS trust policy must enforce:

- `aud = sts.amazonaws.com`
- `sub = repo:ilyesHamdiii/sentinelops:environment:sandbox`

The trust is intentionally not wildcarded and does not include arbitrary branches, tags, or unbounded repositories.

## Security review

### Implemented

- OIDC is used in lieu of static AWS keys.
- Role assumption is handled through `aws-actions/configure-aws-credentials` with `role-to-assume`.
- Terraform uses an OIDC provider resource for `https://token.actions.githubusercontent.com`.
- The workflow is fail-closed if the repository or environment does not match the expected sandbox binding.
- The role policy is read-only and does not include `AdministratorAccess` or write actions.
- Region is pinned to `eu-west-1` in the workflow.

### Locally validated

- Workflow file presence and trust gating are validated by unit tests.
- Terraform OIDC provider and repo/environment subject logic are validated locally.
- The repository is aligned with the plan-only deployment design required for the target sandbox.

### Not validated against AWS

- Actual GitHub-to-AWS OIDC federation exchange.
- Real trust policy evaluation in AWS STS.
- `aud` and `sub` values in a live execution context.
- Creation of any AWS IAM provider or role.

### Requires live verification

- The repo and environment subject claim must be confirmed in the target AWS account.
- The role trust policy in AWS must map exactly to the GitHub workflow and environment.
- The AWS IAM provider and role must be created manually by an authorized user before the workflow can succeed.

## Final assessment

The source configuration is safe, explicit, and least-privilege: the deployment path expects explicit authorization, avoids long-lived credentials, and keeps the workflow restricted to plan-only validation until a human grants live approval. It remains a preflight design until an authorized sandbox run is executed.
