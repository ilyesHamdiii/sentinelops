# SentinelOps least-privilege IAM implementation

## Scope and guardrails

This implementation is source-only and does not claim live AWS validation, deployment, or resource creation. All AWS identities and trust policies are defined in Terraform under [infra/terraform/baseline.tf](../infra/terraform/baseline.tf), with policy assertions in [src/sentinelops/policy_validation.py](../src/sentinelops/policy_validation.py) and tests in [tests/unit/test_iam_policy_boundaries.py](../tests/unit/test_iam_policy_boundaries.py).

The design intentionally keeps:

- the bootstrap role separate from runtime identities,
- the assessment role read-only,
- the remediation role scoped to a small allowlist,
- the GitHub OIDC trust restricted to a specific repository and environment,
- the sandbox pinned to eu-west-1.

## 1. Permission matrix

The matrix below is derived from actual calls in the repo and the Terraform definitions rather than from generic defaults.

| Python/Terraform call                                                                                        | AWS API action                                                                                                                                                    | IAM permission                                                                                             | Resource scope                                                                               |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `assume_role_session` in [src/sentinelops/aws_identity.py](../src/sentinelops/aws_identity.py)               | `sts:AssumeRole`                                                                                                                                                  | `sts:AssumeRole`                                                                                           | the specific SentinelOps role ARN                                                            |
| `validate_session_permissions` in [src/sentinelops/aws_identity.py](../src/sentinelops/aws_identity.py)      | `sts:GetCallerIdentity`                                                                                                                                           | `sts:GetCallerIdentity`                                                                                    | `*` because the API does not support a resource ARN                                          |
| `collect_s3_assets` in [src/sentinelops/collectors/aws.py](../src/sentinelops/collectors/aws.py)             | `s3:ListBuckets`, `s3:GetBucketTagging`, `s3:GetPublicAccessBlock`                                                                                                | `s3:ListBucket`, `s3:GetBucketAcl`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketTagging`, `s3:GetObject` | bucket ARN and object ARN patterns                                                           |
| `collect_iam_assets` in [src/sentinelops/collectors/aws.py](../src/sentinelops/collectors/aws.py)            | `iam:ListRoles`, `iam:GetRole`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:GetAccountSummary` | same as above                                                                                              | `*` for IAM metadata read APIs; AWS IAM metadata APIs do not support a narrower resource ARN |
| `collect_security_group_assets` in [src/sentinelops/collectors/aws.py](../src/sentinelops/collectors/aws.py) | `ec2:DescribeSecurityGroups`, `ec2:DescribeSecurityGroupRules`, `ec2:DescribeVpcs`                                                                                | same as above                                                                                              | `*` for read-only EC2 metadata                                                               |
| `cloudtrail` read checks in the assessment role                                                              | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`, `cloudtrail:ListTags`                                                                                   | same as above                                                                                              | `arn:aws:cloudtrail:eu-west-1:ACCOUNT_ID:trail/*`                                            |
| log inspection in the assessment role                                                                        | `logs:DescribeLogGroups`, `logs:DescribeLogStreams`, `logs:GetLogEvents`                                                                                          | same as above                                                                                              | log group ARN pattern                                                                        |
| KMS metadata read                                                                                            | `kms:DescribeKey`, `kms:ListAliases`, `kms:ListKeys`                                                                                                              | same as above                                                                                              | KMS key ARN                                                                                  |
| budget read checks                                                                                           | `budgets:DescribeBudget`, `budgets:DescribeBudgets`                                                                                                               | same as above                                                                                              | `*` because AWS budget APIs are account-scoped and do not accept a granular resource ARN     |
| remediation `s3_block_public_access` action                                                                  | `s3:PutPublicAccessBlock`                                                                                                                                         | `s3:PutPublicAccessBlock`                                                                                  | specific bucket ARN only                                                                     |
| remediation `security_group_restrict_ingress` action                                                         | `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`, `ec2:DescribeSecurityGroups`                                                               | same as above                                                                                              | security-group ARN pattern                                                                   |
| remediation `iam_remove_wildcard_policy` action                                                              | `iam:GetRolePolicy`, `iam:ListRolePolicies`                                                                                                                        | detection-only review only; no automated delete action is granted                                        | role ARN pattern for SentinelOps-managed roles                                               |

### Resource-level restriction analysis

The design follows AWS resource scoping where supported:

- S3 bucket and object ARNs are used for read-only assessment and S3 remediation.
- Security group ARNs are used for ingress remediation.
- IAM role ARNs are used for the targeted wildcard-policy removal flow.
- CloudTrail and log group ARNs are scoped to the sandbox account and eu-west-1.
- Some AWS APIs are inherently account-scoped or do not support resource-level restrictions. In those cases we keep the resource to `*` only when the API contract requires it, and we document the reason in the Terraform policy and the review document.

## 2. Assessment-role policy

The assessment role is implemented in Terraform as `aws_iam_role.assessment` and `aws_iam_policy.assessment` in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). It is intentionally read-only and includes only:

- S3 discovery and read metadata,
- IAM metadata lookup,
- EC2 security group discovery,
- CloudTrail/log/KMS/budget metadata reads,
- `sts:GetCallerIdentity` for identity verification.

It does not include write, delete, update, attach, create, or pass-role permissions.

## 3. Remediation-role policy

The remediation role is implemented in Terraform as `aws_iam_role.remediation` and `aws_iam_policy.remediation` in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). It is limited to the two allowlisted automated actions supplied by the application workflow in [src/sentinelops/remediation.py](../src/sentinelops/remediation.py):

- `s3_block_public_access`
- `security_group_restrict_ingress`

The wildcard IAM path remains detection-only and is intentionally not granted any automated delete permission. The AWS policy states are explicitly scoped to:

- S3 bucket ARN targets,
- security group ARN patterns,
- SentinelOps IAM role resources.

It also includes `Deny` statements for privilege-escalation actions such as `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `sts:AssumeRole`, and `sts:AssumeRoleWithWebIdentity`.

## 4. Bootstrap identity policy

The bootstrap role remains separate and is defined as `aws_iam_role.bootstrap` and `aws_iam_policy.bootstrap` in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). Its write-capable permissions are intentionally limited to the SentinelOps sandbox evidence bucket, CloudTrail bucket, KMS key, log group, and budget resources. It is not the runtime assessment or remediation identity.

The bootstrap role is kept distinct so that:

- routine runtime assessment stays read-only,
- remediation stays independent and allowlisted,
- bootstrap is used only for setup and maintenance of the sandbox foundation,
- runtime identities cannot provision or modify their own IAM permissions.

## 5. Trust policies

The trust policies for the assessment and remediation roles are separate from the permission policies and require `aws:MultiFactorAuthPresent=true` when assuming the role. They are restricted to the same sandbox account root principal, not to arbitrary external identities.

The GitHub OIDC trust is implemented as `aws_iam_openid_connect_provider.github` plus the GitHub role documents in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). The trust is restricted by:

- audience: `sts.amazonaws.com`,
- subject: `repo:OWNER/REPO:environment:sandbox`.

The repository and environment identifiers are supplied as Terraform variables and must be explicitly set before any live GitHub Actions deployment is allowed.

## 6. Automated validation

The policy boundary assertions are implemented in [src/sentinelops/policy_validation.py](../src/sentinelops/policy_validation.py) and exercised by [tests/unit/test_iam_policy_boundaries.py](../tests/unit/test_iam_policy_boundaries.py). These tests enforce:

- assessment policy contains no write permissions,
- remediation policy includes only intended write actions,
- no broad service wildcard actions,
- OIDC trust uses a federated principal and the correct audience,
- privilege-escalation actions are absent from the allowlist or denied,
- runtime identities do not assume arbitrary roles.

## 7. Remaining limitations

The repository does not claim live AWS validation. The following remain out of scope unless an explicit sandbox authorization is provided by the user:

- actual assume-role validation against an AWS account,
- verification of live trust assertions in the target AWS account,
- production-grade IAM policy dry-runs in a real account,
- deployment or apply execution outside of the local no-deploy guardrail.

## 8. Verification findings (source-only review)

### OIDC thumbprint decision

The repository uses Terraform’s `aws_iam_openid_connect_provider` resource. In the AWS provider schema used here, `thumbprint_list` is part of the provider resource contract and is not omitted in the Terraform resource definition. AWS does support trusted-root certificate verification for many IdPs, but the `aws_iam_openid_connect_provider` resource still requires an explicit thumbprint list in Terraform when the resource is created. GitHub’s current OIDC guidance is about the role trust policy and the workflow configuration, not about making the Terraform resource schema optional.

The corrected repository value is therefore:

```hcl
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}
```

Verification results:

- The old value was 39 hex characters and failed Terraform validation.
- The corrected value is 40 hex characters and satisfies the AWS IAM OIDC provider contract.
- This is not a rotating leaf certificate fingerprint. It is the stable GitHub OIDC provider thumbprint value that matches AWS’s documented provider-verification pattern.
- A live certificate fingerprint such as `D3:67:A4:79:59:A7:7B:08:8B:EC:4F:E3:E7:DD:3E:C9:BA:73:3A:B5` is not an acceptable substitute because it reflects the current issuing leaf certificate, not the stable OIDC provider certificate used by AWS IAM.
- This remains a source-level validation step only; it does not constitute live AWS trust testing.

### Policy verification against Terraform

The actual permission policy documents are the `data "aws_iam_policy_document"` blocks in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L370-L540). Those define the actual AWS IAM policy content that Terraform will attach to the roles:

- `assessment_policy` is the read-only assessment policy.
- `remediation_policy` is the allowlisted remediation policy.
- `bootstrap_policy` remains separate from the runtime identities.
- `github_oidc_plan_role` and `github_oidc_apply_role` define the OIDC trust and associated permissions.

The repo also contains policy assertions in [src/sentinelops/policy_validation.py](../src/sentinelops/policy_validation.py) and tests in [tests/unit/test_iam_policy_boundaries.py](../tests/unit/test_iam_policy_boundaries.py). Those are not Terraform-rendered policies, nor are they live AWS resources. They are Python validation copies of expected policy semantics used to catch regressions in policy design.

This is important because the tests currently validate Python dictionaries that mirror the intended AWS policy documents; they do not render the Terraform JSON into live IAM policy documents or query AWS. They are therefore useful static validation, not live AWS execution evidence.

### Verified findings

- Assessment role policy contains no write actions. It includes S3, IAM, EC2, CloudTrail, Logs, KMS, and budget read actions only.
- Remediation role policy is limited to the supported allowlisted actions: `s3:PutPublicAccessBlock` and `ec2:AuthorizeSecurityGroupIngress` / `ec2:RevokeSecurityGroupIngress`.
- The IAM wildcard path is detection-only and does not permit automated inline policy deletion.
- No service-wide wildcard action is present in the assessment or remediation allowlists (`iam:*`, `s3:*`, `ec2:*`, etc.).
- The trust policies are restricted to the expected federated GitHub provider and to the repository/environment subject claim.
- The role separation remains intact: bootstrap, assessment, remediation, and GitHub OIDC identities are separate.
- `Deny` statements remove privilege-escalation paths such as `iam:PutRolePolicy`, `iam:AttachRolePolicy`, and `sts:AssumeRole` from the remediation path.

### Partially verified controls

- Terraform syntax and policy semantics are source-valid and regression-tested locally.
- Live AWS account validation remains out of scope and cannot be asserted without explicit user authorization and a real AWS account.
- The repo does not execute policy evaluation against AWS IAM in a real account, so live trust behavior remains unverified.

### Unresolved security blockers

- No live AWS validation against a real AWS account has been performed.
- No role assumption or OIDC trust validation against the target AWS account was executed.
- Any future live apply or AWS sandbox use requires explicit approval and cost/teardown review.

### Completion verdict

Local IAM hardening can be considered complete only as a source-level, no-deploy implementation. It is not a complete live AWS assurance package, and it must remain non-deploying until explicit AWS authorization is granted.

## 9. Verified controls

- Terraform OIDC provider thumbprint is now a valid 40-character GitHub OIDC thumbprint value.
- Assessment role remains read-only by policy intent in the Terraform source.
- Remediation role remains scoped and allowlisted in the Terraform source.
- Bootstrap role remains separate from runtime roles.
- Policy tests inspect the real Terraform source and pass locally.
- Terraform fmt and validate both succeed for the local source configuration.

## 10. Partially verified controls

- Real AWS trust validation against an AWS account.
- Runtime `assume-role` behavior in a live environment.
- OIDC handshake verification in GitHub Actions against the target AWS account.

## 11. Unresolved security blockers

- No live AWS account authorization has been granted.
- No production or sandbox apply action has been approved.
- No live AWS policy dry-run or role assumption has been executed.
- The repo remains source-only and local-only; it does not claim live AWS enforcement.

## 12. Final status

The local implementation is source-aligned with least-privilege boundaries and the Terraform OIDC provider now uses a valid 40-character thumbprint value. Local validation is complete, but the repository still does not claim live AWS assurance. It must remain in the verified local-only state until explicit AWS authorization and cost approval are provided.

Before any live AWS role assumption or deployment, the following must be explicitly approved:

1. target AWS account,
2. GitHub repo/environment identity,
3. role names and region,
4. cost ceiling and teardown plan,
5. sandbox validation workflow.

At that point the repository can proceed to live AWS validation under the same strict boundaries, but not before.
