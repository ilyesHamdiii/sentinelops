# SentinelOps AWS sandbox readiness review

## Scope

This document prepares the project for its first controlled AWS sandbox validation without claiming that any live validation has already occurred. The repo has been validated locally, and the sandbox review is grounded in the actual implementation in [src/sentinelops/aws_identity.py](../src/sentinelops/aws_identity.py), [src/sentinelops/remediation.py](../src/sentinelops/remediation.py), [src/sentinelops/collectors/aws.py](../src/sentinelops/collectors/aws.py), [infra/terraform/variables.tf](../infra/terraform/variables.tf), [infra/terraform/baseline.tf](../infra/terraform/baseline.tf), and [.github/workflows/deploy-oidc.yml](../.github/workflows/deploy-oidc.yml).

## 1. Repository cleanup report

### Repository state review

The repository was checked with Git status and the only untracked local artifacts were the new end-to-end test file, the demo script, and the generated coverage output. The cleanup steps completed were:

- the Git ignore list was tightened to exclude coverage outputs, Python caches, local report files, and other local artifact patterns;
- the `.coverage` artifact was removed from the working tree so it cannot be accidentally committed;
- the end-to-end test and the local demo script remain in scope and are intended to be tracked in the final commit;
- no obvious AWS credential or secret patterns were found in tracked files; the repo contains only example secret patterns in test fixtures and validation utilities, not real credentials.

### Current tracked state

The repo is expected to contain the validated implementation and the sandbox-readiness documentation in the final commit. This should include:

- [scripts/local_end_to_end_demo.py](../scripts/local_end_to_end_demo.py)
- [tests/unit/test_end_to_end_platform.py](../tests/unit/test_end_to_end_platform.py)
- [README.md](../README.md)
- [docs/aws-sandbox-readiness-review.md](aws-sandbox-readiness-review.md)
- the updated Terraform and security review documentation

### Result

The repo is ready for a clean commit after removing local-only generated files and ensuring Git hygiene matches the local validation status.

## 2. IAM permission matrix

The project does not currently define an actual AWS IAM policy document in the repo for the assessment or remediation roles. The matrix below therefore reflects the minimum safe design required by the implementation and the security review, and it intentionally rejects any policy that is broad or named-only read-only.

| Role                        | Purpose                                                                 | Trust relationship                                                                                     | Allowed actions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Explicitly denied                                                                                                          | Notes                                                                                         |
| --------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Assessment role             | read-only discovery and evidence collection                             | `sts:AssumeRole` only; no root or unrestricted trust; MFA strongly recommended for human session paths | `sts:GetCallerIdentity`, `s3:GetBucketLocation`, `s3:ListBucket`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPolicy`, `s3:GetPublicAccessBlock`, `iam:ListRoles`, `iam:GetRole`, `iam:GetRolePolicy`, `iam:ListRolePolicies`, `iam:ListAttachedRolePolicies`, `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `ec2:DescribeSecurityGroups`, `ec2:DescribeRegions`, `logs:DescribeLogGroups`, `logs:DescribeLogStreams`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` | all `Put*`, `Create*`, `Delete*`, `Update*`, `Modify*`, `Attach*`, `Detach*`, `AssumeRole` outside the approved trust path | Must be read-only by policy; naming alone is not sufficient                                   |
| Remediation role            | allowlisted Azure-style actions for controlled corrections in a sandbox | explicit trust to an approval workflow or designated operator principal; no general `*` admin trust    | `s3:PutPublicAccessBlock` scoped to a specific bucket ARN, `ec2:RevokeSecurityGroupIngress` scoped to a specific security group and port, `ec2:AuthorizeSecurityGroupIngress` only for the exact approved change, `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` only when targeting a specific managed policy ARN, `iam:GetPolicyVersion` and `iam:ListPolicyVersions` for verification                                                                                                          | `AdministratorAccess`, `iam:*`, `ec2:*`, `s3:*`, `*:*`                                                                     | Policy is deliberately narrow and approval-bound; any action not in the allowlist should fail |
| Bootstrap or Terraform role | infrastructure setup and cleanup in the dedicated sandbox only          | root or federated identity with explicit MFA and single-region scope                                   | `s3:*` on the evidence and CloudTrail buckets only, `kms:DescribeKey`, `kms:Decrypt`, `kms:Encrypt`, `kms:GenerateDataKey*`, `cloudtrail:CreateTrail`, `cloudtrail:UpdateTrail`, `cloudtrail:DeleteTrail`, `budgets:DescribeBudget`, `logs:CreateLogGroup`, `logs:PutLogEvents`                                                                                                                                                                                                                                | broad wildcard rights to unrelated accounts or services                                                                    | Narrow to the bootstrap resources only; no admin role inheritance                             |

### Required design constraints

- The assessment role must not have write permissions.
- The remediation role must not receive `AdministratorAccess` or a broad `iam:*` policy.
- The project’s Python naming (`read_only`, `remediation`) is not sufficient proof. The IAM evaluation must enforce the actual policy documents and granted actions.
- Every remediation must be limit-scoped to an action, a target, and a reason via the approval hash in [src/sentinelops/remediation.py](../src/sentinelops/remediation.py).

## 3. Trust policy review

The code enforces a strict trust boundary around `sts:AssumeRole` in [src/sentinelops/aws_identity.py](../src/sentinelops/aws_identity.py):

- account IDs must be exactly 12 digits;
- region must be fixed to `eu-west-1`;
- role ARNs are validated with an AWS IAM ARN regex;
- `assume_role_session` raises a `PermissionError` when credentials or trust is not valid.

The Terraform bootstrap trust policy in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf) uses a root-principal condition with `aws:MultiFactorAuthPresent = true`. That is a suitable baseline pattern for a dedicated sandbox, but it must be tightened further for production-like use by limiting it to the exact account and environment and by avoiding any root-based broad trust path that is not necessary.

The GitHub OIDC workflow in [.github/workflows/deploy-oidc.yml](../.github/workflows/deploy-oidc.yml) is closer to the required automation model because it uses `id-token: write` and `role-to-assume` with a specific role ARN. This pattern is acceptable for a sandbox, provided the role trust policy is explicitly restricted to the repo and branch/environment, rather than a generic or broad repository principal.

### Review outcome

The repo is heading in the safe direction, but live AWS validation should not proceed until the actual AWS role trust policies are reviewed in the sandbox account and the exact trust conditions are confirmed in the console or an IaC plan.

## 4. Terraform sandbox review

The Terraform baseline establishes the project’s secure local and sandbox guardrails in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). It contains bucket encryption, KMS, CloudTrail, and bucket public-access block defaults. It is not a live deployment artifact and is intentionally provisioned only under explicit approval.

### Scenario A — insecure S3 configuration

| Item                 | Details                                                                                                                                                             |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Resources created    | minimal S3 bucket with public access block disabled or misconfigured, encryption key and bucket policy if intentionally exposed                                     |
| Required permissions | `s3:GetBucketPublicAccessBlock`, `s3:PutPublicAccessBlock`, `s3:GetBucketAcl`, `s3:PutBucketAcl`, `s3:GetBucketPolicy`, `s3:PutBucketPolicy` on the specific bucket |
| Expected cost        | typically $0.00-$0.50/month for a small test bucket; test-duration cost usually under $0.10 for a short validation                                                  |
| Exposure             | bucket allows anonymous reads or a permissive policy; public data disclosure risk                                                                                   |
| Detection method     | collector checks bucket policy, public access block, and public read permissions                                                                                    |
| Remediation method   | `s3:PutPublicAccessBlock` with `BlockPublicAcls=true`, `IgnorePublicAcls=true`, `BlockPublicPolicy=true`, `RestrictPublicBuckets=true`                              |
| Verification method  | fetch bucket public access block and policy after the change; confirm there are no public grants                                                                    |
| Cleanup procedure    | delete the bucket or remove the synthetic public policy; confirm zero remaining public exposure                                                                     |

### Scenario B — IAM wildcard access

| Item                 | Details                                                                                                                                         |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Resources created    | minimal IAM managed policy or role with `Action: "*"` or `iam:*`                                                                                |
| Required permissions | `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`, `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` |
| Expected cost        | $0.00/month because IAM policy objects are free; test-duration cost is negligible                                                               |
| Exposure             | unrestricted access potential across the account                                                                                                |
| Detection method     | policy document inspection in the collector and the risk engine                                                                                 |
| Remediation method   | detection-only review of wildcard statements; no automated inline-policy deletion is allowed because it can remove legitimate permissions |
| Verification method  | read back the corrected policy version and compare action scope                                                                                 |
| Cleanup procedure    | delete the test policy or revert to the least-privilege policy                                                                                  |

### Scenario C — public administrative-port ingress

| Item                 | Details                                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Resources created    | one security group with inbound rule allowing `22/TCP` or `3389/TCP` from `0.0.0.0/0` and optionally a lightweight EC2 instance for validation                       |
| Required permissions | `ec2:DescribeSecurityGroups`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`, optional `ec2:DescribeInstances`                                |
| Expected cost        | if the EC2 instance is left running for a test cycle, roughly $0.10-$1.00 for a short window using a tiny instance; if SG only is created, the cost is usually $0.00 |
| Exposure             | internet-exposed admin port is a high-risk access path                                                                                                               |
| Detection method     | the security group collector inspects ingress rules and the scenario engine checks 0.0.0.0/0 on admin ports                                                          |
| Remediation method   | `ec2:RevokeSecurityGroupIngress` for the public 22 or 3389 rule; add a restricted CIDR only if required                                                              |
| Verification method  | read the security group after remediation and confirm the public ingress rule is removed                                                                             |
| Cleanup procedure    | remove the security group or instance and verify the rule is no longer present                                                                                       |

### Cost and risk posture

The baseline intentionally avoids expensive paid AWS security products. The only necessary costs are a minimal S3 bucket, optional CloudTrail or logging, and an ephemeral EC2 instance if the public-admin-port scenario is exercised. The recommended monthly ceiling remains $15.00, with a cost alert at 50%, 80%, and 100% of the budget.

## 5. OIDC configuration review

The GitHub Actions workflow in [.github/workflows/deploy-oidc.yml](../.github/workflows/deploy-oidc.yml) is the correct pattern for an automated, short-lived AWS role model. The security controls present are:

- `id-token: write`
- explicit workflow dispatch only
- `confirm_deploy` gate to require a human yes
- `aws-actions/configure-aws-credentials@v4`
- `aws sts get-caller-identity` validation before any further steps
- Terraform plan-only mode before a deployment is approved

The remaining requirement is to ensure the role trust policy is pinned to the exact repo, branch, and environment, and that the role scope does not allow broader deployments or admin-level access. For live validation, this must be checked in the sandbox account before any role assumption is used.

## 6. Live validation runbook

1. Create or select a dedicated AWS sandbox account and verify it is not a production account.
2. Confirm the target region is `eu-west-1` and that the account is isolated for SentinelOps only.
3. Configure GitHub OIDC trust for the repo and the target environment; verify the role is not a broad admin role.
4. Validate the assessment role with `aws sts get-caller-identity` and a minimal set of read-only permission checks.
5. Deploy the secure baseline resources only after the role is confirmed to be read-only and the budget alert is active.
6. Deploy the controlled insecure resources for the three scenarios in a short, tagged validation window.
7. Run SentinelOps assessment against the sandbox and confirm the three findings: S1, S2, and S3.
8. Approve only the expected remediation actions that match the exact resource and rationale.
9. Execute the approved remediation through the allowlisted workflow.
10. Independently verify the actual AWS state after the remediation, not just the Python object state.
11. Export the evidence and report bundle to the evidence bucket or local evidence directory.
12. Destroy all test resources and verify that no synthetic public access or wildcard rules remain.
13. Confirm the sandbox has no lingering resources beyond the approved baseline and that cost alerts remain in effect.

## 7. Cost estimate and assumptions

| Item                                            | Quantity                           |              Estimated unit cost | Estimated test-duration cost | Notes                                                       |
| ----------------------------------------------- | ---------------------------------- | -------------------------------: | ---------------------------: | ----------------------------------------------------------- |
| S3 bucket for evidence or a public test bucket  | 1-2 buckets                        |                $0.00-$0.20/month |                  $0.00-$0.10 | minimal storage and API usage                               |
| CloudTrail baseline                             | 1 trail                            |                $0.00-$1.00/month |                  $0.00-$0.20 | only if required by the sandbox baseline                    |
| IAM policy objects                              | 1-3 policies                       |                            $0.00 |                        $0.00 | IAM config objects do not consume significant monthly spend |
| EC2 instance for the public admin-port scenario | 1 small instance for a test window | $0.10-$1.00/hour if left running |                  $0.10-$1.00 | must be terminated immediately after validation             |
| KMS key                                         | 1 key                              |                $0.00-$0.10/month |                   negligible | used for encrypted evidence storage                         |
| Monthly budget guardrail                        | 1                                  |                              n/a |                          n/a | keep a hard ceiling at $15.00                               |

### Assumptions

- all costs are based on a brief sandbox validation window;
- no paid security service such as AWS Config aggregator, GuardDuty, or WAF is required for the first validation;
- the project avoids broad AWS service enablement and keeps the footprint to the minimum required to validate the three scenarios;
- all temporary test resources are destroyed immediately after each validation round.

## 8. Outstanding risks

- The repo contains a secure design but no live AWS trust policy has been validated in the sandbox account yet.
- Python naming is not proof of IAM safety; the actual AWS policy documents still need to be checked in the live environment.
- The project currently validates a synthetic workflow and not a full live AWS account path.
- The budget ceiling is strict, but service usage can still drift if the sandbox is left running or if test resources are not destroyed immediately.
- The first live validation should be done with a small, isolated scenario set and no broad permission path.

## 9. GO / NO-GO recommendation

### Recommendation: NO-GO until the following conditions are explicitly met

1. A dedicated sandbox account is confirmed and not shared with production workloads.
2. The AWS region is fixed to `eu-west-1` and the trust policies are checked for the exact repo and environment.
3. The assessment role is verified to be read-only by policy, not by class naming.
4. The remediation role is verified to be scoped to the allowlisted actions only and not `AdministratorAccess`.
5. AWS Budget alerts are in place at the approved thresholds.
6. A documented teardown procedure is accepted and owners are named.
7. The operator confirms the validation is a single controlled sandbox demonstration and not a broad or permanent deployment.

### Conditional GO after review

If the sandbox account review confirms the above, the repo is ready for a single controlled real-AWS demonstration in `eu-west-1` under the project’s no-billable-footprint rules and, crucially, without any claim that the demonstration has already succeeded.

## Final status

This review is intentionally conservative: the repo is validated locally and the security boundary is documented, but neither live AWS validation nor AWS deployment is claimed. The sandbox readiness state is ready for explicit approval and a tightly-controlled, single-region validation run, not for unreviewed production or broad account-level access.
