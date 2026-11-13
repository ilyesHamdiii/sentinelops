# IAM permission matrix

## Purpose

This matrix documents the intended AWS permissions for the SentinelOps identities in the repository source. It is a design document, not a live AWS permission report.

| Identity      | AWS action                        | Purpose                                  | Resource scope             | Restriction        | Notes                                       |
| ------------- | --------------------------------- | ---------------------------------------- | -------------------------- | ------------------ | ------------------------------------------- |
| Assessment    | sts:GetCallerIdentity             | Confirm active identity and account      | `*`                        | Read-only          | AWS requires account-scoped identity output |
| Assessment    | s3:ListBucket                     | Discover buckets                         | bucket ARN pattern         | Read-only          | Restricted to expected bucket inventory     |
| Assessment    | s3:GetBucketAcl                   | Inspect ACL exposure                     | bucket ARN pattern         | Read-only          | Supports public exposure assessment         |
| Assessment    | s3:GetBucketPublicAccessBlock     | Check public access block                | bucket ARN pattern         | Read-only          | Required for public S3 logic                |
| Assessment    | s3:GetBucketTagging               | Capture tagging and ownership metadata   | bucket ARN pattern         | Read-only          | Supports evidence metadata                  |
| Assessment    | iam:ListRoles                     | Discover roles                           | `*`                        | Read-only          | IAM metadata calls are account-scoped       |
| Assessment    | iam:GetRole                       | Inspect role metadata                    | role ARN pattern           | Read-only          | Supports drift and overprivilege checks     |
| Assessment    | ec2:DescribeSecurityGroups        | Inspect ingress rules                    | `*`                        | Read-only          | Public exposure evaluation                  |
| Assessment    | cloudtrail:DescribeTrails         | Inspect audit trail configuration        | trail ARN pattern          | Read-only          | Supports audit logging checks               |
| Assessment    | logs:DescribeLogGroups            | Inspect log groups                       | log group ARN pattern      | Read-only          | Supports evidence review                    |
| Assessment    | budgets:DescribeBudget            | Check budget metadata                    | `*`                        | Read-only          | AWS budgets are account-scoped              |
| Remediation   | s3:PutPublicAccessBlock           | Correct a public bucket                  | specific bucket ARN        | Allowlisted        | Only for approved actions                   |
| Remediation   | ec2:AuthorizeSecurityGroupIngress | Add or tighten ingress rules             | security group ARN pattern | Allowlisted        | Strictly time-bounded and approval-gated    |
| Remediation   | ec2:RevokeSecurityGroupIngress    | Remove public ingress                    | security group ARN pattern | Allowlisted        | Used only for specific approved fixes       |
| Remediation   | iam:GetRolePolicy                 | Inspect inline policy contents           | role ARN pattern           | Read-only          | Detection-only review; no automatic deletion |
| Remediation   | iam:ListRolePolicies              | Enumerate inline policies               | role ARN pattern           | Read-only          | Detection-only review; no automatic deletion |
| Remediation   | no inline-policy delete action     | No automated IAM wildcard removal path  | none                      | None               | IAM wildcard remediation is detection-only  |
| Bootstrap     | cloudtrail:CreateTrail            | Setup audit trail                        | specific trail ARN         | Setup only         | Not used by runtime identities              |
| Bootstrap     | s3:PutObject                      | Store evidence and operational artifacts | evidence bucket paths      | Setup/cleanup only | Separate from assessment                    |
| Bootstrap     | kms:GenerateDataKey\*             | Encrypt evidence                         | KMS key ARN                | Setup/cleanup only | Needed for evidence storage                 |
| OIDC workflow | sts:AssumeRoleWithWebIdentity     | CI role assumption                       | repository-specific trust  | OIDC only          | Not used by local validation                |

## Restriction notes

- IAM and S3 collection APIs are often inherently account-scoped and therefore cannot be narrowed to a single resource in all cases.
- Wildcard resource strings are not automatically a flaw when the API contract requires account-scope semantics; they are only accepted where necessary and documented.
- The repository explicitly avoids a broad admin role and does not use static AWS keys in CI.
