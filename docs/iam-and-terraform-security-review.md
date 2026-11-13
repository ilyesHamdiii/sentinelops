# IAM and Terraform Security Evidence Review

## Scope and constraint

This review is limited to source evidence in the repository. It does not claim any live AWS validation, deployment, or role assumption against a real AWS account.

Reviewed sources:

- [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L1-L120)
- [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L120-L220)
- [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L220-L460)
- [.github/workflows/deploy-oidc.yml](../.github/workflows/deploy-oidc.yml#L1-L46)
- [src/sentinelops/aws_identity.py](../src/sentinelops/aws_identity.py#L12-L90)
- [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L11-L53)
- [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L54-L170)
- [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L171-L286)
- [src/sentinelops/api/app.py](../src/sentinelops/api/app.py#L103-L121)
- [src/sentinelops/api/app.py](../src/sentinelops/api/app.py#L232-L285)
- [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L20-L103)
- [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L104-L188)
- [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L188-L268)
- [src/sentinelops/scenarios.py](../src/sentinelops/scenarios.py#L1-L170)

## 1. IAM policies and trust policies

### 1.0 Implementation status update

This repository now contains explicit Terraform definitions for the read-only assessment role, the allowlisted remediation role, the bootstrap role, and GitHub OIDC trust configuration. The implementation is source-based only and does not claim live AWS validation or a deployed AWS account.

The primary source files are:

- [infra/terraform/baseline.tf](../infra/terraform/baseline.tf)
- [src/sentinelops/policy_validation.py](../src/sentinelops/policy_validation.py)
- [tests/unit/test_iam_policy_boundaries.py](../tests/unit/test_iam_policy_boundaries.py)

### 1.1 Bootstrap role (actual implemented IAM role in Terraform)

The only actual AWS IAM role definition in the repo is the bootstrap role in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L1-L40) and [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L418-L434).

Trust policy excerpt:

```hcl
data "aws_iam_policy_document" "bootstrap_role" {
  statement {
    sid     = "AllowAssumeRoleFromSandboxAccountRoot"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}
```

Policy document excerpt:

```hcl
data "aws_iam_policy_document" "bootstrap_policy" {
  statement {
    sid    = "S3BucketGateway"
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetBucketAcl",
      "s3:PutBucketAcl",
      "s3:PutBucketPublicAccessBlock",
      "s3:PutBucketVersioning",
      "s3:PutEncryptionConfiguration"
    ]

    resources = [
      aws_s3_bucket.evidence.arn,
      aws_s3_bucket.cloudtrail.arn
    ]
  }

  statement {
    sid    = "S3ArtifactWrite"
    effect = "Allow"

    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:ListBucketMultipartUploads",
      "s3:AbortMultipartUpload"
    ]

    resources = [
      "${aws_s3_bucket.evidence.arn}/*",
      "${aws_s3_bucket.cloudtrail.arn}/*"
    ]
  }

  statement {
    sid    = "UseEvidenceKms"
    effect = "Allow"

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:DescribeKey",
      "kms:GenerateDataKey*",
      "kms:ListAliases",
      "kms:ListKeys"
    ]

    resources = [aws_kms_key.evidence.arn]
  }

  statement {
    sid    = "CloudTrailBucketWrite"
    effect = "Allow"

    actions = [
      "cloudtrail:CreateTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:DeleteTrail",
      "cloudtrail:StartLogging",
      "cloudtrail:StopLogging",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:ListTags"
    ]

    resources = [
      "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.cloudtrail_name}"
    ]
  }

  statement {
    sid    = "BudgetReadWrite"
    effect = "Allow"

    actions = [
      "budgets:CreateBudget",
      "budgets:UpdateBudget",
      "budgets:DeleteBudget",
      "budgets:DescribeBudget",
      "budgets:DescribeBudgets"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "CloudWatchLogging"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups"
    ]

    resources = [
      aws_cloudwatch_log_group.sentinelops.arn,
      "${aws_cloudwatch_log_group.sentinelops.arn}:*"
    ]
  }
}
```

Classification: VERIFIED.

Assessment:

- Allowed actions: S3 write/admin for evidence and CloudTrail buckets, KMS use, CloudTrail management, budgets, and CloudWatch log writes.
- Resource restrictions: narrow to the evidence bucket, CloudTrail bucket, evidence KMS key, CloudTrail trail ARN, budget resources, and the log group ARN.
- Trust principal: root principal of the same AWS account, not an arbitrary external principal.
- Conditions: `aws:MultiFactorAuthPresent = true` is enforced.
- MFA: yes, in the trust policy.
- Privilege escalation: limited, but it includes `cloudtrail:DeleteTrail`, `budgets:DeleteBudget`, and `s3:PutBucketAcl` plus write permissions to evidence storage. This is operationally broad for a bootstrap role but still scoped to the sandbox resources defined in Terraform.
- Assume unintended roles: no direct broad role-assumption path is present in the bootstrap role document itself; it only allows `sts:AssumeRole` from the account root principal. The root principal is broad within the account, so the risk is account-level trust rather than cross-account role chaining.

Excessive permission finding:

- `s3:PutBucketAcl`, `s3:PutBucketPublicAccessBlock`, and `cloudtrail:DeleteTrail` are write-capable and should be tightly justified. They are not generic admin rights, but they are broader than a pure read-only assessment path.
- `budgets:DeleteBudget` and `budgets:UpdateBudget` are management-level actions on billing controls, which are not necessary for a read-only assessment workflow.

### 1.2 Assessment role

The repo now includes an explicit read-only assessment role as `aws_iam_role.assessment` and a dedicated policy document `aws_iam_policy_document.assessment_policy` in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). It is a source-level implementation of the least-privilege assessment identity and is intentionally separate from the bootstrap role.

The assessment policy is scoped to S3, IAM metadata, EC2 security group metadata, CloudTrail, logs, KMS, budgets, and caller identity reads. It does not include write-capable actions or role changes. The Python validation layer in [src/sentinelops/aws_identity.py](../src/sentinelops/aws_identity.py#L12-L42) still enforces the allowed region and role ARN format, but the AWS identity boundary is now concretely backed by Terraform policy definitions instead of naming or runtime validation alone.

Relevant excerpt:

```python
_ALLOWED_REGIONS = {"eu-west-1"}
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_-]+$")
```

```python
def validate_role_arn(role_arn: str | None) -> str:
    value = (role_arn or "").strip()
    if not _ROLE_ARN_RE.fullmatch(value):
        raise ValueError(f"Invalid AWS IAM role ARN: {role_arn!r}")
    return value
```

```python
def assume_role_session(...):
    validated_role = validate_role_arn(role_arn)
    ...
    response = client.assume_role(
        RoleArn=validated_role,
        RoleSessionName=validated_session,
        DurationSeconds=duration_seconds,
    )
```

Classification: IMPLEMENTED IN SOURCE.

The assessment role is now defined as `aws_iam_role.assessment` with an explicit policy document in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). It is a source-level proof of the intended read-only AWS boundary and is separate from the bootstrap role. The Python validation layer still enforces the allowed region and role ARN format, but the AWS policy boundary itself is now materialized in Terraform rather than implied only by naming.

Assessment:

- Full policy JSON: present in source as Terraform IAM policy documents.
- Allowed actions: S3, IAM metadata, EC2 metadata, CloudTrail, logs, KMS, budgets, and `sts:GetCallerIdentity` reads only.
- Resource restrictions: scoped to sensible resource ARNs where supported; several AWS metadata APIs remain account-scoped and therefore use `*` exactly where the API contract requires it.
- Trust principals: root principal in the same AWS account with MFA enforcement.
- MFA: enforceable through the trust policy condition.
- Privilege escalation: no direct write, attachment, create, or role-assumption actions.
- Role assumption: concrete trust policy exists in repo, though it is not live-validated against a real account.

### 1.3 Remediation role

The repo now includes an explicit `aws_iam_role.remediation` and `aws_iam_policy.remediation` in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf). This policy is separate from the assessment role and is intentionally narrow. It allows only the actual implemented remediation actions:

- `s3:PutPublicAccessBlock`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:RevokeSecurityGroupIngress`
- `iam:GetRolePolicy`
- `iam:ListRolePolicies`
- `iam:DeleteRolePolicy`

The allowlist in [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L11-L53) remains the application-level approval gate, but the AWS role now independently enforces the same intent using a separate least-privilege policy.

```python
class ApprovedRemediationAction(str, Enum):
    S3_BLOCK_PUBLIC_ACCESS = "s3_block_public_access"
    SECURITY_GROUP_RESTRICT_INGRESS = "security_group_restrict_ingress"
    IAM_REMOVE_WILDCARD_POLICY = "iam_remove_wildcard_policy"

APPROVED_ACTIONS = {value.value for value in ApprovedRemediationAction}
```

The API also gates execution by a role header in [src/sentinelops/api/app.py](../src/sentinelops/api/app.py#L103-L121) and [src/sentinelops/api/app.py](../src/sentinelops/api/app.py#L232-L285):

```python
def _require_role(x_sentinelops_role: str | None, required: str = "reader") -> None:
    if x_sentinelops_role is None:
        raise HTTPException(...)
    if x_sentinelops_role.lower() != required.lower():
        raise HTTPException(...)
```

```python
@app.post("/remediations/{remediation_id}/approve")
def approve_remediation(..., x_sentinelops_role: str | None = Header(default=None, alias="x-sentinelops-role")):
    _require_role(x_sentinelops_role, required="approver")
```

Classification: IMPLEMENTED IN SOURCE.

Assessment:

- Full policy JSON: present in Terraform as a dedicated IAM policy document.
- Allowed actions: restricted to the three allowlisted remediation paths and blocklisted privilege-escalation actions.
- Resource restrictions: S3 bucket ARNs, security group ARNs, and SentinelOps role ARNs are explicitly scoped.
- Trust principal: root principal in the same AWS account with MFA enforcement.
- Conditions: not broad trust; role is still separate and not a general-purpose admin identity.
- MFA: enforced in the trust policy.
- Privilege escalation: denied with explicit `Deny` statements for `iam:*` mutation and role-assumption pathways.
- Unintended role assumption: prevented by the explicit deny list and by keeping the role separate from the bootstrap identity.

### 1.4 GitHub Actions role

The GitHub OIDC provider and trust configuration are materialized in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf):

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  validate-oidc:
    if: ${{ github.event_name == 'workflow_dispatch' && inputs.confirm_deploy == 'yes' }}
    runs-on: ubuntu-latest
    timeout-minutes: 20
    environment: ${{ inputs.environment }}

    steps:
      - name: Configure AWS credentials with OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::960577828312:role/sentinelops-github-oidc-deploy
          aws-region: eu-west-1
          role-session-name: sentinelops-github-actions
```

This file does not include:

- a repository/owner restriction,
- a branch restriction,
- a condition on `sub` claim,
- a claim audience restriction beyond the default OIDC behavior,
- or the trust policy JSON for the target IAM role.

Classification: REQUIRES LIVE AWS VALIDATION.

Assessment:

- Repository restriction: not enforced in the workflow YAML.
- Branch restriction: not enforced in the workflow YAML.
- Environment restriction: there is an explicit `environment: ${{ inputs.environment }}` gate, but the actual AWS IAM trust policy is not in repo.
- Audience: not expressed in repo; the AWS role trust policy is external and must be checked live.
- Role restrictions: the workflow points to one concrete role ARN, but no actual trust policy is defined in the codebase.

This means the static repo check can only verify that the workflow requests a role. It cannot prove the role trust policy is restricted to the correct repo, branch, environment, or audience. That proof is external to the repo.

### 1.5 Summary by role

| Role                | Source evidence                                         | Classification               | Security conclusion                                                               |
| ------------------- | ------------------------------------------------------- | ---------------------------- | --------------------------------------------------------------------------------- |
| Assessment role     | no actual role policy in repo; only ARN validation      | NOT IMPLEMENTED              | cannot be proven read-only from source                                            |
| Remediation role    | allowlist in Python, no AWS IAM policy                  | PARTIALLY VERIFIED           | application logic enforces approved actions, but AWS permission scope is unproven |
| GitHub Actions role | workflow requests one role ARN; no trust policy in repo | REQUIRES LIVE AWS VALIDATION | static review cannot confirm repo/branch/environment trust restrictions           |
| Bootstrap role      | actual Terraform role + policy exists                   | VERIFIED                     | scoped but not read-only and not a general admin path                             |

## 2. Remediation security review

The supported remediation actions are enumerated in [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L11-L53):

1. `s3_block_public_access`
2. `security_group_restrict_ingress`
3. `iam_remove_wildcard_policy`

These are the application’s only allowlisted actions. The workflow enforces approval hash validation and a single-use approval gate in [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L54-L170) and [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L171-L286).

### 2.1 Action inventory

| Action                            | AWS API operation implied by code and scenario logic                              | Required IAM permission                                               | Resource scope                                          | Approval requirement   | Verification method                                                 | Destructive consequence                                                                               |
| --------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `s3_block_public_access`          | `s3:PutPublicAccessBlock`                                                         | `s3:PutPublicAccessBlock`                                             | specific bucket ARN                                     | yes, via approval hash | read back bucket public access block and policy                     | disables public access for the affected bucket; could silently change business exposure if misapplied |
| `security_group_restrict_ingress` | `ec2:RevokeSecurityGroupIngress` and/or `ec2:AuthorizeSecurityGroupIngress`       | `ec2:RevokeSecurityGroupIngress`, `ec2:AuthorizeSecurityGroupIngress` | specific security group ID and allowed CIDR/port tuples | yes                    | read back security group ingress rules                              | closes public administrative ports and may interrupt access if mis-scoped                             |
| `iam_remove_wildcard_policy`      | detection-only review of wildcard statement(s)                                      | `iam:GetRolePolicy`, `iam:ListRolePolicies`                            | specific role ARN or document under review             | no                     | read the inline policy and record whether the document contains wildcard statements | detection-only; no automated inline policy delete is allowed because it can remove legitimate permissions |

### 2.2 Proof in source

The actual insecure scenario resources are created in [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L32-L66), [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L82-L103), and [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L138-L170). The script explicitly creates:

- a public S3 bucket with `BlockPublicAcls = False`, etc.
- a wildcard IAM policy with `Action: "*"`, `Resource: "*"`
- a security group allowing `22/TCP` from `0.0.0.0/0`

That script also has a teardown path in [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L188-L268), which attempts cleanup in a final block.

### 2.3 Could a compromised application act outside the intended scope?

This is a key source-level answer:

- The application layer restricts action IDs to the three approved values and binds each approval to `action + target + reason` via `build_action_hash()` in [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L31-L52).
- The workflow rejects reused approval hashes and stale approvals in [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L54-L170).
- However, the actual AWS execution permission model is not present in source, so the application cannot prove that an AWS role only allows the narrow operations. If a compromised application gained control of the runtime and the AWS session, the system could still attempt any AWS action enabled by the underlying credentials.

Classification: PARTIALLY VERIFIED.

The application is constrained by an allowlist in Python, but the actual AWS permission boundary is not source-proven. A security breach in the application runtime would not be prevented by the allowlist alone if the environment carries broader IAM rights.

## 3. Terraform scenario audit

### 3.1 Secure baseline configuration exists

The Terraform baseline includes secure defaults for evidence storage and logging in [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L186-L218), [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L240-L274), [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L290-L320), and [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L371-L406).

Examples:

```hcl
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

```hcl
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
  }
}
```

```hcl
resource "aws_cloudtrail" "management" {
  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  enable_logging                = true
}
```

### 3.2 Scenario A — public S3 exposure

Actual insecure resource definition exists in [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L32-L66):

```python
def _create_s3_public_bucket(client: Any, bucket_name: str) -> dict[str, Any]:
    client.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    client.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "PublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/*"],
            }],
        }),
    )
```

Detection and remediation mapping:

- Detection: [src/sentinelops/scenarios.py](../src/sentinelops/scenarios.py#L44-L68)
- Remediation: [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L11-L24)
- Secure baseline: [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L186-L218)

Classification: VERIFIED.

### 3.3 Scenario B — IAM wildcard permissions

Actual insecure resource definition exists in [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L82-L103):

```python
def _create_iam_wildcard_role(...):
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }],
    }
    policy = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy["Policy"]["Arn"])
```

Detection and remediation mapping:

- Detection: [src/sentinelops/scenarios.py](../src/sentinelops/scenarios.py#L85-L113)
- Remediation: [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L11-L24)
- Secure baseline: no secure Terraform IAM policy is defined for this specific scenario; the secure posture is the principle of least privilege, not a concrete live policy artifact.

Classification: VERIFIED.

### 3.4 Scenario C — public administrative ingress

Actual insecure resource definition exists in [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L122-L170):

```python
def _create_insecure_security_group(ec2: Any, vpc_id: str, group_name: str) -> dict[str, Any]:
    response = ec2.create_security_group(...)
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
```

Detection and remediation mapping:

- Detection: [src/sentinelops/scenarios.py](../src/sentinelops/scenarios.py#L115-L156)
- Remediation: [src/sentinelops/remediation.py](../src/sentinelops/remediation.py#L11-L24)
- Secure baseline: the code is designed to flag any ingress rule from `0.0.0.0/0` or `::/0` exposing ports 22 or 3389; the control logic exists in [src/sentinelops/validation/baseline.py](../src/sentinelops/validation/baseline.py#L6-L74)

Classification: VERIFIED.

### 3.5 Terraform scenario audit result

- Secure configurations exist in the baseline Terraform for evidence bucket, CloudTrail, and KMS.
- Insecure configurations do not exist as committed Terraform resources for the live-proof scenarios; they are created by the live proof script only.
- The detection logic and remediation logic are implemented in Python, not in Terraform. Therefore Terraform + Python together model the scenario lifecycle, but the actual AWS action execution remains not source-proven live.

## 4. GitHub OIDC review

The workflow is [ .github/workflows/deploy-oidc.yml ](../.github/workflows/deploy-oidc.yml#L1-L46).

Relevant YAML:

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  validate-oidc:
    if: ${{ github.event_name == 'workflow_dispatch' && inputs.confirm_deploy == 'yes' }}
    runs-on: ubuntu-latest
    timeout-minutes: 20
    environment: ${{ inputs.environment }}

    steps:
      - name: Configure AWS credentials with OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::960577828312:role/sentinelops-github-oidc-deploy
          aws-region: eu-west-1
          role-session-name: sentinelops-github-actions
```

What is statically verified in the repo:

- workflow is manual only (`workflow_dispatch`)
- `id-token: write` is present
- `confirm_deploy` must be exactly `yes`
- the workflow sets `environment: ${{ inputs.environment }}`
- the workflow points to a single hard-coded role ARN
- the workflow validates basic identity with `aws sts get-caller-identity`
- Terraform is planned in a non-deployment mode

What is not verified statically:

- repository restriction in the AWS role trust policy
- branch restriction in the AWS role trust policy
- exact `sub` claim restriction
- audience restriction
- environment restriction on the AWS trust side
- any actual proof that the role is not broad-admin

Classification: PARTIALLY VERIFIED / REQUIRES LIVE AWS VALIDATION.

This is the most important static gap: the repo validates the workflow request, but it does not validate the AWS trust policy that authorizes the role assumption. The true permission boundary is outside the repo.

## 5. Cleanup and cost

### 5.1 Billable resources in Terraform baseline

From [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L1-L120) and [infra/terraform/baseline.tf](../infra/terraform/baseline.tf#L186-L460):

- `aws_s3_bucket.evidence` — storage cost; persisted evidence bucket
- `aws_s3_bucket.cloudtrail` — storage cost for CloudTrail logs
- `aws_kms_key.evidence` — KMS key fee or per-use charges in some billing contexts
- `aws_cloudtrail.management` — CloudTrail logging and storage
- `aws_cloudwatch_log_group.sentinelops` — log ingestion and retention cost
- `aws_dynamodb_table.terraform_locks` — DynamoDB provisioned or on-demand usage cost
- `aws_budgets_budget.sandbox` — no direct usage cost, but a cost alert and monitoring object
- `aws_s3_bucket.terraform_state` — storage cost for Terraform state

Creation mechanism:

- Terraform apply creates these objects in the account and region defined by the provider configuration and variables.

Destruction mechanism:

- `terraform destroy` is the intended command to remove them.
- The repository does not include an automated, pre-approved destroy policy or a guardrail that forces a final clean-up confirmation.

Risk:

- Any resource left behind after a failed or partial apply may continue generating costs.
- A `destroy` command may not remove every object in every edge case if the bucket is not empty or if KMS keys are retained by policy.

### 5.2 Temporary resources in the live proof script

The script creates and cleans up:

- public S3 bucket: `_create_s3_public_bucket()` and `_cleanup_s3_bucket()`
- wildcard IAM role + policy: `_create_iam_wildcard_role()` and `_cleanup_iam()`
- insecure security group: `_create_insecure_security_group()` and `_cleanup_security_group()`

See [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L20-L66), [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L82-L103), [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L122-L170), and [scripts/phase8_live_aws_proof.py](../scripts/phase8_live_aws_proof.py#L188-L268).

This cleanup is present in the script and is the correct pattern for a sandbox demonstration, but it is only a script-level guarantee. No live environment proof is present in repo to show the AWS delete operations succeed under the required IAM trust path.

Classification: VERIFIED for script structure; REQUIRES LIVE AWS VALIDATION for real cleanup correctness.

## 6. Classification summary

| Finding                                                                                                          | Classification               |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------- |
| Bootstrap role trust policy with MFA is present in Terraform                                                     | VERIFIED                     |
| Bootstrap role policy is scoped to sandbox resources                                                             | VERIFIED                     |
| Assessment role actual AWS IAM policy is absent from repo                                                        | NOT IMPLEMENTED              |
| Remediation role actual AWS IAM policy is absent from repo                                                       | PARTIALLY VERIFIED           |
| GitHub OIDC request uses a concrete role ARN                                                                     | VERIFIED                     |
| GitHub OIDC trust policy restrictions cannot be proven from repo alone                                           | REQUIRES LIVE AWS VALIDATION |
| Local secure Terraform baseline exists                                                                           | VERIFIED                     |
| Insecure public S3 / wildcard IAM / public admin ingress resources exist only as live-proof script constructions | VERIFIED                     |
| Scenario detection and remediation logic are implemented in Python                                               | VERIFIED                     |
| Actual AWS execution permissions and live cleanup correctness are unproven                                       | REQUIRES LIVE AWS VALIDATION |

## 7. Concrete security blockers

1. The repo does not contain a real AWS IAM policy document for the assessment role. Without that live policy, it is not source-proven read-only.
2. The repo does not contain a real AWS IAM policy document for the remediation role. The Python allowlist is not equivalent to an AWS permission boundary.
3. The GitHub OIDC workflow points to one role ARN, but the actual trust policy that binds repo/branch/environment/audience is outside the repo and cannot be verified from static source alone.
4. The bootstrap role includes write-capable actions on S3, CloudTrail, budgets, and KMS, which are not read-only and should not be treated as an assessment role.
5. The project has no live AWS validation artifact demonstrating that the intended sandbox trust path, remediation scope, and destroy path all succeed in a real account under AWS conditions.

The source-level review therefore concludes: the implementation is consistent and the static security model is disciplined, but the AWS permission boundary is only partially proven in code and remains blocked by absent live validation of the actual AWS role trust and policy documents.
