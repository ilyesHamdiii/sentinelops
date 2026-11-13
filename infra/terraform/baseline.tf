data "aws_caller_identity" "current" {}

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

data "aws_iam_policy_document" "bootstrap_policy" {
  statement {
    sid    = "S3BucketGateway"
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetBucketAcl",
      "s3:PutBucketAcl",
      "s3:PutPublicAccessBlock",
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

locals {
  account_id        = data.aws_caller_identity.current.account_id
  evidence_bucket   = "sentinelops-evidence-${local.account_id}"
  cloudtrail_bucket = "sentinelops-cloudtrail-${local.account_id}"
  cloudtrail_name   = "${var.project}-${var.environment}-trail"
  bootstrap_role    = "${var.project}-${var.environment}-bootstrap"
  log_group_name    = "/aws/sentinelops/${var.project}/${var.environment}"
}

data "aws_iam_policy_document" "evidence_kms" {
  statement {
    sid    = "EnableRootAccountAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogsUse"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]

    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:logGroupArn"
      values   = ["arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "evidence" {
  description             = "KMS key for SentinelOps evidence and operational data in the ${var.environment} sandbox."
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.evidence_kms.json

  tags = local.default_tags
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${var.project}-${var.environment}-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

resource "aws_s3_bucket" "evidence" {
  bucket = local.evidence_bucket

  tags = merge(local.default_tags, {
    Name = "sentinelops-evidence"
  })
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "retain-evidence"
    status = "Enabled"

    filter {
      prefix = ""
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = local.cloudtrail_bucket

  tags = merge(local.default_tags, {
    Name = "sentinelops-cloudtrail"
  })
}

resource "aws_s3_bucket" "terraform_state" {
  bucket = "sentinelops-terraform-state"

  tags = merge(local.default_tags, {
    Name = "sentinelops-terraform-state"
  })
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.cloudtrail_name}"]
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.cloudtrail_name}"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

resource "aws_cloudtrail" "management" {
  name                          = local.cloudtrail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = local.default_tags
}

resource "aws_cloudwatch_log_group" "sentinelops" {
  name              = local.log_group_name
  retention_in_days = 3
  kms_key_id        = aws_kms_key.evidence.arn

  tags = local.default_tags
}

resource "aws_dynamodb_table" "terraform_locks" {
  name         = "sentinelops-terraform-locks"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = merge(local.default_tags, {
    Name = "sentinelops-terraform-locks"
  })
}

data "aws_iam_policy_document" "assessment_role" {
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

data "aws_iam_policy_document" "assessment_policy" {
  statement {
    sid    = "S3ReadOnlyEvidence"
    effect = "Allow"

    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetBucketAcl",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetObject",
      "s3:GetObjectVersion"
    ]

    resources = [
      aws_s3_bucket.evidence.arn,
      aws_s3_bucket.cloudtrail.arn,
      "${aws_s3_bucket.evidence.arn}/*",
      "${aws_s3_bucket.cloudtrail.arn}/*"
    ]
  }

  statement {
    sid    = "IAMReadOnlyMetadata"
    effect = "Allow"

    actions = [
      "iam:ListRoles",
      "iam:GetRole",
      "iam:ListRolePolicies",
      "iam:GetRolePolicy",
      "iam:ListPolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetAccountSummary"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "DescribeSecurityGroups"
    effect = "Allow"

    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeVpcs"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "CloudTrailReadOnly"
    effect = "Allow"

    actions = [
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:ListTags"
    ]

    resources = ["arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/*"]
  }

  statement {
    sid    = "LogsReadOnly"
    effect = "Allow"

    actions = [
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents"
    ]

    resources = ["arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:*"]
  }

  statement {
    sid    = "KMSReadOnly"
    effect = "Allow"

    actions = [
      "kms:DescribeKey",
      "kms:ListAliases",
      "kms:ListKeys"
    ]

    resources = [aws_kms_key.evidence.arn]
  }

  statement {
    sid    = "BudgetReadOnly"
    effect = "Allow"

    actions = [
      "budgets:DescribeBudget",
      "budgets:DescribeBudgets"
    ]

    resources = ["*"]
  }

  statement {
    sid    = "IdentityReadOnly"
    effect = "Allow"

    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "remediation_role" {
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

data "aws_iam_policy_document" "remediation_policy" {
  statement {
    sid    = "ScopedS3PublicAccessRemediation"
    effect = "Allow"

    actions = ["s3:PutPublicAccessBlock"]

    resources = [
      aws_s3_bucket.evidence.arn,
      aws_s3_bucket.cloudtrail.arn
    ]
  }

  statement {
    sid    = "ScopedSecurityGroupIngressRemediation"
    effect = "Allow"

    actions = [
      "ec2:DescribeSecurityGroups",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupIngress"
    ]

    resources = ["arn:aws:ec2:${var.aws_region}:${local.account_id}:security-group/*"]
  }

  statement {
    sid    = "DetectWildcardIamPolicies"
    effect = "Allow"

    actions = [
      "iam:GetRolePolicy",
      "iam:ListRolePolicies"
    ]

    resources = ["arn:aws:iam::${local.account_id}:role/sentinelops-*"]
  }

  statement {
    sid    = "DenyPrivilegeEscalation"
    effect = "Deny"

    actions = [
      "iam:AttachRolePolicy",
      "iam:PutRolePolicy",
      "iam:CreatePolicy",
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion",
      "iam:PassRole",
      "iam:UpdateAssumeRolePolicy",
      "sts:AssumeRole",
      "sts:AssumeRoleWithWebIdentity",
      "sts:AssumeRoleWithSAML"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role" "bootstrap" {
  name = local.bootstrap_role

  assume_role_policy = data.aws_iam_policy_document.bootstrap_role.json

  tags = local.default_tags
}

resource "aws_iam_policy" "bootstrap" {
  name        = "${local.bootstrap_role}-policy"
  description = "Least-privilege baseline policy for the SentinelOps sandbox bootstrap and future automation."
  policy      = data.aws_iam_policy_document.bootstrap_policy.json
}

resource "aws_iam_role_policy_attachment" "bootstrap" {
  role       = aws_iam_role.bootstrap.name
  policy_arn = aws_iam_policy.bootstrap.arn
}

resource "aws_iam_role" "assessment" {
  name = var.assessment_role_name

  assume_role_policy = data.aws_iam_policy_document.assessment_role.json

  tags = local.default_tags
}

resource "aws_iam_policy" "assessment" {
  name        = "${var.assessment_role_name}-policy"
  description = "Read-only evidence collection policy for SentinelOps assessment workflows."
  policy      = data.aws_iam_policy_document.assessment_policy.json
}

resource "aws_iam_role_policy_attachment" "assessment" {
  role       = aws_iam_role.assessment.name
  policy_arn = aws_iam_policy.assessment.arn
}

resource "aws_iam_role" "remediation" {
  name = var.remediation_role_name

  assume_role_policy = data.aws_iam_policy_document.remediation_role.json

  tags = local.default_tags
}

resource "aws_iam_policy" "remediation" {
  name        = "${var.remediation_role_name}-policy"
  description = "Allowlisted only for the SentinelOps remediation actions that are explicitly approved by the application workflow."
  policy      = data.aws_iam_policy_document.remediation_policy.json
}

resource "aws_iam_role_policy_attachment" "remediation" {
  role       = aws_iam_role.remediation.name
  policy_arn = aws_iam_policy.remediation.arn
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "github_oidc_plan_role" {
  statement {
    sid     = "AllowGithubActionsAssumeRoleWithWebIdentity"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

data "aws_iam_policy_document" "github_plan_policy" {
  statement {
    sid    = "PlanReadOnlyIdentity"
    effect = "Allow"

    actions = [
      "sts:GetCallerIdentity",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetBucketAcl",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "iam:ListPolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListRoles",
      "iam:GetRole",
      "iam:GetAccountSummary",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeVpcs",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:ListTags",
      "budgets:DescribeBudget",
      "budgets:DescribeBudgets",
      "kms:DescribeKey",
      "kms:ListAliases",
      "kms:ListKeys"
    ]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "github_oidc_apply_role" {
  statement {
    sid     = "AllowGithubActionsAssumeRoleWithWebIdentity"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

data "aws_iam_policy_document" "github_apply_policy" {
  statement {
    sid    = "GitHubApplyReservedReadOnly"
    effect = "Allow"

    actions = [
      "sts:GetCallerIdentity",
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:GetBucketAcl",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketTagging",
      "s3:GetObject",
      "s3:GetObjectVersion",
      "iam:ListPolicies",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListRoles",
      "iam:GetRole",
      "iam:GetAccountSummary",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeVpcs",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:GetLogEvents",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:ListTags",
      "budgets:DescribeBudget",
      "budgets:DescribeBudgets",
      "kms:DescribeKey",
      "kms:ListAliases",
      "kms:ListKeys"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role" "github_plan" {
  name = var.github_plan_role_name

  assume_role_policy = data.aws_iam_policy_document.github_oidc_plan_role.json

  tags = local.default_tags
}

resource "aws_iam_policy" "github_plan" {
  name        = "${var.github_plan_role_name}-policy"
  description = "Read-only Terraform validation policy for the GitHub OIDC deploy role."
  policy      = data.aws_iam_policy_document.github_plan_policy.json
}

resource "aws_iam_role_policy_attachment" "github_plan" {
  role       = aws_iam_role.github_plan.name
  policy_arn = aws_iam_policy.github_plan.arn
}

resource "aws_iam_role" "github_apply" {
  name = var.github_apply_role_name

  assume_role_policy = data.aws_iam_policy_document.github_oidc_apply_role.json

  tags = local.default_tags
}

resource "aws_iam_policy" "github_apply" {
  name        = "${var.github_apply_role_name}-policy"
  description = "Reserved read-only GitHub OIDC policy. No write operations are allowed without explicit AWS authorization."
  policy      = data.aws_iam_policy_document.github_apply_policy.json
}

resource "aws_iam_role_policy_attachment" "github_apply" {
  role       = aws_iam_role.github_apply.name
  policy_arn = aws_iam_policy.github_apply.arn
}

resource "aws_budgets_budget" "sandbox" {
  name              = "${var.project}-${var.environment}-monthly-budget"
  budget_type       = "COST"
  limit_amount      = tostring(var.budget_monthly_limit)
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = formatdate("YYYY-MM-01_00:00", timestamp())

  cost_types {
    include_tax                = false
    include_subscription       = true
    include_support            = true
    include_upfront            = false
    include_recurring          = true
    include_other_subscription = false
    use_blended                = false
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_notification_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_notification_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_notification_email]
  }
}
