output "aws_region" {
  description = "Configured AWS region for this Terraform foundation."
  value       = var.aws_region
}

output "project" {
  description = "Project name used for all SentinelOps sandbox resources."
  value       = var.project
}

output "environment" {
  description = "Environment label applied to sandbox resources."
  value       = var.environment
}

output "default_tags" {
  description = "Mandatory tags applied to all future SentinelOps resources."
  value       = local.default_tags
}

output "budget_monthly_limit" {
  description = "Configured monthly budget ceiling for sandbox validation activities."
  value       = var.budget_monthly_limit
}

output "budget_notification_email" {
  description = "Monitored email configured for AWS budget notifications."
  value       = var.budget_notification_email
}

output "terraform_state_bucket_name" {
  description = "Private S3 bucket used for SentinelOps Terraform remote state."
  value       = aws_s3_bucket.terraform_state.bucket
}

output "terraform_lock_table_name" {
  description = "DynamoDB table used to lock the SentinelOps Terraform state."
  value       = aws_dynamodb_table.terraform_locks.name
}

output "evidence_bucket_name" {
  description = "Name of the S3 bucket reserved for evidence and report artifacts."
  value       = aws_s3_bucket.evidence.bucket
}

output "cloudtrail_bucket_name" {
  description = "Name of the S3 bucket reserved for CloudTrail log storage."
  value       = aws_s3_bucket.cloudtrail.bucket
}

output "cloudtrail_name" {
  description = "CloudTrail trail name for the SentinelOps sandbox baseline."
  value       = aws_cloudtrail.management.name
}

output "bootstrap_role_arn" {
  description = "ARN of the least-privilege role intended for future Terraform or automation bootstrap use."
  value       = aws_iam_role.bootstrap.arn
}

output "findings_table_name" {
  description = "DynamoDB table used to persist normalized SentinelOps findings."
  value       = aws_dynamodb_table.findings.name
}

output "idempotency_table_name" {
  description = "DynamoDB table used to guard duplicate or replayed inbound events."
  value       = aws_dynamodb_table.idempotency.name
}
