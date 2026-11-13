variable "aws_region" {
  description = "AWS region for the SentinelOps sandbox and future test workloads. This sandbox is strictly pinned to eu-west-1."
  type        = string
  default     = "eu-west-1"

  validation {
    condition     = var.aws_region == "eu-west-1"
    error_message = "The SentinelOps sandbox must remain pinned to eu-west-1."
  }
}

variable "project" {
  description = "Project name used in cost and resource tagging."
  type        = string
  default     = "sentinelops"
}

variable "environment" {
  description = "Environment name applied to all sandbox resources."
  type        = string
  default     = "sandbox"
}

variable "budget_monthly_limit" {
  description = "Monthly spend ceiling for sandbox workloads. This is a governance guardrail, not a deployment target."
  type        = number
  default     = 15

  validation {
    condition     = var.budget_monthly_limit == 15
    error_message = "The SentinelOps sandbox budget ceiling is strictly $15/month."
  }
}

variable "budget_notification_email" {
  description = "Monitored email used for sandbox budget notifications."
  type        = string
  default     = "ilyesilyeshamdi10@gmail.com"

  validation {
    condition     = can(regex("^[^@]+@[^@]+\\.[^@]+$", var.budget_notification_email))
    error_message = "The budget notification email must be a valid address."
  }
}

variable "github_repository" {
  description = "GitHub repository in the form owner/repo for OIDC trust restrictions."
  type        = string
  default     = "ilyesHamdiii/sentinelops"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "The GitHub repository must be provided as owner/repo."
  }
}

variable "github_environment" {
  description = "GitHub Actions environment name restricted by the OIDC trust policy."
  type        = string
  default     = "sandbox"
}

variable "assessment_role_name" {
  description = "Role name for the read-only SentinelOps assessment identity."
  type        = string
  default     = "sentinelops-assessment"
}

variable "remediation_role_name" {
  description = "Role name for the allowlisted SentinelOps remediation identity."
  type        = string
  default     = "sentinelops-remediation"
}

variable "github_deploy_role_name" {
  description = "GitHub OIDC deployment/validation role for the sandbox, restricted to plan-only validation until AWS authorization is granted."
  type        = string
  default     = "sentinelops-github-oidc-deploy"
}

variable "github_plan_role_name" {
  description = "Backwards-compatible alias for the GitHub OIDC deployment/plan validation role."
  type        = string
  default     = "sentinelops-github-oidc-deploy"
}

variable "github_apply_role_name" {
  description = "Reserved future GitHub OIDC apply identity. This remains non-write until explicit AWS authorization and a separate approval process."
  type        = string
  default     = "sentinelops-github-oidc-apply"
}
