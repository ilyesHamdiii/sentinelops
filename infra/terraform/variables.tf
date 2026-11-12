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
