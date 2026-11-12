locals {
  default_tags = {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = "sentinelops"
    CostGuard   = "sandbox-budget"
  }
}
