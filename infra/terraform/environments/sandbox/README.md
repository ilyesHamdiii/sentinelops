# Sandbox environment placeholder

This directory is reserved for the sandbox environment configuration used by SentinelOps.

## Policy

- only the `eu-east-1` region is approved for this workload
- resources must carry the required tags: `Project = "sentinelops"` and `Environment = "sandbox"`
- no Terraform apply is authorized until explicit user approval is given
- local validation and `terraform validate` checks are allowed, but no real AWS deployment is permitted
