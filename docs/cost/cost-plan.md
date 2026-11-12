# SentinelOps cost plan

## Phase 0 policy

No billable AWS resources should be provisioned in this phase. The project relies on local documentation and synthetic validation only.

## Cost guardrails

- Keep all initial validation local.
- Do not run Terraform apply while the project is in Phase 0.
- Require explicit user approval before any AWS account or test environment work.
- Budget and cleanup assumptions must be reviewed before any deployment.

## Typical future cost drivers

- AWS Config recording and evaluation
- GuardDuty and Security Hub findings
- CloudTrail event volume and data-event logging
- CloudWatch logs and metric retention
- EventBridge and Step Functions usage
- S3 storage and lifecycle management
- Lambda execution and DynamoDB throughput
- KMS requests and key usage
- NAT Gateway or public networking costs

## Required future controls

- set a clear budget ceiling before live deployment
- retain only purposely selected AWS regions and services
- prefer management-event logging before data-event logging
- require cleanup and teardown documentation for every provisioning step
- explicitly state resources that remain active after a demo or validation run

## Current state

- Active AWS spend: none
- This document is a placeholder for future cost review in later phases.
