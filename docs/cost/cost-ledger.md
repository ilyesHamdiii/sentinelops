# SentinelOps cost ledger

## Budget guardrail

- Monthly hard ceiling: $15.00 USD
- Region assumption: `eu-west-1`
- Purpose: sandbox-only validation and local-first project work
- Status: no active AWS spend under the current code and release scope

## Resource cost model

| Service / component                   | Typical driver                  | Expected monthly range | Notes                                                 |
| ------------------------------------- | ------------------------------- | ---------------------: | ----------------------------------------------------- |
| AWS Config                            | resource recording + evaluation |                  $0-$5 | Only enable if required by a live validation scenario |
| GuardDuty / Security Hub              | managed findings and checks     |                  $0-$7 | Usually the most variable cost area                   |
| CloudTrail                            | management/data events          |                  $0-$3 | Keep logging minimal and event-scoped                 |
| CloudWatch                            | logs and metrics                |                  $0-$2 | Retention and metric volume should be controlled      |
| S3 storage                            | evidence retention              |                  $0-$2 | Lifecycle and retention should be explicit            |
| Lambda + EventBridge + Step Functions | execution and event volume      |                  $0-$3 | Prefer low-volume local validation                    |
| DynamoDB                              | read/write activity             |                  $0-$2 | Keep workload small and deterministic                 |
| KMS                                   | encryption requests             |                  $0-$1 | Only if required for evidence or resource encryption  |

## Current state

- Active AWS spend: $0.00
- Active project posture: local-first, no billable AWS deployment for the release package
- Budget risk: low as long as the project remains in its documented no-live-deploy posture

## Approval policy before any live spend

Before enabling any AWS resource beyond the approved sandbox baseline, the project must document:

1. the exact services and drivers,
2. the expected monthly cost range,
3. the teardown steps,
4. the role assumption path and OIDC requirements,
5. the proof of approval from the human operator.

## Release note

This phase keeps all evidence within the repository and treats cost as a required control, not a hidden assumption. The project remains intentionally under the $15/month guardrail unless a new explicit deployment decision is approved.
