# AWS deployment plan

## Purpose

This plan defines the future controlled sandbox demonstration path for SentinelOps. It is intentionally not a live deployment record.

## Target environment

- Region: `eu-west-1`
- Account: authorized sandbox account only
- Scope: non-production demonstration only

## Identity separation

- Assessment identity: read-only discovery
- Remediation identity: narrow allowlist
- Bootstrap identity: setup and teardown only
- OIDC identity: GitHub Actions trust path only; the workflow uses `arn:aws:iam::960577828312:role/sentinelops-github-oidc-deploy` and is plan-only

## Required safeguards

- Budget guardrails must be set before any AWS action.
- All resource names and tags must be specific to the sandbox exercise.
- Cleanup must be validated after each run.
- Any AWS action sequence must be logged to the evidence ledger.
- The GitHub environment must be `sandbox` and the trust subject must remain `repo:ilyesHamdiii/sentinelops:environment:sandbox`.

## Resource inventory

- public S3 bucket for misconfigured access
- IAM policy resource for wildcard access demonstration
- EC2 security group with public ingress on 22 and/or 3389
- associated audit and logging resources for evidence collection

## Not executed

This deployment plan remains a pre-authorized blueprint only. No actual cloud actions have been run in this workspace.
