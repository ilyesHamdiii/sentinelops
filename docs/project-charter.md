# SentinelOps project charter

## Mission

SentinelOps is an AWS-focused cloud security and resilience platform that discovers cloud weaknesses, explains their risk, validates security controls, coordinates safe remediation, verifies the final state, and preserves evidence.

## Problem addressed

Small and medium-sized organizations often lack dedicated cloud security teams. Their AWS findings are fragmented across services, making it difficult to prioritize risk, assess whether controls work, and verify that changes actually improved security.

## Scope

The project will implement a disciplined, evidence-driven workflow for:

- collecting AWS asset and configuration evidence
- normalizing findings from multiple sources
- assessing risk with explainable rules
- validating controls through controlled scenarios
- generating remediation proposals with approval gates
- executing allowlisted actions safely
- verifying real AWS state after remediation
- publishing auditable reports and history

## Non-goals

- Autonomous unrestricted remediation without approval
- replacement of a full SIEM or commercial CSPM
- multi-account enterprise rollout in the MVP
- Kubernetes or complex microservice architecture without necessity
- live production incident response
- unbounded LLM autonomy in the security decision path
- deployment of billable AWS resources without explicit user authorization

## Security constraints

- Use least privilege IAM policies and role separation.
- Do not commit secrets, tokens, or live customer data.
- Local synthetic data is required before AWS integration.
- No Class 2 remediation without explicit approval.
- Verification must be independent from execution.
- API access must remain localhost-bound until authorization is implemented.

## Cost and operational boundaries

- Budget ceiling must be documented and reviewed before any AWS deployment.
- Local mock and unit-based validation is the default path in early phases.
- No Terraform apply or live AWS deployment is permitted without explicit user approval.
- Resources must be tracked, cleaned up, and documented as required.

## Phase 0 focus

The immediate objective is to establish the repository control baseline, governance, documentation, and technical acceptance gates before any application code or cloud provisioning work begins.

## Success indicators

- Repository and document structure match the specification.
- ADR framework exists and is used for material decisions.
- Threat model, scope, and cost guardrails are documented.
- Local validation plan is ready before AWS integration.
- No unsupported deployment step is executed without approval.
