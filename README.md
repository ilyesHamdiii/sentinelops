# SentinelOps

SentinelOps is an AWS cloud security and resilience platform designed to discover weaknesses, explain risk, validate controls, coordinate safe remediation, verify final state, and preserve evidence.

## Current status

This repository is currently in Phase 12: release and portfolio. The platform remains local-first and approval-gated; no Terraform apply, no live AWS deployment, and no billable resources are authorized in this phase.

## Project scope

The platform follows the master project specification and focuses on a disciplined, evidence-driven workflow:

- collect AWS asset and configuration evidence
- normalize findings from multiple AWS sources
- score risk with explainable rules
- validate security controls with synthetic scenarios
- generate approval-gated remediation proposals
- verify actual AWS state before declaring a finding resolved

## Repository structure

The repository is scaffolded to match the specification and includes the required directories for architecture, testing, security scenarios, infrastructure, and delivery artifacts.

## Safety rules

- No live AWS deployment without explicit user approval.
- No Terraform apply while Phase 0 is in progress.
- Keep the initial work local, synthetic, and test-driven.
- Treat event payloads as untrusted and validate them before further processing.

## Phase 0 evidence

- project charter written
- ADR framework created
- cost guardrails recorded
- repository layout initialized
- progress tracking established
