# Phase 6 — Managed security integrations

## Objective

Define the local contract for how SentinelOps accepts and normalizes findings from managed AWS security sources before they enter the internal risk engine. This phase intentionally keeps all validation local, deterministic, and non-destructive.

## Why this is necessary

A platform that ingests security findings from multiple sources must preserve the original source identity and reject unsupported or malformed payloads. Without these safeguards, duplicate events, unsupported data, and ambiguous provenance can distort risk scoring and create false confidence.

## Supported source model

SentinelOps accepts only the following finding sources:

- `securityhub`
- `guardduty`
- `aws_config`
- `sentinelops`

Any source outside this set is treated as unsupported and cannot be processed by the internal pipeline.

## Provenance and deduplication rules

Every ingested finding should carry enough trace metadata to answer: where did it come from, which AWS account and region did it affect, and what is the original source identifier?

The local deduplication key is derived from:

- source
- account ID
- region
- source finding ID

This yields an idempotent identity that prevents repeated ingestion of the same event while preserving source traceability.

## Local ingestion contract

The validation layer should enforce these requirements before a finding can be classified as supported:

1. `source` is present and supported.
2. `source_finding_id` is present.
3. `account_id` is present.
4. `region` is present.
5. The payload is a structured dictionary and not empty.

If any requirement fails, the finding is rejected with deterministic logic rather than defaulting to a pass state.

## Design rules

- Preserve the original source information for attribution and auditing.
- Reject unsupported integrations early to avoid policy drift.
- Deduplicate based on a stable, deterministic key.
- Treat malformed or partially populated payloads as invalid, not compliant.
- Continue to run all validation locally and without AWS credentials.

## Acceptance criteria

Phase 6 is ready when all of the following are true:

- the supported source set is documented and consistent across code and tests,
- unsupported sources are rejected before model normalization,
- duplicate findings produce the same dedupe key for the same source event,
- malformed findings fail fast and do not pass through the main pipeline,
- and the design remains explicitly read-only until the user approves a live AWS integration path.
