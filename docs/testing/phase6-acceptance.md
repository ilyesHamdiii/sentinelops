# Phase 6 acceptance checks

## Goal

Validate the SentinelOps managed integration contract before any live AWS ingestion is enabled.

## Required acceptance checks

### 1. Supported-source handling

- Security Hub, GuardDuty, AWS Config, and SentinelOps are accepted as valid sources.
- Unsupported values such as `cloudtrail` are rejected.
- Source support is deterministic and stable across repeated checks.

### 2. Duplicate prevention

- The same source event repeated under the same account, region, and source finding ID produces the same deduplication key.
- The result is safe for idempotent processing in a future ingestion pipeline.

### 3. Malformed findings

- Missing `source_finding_id`, `account_id`, or `region` causes rejection.
- Non-dictionary inputs are rejected.
- Unsupported source data must not be treated as compliant.

### 4. Provenance traceability

- The data must preserve source metadata so future correlation and reporting can identify the upstream ecosystem.
- The finding cannot lose its origin while being normalized inside SentinelOps.

### 5. Local-only validation

- All validation is performed with local synthetic fixtures.
- No live AWS APIs or deployment actions are required.

## Pass/fail outcome

The phase passes when the managed integration layer reliably accepts only supported sources and rejects malformed or duplicate work without any dependency on cloud connectivity or billable infrastructure.
