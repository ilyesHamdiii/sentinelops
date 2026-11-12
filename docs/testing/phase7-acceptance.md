# Phase 7 acceptance checks

## Goal

Validate the SentinelOps risk engine before any live AWS inventory or remediation workflow is connected.

## Required acceptance checks

### 1. Deterministic scoring

- The same input values produce the same risk score on repeated execution.
- The final risk is bounded to the 0-100 range.
- Policy versioning is included so the scoring logic can be explained and compared later.

### 2. Severity and confidence separation

- Source severity and confidence remain distinct variables in the model.
- A high-confidence finding of moderate severity does not collapse into a generic "high" result without explanation.

### 3. Asset criticality bias

- Critical assets increase the score for otherwise similar findings.
- Standard assets do not receive the same escalation boost.

### 4. Correlation grouping

- Multiple findings for the same resource are grouped together.
- The summary includes both count and maximum observed risk score for the resource.

### 5. Local-only validation

- All checks are performed using synthetic fixtures, not real AWS telemetry or account data.
- No live AWS resources or credentials are required.

## Pass/fail outcome

The phase passes when the risk engine produces deterministic, explainable, and resource-aware scores for local findings without any dependency on cloud connectivity or live security event ingestion.
