# Phase 8 acceptance checks

## Goal

Validate the local scenario catalog before any live AWS scenario execution is approved.

## Required acceptance checks

### 1. Scenario catalogue

- Exactly six scenarios are defined and match the specification.
- Each scenario has a stable ID and title.

### 2. Expected outcome validation

- A valid scenario with a matching observed outcome passes.
- A valid scenario with an unexpected observed outcome fails.
- Unknown scenario IDs return `UNKNOWN` instead of a false pass.

### 3. Local-only execution

- Scenario checks run using synthetic metadata and expected results only.
- No live AWS APIs or credentials are required for validation.

### 4. Regression safety

- The test system is deterministic for repeated runs.
- The validation contract is strict enough to detect mismatched scenario outcomes before real execution.

### 5. IAM wildcard handling

- IAM wildcard findings are detected and reported without allowing automatic deletion of an inline policy.
- The remediation role does not permit `iam:DeleteRolePolicy`.
- Mixed policies containing both excessive wildcard permissions and legitimate permissions are explicitly treated as a routine manual review case.

## Pass/fail outcome

The phase passes when the six scenario definitions and expected outcomes behave deterministically in a local, read-only environment and are ready for a future approval-gated AWS test run.
