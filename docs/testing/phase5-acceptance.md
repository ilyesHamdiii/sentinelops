# Phase 5 acceptance checks

## Goal

Validate the SentinelOps baseline control engine before it is connected to any live AWS inventory.

## Required acceptance checks

### 1. Secure resource path

- A secure S3 bucket with full public access blocking passes the baseline check.
- A restrictive Security Group without public ingress passes the baseline check.
- A least-privilege IAM policy passes the baseline check.

### 2. Insecure resource path

- A bucket with missing or false public access block flags fails the baseline check.
- A security group exposing SSH or RDP to the internet fails the baseline check.
- A wildcard IAM policy fails the baseline check.

### 3. Unknown resource behavior

- Any resource type not explicitly covered by the rule set returns `UNKNOWN` rather than `PASS`.
- The result includes a clear explanation that the resource type has not yet been evaluated.

### 4. Deterministic behavior

- The evaluation result must be stable for the same resource input.
- The outcome should not depend on live AWS state or external network access.

### 5. Evidence traceability

- Every baseline result includes a summary and a list of findings that can be logged or preserved as evidence.
- Synthetic fixtures can be used to reproduce the evaluation without AWS access.

## Pass/fail outcome

The phase passes when the local baseline engine behaves consistently for secure, insecure, and unknown resources and there are no hidden assumptions about live AWS configuration.
