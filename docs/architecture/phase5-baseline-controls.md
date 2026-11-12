# Phase 5 — Baseline controls and asset assessment

## Objective

Define the local baseline posture used before SentinelOps performs any live AWS assessment or remediation work. The project uses these controls to evaluate whether an AWS resource is clearly secure, clearly insecure, or not yet assessable without live evidence.

## Why this is necessary

A security platform cannot safely reason about real AWS state without a baseline policy that defines:

- which configurations are acceptable,
- which patterns are dangerous,
- which resources can be evaluated locally from structured fixtures, and
- which resources require an authenticated AWS inventory or Config read.

This phase creates the guardrails that protect later assessment work from false certainty and unsafe assumptions.

## Baseline policy

### S3 bucket controls

A bucket passes the baseline only when all of the following are true:

- `BlockPublicAcls = true`
- `BlockPublicPolicy = true`
- `IgnorePublicAcls = true`
- `RestrictPublicBuckets = true`

If any of these are missing or false, the asset is treated as a baseline failure.

### Security group controls

Any inbound rule that exposes port 22 or 3389 to `0.0.0.0/0` or `::/0` is considered a baseline failure.

### IAM controls

A policy is considered a baseline failure when it grants broad or wildcard access such as:

- `*` actions,
- `AdministratorAccess`,
- or a resource wildcard that violates least-privilege expectations.

### Unknown resource types

Resources not yet evaluated by the policy remain in an `UNKNOWN` state until the relevant rule set is explicitly coded. This avoids false compliance claims.

## Local workflow

The baseline check should be implemented as a read-only evaluator over a normalized asset model. It must:

1. accept a structured AWS-like resource object,
2. evaluate only the known rules for that resource type,
3. return PASS, FAIL, or UNKNOWN,
4. preserve evidence in a machine-readable result object.

## Design rules

- Never treat an unknown resource as compliant.
- Prefer explicit failure over silent assumption.
- Keep the evaluator deterministic and testable with synthetic fixtures.
- Store the result alongside evidence metadata so that later AWS checks can compare baseline vs. observed state.

## Acceptance criteria

Phase 5 is ready when all of the following are true:

- secure and insecure local fixtures exist for S3, Security Group, and IAM policies,
- the evaluator returns PASS/FAIL/UNKNOWN deterministically,
- no live AWS resources or privileged actions are required to exercise the checks,
- baseline findings are documented and traceable,
- and the project can explain why unknown or unrecognized resources do not pass by default.
