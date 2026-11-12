# Remediation approval and verification runbook

## Purpose

This runbook explains how to approve, execute, and verify a remediation proposal without allowing unsafe or replayed actions. It matches the current implementation in `src/sentinelops/remediation.py`.

## Preconditions

- The target issue is an allowed SentinelOps finding.
- The requested action is in the allowlist.
- The reviewer has identified the exact resource, reason, and expected outcome.
- The environment is local-only unless an explicit live AWS deployment path is approved separately.

## Approval process

1. Inspect the proposed action, target ARN or identifier, and rationale.
2. Confirm the action matches an allowlisted remediation.
3. Confirm the approval hash binds the exact action, target, and reason.
4. Reject any stale, tampered, or replayed approval.

## Execution checks

The execution flow validates:

- action is allowlisted
- target matches the approved proposal
- approval hash matches the action, target, and rationale
- approval is not expired
- execution is not being replayed
- post-execution verification is present

If any check fails, the workflow returns a rejected or failed result and leaves the finding open.

## Verification pattern

After a remediation attempt, the workflow requires independent verification of the actual target state. If the state does not match the expected final value, the finding remains `OPEN` and the approval is considered unsuccessful.

## Failure modes

- expired approvals
- mismatched target or action
- replayed approval
- failed verification
- unapproved action type
- destructive action outside the allowlist

## Exit criteria

Only a verified remediation that passes the post-action validation and matches the approved target and reason is considered resolved.
