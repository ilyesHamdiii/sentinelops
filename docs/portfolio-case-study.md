# Portfolio case study

## Problem

Cloud security posture tools often fail in one of two ways: they either report findings without a trustworthy remediation workflow, or they permit remediation without independent verification. In practice, that creates a false sense of control and can lead to a dangerous mismatch between observed risk and actual state.

SentinelOps was built to address that gap with a disciplined assessment and remediation pipeline that keeps evidence, decisions, and verification separate.

## Architecture

The project uses a headless Python backend with a deterministic scenario engine and a risk scoring layer. It reads evidence from AWS-inspired collectors, evaluates security policy conditions, and requires an approval before a remediation action can proceed. The workflow reaches a resolved state only after fresh evidence confirms the original issue is gone.

## Important security decisions

- Approval is not just a UI action; it is a cryptographically bound approval record with the action, target, and rationale embedded in the hash.
- Remediation action execution is allowlisted and cannot proceed without a valid approval.
- Replay protection uses a durable ledger so a previously consumed approval cannot be reused after process restarts.
- Fresh evidence is required for verification, which prevents stale findings from being declared resolved.
- The assessment identity remains read-only and separate from the remediation identity.

## Why approval-gated remediation was chosen

Remediation without approval creates a dangerous control gap in security operations. An attacker, a misconfigured automation path, or an overly broad operator action could trigger a destructive or unsafe change. SentinelOps demonstrates the safer model: approvals are explicit, recorded, and validated against policy.

## Least privilege implementation

The source Terraform documents separate trust and permissions for bootstrap, assessment, remediation, and GitHub OIDC workflow use. The assessment role is intentionally read-only. The remediation role is limited to the supported action set. There is no broad admin role in the default local security model.

## Replay protection and verification

The SQLite ledger ensures a consumed approval cannot be reused. The project also prevents reused assessment session IDs and rejects stale evidence older than the validation window. Verification collects fresh evidence and re-evaluates the scenario before a finding is closed.

## What was tested locally

The project validates:

- scenario detection logic,
- risk evaluation,
- approval creation and validation,
- replay rejection,
- session reuse rejection,
- stale-evidence rejection,
- verification failure semantics,
- end-to-end deterministic workflow behavior.

## What remains unvalidated

No live AWS validation has been performed. The repository remains source-based and locally validated only. Any AWS sandbox demonstration must be approved separately and executed under explicit guardrails.

## Lessons learned

The critical lesson is that security automation is only as strong as its replay and verification controls. A tool that can detect a vulnerability but cannot prove that the fix is in place is not operationally complete. SentinelOps is designed to demonstrate that difference clearly.
