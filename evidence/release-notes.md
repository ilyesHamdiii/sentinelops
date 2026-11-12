# SentinelOps release notes

## Release status

SentinelOps is complete for the current portfolio milestone and remains intentionally local-first, read-only by default, and intentionally limited to a no-live-deploy posture unless the user explicitly approves future AWS activity.

## Included in this release

- architecture overview and implementation-aligned diagrams
- phase-by-phase progress ledger
- secure remediation workflow with allowlist and verification gates
- deterministic risk scoring and scenario validation
- sanitized report and API outputs
- GitHub Actions CI and OIDC hardening controls
- operational runbooks and cost ledger

## Security posture

- no static AWS credentials in repository automation
- GitHub OIDC preferred for deployment trust
- all remediation actions require approval and verification
- evidence files are sanitized and secret-free

## Verification status

- pytest: passed
- Ruff: passed
- mypy: passed

## Known limitations

- no live AWS deployment is included in this release package
- the project remains suitable for controlled local validation and review rather than production cloud enforcement
- future cloud deployment must be explicitly approved and scoped to the sandbox budget guardrail
