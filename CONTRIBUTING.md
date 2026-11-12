# Contributing to SentinelOps

## Repository expectations

- Keep changes aligned with the SentinelOps master specification.
- Do not deploy live AWS resources without explicit approval.
- Use local synthetic fixtures and unit tests before AWS integration work.
- Record important decisions in the ADR folder.
- Maintain documentation when architecture or security controls change.

## Workflow

1. Review the current phase and gate requirements.
2. Update the progress log when work changes phase or status.
3. Add or update tests for any behavioral change.
4. Confirm that security controls and cost implications are documented.
5. Avoid broad IAM access or operational changes without review.

## Documentation requirements

- Maintain the project charter and ADR records.
- Capture cost assumptions and cleanup requirements before provisioning.
- Keep architecture, threat model, and test documentation synced with implementation.
