# Phase 1 acceptance tests

## Functional acceptance

- A valid finding payload passes schema validation without modification.
- An invalid finding payload fails with a clear validation error.
- A valid event envelope is accepted and stored with the required metadata.
- A missing required event field is rejected and does not enter the processing path.
- A finding risk score is numerically bounded to 0-100.

## Security acceptance

- Event payloads are treated as untrusted inputs.
- No implementation path accepts malformed fields silently.
- Approval and remediation transitions remain design-controlled rather than UI-only.
- Synthetic tests remain local and do not require AWS deployment.

## Documentation acceptance

- Architecture diagrams and trust boundaries are documented.
- The threat model identifies the main failure modes and controls.
- State machine and approval flow requirements are traceable to the project specification.
- The project documents the no-deploy posture for this phase.
