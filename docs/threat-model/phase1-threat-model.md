# Phase 1 threat model

## Assets

- AWS account and test resources
- IAM identities and trust policies
- S3 evidence and reports
- DynamoDB finding and workflow records
- EventBridge and Step Functions execution state
- GitHub repository and CI identity
- Approval records and audit logs

## Threats identified

- malformed or malicious event payloads
- duplicate or replayed findings
- privilege escalation through broad IAM permissions
- approval bypass or stale approval reuse
- remediation targeting the wrong resource
- secret leakage through logs and reports
- drift between expected and actual resource state
- false resolved status after failed verification

## Security controls required by Phase 1

- schema validation on all inbound events
- event size and payload constraints
- idempotency keys and deduplication strategy
- least-privilege IAM design and role separation
- explicit approval gate for operationally disruptive actions
- structured logs with secret redaction
- independent post-action verification before resolution
- sandboxed synthetic scenarios before any live AWS activity

## Trust-boundary assessment

The highest-risk boundary is the transition from untrusted event input into internal processing. This is where malformed payloads, replayed events, and duplicate writes are prevented. The second major risk is the transition from a proposed remediation to actual control execution, which must be blocked unless the approval flow is valid and the action is allowlisted.

## Phase 1 risk posture

The project remains in a restricted local-only state. The threat model is designed to keep the system safe even before AWS integration by validating events and controlling the workflow contract at the application boundary.
