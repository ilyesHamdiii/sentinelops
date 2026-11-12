# SentinelOps Phase 12 architecture and sequence diagrams

## System context

```mermaid
flowchart LR
    OP[Operator / approver] --> API[SentinelOps API]
    API --> NORM[Normalization and validation]
    NORM --> RISK[Deterministic risk engine]
    RISK --> SCEN[Scenario validation]
    SCEN --> REM[Approval-gated remediation]
    REM --> VERIFY[Independent verification]
    VERIFY --> REPORT[Sanitized reporting]

    AWS[AWS evidence sources] --> NORM
    LOCAL[Synthetic fixtures and local validation] --> NORM
    GH[GitHub Actions] --> OIDC[GitHub OIDC]
    OIDC --> CI[PR and deployment gates]
    CI --> AWS
```

## Ingestion and scoring flow

```mermaid
sequenceDiagram
    participant Source as AWS source / fixture
    participant Ingest as Ingestion validation
    participant Normalize as Normalization handlers
    participant Risk as Risk engine
    participant Store as Local evidence state
    Source->>Ingest: Event or finding payload
    Ingest->>Ingest: Validate schema, source, idempotency
    Ingest->>Normalize: Canonical payload
    Normalize->>Risk: Normalized finding
    Risk->>Risk: Score severity + confidence + exposure + criticality
    Risk->>Store: Risk evidence + rationale
    Store-->>Source: Traceable finding record
```

## Scenario validation and approval flow

```mermaid
sequenceDiagram
    participant User as Reviewer
    participant API as API / workflow
    participant Eval as Scenario evaluator
    participant Remed as Remediation workflow
    participant Verify as Post-action verifier
    participant Store as Evidence / audit store

    User->>API: Request scenario or remediation proposal
    API->>Eval: Evaluate S1-S6 logic
    Eval-->>API: Risk or validation result
    API->>Remed: Propose action with target and rationale
    User->>Remed: Approve hash-bound action
    Remed->>Verify: Execute allowlisted action
    Verify->>Store: Record actual state and verification output
    Verify-->>User: Verified or rejected outcome
```

## Actual implementation mapping

This release package reflects the current implementation in the repository:

- Validation and source gating: `src/sentinelops/validation/integrations.py`
- Canonical normalization: `src/sentinelops/normalization/handlers.py`
- Risk scoring and correlation: `src/sentinelops/risk.py`
- Scenario suite: `src/sentinelops/scenarios.py`
- Secure approval workflow: `src/sentinelops/remediation.py`
- Read-only API and sanitized reporting: `src/sentinelops/api/app.py` and `src/sentinelops/reporting/reporting.py`
- CI/CD hardening workflow: `.github/workflows/phase0-placeholder.yml` and `.github/workflows/deploy-oidc.yml`

These diagrams intentionally represent the implemented architecture: local-first validation, read-only by default, deterministic scoring, approval-gated remediations, and zero static AWS credentials in automation.
