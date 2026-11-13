# SentinelOps --- AWS Cloud Security & Resilience Platform

## Master project specification and AI-agent build brief

**Version:** 1.0 \| **Status:** Proposed architecture; verify current
AWS behavior, pricing, quotas, and regional availability before
deployment.\
**Estimated duration:** 20--24 weeks at 8--10 hours/week (160--240
focused hours). If starting with little AWS/Terraform/Python experience,
plan 24--32 weeks.\
**Primary objective:** Build a reproducible AWS security engineering
platform that discovers cloud weaknesses, explains their risk, validates
controls, coordinates safe remediation, verifies the actual final state,
and preserves evidence.

------------------------------------------------------------------------

# 0. Instructions for the AI agent

Act as senior cloud security architect, Python/AWS mentor,
implementation partner, and strict technical reviewer. Build this
incrementally. Do not generate the whole application at once.

## Mandatory rules

1.  Teach the user the reason behind each design and implementation
    decision.
2.  Never claim a feature is complete without reproducible evidence and
    passing acceptance tests.
3.  Use least privilege. Never casually use `AdministratorAccess`,
    wildcard permissions, hardcoded credentials, or broad trust
    policies.
4.  Never commit AWS credentials, tokens, secrets, real customer data,
    or sensitive logs.
5.  Start read-only. All potentially disruptive remediation must require
    explicit approval, an allowlisted action, a target-bound approval,
    an audit record, and post-action verification.
6.  Treat events and API inputs as untrusted. Validate schemas, enforce
    size limits, redact secrets, and handle malformed data.
7.  Design for duplicate events, retries, timeouts, partial failure,
    idempotency, and replay.
8.  Check current official AWS/HashiCorp/GitHub documentation and
    pricing before enabling services or writing service-specific code.
    Do not rely on memory for current product names, regional support,
    quotas, APIs, or pricing.
9.  Never assume AWS Free Tier covers a service or usage pattern. A
    budget alert is not a hard spending cap.
10. Do not assume GuardDuty detects arbitrary simulated API activity.
    Use supported sample findings or documented test mechanisms; test
    custom detection logic separately with synthetic fixtures.
11. Do not introduce Kubernetes, multi-cloud, LLM-based autonomous
    decisions, microservices, or a complex UI without a clear
    requirement.
12. Keep an Architecture Decision Record (ADR) for material design
    changes.
13. At each session end, report current phase, files changed, commands
    run, test outcomes, blockers, cost/cleanup status, and next three
    tasks.
14. Ask only questions that block progress; otherwise state assumptions
    and proceed.
15. Never deploy billable resources without first explaining services,
    cost drivers, expected usage, cleanup, and obtaining the user's
    explicit go-ahead.

## Required format for every implementation task

-   Objective and rationale.
-   Prerequisites and architecture impact.
-   Exact files to create/change.
-   Complete code and commands.
-   Expected output.
-   Tests and acceptance criteria.
-   IAM permissions and security implications.
-   Cost implications and cleanup.
-   Common failure modes.
-   What the user must learn and explain in an interview.

Do not provide unexplained fragments. Do not conceal uncertainty. Review
code for correctness, IAM scope, secrets, idempotency, retries, event
ordering, logging, tests, rollback, cost, and documentation.

------------------------------------------------------------------------

# 1. Product definition

## 1.1 Real problem

Small and medium-sized organizations use AWS but may lack a dedicated
cloud security team. Findings are scattered across services; operators
may not know which issues matter most, whether controls work, how to
remediate safely, or whether a fix actually succeeded.

## 1.2 Mission

**Discover cloud weaknesses, explain their risk, validate security
controls, coordinate safe remediation, and prove the final state.**

## 1.3 Product behavior

SentinelOps is a lightweight cloud security assessment, validation, and
controlled-remediation platform. It: 1. Collects AWS
asset/configuration/security evidence. 2. Normalizes findings from
different sources. 3. Correlates evidence and calculates explainable
risk. 4. Validates selected controls with controlled scenarios. 5.
Creates remediation proposals. 6. Requires approval for disruptive
changes. 7. Executes narrowly scoped actions. 8. Re-reads AWS to verify
the result. 9. Preserves evidence, history, and reports.

## 1.4 Intended users

Cloud administrator, security analyst, cloud security engineer,
small-company IT manager, technical reviewer.

## 1.5 Not the goal

Not a SIEM replacement, commercial CSPM, full compliance certification,
autonomous unrestricted agent, production incident-response service, or
guarantee of complete cloud security.

## 1.6 Success criteria

-   Six security scenarios implemented and tested.
-   At least three scenarios demonstrated against isolated real AWS
    resources.
-   Positive, negative, regression, and failure tests for applicable
    controls.
-   Reproducible Terraform deployment and teardown.
-   Least-privilege IAM roles.
-   Duplicate events do not cause duplicate actions.
-   No Class 2 remediation without approval.
-   Finding is resolved only after independent verification.
-   CI runs tests and infrastructure checks.
-   Full architecture, threat model, runbooks, cost notes, limitations,
    and demo are published.

Do not claim precision/recall unless the dataset and measurement method
justify it. State dataset size and limitations.

### Live AWS sandbox evidence (actual, not synthesized)

The repository was exercised against a real AWS sandbox account on 2026-11-13 under explicit approval. The live findings were recorded in [evidence/live-discovery-2026-11-13.json](evidence/live-discovery-2026-11-13.json) and captured as:

- S1: `finding_detected` for public or unsafe S3 access
- S2: `finding_detected` for excessive IAM privileges
- S3: `finding_detected` for public administrative ingress on SSH/RDP

A controlled remediation and cleanup flow was then performed for the temporary public demo resources only. The resulting final state was recorded in [evidence/live-discovery-2026-11-13-post-remediation.json](evidence/live-discovery-2026-11-13-post-remediation.json) and reflects the post-cleanup result (`no_finding_detected`) for the temporary demo resources.

This is distinct from the local automated test suite. Local tests prove the application logic, approval gate, replay prevention, and verification policy in a deterministic environment. The live AWS evidence proves actual account-state behavior under explicit sandbox conditions and must not be confused with synthetic test results.

### Workflow provenance and ledger truth

The project’s approval and session ledger were inspected to confirm the actual execution provenance. The `approval-ledger.sqlite3` file contains consumed approval hashes from the workflow, and `session-ledger.sqlite3` contains the `live-verify-s1-remediation` verification session. The live AWS mutations themselves were performed by direct AWS CLI / boto3 operations in the sandbox account, and the application workflow was then invoked to validate the result and record the ledger state. This distinction matters: the application workflow did not originate the live mutation; it validated and logged the post-change state.

### Required governance for live execution

Live AWS operations must remain narrow, approval-bound, and recovery-aware. No broad Terraform apply or destroy, no account-wide public access change, no unrelated resource deletion, and no unapproved cleanup are allowed.

------------------------------------------------------------------------

# 2. Architecture

## 2.1 Context diagram

``` mermaid
flowchart LR
  OP[Operator] --> UI[CLI / Dashboard]
  UI --> API[SentinelOps API]
  API --> DB[(DynamoDB)]
  API --> S3[(Evidence S3)]
  AWS[AWS test environment] --> SRC[Config / GuardDuty / Security Hub / CloudTrail]
  SRC --> EB[EventBridge]
  EB --> ING[Ingestion Lambda]
  ING --> NORM[Validate and normalize]
  NORM --> DB
  NORM --> RISK[Risk engine]
  RISK --> DB
  DB --> WF[Step Functions workflow]
  WF --> APPROVE[Human approval]
  APPROVE --> REM[Scoped remediation Lambda]
  REM --> AWS
  REM --> VERIFY[Independent verifier]
  VERIFY --> DB
  VERIFY --> S3
  GH[GitHub Actions] --> OIDC[GitHub OIDC]
  OIDC --> TF[Terraform deployment role]
  TF --> AWS
```

## 2.2 Logical layers

1.  **AWS environment:** test resources and security services.
2.  **Collection:** AWS Config, Security Hub CSPM, GuardDuty,
    CloudTrail-derived events.
3.  **Normalization:** versioned internal schema, preserve source
    references.
4.  **Assessment:** deterministic risk rules with explainable factors.
5.  **Validation:** controlled test scenarios and expected outcomes.
6.  **Response:** proposal, approval, allowlisted execution,
    verification.
7.  **Presentation/evidence:** API, reports, workflow history, test
    evidence.

## 2.3 Service map

  -----------------------------------------------------------------------
  Need                    AWS service /           Responsibility
                          technology              
  ----------------------- ----------------------- -----------------------
  Identity and temporary  IAM, STS                Roles, policies, trust,
  credentials                                     AssumeRole

  Network                 VPC, subnets, route     Network boundaries
                          tables, Security        
                          Groups, NACLs           

  Storage                 S3                      Evidence, reports, test
                                                  objects

  Encryption              KMS                     Key management and
                                                  encryption

  Audit                   CloudTrail              API activity

  Configuration           AWS Config              Resource history and
                                                  compliance evaluations

  Threat detection        GuardDuty               Managed threat findings

  Security                Security Hub CSPM       Findings and security
  posture/findings                                checks

  Identity analysis       IAM Access Analyzer     External access and
                                                  policy analysis

  Event routing           EventBridge             Event routing and
                                                  filtering

  Compute                 Lambda                  Ingestion, assessment,
                                                  remediation,
                                                  verification

  Workflow                Step Functions          Approval and response
                                                  state

  Metadata                DynamoDB                Findings, approvals,
                                                  history, idempotency

  Observability           CloudWatch              Logs, metrics, alarms

  API                     FastAPI locally OR API  Choose one MVP path
                          Gateway + Lambda        

  UI                      CLI/report first; React Operator interface
                          later if justified      

  IaC                     Terraform               Repeatable
                                                  infrastructure

  CI/CD                   GitHub Actions with     Automated
                          OIDC                    checks/deployment

  Tests                   pytest, moto/local      Quality evidence
                          mocks where             
                          appropriate, AWS        
                          integration tests       
  -----------------------------------------------------------------------

**MVP deployment:** single dedicated AWS account, one selected region,
isolated test resources. Multi-account AWS Organizations is a later
extension. Begin with local synthetic fixtures and read-only collectors.
Enable paid managed services only after pricing review.

## 2.4 Key architectural decisions

-   Single account first; design resource identifiers so multi-account
    can be added later.
-   Event-driven ingestion plus scheduled reconciliation for missed
    events.
-   DynamoDB for small workflow/finding state; justify table design from
    access patterns.
-   API: select FastAPI for portable Python demonstration OR API
    Gateway/Lambda for AWS-native deployment. Do not build both without
    reason.
-   UI is secondary; CLI and generated reports are acceptable for MVP.
-   CloudTrail management events first; data events only for limited
    test resources when needed.
-   AWS Config recording/evaluations and GuardDuty/Security Hub can
    incur charges; enable selectively.
-   Keep the core risk engine deterministic. LLMs may summarize evidence
    later but must not authorize security changes.

------------------------------------------------------------------------

# 3. Threat model and security requirements

## 3.1 Assets

AWS account/resources; IAM identities and policies; S3 evidence;
DynamoDB records; KMS keys; Lambda execution roles; EventBridge/Step
Functions; GitHub repository and CI identity; approval records; reports
and logs.

## 3.2 Trust boundaries

-   GitHub Actions → AWS through OIDC.
-   AWS sources → EventBridge.
-   EventBridge → ingestion Lambda.
-   Lambda → DynamoDB/S3.
-   Operator → API/UI.
-   Workflow → approval mechanism.
-   Remediation role → target resources.
-   Test harness → AWS test environment.

## 3.3 Threats

Compromised credentials; malicious Terraform change; overprivileged
operator; malformed event; duplicate/replayed event; approval bypass;
remediation targeting wrong resource; CI compromise; secret leakage;
event flood/cost abuse; dropped findings; false resolved status.

## 3.4 Required controls

-   MFA and no daily root use.
-   IAM least privilege, role separation, scoped trust policies.
-   GitHub OIDC conditions restricted to repository and
    branch/environment.
-   No long-lived AWS keys in GitHub.
-   Encryption at rest and TLS in transit.
-   S3 Block Public Access and restrictive bucket policies.
-   Input/schema validation, event size limits, schema versioning.
-   Idempotency keys and duplicate detection.
-   Retry/DLQ strategy where appropriate.
-   Structured logs with secret redaction.
-   Approval for disruptive remediation.
-   Allowlisted actions and resource types.
-   Immutable action hash bound to approval.
-   Independent post-action verification.
-   Resource tags, cost alerts, retention and cleanup policy.
-   Localhost-only API until authentication/authorization is
    implemented.
-   Synthetic data only.

## 3.5 Remediation safety classes

-   **Class 0: Read-only.** Inspect, collect, score. No approval.
-   **Class 1: Low-impact/reversible.** May be auto-executed only after
    explicit configuration and extensive tests.
-   **Class 2: Potentially disruptive.** IAM, network, bucket access,
    key policy, or availability changes. Explicit approval and rollback
    plan required.
-   No automated resource deletion in MVP.

------------------------------------------------------------------------

# 4. Functional requirements

## FR-01 Asset/configuration assessment

Inventory supported resources (at least S3 buckets, IAM roles/policies,
EC2 Security Groups); collect identifiers, region, tags, timestamps,
evidence; distinguish unknown/error from compliant; enforce scope.

**Acceptance:** secure/insecure test fixtures; errors visible; inventory
export; out-of-scope resources not inspected.

## FR-02 Finding ingestion

Accept selected Security Hub, GuardDuty, AWS Config and custom test
events; validate; normalize; preserve source reference; deduplicate;
safely handle malformed events.

**Acceptance:** fixture tests; duplicate idempotency; source
traceability; malformed events rejected safely.

## FR-03 Risk engine

Keep source severity, platform risk, and confidence separate. Consider
exposure, asset criticality, privilege, evidence confidence,
exploitability indicators. Every score must have rationale and policy
version.

Illustrative formula only:
`risk = severity_weight × exposure_factor × asset_criticality × confidence_factor`,
normalized to 0--100. Define factor ranges, boundaries, missing-data
behavior, and version. This is a project-specific heuristic, not an
industry standard.

**Acceptance:** deterministic scoring; rationale; boundary tests;
missing evidence does not imply safe state.

## FR-04 Validation scenarios

Implement the six scenarios in Section 5. Each must specify ID/version,
preconditions, setup, test action, expected telemetry, finding, risk
rationale, remediation, approval, expected final state, cleanup,
positive/negative/regression tests.

## FR-05 Remediation

Generate proposal with target, exact change, reason, risk, rollback,
expected result; approve/reject; bind approval to action hash;
invalidate stale approvals; execute allowlisted actions; record
actor/timestamps/outcome; verify actual state.

**Acceptance:** no Class 2 action without approval; replay protection;
wrong target/hash rejected; failure does not resolve finding;
verification required.

## FR-06 Reporting

Report findings by severity/source/status; affected resources; risk
rationale; remediation state; validation results; trends only where data
supports them; limitations and unassessed areas; generation time and
policy version.

**Acceptance:** all metrics trace to source records; no unsupported
compliance claims.

------------------------------------------------------------------------

# 5. Six core security scenarios

## S1 --- Public or unsafe S3 access

Create dedicated test bucket with synthetic content. Establish private
baseline. Introduce controlled unsafe policy/settings only in isolated
test. Collect evidence, detect, propose correction, require approval,
remediate, re-read policy/public-access settings, verify, clean up.

Tests: public → finding; private → no finding; malformed policy →
unknown/error; failed remediation → remains open; successful verified
remediation → resolved.

## S2 --- Excessive IAM privileges

Create test role/policies. Introduce broad permissions or risky trust.
Inspect policy/trust documents; identify risky wildcard patterns;
explain rationale; propose least-privilege alternative; require
approval; verify effective configuration.

Nuance: wildcard is not automatically exploitable in every context.
Managed policies, boundaries, resource policies, session policies, and
explicit deny affect evaluation. Do not claim complete
effective-permission analysis unless implemented.

## S3 --- Network exposure

Create isolated VPC/test security group. Introduce broad ingress to an
administrative port from `0.0.0.0/0` only in test. Detect
protocol/port/CIDR/target; recommend narrowing; require approval; verify
rules; clean up. Prefer configuration-only test; do not launch a
publicly vulnerable host.

## S4 --- Audit logging tampering / suspicious API activity

Use a dedicated test trail/configuration. Generate controlled management
API events. Test EventBridge patterns for trail configuration, Security
Group, bucket policy, and IAM policy changes. Validate custom logic with
synthetic CloudTrail fixtures. Use documented GuardDuty sample
mechanisms for integration; do not assume arbitrary actions create
GuardDuty findings. Never disable production/organization logging.

## S5 --- Encryption and secret-management weakness

Use test-only S3/KMS resources. Inspect default encryption, bucket
policy, KMS key policy/grants, and optional Secrets Manager settings.
Detect explicitly defined unsafe conditions. Propose correction; require
approval for key policy changes; verify. Do not automate key deletion or
secret rotation in MVP.

## S6 --- Configuration drift

Deploy baseline with Terraform. Record expected state. Make controlled
out-of-band change to test resource. Detect with Terraform plan and/or
AWS Config; correlate CloudTrail if available; show expected versus
actual; review code change; apply; verify drift cleared.

Important: Terraform drift and AWS Config configuration
history/evaluations are related but different. Explain their different
data and semantics.

------------------------------------------------------------------------

# 6. Data contracts and state

## 6.1 Canonical finding schema (illustrative)

``` json
{
  "schema_version": "1.0",
  "finding_id": "stable-internal-id",
  "source": "securityhub|guardduty|aws_config|sentinelops",
  "source_finding_id": "original-source-id",
  "account_id": "test-account",
  "region": "aws-region",
  "resource": {
    "type": "AWS::S3::Bucket",
    "id": "test-resource-id",
    "arn": "resource-arn",
    "tags": {}
  },
  "title": "Unsafe storage access configuration",
  "description": "Evidence-based description",
  "severity_source": "HIGH",
  "risk_score": 78,
  "risk_policy_version": "1.0",
  "status": "OPEN",
  "first_seen": "ISO-8601",
  "last_seen": "ISO-8601",
  "evidence_refs": [],
  "scenario_id": "S3-001",
  "confidence": "HIGH",
  "remediation_state": "PROPOSED"
}
```

Never store secret values, access keys, session tokens, or unnecessary
personal data.

## 6.2 Suggested DynamoDB entities

-   Findings: `PK=FINDING#<id>`, `SK=CURRENT`.
-   Finding history: `PK=FINDING#<id>`,
    `SK=EVENT#<timestamp>#<event_id>`.
-   Remediation: `PK=REMEDIATION#<id>`, `SK=METADATA`.
-   Idempotency: `PK=IDEMPOTENCY#<source>#<event_id>`, optional TTL.
    Choose single-table or multiple-table design from access patterns;
    document the choice. TTL is not an evidence retention policy.

## 6.3 Event envelope

`event_id`, `event_type`, `schema_version`, `occurred_at`,
`received_at`, `source`, `correlation_id`, `account_id`, `region`,
`payload`, optional trace context.

Validate size, type, schema, and source. Treat event payload as
untrusted.

## 6.4 State machines

``` mermaid
stateDiagram-v2
  [*] --> OPEN
  OPEN --> TRIAGED
  TRIAGED --> PROPOSED
  PROPOSED --> APPROVED
  PROPOSED --> REJECTED
  APPROVED --> EXECUTING
  EXECUTING --> VERIFYING
  VERIFYING --> RESOLVED
  VERIFYING --> OPEN: Verification failed
  EXECUTING --> FAILED
  FAILED --> TRIAGED
  REJECTED --> TRIAGED
  RESOLVED --> OPEN: New evidence
```

``` mermaid
stateDiagram-v2
  [*] --> DRAFT
  DRAFT --> PENDING_APPROVAL
  PENDING_APPROVAL --> APPROVED
  PENDING_APPROVAL --> REJECTED
  APPROVED --> EXECUTING
  EXECUTING --> SUCCEEDED
  EXECUTING --> FAILED
  SUCCEEDED --> VERIFYING
  VERIFYING --> VERIFIED
  VERIFYING --> UNVERIFIED
```

Enforce transitions server-side, not in the UI.

------------------------------------------------------------------------

# 7. API and application design

Choose FastAPI (portable Python demo) OR API Gateway + Lambda
(AWS-native). Avoid maintaining both initially.

Suggested endpoints: - `GET /health` - `GET /findings`,
`GET /findings/{id}` - `GET /assets` - `GET /metrics/summary` -
`GET /scenarios` - `POST /scenarios/{id}/run` - `POST /remediations` -
`GET /remediations/{id}` - `POST /remediations/{id}/approve` -
`POST /remediations/{id}/reject` - `POST /remediations/{id}/execute` -
`GET /reports/{id}`

Requirements: Pydantic schemas; authn/authz before remote exposure;
role-based read/approve/execute; request limits; pagination; correlation
IDs; structured errors; OpenAPI; no secret exposure; rate limits if
internet-accessible. Local MVP binds to localhost.

CLI and generated reports are enough initially. Add React only after
backend and workflow are reliable.

------------------------------------------------------------------------

# 8. Repository structure

``` text
sentinelops/
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── .gitignore
├── pyproject.toml
├── Makefile
├── docs/
│   ├── project-charter.md
│   ├── progress.md
│   ├── architecture/
│   ├── threat-model/
│   ├── adr/
│   ├── runbooks/
│   ├── testing/
│   └── cost/
├── infra/
│   └── terraform/
│       ├── bootstrap/
│       ├── modules/
│       ├── environments/
│       └── tests/
├── src/sentinelops/
│   ├── common/
│   ├── collectors/
│   ├── normalization/
│   ├── correlation/
│   ├── risk/
│   ├── validation/
│   ├── remediation/
│   ├── reporting/
│   └── api/
├── lambdas/
│   ├── ingestion/
│   ├── assessment/
│   ├── remediation/
│   └── verification/
├── workflows/state-machines/
├── scenarios/
│   ├── s3-public-access/
│   ├── iam-overprivilege/
│   ├── security-group-exposure/
│   ├── audit-tampering/
│   ├── encryption-secrets/
│   └── configuration-drift/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── security/
│   └── end_to_end/
├── scripts/
├── dashboard/
└── .github/workflows/
```

Create directories as needed; avoid empty scaffolding and premature
abstraction.

------------------------------------------------------------------------

# 9. Toolchain

## Core

-   AWS account dedicated to testing.
-   AWS CLI v2.
-   IAM Identity Center or secure federated access where practical.
-   Terraform CLI and pinned AWS provider.
-   Python version pinned.
-   boto3.
-   pytest.
-   Git/GitHub.
-   GitHub Actions.
-   Docker for local reproducibility if useful.

## Quality/security tools

-   Ruff.
-   mypy or pyright.
-   pytest.
-   Bandit.
-   pip-audit.
-   TFLint.
-   Terraform fmt/validate.
-   Checkov or Trivy configuration scanning (select one maintained
    scanner).
-   pre-commit.
-   actionlint.
-   Dependabot or dependency review.

Use LocalStack only for APIs it supports; document gaps. Do not assume
it emulates GuardDuty, Security Hub, or all AWS behavior.

------------------------------------------------------------------------

# 10. Skills to acquire and evidence required

  -----------------------------------------------------------------------
  Skill domain            Specific skills         Evidence required
  ----------------------- ----------------------- -----------------------
  AWS foundations         Regions/AZs, accounts,  Deploy and troubleshoot
                          ARNs, tags, quotas,     resources
                          CLI, SDK                

  Networking              VPC, subnets, routes,   Explain and test
                          SG vs NACL, endpoints,  network boundaries
                          DNS, TLS                

  IAM                     Roles, users, policies, Role separation and
                          trust, STS, AssumeRole, least privilege
                          boundaries, resource    
                          policies, explicit deny 

  Storage/crypto          S3 policies, KMS,       Secure storage and
                          encryption, key policy, explain key access
                          secrets                 

  Monitoring              CloudTrail, CloudWatch, Trace changes and
                          Config                  explain telemetry gaps

  Detection               GuardDuty, Security     Tested detections and
                          Hub, EventBridge        documented limits
                          patterns,               
                          normalization, ATT&CK   

  Automation              Python, boto3, Lambda,  Reliable event-driven
                          Step Functions,         workflow
                          retries, idempotency    

  IaC                     Terraform modules,      Reproducible deployment
                          state, plan/apply,      
                          drift, imports          

  DevSecOps               GitHub Actions, OIDC,   CI with no static AWS
                          security scanning,      keys
                          review gates            

  App engineering         FastAPI/Pydantic or API Tested API and data
                          Gateway, REST, DynamoDB model

  Testing                 Unit, contract,         Automated test evidence
                          integration, negative,  
                          regression, E2E         

  Operations              Incident triage,        Reproducible
                          runbooks, rollback,     operational guide
                          cost control            

  Architecture            Threat modeling, ADRs,  Defensible design
                          diagrams, trade-offs    decisions
  -----------------------------------------------------------------------

Also strengthen Linux administration, Windows fundamentals, TCP/IP, DNS,
HTTP/S, TLS, Python testing, Git, JSON/APIs, troubleshooting, technical
English, and written communication.

Do not list a skill on the CV merely because a service appears in
Terraform. The user must be able to explain configuration, permissions,
costs, limitations, and failure modes.

------------------------------------------------------------------------

# 11. Phases, time, deliverables, and completion verification

**Planning estimate:** 20--24 weeks × 8--10 hours/week. Newer learners
may need 24--32 weeks. Re-estimate after baseline assessment.

## Phase 0 --- Project control and baseline (Week 0)

Tasks: create repository, charter, project board, budget ceiling, skill
baseline, naming/tagging standard, decision log. Deliverables: repo,
`docs/project-charter.md`, `docs/progress.md`, ADR folder, cost plan.
Verify: scope/non-goals defined; no AWS resources deployed; cleanup and
cost policies written.

## Phase 1 --- Requirements, architecture, threat model (Weeks 1--3)

Tasks: define fictional company/assets; security requirements; six
scenarios; context/logical/deployment/data-flow diagrams; trust
boundaries; role separation; finding schema; lifecycle; risk model;
ADRs. Deliverables: requirements, threat model, architecture diagrams,
event schema, state machine, test plan. Verify: every requirement maps
to component and test; trust boundaries documented; approval bypass
impossible by design; architecture reviewed.

## Phase 2 --- Local development foundation (Weeks 3--4)

Tasks: Python/Git/Terraform/AWS CLI setup; package and lockfile;
Ruff/pytest/type checks; structured logging; schema validation;
synthetic fixtures; pre-commit. Verify: clean setup works; tests/lint
run; malformed fixtures rejected; no secrets committed.

## Phase 3 --- AWS account and identity (Weeks 4--5)

Tasks: dedicated account; root MFA; no daily root use; federated access;
CLI profile; tags; budget alerts; minimal bootstrap roles;
region/service review. Verify: daily work non-root; no unnecessary
long-lived keys; budget alert configured; user can identify resources
and costs.

## Phase 4 --- Terraform foundation (Weeks 5--7)

Tasks: pin versions; modular layout; state strategy; baseline IAM;
minimal VPC if needed; private encrypted S3 evidence bucket; CloudTrail
management events; logs/retention; tags; outputs; destroy instructions.
Verify: `terraform fmt -check`, `terraform validate`; review plan;
apply; inspect resources; destroy; state not committed.

## Phase 5 --- Baseline controls and asset assessment (Weeks 7--9)

Tasks: S3/IAM/Security Group baseline rules; read-only boto3 or Config
collectors; normalize evidence; unknown/error state; baseline report;
secure/insecure fixtures. Verify: positive/negative tests; API errors
not treated as compliant; scope enforced; edge cases covered.

## Phase 6 --- Managed security integrations (Weeks 9--11)

Tasks: pricing review; selective Config; Security Hub CSPM/GuardDuty if
justified; EventBridge patterns; CloudTrail-derived events; supported
sample findings; source preservation; deduplication/versioning. Verify:
supported sample/real finding enters pipeline; malformed event rejected;
duplicate idempotent; source traceable; costs/cleanup documented.

## Phase 7 --- Risk engine/correlation (Weeks 11--13)

Tasks: scoring factors; separate source severity/risk/confidence;
deterministic scoring; asset criticality; correlation; policy version;
rationale. Verify: deterministic result; boundaries tested; rationale
stored; missing evidence handled conservatively.

## Phase 8 --- Six scenarios and validation (Weeks 13--16)

Tasks: scenario specs; synthetic fixtures; positive/negative/regression
tests; isolated real AWS tests; evidence; cleanup;
expected-versus-actual. Verify: six deterministic suites pass; at least
three demonstrated in real isolated AWS; cleanup verified; service
limitations documented.

## Phase 9 --- Remediation workflow (Weeks 16--18)

Tasks: allowlisted actions; proposals; action-hash approval;
approval/rejection; Step Functions if justified; scoped Lambda;
idempotency/retries; verification; rollback. Verify: no approval means
no Class 2 execution; changed hash invalidates approval; duplicates
safe; failure not resolved; actual final state verified.

## Phase 10 --- API/reporting/UI (Weeks 18--21)

Tasks: read-only API first; authorization; finding/remediation
endpoints; CLI/report; optional UI; history/filtering; evidence links.
Verify: API tests; unauthorized action rejected; report traceable; no
sensitive values; UI not needed for core tests.

## Phase 11 --- CI/CD and hardening (Weeks 21--23)

Tasks: GitHub Actions; OIDC; Python lint/type/tests; Terraform
checks/scanning; dependency audit; integration test limits; IAM review;
log/secret review; E2E. Verify: PR pipeline passes; no static keys;
least privilege reviewed; E2E works; cleanup works; residual risks
documented.

## Phase 12 --- Release and portfolio (Weeks 23--24)

Tasks: versioned release; diagrams; setup/teardown; threat model/ADRs;
sanitized evidence; 5--8 minute demo; case study; CV entry; final cost
review; destroy unneeded resources. Verify: another engineer can follow
instructions; demo reproducible; no secrets exposed; retained
resources/costs understood; limitations clear.

## Phase gate

A phase is complete only if it passes: 1. Functional behavior. 2.
Security review. 3. Automated tests. 4. Reproducible evidence. 5.
Documentation. 6. Cost/cleanup review. 7. Knowledge check: user can
explain and troubleshoot the work without blindly following
instructions.

Maintain `docs/progress.md` with phase, criteria, evidence, blockers,
cost state, knowledge gaps, and next tasks.

------------------------------------------------------------------------

# 12. Testing strategy

**Unit:** parser, schema, normalization, scoring, policy, idempotency,
state transitions, proposal generation.\
**Contract:** AWS event fixtures, internal schema versions, API models.\
**Integration:** boto3 against isolated resources, EventBridge, Lambda,
DynamoDB, S3, workflows.\
**Security:** unauthorized remediation, stale approval, replay, wrong
target, malformed event, secret leakage, privilege escalation, unsafe
S3/SG/IAM settings, API authorization.\
**End-to-end:** deploy baseline → controlled misconfiguration → ingest →
normalize → score → propose → approve → execute → verify actual AWS
state → resolve → report → teardown.

Evidence structure:

``` text
evidence/
├── architecture/
├── terraform/
├── scenario-results/
├── api/
├── ci/
├── remediation/
├── cost/
└── demo/
```

Sanitize all evidence. Do not commit raw sensitive logs or identifiers
unnecessarily.

------------------------------------------------------------------------

# 13. CI/CD and deployment controls

## Pull request pipeline

1.  Checkout.
2.  Install pinned Python/dependencies.
3.  Ruff.
4.  Type checks.
5.  Unit and contract tests.
6.  Dependency audit.
7.  Terraform fmt/validate.
8.  Terraform security scanner.
9.  Publish test results.

## Deployment pipeline

-   Protected branch/environment.
-   GitHub OIDC to assume narrowly scoped role.
-   Restrict OIDC trust to expected repo/ref/environment.
-   Require review before apply.
-   Review Terraform plan.
-   Keep deployment and remediation roles separate.
-   Never let unreviewed pull requests trigger destructive remediation.

## Recovery

Document recovery for failed deployment, state problems, partial
remediation, and accidental changes. Record before/after configuration.
Prefer reversible actions; do not delete resources as an automatic
rollback shortcut.

------------------------------------------------------------------------

# 14. Cost management

Potential cost drivers: - AWS Config recording/evaluations. -
GuardDuty. - Security Hub CSPM checks/findings. - CloudTrail data events
and additional trails. - CloudWatch ingestion/storage/queries. - KMS
keys and requests. - Lambda duration/invocations. - EventBridge
events. - Step Functions transitions. - DynamoDB storage/requests. - S3
storage/requests. - NAT Gateway, public IPv4, data transfer, EC2.

Controls: - local synthetic fixtures first; - only required
regions/services; - management events before data events; - limited
data-event windows; - log retention; - S3 lifecycle; - avoid always-on
EC2/NAT unless required; - AWS Budget notifications and Cost Explorer
review; - teardown scripts; - `docs/cost/cost-ledger.md`; - explicitly
list retained resources.

Before each deployment, state resources, pricing dimensions, usage
assumptions, expected ongoing costs, teardown commands, and resources
not removed automatically. Never promise a fixed monthly price without a
current pricing calculation.

------------------------------------------------------------------------

# 15. Required diagrams and documents

Required diagrams: 1. System context. 2. Logical component architecture.
3. AWS deployment architecture. 4. Data-flow diagram. 5. Trust-boundary
diagram. 6. IAM role/permission relationships. 7. Event ingestion
sequence. 8. Remediation approval sequence. 9. Finding state machine.
10. CI/deployment sequence.

Remediation sequence:

``` mermaid
sequenceDiagram
  participant SRC as AWS source
  participant EB as EventBridge
  participant ING as Ingestion
  participant DB as DynamoDB
  participant WF as Workflow
  participant OP as Operator
  participant REM as Remediator
  participant VER as Verifier
  SRC->>EB: Finding/config event
  EB->>ING: Route event
  ING->>ING: Validate/normalize
  ING->>DB: Idempotent write
  ING->>DB: Store risk/rationale
  OP->>WF: Review proposal
  WF->>OP: Request approval
  OP->>WF: Approve exact action
  WF->>REM: Invoke scoped action
  REM->>SRC: Apply change
  REM->>VER: Verify request
  VER->>SRC: Read actual state
  VER->>DB: Record verified outcome
```

All diagrams must match actual implementation. Update them after
architecture changes.

------------------------------------------------------------------------

# 16. Runbooks required

1.  Bootstrap AWS test account.
2.  Deploy infrastructure.
3.  Destroy infrastructure.
4.  Revoke/rotate test credentials.
5.  Investigate a finding.
6.  Approve/reject remediation.
7.  Recover failed remediation.
8.  Handle duplicate events.
9.  Handle malformed event.
10. Handle missing telemetry.
11. Troubleshoot CI OIDC.
12. Respond to unexpected AWS charges.
13. Restore accidental configuration changes.
14. Publish a release.

Each runbook states prerequisites, permissions, commands, expected
result, rollback, and cleanup.

------------------------------------------------------------------------

# 17. Portfolio package and demonstration

Final package: - README with problem, solution, architecture, demo,
setup, tests, cost, limitations. - Architecture diagrams and threat
model. - ADRs and security requirements. - Terraform and Python
source. - Detection/scenario definitions. - Automated tests and CI. -
Runbooks and cost ledger. - Sanitized evidence and sample reports. -
5--8 minute demo. - Technical case study.

Demo flow: 1. Show secure baseline. 2. Introduce a controlled S3 or
Security Group misconfiguration. 3. Show ingestion and risk rationale.
4. Generate remediation proposal. 5. Approve it. 6. Execute. 7. Verify
actual AWS state. 8. Show audit history and report.

------------------------------------------------------------------------

# 18. CV and interview readiness

Only list technologies after meaningful implementation and
understanding.

**AWS:** IAM, STS, VPC, S3, KMS, CloudTrail, CloudWatch, AWS Config,
GuardDuty, Security Hub, EventBridge, Lambda, Step Functions, DynamoDB.\
**Cloud security:** least privilege, cloud posture assessment, network
security, encryption, threat detection, security automation, incident
response workflows.\
**IaC/DevSecOps:** Terraform, GitHub Actions, OIDC federation, CI/CD
security checks.\
**Programming:** Python, boto3, FastAPI (if implemented), REST, pytest.

Target CV wording after completion:

**SentinelOps --- AWS Cloud Security & Resilience Platform**\
Designed and implemented an AWS cloud security platform for
evidence-driven security assessment, detection validation, and
controlled remediation. - Provisioned secure AWS infrastructure using
Terraform, implementing IAM least privilege, network controls,
encryption, and audit logging. - Integrated AWS Config, Security Hub,
GuardDuty, and CloudTrail to centralize configuration and threat
findings. - Developed a Python assessment engine for finding
normalization, explainable risk prioritization, and evidence
correlation. - Built controlled security scenarios and automated tests
to validate cloud security controls and detection outcomes. -
Orchestrated human-approved remediation using EventBridge, Lambda, and
Step Functions, with idempotency, audit history, and post-remediation
verification. - Integrated infrastructure and application validation
into GitHub Actions CI/CD using AWS OIDC federation.

Delete any bullet not proven by implementation.

Interview questions: - Shared responsibility model? - IAM trust policy
versus permission policy? - STS AssumeRole? - How does GitHub OIDC avoid
static keys? - Security Groups versus NACLs? - S3 bucket policy versus
identity policy? - What does CloudTrail record? - GuardDuty versus
Security Hub? - What does AWS Config evaluate? - EventBridge routing? -
Lambda retries and duplicate events? - Why idempotency? - Step Functions
state and failure handling? - Terraform state and drift? - How prevent
remediation privilege escalation? - How prove remediation succeeded? -
What if verification fails? - KMS key policies? - AWS cost controls? -
Risk-model limitations? - What does the platform not detect? - How
extend to multi-account AWS?

The AI agent should quiz the user after each major phase and identify
gaps before progressing.

------------------------------------------------------------------------

# 19. Risks and scope control

Major risks: - Scope explosion. - Uncontrolled AWS charges. - False
confidence from missing findings. - Unsafe remediation. - Broad IAM
permissions. - UI/microservices before core workflow. - Screenshots
without reproducible evidence. - Incorrect assumptions about managed
detections. - Forgotten resources and costs. - User unable to explain
copied code.

Rules: - Build one scenario end-to-end before all six. - Read-only
assessment first. - Add approval/remediation only after ingestion and
validation work. - UI only after backend workflow stabilizes. -
Multi-account only after robust single-account MVP. - No LLM in security
decision path. - No Kubernetes without a requirement. - Every feature
maps to a requirement and test.

------------------------------------------------------------------------

# 20. Official references

Verify current versions and pricing before implementation.

**AWS foundations** - Documentation: https://docs.aws.amazon.com/ -
Well-Architected Framework:
https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html -
Security Pillar:
https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html -
Skill Builder: https://skillbuilder.aws/

**Security** - IAM User Guide:
https://docs.aws.amazon.com/IAM/latest/UserGuide/ - IAM best practices:
https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html -
IAM Access Analyzer:
https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html -
GuardDuty:
https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html -
Security Hub:
https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html -
AWS Config:
https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html -
CloudTrail:
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html

**Automation** - Lambda:
https://docs.aws.amazon.com/lambda/latest/dg/welcome.html - EventBridge:
https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html -
Step Functions:
https://docs.aws.amazon.com/step-functions/latest/dg/welcome.html -
boto3:
https://boto3.amazonaws.com/v1/documentation/api/latest/index.html

**IaC/CI** - Terraform AWS tutorial:
https://developer.hashicorp.com/terraform/tutorials/aws-get-started -
AWS provider:
https://registry.terraform.io/providers/hashicorp/aws/latest/docs -
GitHub OIDC with AWS:
https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws

**Pricing** - AWS Pricing Calculator: https://calculator.aws/ - AWS
pricing: https://aws.amazon.com/pricing/

------------------------------------------------------------------------

# 21. First ten tasks

1.  Create a GitHub repository named `sentinelops`; never publish
    secrets.
2.  Save this specification as `docs/master-project-specification.md`.
3.  Create `docs/progress.md` and `docs/adr/`.
4.  Write a one-page charter and define MVP/non-goals.
5.  Draw context and logical architecture diagrams.
6.  Write threat model and trust boundaries.
7.  Set a budget ceiling; choose region only after pricing and service
    checks.
8.  Assess current AWS, IAM, networking, Python, Terraform, Git, and
    testing knowledge.
9.  Define finding schema and six scenario specifications.
10. Build local schema validation and unit tests before provisioning
    AWS.

**First milestone:** reviewed architecture, threat model, event schema,
scenario catalogue, and cost plan---without unnecessary running AWS
resources.

------------------------------------------------------------------------

# 22. Definition of done

-   [ ] Problem, users, scope and non-goals defined.
-   [ ] Architecture diagrams match implementation.
-   [ ] Threat model and trust boundaries documented.
-   [ ] AWS account secured and costs monitored.
-   [ ] Terraform deploys reproducible baseline.
-   [ ] IAM roles follow least privilege.
-   [ ] Audit/configuration/security sources integrated.
-   [ ] Findings normalized and deduplicated.
-   [ ] Risk scores explainable and versioned.
-   [ ] Six scenarios documented and tested.
-   [ ] At least three scenarios demonstrated in isolated real AWS.
-   [ ] Detection tests include positive and negative cases.
-   [ ] Remediation approval enforced.
-   [ ] Remediation idempotent and audited.
-   [ ] Post-remediation verification reads actual AWS state.
-   [ ] Failures do not produce false resolved status.
-   [ ] API/report protects sensitive information.
-   [ ] CI validates Python and Terraform.
-   [ ] CI uses OIDC, not static AWS keys.
-   [ ] Deployment, rollback and teardown documented.
-   [ ] Costs and retained resources accounted for.
-   [ ] Demo reproducible.
-   [ ] User can independently explain and defend implementation.

------------------------------------------------------------------------

# 23. First response required from the AI agent

Do not generate the application immediately. First: 1. Assess the user's
current knowledge in AWS, IAM, networking, Python, Terraform, Git, and
testing. 2. Identify prerequisites and learning gaps. 3. Review
architecture feasibility, security, and cost. 4. Produce Phase 0 and
Phase 1 tasks. 5. Define initial acceptance tests. 6. Wait for explicit
user confirmation before any billable AWS deployment.

Treat this specification as the source of truth but challenge it when
AWS behavior, cost, security, or evidence requires a change. Record
changes in ADRs and update requirements, diagrams, tests, and
documentation.

**The objective is not to look like a cloud security engineer. The
objective is to become capable of doing the work---and make that
capability independently verifiable.**
