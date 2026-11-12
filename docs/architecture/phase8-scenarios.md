# Phase 8 — Six scenarios and validation

## Objective

Define and validate the six canonical security scenarios that SentinelOps will eventually execute against controlled AWS test resources. This phase remains entirely local-first so the test expectations are defined and reproducible before any AWS deployment occurs.

## Why this is necessary

The project requires a repeatable catalog of security scenarios, each with a clear expected outcome and a clean validation path. Without a scenario contract, later AWS validation can drift into ambiguous testing or false confidence.

## Scenario catalogue

- S1: Public or unsafe S3 access
- S2: Excessive IAM privileges
- S3: Network exposure
- S4: Audit logging tampering / suspicious API activity
- S5: Encryption and secret-management weakness
- S6: Configuration drift

Each scenario is represented by an ID and an expected outcome. The local validation layer checks whether the observed result matches the design expectation.

## Local validation model

The validation contract intentionally does not require AWS connectivity. It simply ensures that:

1. each scenario exists in the canonical list,
2. each scenario has a valid expected outcome,
3. a matching positive/negative signal can be compared locally,
4. unknown scenarios return an explicit UNKNOWN status rather than being treated as successful.

## Acceptance criteria

Phase 8 is ready when all of the following are true:

- the six scenario definitions are traceable to the specification,
- each scenario has a documented expected result,
- local validation can distinguish PASS, FAIL, and UNKNOWN,
- the path remains local-only with no cloud provisioning or billing,
- and the scenario catalogue is ready for future live AWS execution under explicit approval.
