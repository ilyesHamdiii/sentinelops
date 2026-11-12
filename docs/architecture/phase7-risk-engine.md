# Phase 7 — Risk engine and correlation

## Objective

Define the local risk model used by SentinelOps to combine security signal quality, business impact, and evidence confidence into a deterministic, explainable risk score before any live AWS ingestion occurs.

## Why this is necessary

Security platforms cannot safely prioritize findings without distinguishing among:

- the source severity reported by the upstream service,
- the normalized risk score already assigned by the platform,
- the confidence that the evidence is valid,
- and the criticality of the affected asset.

If these are collapsed into a single value too early, the platform risks both false positives and missed escalation signals.

## Risk model

The local scoring model should preserve each input separately and combine them in a deterministic way:

- `severity_source` from upstream security telemetry
- `risk_score` from the platform’s internal interpretation
- `confidence` from evidence quality and validation
- `asset_criticality` from the resource’s likely blast radius

The engine uses a bounded 0-100 scoring model and clamps results to keep the output deterministic and explainable.

## Correlation model

Related findings must be grouped by the affected resource identity so the system can answer:

- which asset has the highest concentration of issues,
- which resource is driving the highest aggregated risk,
- and whether multiple observations support the same incident.

The local correlation model uses a stable resource identifier and summarizes:

- resource ID,
- total finding count,
- maximum risk score in the resource group.

## Design rules

- Keep the scoring model deterministic for the same input.
- Preserve evidence provenance and source severity independently.
- Treat unknown or incomplete inputs conservatively rather than assuming safety.
- Derive resource grouping only from normalized resource identity.
- Keep all logic local and read-only until the user approves an AWS-connected assessment path.

## Acceptance criteria

Phase 7 is ready when all of the following are true:

- the scoring function produces stable results for consistent inputs,
- critical assets elevate the final risk score appropriately,
- related findings group by resource identity without depending on live AWS data,
- the result remains explainable and versioned with a policy version,
- and no cloud access is required to exercise the logic.
