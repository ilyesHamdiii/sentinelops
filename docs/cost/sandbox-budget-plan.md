# Sandbox budget plan

## Approved budget

- Hard monthly ceiling: `$15.00`
- Budget alert thresholds: `$7.50`, `$12.00`, and `$15.00`
- Region: `eu-east-1`
- Account purpose: shared sandbox for SentinelOps and future cloud security/engineering work

## Budget logic

The sandbox is intentionally small and controlled. The goal is to preserve the user's AWS credit balance while enabling limited, traceable validation work.

## Tagging requirement

All resources created in sandbox must include:

- `Project = "sentinelops"`
- `Environment = "sandbox"`

This ensures rapid filtering in Cost Explorer and a clean teardown record.

## Cost management rules

1. Prefer read-only and synthetic validation before any paid AWS service.
2. Keep the workload to a single region and a minimal service footprint.
3. Enable only necessary CloudTrail, Config, and logging services with documented retention.
4. Destroy temporary resources after each validation round.
5. Treat the budget as a strict cutoff, not a warning threshold.

## Cleanup principle

Any resource not needed for the approved sandbox validation should be removed before the next budget cycle.
