# Bootstrap resources

This directory is reserved for the minimal bootstrap resources required for an approved SentinelOps sandbox deployment in eu-west-1.

Current review scope includes:

- billing and budget alerts
- least-privilege IAM roles
- CloudTrail and evidence storage guardrails
- S3 evidence retention settings with encryption and lifecycle policies

The Terraform baseline is intentionally review-only until the dedicated sandbox account and explicit approval are in place. No live AWS apply is executed from this repository.
