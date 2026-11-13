# AWS cleanup runbook

## Status

This is a future cleanup procedure for an authorized sandbox deployment. It is not executed in the current workspace.

## Precondition

Cleanup must be executed only after a human approval gate and under the bootstrap identity, never under the assessment or remediation identity.

## Procedure

1. Confirm the sandbox environment and resource inventory.
2. Remove the demo S3 objects and bucket configuration.
3. Remove the public ingress rules from the test security group.
4. Remove the intentionally permissive IAM policy objects.
5. Delete the test CloudTrail and log resources if they were created for the demonstration.
6. Confirm that no unintended resources remain.
7. Archive the final evidence record and cleanup result.

## Safety checks

- require explicit confirmation before each destructive action,
- verify resource names and tags before deletion,
- do not remove any resource outside the sandbox inventory.

## Execution status

Not executed in this workspace.
