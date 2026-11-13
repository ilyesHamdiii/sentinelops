"""Compatibility wrapper around the secure remediation workflow.

This keeps the legacy validation import path stable while Phase 9 introduces
stronger enforcement in the canonical remediation module.
"""

from __future__ import annotations

from sentinelops.remediation import (
    APPROVED_ACTIONS,
    ApprovedRemediationAction,
    RemediationWorkflow,
    analyze_iam_wildcard_policy,
    approve_remediation,
    build_action_hash,
    execute_remediation,
    validate_remediation_approval,
    validate_remediation_execution,
)

__all__ = [
    "APPROVED_ACTIONS",
    "ApprovedRemediationAction",
    "RemediationWorkflow",
    "analyze_iam_wildcard_policy",
    "approve_remediation",
    "build_action_hash",
    "execute_remediation",
    "validate_remediation_approval",
    "validate_remediation_execution",
]
