"""Compatibility wrapper for the canonical Phase 8 scenario catalogue."""

from __future__ import annotations

from sentinelops.scenarios import (
    SCENARIO_DEFINITIONS,
    evaluate_scenario,
    validate_scenario_definition,
    validate_scenario_result,
)

__all__ = [
    "SCENARIO_DEFINITIONS",
    "evaluate_scenario",
    "validate_scenario_definition",
    "validate_scenario_result",
]
