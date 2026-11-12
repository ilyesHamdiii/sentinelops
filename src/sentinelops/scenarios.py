"""Canonical scenario definitions and deterministic evaluation for Phase 8."""

from __future__ import annotations

from typing import Any

SCENARIO_DEFINITIONS: dict[str, dict[str, str]] = {
    "S1": {
        "title": "Public or unsafe S3 access",
        "expected_outcome": "finding_detected",
        "description": "Bucket is publicly readable or exposes unsafe public access policies.",
    },
    "S2": {
        "title": "Excessive IAM privileges",
        "expected_outcome": "finding_detected",
        "description": "Policy or trust document grants wildcard or privilege-escalation access.",
    },
    "S3": {
        "title": "Network exposure",
        "expected_outcome": "finding_detected",
        "description": "Public ingress to administrative services exposes the environment.",
    },
    "S4": {
        "title": "Audit logging tampering / suspicious API activity",
        "expected_outcome": "finding_detected",
        "description": "CloudTrail or audit controls are disabled or suspicious removal events appear.",
    },
    "S5": {
        "title": "Encryption and secret-management weakness",
        "expected_outcome": "finding_detected",
        "description": "Data encryption or secret rotation is missing or intentionally weakened.",
    },
    "S6": {
        "title": "Configuration drift",
        "expected_outcome": "drift_detected",
        "description": "Actual resource configuration diverges from the expected baseline state.",
    },
}


def validate_scenario_definition(definition: dict[str, Any]) -> bool:
    if not isinstance(definition, dict):
        return False

    scenario_id = str(definition.get("scenario_id", "")).strip()
    title = str(definition.get("title", "")).strip()
    expected_outcome = str(definition.get("expected_outcome", "")).strip()

    if not scenario_id or not title or not expected_outcome:
        return False

    return scenario_id in SCENARIO_DEFINITIONS or scenario_id.startswith("S")


def validate_scenario_result(scenario_id: str, expected_outcome: str, observed_outcome: str) -> str:
    if scenario_id not in SCENARIO_DEFINITIONS:
        return "UNKNOWN"
    if expected_outcome == observed_outcome:
        return "PASS"
    return "FAIL"


def _coerce_statements(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        statements = value.get("Statement")
        if isinstance(statements, list):
            return [item for item in statements if isinstance(item, dict)]
    return []


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for key, value in principal.items():
            if key in {"AWS", "CanonicalUser", "Federated"}:
                if value == "*":
                    return True
                if isinstance(value, list) and "*" in value:
                    return True
                if isinstance(value, str) and value.strip() == "*":
                    return True
    return False


def _evaluate_s1(evidence: dict[str, Any]) -> dict[str, Any]:
    public_access_block = evidence.get("public_access_block") or {}
    required_flags = (
        "BlockPublicAcls",
        "BlockPublicPolicy",
        "IgnorePublicAcls",
        "RestrictPublicBuckets",
    )
    public_block_weak = any(public_access_block.get(flag) is not True for flag in required_flags)

    bucket_policy = evidence.get("bucket_policy") or {}
    statements = _coerce_statements(bucket_policy)
    public_policy = any(
        statement.get("Effect") == "Allow"
        and _is_public_principal(statement.get("Principal"))
        and "s3:GetObject" in str(statement.get("Action", "")).split(",")
        for statement in statements
    )

    if public_block_weak or public_policy:
        return {
            "scenario_id": "S1",
            "status": "finding_detected",
            "rationale": "Bucket is publicly readable or public access controls are not fully enforced.",
            "expected_outcome": "finding_detected",
        }

    return {
        "scenario_id": "S1",
        "status": "no_finding_detected",
        "rationale": "Bucket access is restricted and public access controls are enforced.",
        "expected_outcome": "finding_detected",
    }


def _evaluate_s2(evidence: dict[str, Any]) -> dict[str, Any]:
    statements = _coerce_statements(evidence.get("policy_statements") or evidence)
    risky = False
    reasons: list[str] = []

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action")
        resources = statement.get("Resource")
        action_values = actions if isinstance(actions, list) else [actions]
        if any(str(value).strip() in {"*", "iam:*", "AdministratorAccess"} for value in action_values):
            risky = True
            reasons.append("Wildcard action grant")
        if resources == "*":
            risky = True
            reasons.append("Wildcard resource grant")
    if risky:
        return {
            "scenario_id": "S2",
            "status": "finding_detected",
            "rationale": "; ".join(reasons) or "Wildcard or over-broad IAM access is present.",
            "expected_outcome": "finding_detected",
        }

    return {
        "scenario_id": "S2",
        "status": "no_finding_detected",
        "rationale": "IAM access is constrained to least-privilege statements.",
        "expected_outcome": "finding_detected",
    }


def _evaluate_s3(evidence: dict[str, Any]) -> dict[str, Any]:
    ingress = evidence.get("ingress") or []
    for rule in ingress:
        if not isinstance(rule, dict):
            continue
        cidr = str(rule.get("CidrIp") or "")
        if cidr not in {"0.0.0.0/0", "::/0"}:
            continue
        protocol = str(rule.get("IpProtocol") or "-1")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if protocol in {"-1", "all", "ALL"}:
            return {
                "scenario_id": "S3",
                "status": "finding_detected",
                "rationale": "Security group allows unrestricted public ingress.",
                "expected_outcome": "finding_detected",
            }
        if isinstance(from_port, int) and isinstance(to_port, int):
            if from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
                return {
                    "scenario_id": "S3",
                    "status": "finding_detected",
                    "rationale": "Administrative ports 22/3389 are publicly exposed.",
                    "expected_outcome": "finding_detected",
                }

    return {
        "scenario_id": "S3",
        "status": "no_finding_detected",
        "rationale": "Ingress rules do not expose administrative ports to the public internet.",
        "expected_outcome": "finding_detected",
    }


def _evaluate_s4(evidence: dict[str, Any]) -> dict[str, Any]:
    trail = evidence.get("trail") or {}
    recent_events = evidence.get("recent_events") or []
    suspicious_events = {"DeleteTrail", "StopLogging", "PutBucketPolicy", "DeleteBucketPolicy", "UpdateTrail"}

    trail_insecure = (
        not trail.get("is_multi_region_trail", True)
        or not trail.get("log_file_validation_enabled", True)
    )
    suspicious_activity = any(str(event.get("eventName", "")).strip() in suspicious_events for event in recent_events if isinstance(event, dict))

    if trail_insecure or suspicious_activity:
        return {
            "scenario_id": "S4",
            "status": "finding_detected",
            "rationale": "Audit trail logging is weak or suspicious trail changes were observed.",
            "expected_outcome": "finding_detected",
        }

    return {
        "scenario_id": "S4",
        "status": "no_finding_detected",
        "rationale": "CloudTrail configuration and recent activity appear to be intact.",
        "expected_outcome": "finding_detected",
    }


def _evaluate_s5(evidence: dict[str, Any]) -> dict[str, Any]:
    weak = (
        evidence.get("sse_enabled") is not True
        or evidence.get("kms_key_id") in {None, ""}
        or evidence.get("secret_rotation_enabled") is not True
    )
    if weak:
        return {
            "scenario_id": "S5",
            "status": "finding_detected",
            "rationale": "A required encryption or rotation control is missing or disabled.",
            "expected_outcome": "finding_detected",
        }

    return {
        "scenario_id": "S5",
        "status": "no_finding_detected",
        "rationale": "Encryption and secret rotation controls are present and enabled.",
        "expected_outcome": "finding_detected",
    }


def _evaluate_s6(evidence: dict[str, Any]) -> dict[str, Any]:
    expected = evidence.get("expected_state") or {}
    actual = evidence.get("actual_state") or {}

    if expected != actual:
        return {
            "scenario_id": "S6",
            "status": "drift_detected",
            "rationale": "The actual resource state diverges from the expected baseline configuration.",
            "expected_outcome": "drift_detected",
        }

    return {
        "scenario_id": "S6",
        "status": "drift_resolved",
        "rationale": "The resource matches the approved baseline and no drift is present.",
        "expected_outcome": "drift_detected",
    }


def evaluate_scenario(scenario_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    scenario_key = str(scenario_id or "").upper()
    if scenario_key not in SCENARIO_DEFINITIONS:
        return {
            "scenario_id": scenario_key,
            "status": "unknown",
            "rationale": "Scenario is not defined in the SentinelOps scenario catalogue.",
            "expected_outcome": "unknown",
        }

    evaluator_map = {
        "S1": _evaluate_s1,
        "S2": _evaluate_s2,
        "S3": _evaluate_s3,
        "S4": _evaluate_s4,
        "S5": _evaluate_s5,
        "S6": _evaluate_s6,
    }

    result = evaluator_map[scenario_key](evidence)
    result["title"] = SCENARIO_DEFINITIONS[scenario_key]["title"]
    result["description"] = SCENARIO_DEFINITIONS[scenario_key]["description"]
    result["policy_version"] = "1.0"
    return result
