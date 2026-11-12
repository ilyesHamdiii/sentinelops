"""AWS identity validation and read-only session context for SentinelOps."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError

_ALLOWED_REGIONS = {"eu-west-1"}
_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_ROLE_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_-]+$")


def validate_account_id(account_id: str | None) -> str:
    """Validate a 12-digit AWS account identifier."""
    value = (account_id or "").strip()
    if not _ACCOUNT_ID_RE.fullmatch(value):
        raise ValueError(
            "AWS account ID must be a 12-digit numeric identifier; received "
            f"{account_id!r}."
        )
    return value


def validate_aws_region(region: str | None) -> str:
    """Validate the supported regional target for the sentinelops sandbox."""
    value = (region or "").strip()
    if value not in _ALLOWED_REGIONS:
        raise ValueError(
            "SentinelOps sandbox only supports the eu-west-1 region. "
            f"Received {region!r}."
        )
    return value


def validate_role_arn(role_arn: str | None) -> str:
    """Validate an AWS IAM role ARN assuming the SentinelOps trust model."""
    value = (role_arn or "").strip()
    if not _ROLE_ARN_RE.fullmatch(value):
        raise ValueError(f"Invalid AWS IAM role ARN: {role_arn!r}")
    return value


def validate_session_name(session_name: str | None) -> str | None:
    """Validate and normalise the STS session name used for evidence provenance."""
    if session_name is None:
        return None
    cleaned = session_name.strip()
    if not cleaned:
        return None
    if len(cleaned) > 64:
        raise ValueError("AWS session names must be 64 characters or fewer.")
    return cleaned


def assume_role_session(
    *,
    sts_client: Any | None = None,
    role_arn: str | None,
    session_name: str | None,
    region: str | None,
    account_id: str | None,
    duration_seconds: int = 3600,
) -> dict[str, Any]:
    """Assume the SentinelOps assessment role and return a structured evidence context."""
    validated_role = validate_role_arn(role_arn)
    validated_account = validate_account_id(account_id)
    validated_region = validate_aws_region(region)
    validated_session = validate_session_name(session_name) or "sentinelops-assessment"

    client = sts_client
    if client is None:
        import boto3

        client = boto3.client("sts", region_name=validated_region)

    try:
        response = client.assume_role(
            RoleArn=validated_role,
            RoleSessionName=validated_session,
            DurationSeconds=duration_seconds,
        )
    except (NoCredentialsError, PartialCredentialsError, ClientError, PermissionError, RuntimeError) as exc:
        raise PermissionError(
            "Failed to assume the SentinelOps read-only AWS role. The local session must be authenticated and the IAM trust policy must allow sts:AssumeRole."
        ) from exc

    credentials = response.get("Credentials", {})
    identity = AWSIdentityContext(
        account_id=validated_account,
        region=validated_region,
        role_arn=validated_role,
        role_type="read_only",
        session_name=validated_session,
        provenance="aws_assume_role",
    )

    evidence = identity.as_evidence()
    evidence.update(
        {
            "access_key_id": credentials.get("AccessKeyId"),
            "expiration": credentials.get("Expiration"),
            "assumed_role_user": response.get("AssumedRoleUser", {}),
            "source": "sts_assume_role",
        }
    )
    return evidence


def validate_session_permissions(
    sts_client: Any,
    *,
    required_actions: tuple[str, ...] = ("sts:GetCallerIdentity",),
) -> dict[str, Any]:
    """Validate that the current AWS session can authenticate and call the required read-only actions."""
    try:
        identity = sts_client.get_caller_identity()
    except (NoCredentialsError, PartialCredentialsError, ClientError, PermissionError, RuntimeError) as exc:
        raise PermissionError(
            "AWS credentials are missing, expired, or do not allow sts:GetCallerIdentity for SentinelOps assessment."
        ) from exc

    payload = {
        "account_id": identity.get("Account"),
        "arn": identity.get("Arn"),
        "user_id": identity.get("UserId"),
        "required_actions": list(required_actions),
        "source": "sts_get_caller_identity",
    }
    if not payload["account_id"] or not payload["arn"]:
        raise PermissionError("The active AWS session did not return a valid caller identity.")
    return payload


@dataclass(slots=True)
class AWSIdentityContext:
    """Describe the current AWS session context used for assessment or remediation."""

    account_id: str
    region: str
    role_arn: str | None = None
    role_type: str = "read_only"
    session_name: str | None = None
    provenance: str = "aws_assume_role"
    collection_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "structured_identity_context"

    def __post_init__(self) -> None:
        self.account_id = validate_account_id(self.account_id)
        self.region = validate_aws_region(self.region)
        if self.role_arn is not None:
            self.role_arn = validate_role_arn(self.role_arn)
        self.role_type = (self.role_type or "read_only").strip().lower()
        if self.role_type not in {"read_only", "remediation"}:
            raise ValueError("role_type must be either 'read_only' or 'remediation'")
        if self.session_name is not None:
            self.session_name = self.session_name.strip() or None
        self.provenance = "aws_assume_role"
        self.source = "structured_identity_context"

    def as_evidence(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "region": self.region,
            "role_arn": self.role_arn,
            "role_type": self.role_type,
            "session_name": self.session_name,
            "provenance": self.provenance,
            "source": self.source,
            "collection_time": self.collection_time.isoformat(),
        }
