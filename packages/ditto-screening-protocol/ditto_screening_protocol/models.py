"""Wire models for the Ditto screening boundary."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCREENING_POLICY_VERSION = 6

_SS58_PATTERN = r"^[1-9A-HJ-NP-Za-km-z]{47,48}$"
_SIGNATURE_HEX_PATTERN = r"^[0-9a-fA-F]{128}$"


class AgentStatus(StrEnum):
    """Lifecycle state of an agent submission."""

    UPLOADED = "uploaded"
    SCREENING = "screening"
    SCREENING_PASSED = "screening_passed"
    SCREENING_FAILED = "screening_failed"
    QUARANTINED = "quarantined"
    REJECTED = "rejected"
    EVALUATING = "evaluating"
    SCORED = "scored"
    LIVE = "live"
    ATH_PENDING_REVIEW = "ath_pending_review"
    BANNED = "banned"


class ScreenResultOutcome(StrEnum):
    """Typed screener result; non-verdict outcomes never become rejection."""

    PASS = "pass"
    DETERMINISTIC_REJECT = "deterministic_reject"
    RETRYABLE_INFRA = "retryable_infra"
    QUARANTINE = "quarantine"
    INCONCLUSIVE = "inconclusive"


class ArtifactResponse(BaseModel):
    """Short-lived artifact metadata returned to a screening worker."""

    agent_id: Annotated[UUID, Field(description="Echoes the path-param id.")]
    sha256: Annotated[
        str, Field(description="Expected SHA-256 of the tarball, lowercase hex.")
    ]
    download_url: Annotated[
        str, Field(description="Pre-signed URL used to download the tarball.")
    ]
    expires_at: Annotated[
        datetime, Field(description="When the download URL expires (UTC).")
    ]


class ScreenerQueueItem(BaseModel):
    """One agent awaiting screening."""

    agent_id: Annotated[UUID, Field(description="Server-generated agent identifier.")]
    miner_hotkey: Annotated[str, Field(description="Submitting miner's SS58 hotkey.")]
    name: Annotated[str, Field(description="Miner-chosen agent name.")]
    sha256: Annotated[
        str, Field(description="SHA-256 of the uploaded tarball, lowercase hex.")
    ]
    status: Annotated[
        AgentStatus, Field(description="Lifecycle state at queue read time.")
    ]
    created_at: Annotated[
        datetime, Field(description="When the upload row was inserted (UTC).")
    ]
    attempt_id: Annotated[
        UUID | None,
        Field(
            description=(
                "Opaque lease id returned by the claim endpoint. Null only for "
                "legacy read-only queue responses."
            ),
        ),
    ] = None
    lease_deadline: Annotated[
        datetime | None,
        Field(
            description=(
                "UTC deadline for this screening attempt. A verdict arriving "
                "after it expires must not be accepted."
            ),
        ),
    ] = None


class ScreenerQueueResponse(BaseModel):
    """Response returned by ``GET /screener/queue``."""

    items: Annotated[
        list[ScreenerQueueItem],
        Field(description="Agents awaiting screening, oldest first."),
    ]
    count: Annotated[int, Field(ge=0, description="Number of items returned.")]
    required_policy_version: Annotated[
        int,
        Field(
            ge=1,
            description="Minimum screening policy a passing verdict must attest.",
        ),
    ]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [
                    {
                        "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                        "miner_hotkey": (
                            "5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm"
                        ),
                        "name": "alpha-agent",
                        "sha256": "deadbeef" * 8,
                        "status": "uploaded",
                        "created_at": "2026-06-08T12:00:00Z",
                    }
                ],
                "count": 1,
            }
        }
    )


class ScreenResultRequest(BaseModel):
    """Signed result posted to ``/screener/agent/{agent_id}/result``."""

    screener_hotkey: Annotated[
        str,
        Field(pattern=_SS58_PATTERN, description="Reporting screener's SS58 hotkey."),
    ]
    attempt_id: Annotated[
        UUID | None,
        Field(
            description=(
                "Claimed screening-attempt lease. Required by lease-aware "
                "platforms and bound into the v2 verdict signature."
            ),
        ),
    ] = None
    signature: Annotated[
        str,
        Field(
            pattern=_SIGNATURE_HEX_PATTERN,
            description="Hex sr25519 signature over the versioned verdict.",
        ),
    ]
    passed: Annotated[
        bool,
        Field(description="True promotes to evaluating; False -> screening_failed."),
    ]
    outcome: ScreenResultOutcome | None = None
    manifest_digest: Annotated[str | None, Field(pattern=r"^[0-9a-f]{64}$")] = None
    finding_digest: Annotated[str | None, Field(pattern=r"^[0-9a-f]{64}$")] = None
    reason_code: Annotated[str | None, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")] = (
        None
    )
    policy_version: Annotated[
        int,
        Field(
            default=1,
            ge=1,
            description="Screening policy version bound into the signature.",
        ),
    ]
    detail: Annotated[
        str,
        Field(
            default="",
            max_length=4000,
            description=(
                "Optional reason / build-log tail; the platform must treat it as "
                "untrusted."
            ),
        ),
    ]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "screener_hotkey": ("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"),
                "signature": "ab" * 64,
                "passed": True,
                "policy_version": SCREENING_POLICY_VERSION,
                "detail": "",
            }
        }
    )

    @model_validator(mode="after")
    def validate_typed_outcome(self) -> ScreenResultRequest:
        if self.outcome is None:
            return self
        if self.passed != (self.outcome == ScreenResultOutcome.PASS):
            raise ValueError("passed must agree with outcome")
        if (
            self.outcome
            in {
                ScreenResultOutcome.QUARANTINE,
                ScreenResultOutcome.INCONCLUSIVE,
            }
            and self.attempt_id is None
        ):
            raise ValueError("non-verdict outcome requires attempt_id")
        if self.outcome == ScreenResultOutcome.QUARANTINE and (
            self.manifest_digest is None or self.reason_code is None
        ):
            raise ValueError("quarantine requires manifest_digest and reason_code")
        return self


class ScreenResultResponse(BaseModel):
    """Response returned after a screener verdict is applied."""

    agent_id: Annotated[UUID, Field(description="Echoes the path-param id.")]
    status: Annotated[
        AgentStatus, Field(description="Lifecycle state after the verdict.")
    ]
    accepted: Annotated[bool, Field(description="True when the verdict was applied.")]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "evaluating",
                "accepted": True,
            }
        }
    )
