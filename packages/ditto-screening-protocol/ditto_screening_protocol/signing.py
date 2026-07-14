"""Canonical signing payload for versioned screener verdicts."""

from __future__ import annotations

from uuid import UUID

from ditto_screening_protocol.models import (
    SCREENING_POLICY_VERSION,
    ScreenResultOutcome,
)


def verdict_signing_message(
    *,
    screener_hotkey: str,
    agent_id: UUID,
    passed: bool,
    policy_version: int = SCREENING_POLICY_VERSION,
    attempt_id: UUID | None = None,
    outcome: ScreenResultOutcome | None = None,
    manifest_digest: str | None = None,
    finding_digest: str | None = None,
    reason_code: str | None = None,
) -> bytes:
    """Return the exact bytes signed by the screener and verified by the API."""
    if outcome is not None:
        if attempt_id is None:
            raise ValueError("typed result signature requires attempt_id")
        return (
            "ditto-screen-result:v3:"
            f"{screener_hotkey}:{agent_id}:{attempt_id}:{outcome}:"
            f"{policy_version}:{manifest_digest or ''}:{finding_digest or ''}:"
            f"{reason_code or ''}"
        ).encode()
    if attempt_id is not None:
        return (
            "ditto-screen-verdict:v2:"
            f"{screener_hotkey}:{agent_id}:{attempt_id}:{passed}:{policy_version}"
        ).encode()
    return f"{screener_hotkey}:{agent_id}:{passed}:{policy_version}".encode()
