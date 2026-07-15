"""Async client for the platform's ``/screener/*`` HTTP API.

The worker is HTTP-decoupled from the platform: it pulls work and posts verdicts
over the public ``/screener/*`` contract, authenticating every request with a
bearer token and the ``X-Screener-Hotkey`` header. Verdict POSTs additionally
carry an sr25519 signature. It never touches the platform DB.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from uuid import UUID

import httpx

from ditto_screener.errors import PlatformError
from ditto_screener.heartbeat import (
    ScreenerHeartbeatRequest,
    ScreenerHeartbeatResponse,
)
from ditto_screening_protocol import (
    ArtifactResponse,
    ScreenerQueueResponse,
    ScreenEvidenceItem,
    ScreenResultOutcome,
    ScreenResultRequest,
    ScreenResultResponse,
    SourceReviewFinding,
)

if TYPE_CHECKING:
    from ditto_screener.config import ScreenerConfig

logger = logging.getLogger(__name__)

_PREFIX = "/api/v1/screener"


class PlatformClient:
    """HTTP client for one platform base URL, screener-flavoured."""

    def __init__(self, config: ScreenerConfig, client: httpx.AsyncClient) -> None:
        self._config = config
        self._client = client
        self._base = config.platform_api_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {config.api_token}",
            "X-Screener-Hotkey": config.screener_hotkey,
        }

    async def submit_heartbeat(
        self, request: ScreenerHeartbeatRequest
    ) -> ScreenerHeartbeatResponse:
        """Publish a best-effort signed fleet-health report."""
        url = f"{self._base}{_PREFIX}/heartbeat"
        try:
            resp = await self._client.post(
                url, json=request.model_dump(mode="json"), headers=self._headers
            )
        except httpx.HTTPError as error:
            raise PlatformError(f"screener heartbeat failed: {error}") from error
        if resp.status_code != 200:
            raise PlatformError(
                f"screener heartbeat rejected ({resp.status_code}): {resp.text[:200]}"
            )
        return ScreenerHeartbeatResponse.model_validate(resp.json())

    async def get_required_policy_version(self) -> int:
        """Read the platform policy without claiming or mutating queue state."""
        url = f"{self._base}{_PREFIX}/queue"
        try:
            resp = await self._client.get(
                url, params={"limit": 1}, headers=self._headers
            )
        except httpx.HTTPError as e:
            raise PlatformError(f"screening policy check failed: {e}") from e
        if resp.status_code != 200:
            raise PlatformError(
                f"screening policy check rejected ({resp.status_code}): "
                f"{resp.text[:200]}"
            )
        return ScreenerQueueResponse.model_validate(resp.json()).required_policy_version

    async def claim_next(self, *, policy_version: int) -> ScreenerQueueResponse:
        """Lease one agent for screening, oldest eligible first."""
        url = f"{self._base}{_PREFIX}/claim"
        params = {"limit": 1, "policy_version": policy_version}
        try:
            resp = await self._client.post(url, params=params, headers=self._headers)
        except httpx.HTTPError as e:
            raise PlatformError(f"screening claim failed: {e}") from e
        if resp.status_code != 200:
            raise PlatformError(
                f"screening claim rejected ({resp.status_code}): {resp.text[:200]}"
            )
        return ScreenerQueueResponse.model_validate(resp.json())

    async def get_artifact(self, agent_id: UUID) -> ArtifactResponse:
        """Get a presigned tarball download URL for ``agent_id``."""
        url = f"{self._base}{_PREFIX}/agent/{agent_id}/artifact"
        try:
            resp = await self._client.get(url, headers=self._headers)
        except httpx.HTTPError as e:
            raise PlatformError(f"artifact fetch failed: {e}") from e
        if resp.status_code != 200:
            raise PlatformError(
                f"artifact rejected ({resp.status_code}): {resp.text[:200]}"
            )
        return ArtifactResponse.model_validate(resp.json())

    async def submit_result(
        self,
        agent_id: UUID,
        *,
        signature: str,
        passed: bool,
        policy_version: int,
        detail: str = "",
        attempt_id: UUID,
        outcome: ScreenResultOutcome | None = None,
        manifest_digest: str | None = None,
        finding_digest: str | None = None,
        reason_code: str | None = None,
        evidence: list[ScreenEvidenceItem] | None = None,
        finding: SourceReviewFinding | None = None,
    ) -> ScreenResultResponse:
        """Report a signed pass/fail verdict for ``agent_id``."""
        url = f"{self._base}{_PREFIX}/agent/{agent_id}/result"
        payload = ScreenResultRequest(
            screener_hotkey=self._config.screener_hotkey,
            signature=signature,
            passed=passed,
            policy_version=policy_version,
            detail=detail,
            attempt_id=attempt_id,
            outcome=outcome,
            manifest_digest=manifest_digest,
            finding_digest=finding_digest,
            reason_code=reason_code,
            evidence=evidence,
            finding=finding,
        )
        try:
            resp = await self._client.post(
                url, json=payload.model_dump(mode="json"), headers=self._headers
            )
        except httpx.HTTPError as e:
            raise PlatformError(f"verdict submit failed: {e}") from e
        if resp.status_code != 200:
            raise PlatformError(
                f"verdict rejected ({resp.status_code}): {resp.text[:200]}"
            )
        return ScreenResultResponse.model_validate(resp.json())
