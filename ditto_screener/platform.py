"""Async client for the platform's ``/screener/*`` HTTP API.

The worker is HTTP-decoupled from the platform: it pulls work and posts verdicts
over the public ``/screener/*`` contract, authenticating every request with a
bearer token and the ``X-Screener-Hotkey`` header. Verdict POSTs additionally
carry an sr25519 signature. It never touches the platform DB.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

import httpx

from ditto_screener.errors import PlatformError
from ditto_screener.heartbeat import (
    ScreenerHeartbeatRequest,
    ScreenerHeartbeatResponse,
)
from ditto_screener.review_settings import (
    EffectiveReviewSettings,
    ReviewSettingsCache,
    bootstrap_review_settings,
)
from ditto_screening_protocol import (
    ArtifactResponse,
    ScreenedImageCompletedPart,
    ScreenedImagePartUploadRequest,
    ScreenedImagePartUploadResponse,
    ScreenedImageUploadAbortRequest,
    ScreenedImageUploadAbortResponse,
    ScreenedImageUploadCompleteRequest,
    ScreenedImageUploadCompleteResponse,
    ScreenedImageUploadRequest,
    ScreenedImageUploadResponse,
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
_IMAGE_REQUEST_TIMEOUT = httpx.Timeout(300.0, connect=30.0, pool=30.0)
_IMAGE_UPLOAD_ATTEMPTS = 3


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
        self._review_settings_cache = ReviewSettingsCache(
            config.review_settings_cache_file
        )
        self._review_settings: EffectiveReviewSettings | None = None
        self._review_settings_fetched_at = float("-inf")

    async def get_review_settings(self, instance_id: str) -> EffectiveReviewSettings:
        """Fetch settings before a claim, falling back only to bounded valid state."""
        now = time.monotonic()
        if (
            self._review_settings is not None
            and now - self._review_settings_fetched_at
            < self._review_settings.max_age_seconds
        ):
            return self._review_settings
        url = f"{self._base}{_PREFIX}/review-settings"
        try:
            response = await self._client.get(
                url, params={"instance_id": instance_id}, headers=self._headers
            )
            if response.status_code != 200:
                raise PlatformError(
                    "review settings rejected "
                    f"({response.status_code}): {response.text[:200]}"
                )
            effective = EffectiveReviewSettings.model_validate_json(response.text)
            self._review_settings_cache.store(effective)
            self._review_settings = effective
            self._review_settings_fetched_at = now
            return effective
        except (httpx.HTTPError, ValueError, OSError, PlatformError) as error:
            cached = self._review_settings_cache.load()
            if cached is not None:
                age = max(0, int(time.time()) - cached.cached_at)
                if age <= self._config.review_settings_max_stale_seconds:
                    logger.warning(
                        "using cached review settings revision=%d age_s=%d: %s",
                        cached.effective.revision,
                        age,
                        error,
                    )
                    self._review_settings = cached.effective
                    self._review_settings_fetched_at = now
                    return cached.effective
                if cached.effective.settings.mode == "enforce":
                    raise PlatformError(
                        "enforced review settings expired; refusing new claims"
                    ) from error
            bootstrap = bootstrap_review_settings(self._config)
            if bootstrap.settings.mode == "enforce":
                raise PlatformError(
                    "platform review settings unavailable in enforce mode"
                ) from error
            logger.warning("review settings unavailable; using bootstrap %s", error)
            self._review_settings = bootstrap
            self._review_settings_fetched_at = now
            return bootstrap

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
        image_sha256: str | None = None,
        image_size_bytes: int | None = None,
        image_id: str | None = None,
        image_ref: str | None = None,
        image_upload_id: UUID | None = None,
        build_only: bool = False,
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
            image_sha256=image_sha256,
            image_size_bytes=image_size_bytes,
            image_id=image_id,
            image_ref=image_ref,
            image_upload_id=image_upload_id,
            build_only=build_only,
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

    async def upload_screened_image(
        self,
        agent_id: UUID,
        *,
        attempt_id: UUID,
        path: str,
        sha256: str,
        size_bytes: int,
        image_id: str,
        image_ref: str,
    ) -> UUID:
        """Upload an image in bounded parts and return its verified upload id."""
        archive = Path(path)
        if archive.stat().st_size != size_bytes:
            raise PlatformError("screened image changed before multipart upload")
        request = ScreenedImageUploadRequest(
            attempt_id=attempt_id,
            sha256=sha256,
            size_bytes=size_bytes,
            image_id=image_id,
            image_ref=image_ref,
        )
        base_url = f"{self._base}{_PREFIX}/agent/{agent_id}/screened-image-upload"
        upload: ScreenedImageUploadResponse | None = None
        try:
            response = await self._image_request(
                "POST",
                base_url,
                operation="image upload initiate",
                json=request.model_dump(mode="json"),
                headers=self._headers,
            )
            upload = ScreenedImageUploadResponse.model_validate(response.json())
            completed: list[ScreenedImageCompletedPart] = []
            with archive.open("rb") as handle:
                part_number = 1
                uploaded_bytes = 0
                while uploaded_bytes < size_bytes:
                    part = await asyncio.to_thread(handle.read, upload.part_size_bytes)
                    if not part:
                        raise PlatformError(
                            "screened image ended before declared multipart size"
                        )
                    uploaded_bytes += len(part)
                    part_request = ScreenedImagePartUploadRequest(
                        attempt_id=attempt_id,
                        storage_upload_id=upload.storage_upload_id,
                        part_number=part_number,
                        size_bytes=len(part),
                    )
                    part_response = await self._image_request(
                        "POST",
                        f"{base_url}/{upload.image_upload_id}/part",
                        operation=f"image part {part_number} mint",
                        json=part_request.model_dump(mode="json"),
                        headers=self._headers,
                    )
                    part_upload = ScreenedImagePartUploadResponse.model_validate(
                        part_response.json()
                    )
                    stored = await self._image_request(
                        "PUT",
                        part_upload.upload_url,
                        operation=f"image part {part_number} upload",
                        content=part,
                        headers=part_upload.required_headers,
                        accepted=frozenset({200, 201, 204}),
                    )
                    etag = stored.headers.get("etag")
                    if not etag:
                        raise PlatformError(
                            f"image part {part_number} upload returned no ETag"
                        )
                    completed.append(
                        ScreenedImageCompletedPart(
                            part_number=part_number,
                            etag=etag,
                        )
                    )
                    part_number += 1
            if uploaded_bytes != size_bytes or archive.stat().st_size != size_bytes:
                raise PlatformError(
                    "screened image size changed during multipart upload"
                )
            complete = ScreenedImageUploadCompleteRequest(
                attempt_id=attempt_id,
                storage_upload_id=upload.storage_upload_id,
                sha256=sha256,
                size_bytes=size_bytes,
                image_id=image_id,
                image_ref=image_ref,
                parts=completed,
            )
            completed_response = await self._image_request(
                "POST",
                f"{base_url}/{upload.image_upload_id}/complete",
                operation="image upload complete",
                json=complete.model_dump(mode="json"),
                headers=self._headers,
            )
            ScreenedImageUploadCompleteResponse.model_validate(
                completed_response.json()
            )
            return upload.image_upload_id
        except BaseException:
            if upload is not None:
                with contextlib.suppress(Exception):
                    await asyncio.shield(
                        self._abort_screened_image_upload(
                            base_url,
                            upload,
                            attempt_id=attempt_id,
                        )
                    )
            raise

    async def _image_request(
        self,
        method: str,
        url: str,
        *,
        operation: str,
        accepted: frozenset[int] = frozenset({200}),
        **kwargs: Any,
    ) -> httpx.Response:
        """Issue one finite image request, retrying transport and server failures."""
        for attempt in range(1, _IMAGE_UPLOAD_ATTEMPTS + 1):
            try:
                response = await self._client.request(
                    method,
                    url,
                    timeout=_IMAGE_REQUEST_TIMEOUT,
                    **kwargs,
                )
            except httpx.HTTPError as error:
                if attempt == _IMAGE_UPLOAD_ATTEMPTS:
                    raise PlatformError(f"{operation} failed: {error}") from error
            else:
                if response.status_code in accepted:
                    return response
                if response.status_code not in {429, 500, 502, 503, 504}:
                    raise PlatformError(
                        f"{operation} rejected ({response.status_code}): "
                        f"{response.text[:200]}"
                    )
                if attempt == _IMAGE_UPLOAD_ATTEMPTS:
                    raise PlatformError(
                        f"{operation} failed after retries ({response.status_code}): "
                        f"{response.text[:200]}"
                    )
            await asyncio.sleep(0.5 * attempt)
        raise AssertionError("image request retry loop exhausted")

    async def _abort_screened_image_upload(
        self,
        base_url: str,
        upload: ScreenedImageUploadResponse,
        *,
        attempt_id: UUID,
    ) -> None:
        """Best-effort abort so failed multipart parts do not accumulate."""
        request = ScreenedImageUploadAbortRequest(
            attempt_id=attempt_id,
            storage_upload_id=upload.storage_upload_id,
        )
        try:
            response = await self._image_request(
                "POST",
                f"{base_url}/{upload.image_upload_id}/abort",
                operation="image upload abort",
                json=request.model_dump(mode="json"),
                headers=self._headers,
            )
            ScreenedImageUploadAbortResponse.model_validate(response.json())
        except PlatformError as error:
            logger.warning(
                "failed to abort image_upload_id=%s: %s",
                upload.image_upload_id,
                error,
            )
