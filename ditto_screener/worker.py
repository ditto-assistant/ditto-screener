"""The screener sweep loop.

One sweep: lease one eligible agent from the platform, screen it through the
build gate, and post a lease-bound signed verdict. Agents are processed one at
a time because builds are heavy and serial execution keeps host load predictable.

A single bad submission or a transient platform error must never stall the loop:
each agent is guarded, and a failed platform call is logged and retried next
sweep. The loop drains promptly when the queue is non-empty and sleeps
``poll_seconds`` when it is idle, exiting cleanly when ``stop`` is set.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from ditto_screener import __version__
from ditto_screener.errors import PlatformError
from ditto_screener.heartbeat import (
    ScreenerHeartbeatRequest,
    ScreenerProgress,
    ScreenerProgressStage,
    ScreenerRuntimeState,
)
from ditto_screener.policy import ScreeningOutcome, core_decision
from ditto_screener.signing import sign_heartbeat, sign_verdict
from ditto_screening_protocol import (
    SCREENING_POLICY_VERSION,
    ScreenerQueueItem,
    ScreenEvidenceItem,
    ScreenResultOutcome,
    SourceReviewFinding,
)

if TYPE_CHECKING:
    from uuid import UUID

    from ditto_screener.config import ScreenerConfig
    from ditto_screener.gate import BuildGate
    from ditto_screener.heartbeat import SystemMetricsCollector
    from ditto_screener.platform import PlatformClient

logger = logging.getLogger(__name__)

EXACT_CROSS_MINER_DUPLICATE = "exact-cross-miner-duplicate"

_HEARTBEAT_PROTOCOL_VERSION = 2
_HEARTBEAT_MIN_INTERVAL_SECONDS = 120.0
_ACTIVE_HEARTBEAT_SECONDS = 120.0
# Slice of the lease reserved for signing and POSTing the verdict once screening
# finishes, so a result computed just under the deadline still lands before the
# platform rejects it as expired. The gate stops screening at this many seconds
# before the lease deadline.
_LEASE_SUBMIT_MARGIN_SECONDS = 10.0


class ScreenerWorker:
    """Drains the screener queue, gating each agent and posting a verdict."""

    def __init__(
        self,
        *,
        config: ScreenerConfig,
        platform: PlatformClient,
        gate: BuildGate,
        keypair: Any,
        system_metrics: SystemMetricsCollector | None = None,
    ) -> None:
        self._config = config
        self._platform = platform
        self._gate = gate
        self._keypair = keypair
        self._system_metrics = system_metrics
        self._active_agent_id: UUID | None = None
        self._active_progress_stage: ScreenerProgressStage | None = None
        self._job_started_at: int | None = None
        self._last_heartbeat_timestamp = 0
        self._last_heartbeat_monotonic = float("-inf")
        self._last_heartbeat_state: ScreenerRuntimeState | None = None
        self._progress_heartbeat_tasks: set[asyncio.Task[None]] = set()

    def _set_progress(self, stage: ScreenerProgressStage) -> None:
        """Advance public-safe progress without waiting on telemetry I/O."""
        if self._active_agent_id is None or self._job_started_at is None:
            return
        self._active_progress_stage = stage
        progress = ScreenerProgress(stage=stage, started_at=self._job_started_at)
        task = asyncio.create_task(
            self._report_heartbeat("screening", force=True, progress_override=progress)
        )
        self._progress_heartbeat_tasks.add(task)
        task.add_done_callback(self._progress_heartbeat_tasks.discard)

    def _screen_deadline(self, lease_deadline: datetime | None) -> float | None:
        """Monotonic budget for one screen, or ``None`` when the lease is open.

        Converts the platform's wall-clock ``lease_deadline`` into a
        ``loop.time()`` bound and reserves ``_LEASE_SUBMIT_MARGIN_SECONDS`` for
        signing and posting the verdict. A past/near deadline yields a bound in
        the past so the caller skips the build and reports retryable at once.
        """
        if lease_deadline is None:
            return None
        remaining = (
            lease_deadline - datetime.now(UTC)
        ).total_seconds() - _LEASE_SUBMIT_MARGIN_SECONDS
        return asyncio.get_running_loop().time() + remaining

    async def run_forever(self, stop: asyncio.Event) -> None:
        """Sweep until ``stop`` is set, sleeping when the queue is empty."""
        logger.info(
            "screener worker started hotkey=%s netuid=%d platform=%s",
            self._config.screener_hotkey,
            self._config.netuid,
            self._config.platform_api_url,
        )
        while not stop.is_set():
            await self._report_heartbeat("polling")
            try:
                processed = await self._sweep(stop)
            except PlatformError as e:
                logger.warning("sweep failed (retrying next cycle): %s", e)
                processed = 0
            if processed == 0 and not stop.is_set():
                await self._sleep_or_stop(stop, self._config.poll_seconds)
        logger.info("screener worker stopped")

    async def _report_heartbeat(
        self,
        state: ScreenerRuntimeState,
        *,
        force: bool = False,
        progress_override: ScreenerProgress | None = None,
    ) -> None:
        """Publish privacy-bounded fleet health without gating screening."""
        now_monotonic = time.monotonic()
        if (
            not force
            and state == self._last_heartbeat_state
            and now_monotonic - self._last_heartbeat_monotonic
            < _HEARTBEAT_MIN_INTERVAL_SECONDS
        ):
            return
        try:
            timestamp = max(int(time.time()), self._last_heartbeat_timestamp + 1)
            # Allocate before network I/O so concurrent best-effort stage reports
            # remain strictly ordered even if they arrive out of order.
            self._last_heartbeat_timestamp = timestamp
            metrics = (
                self._system_metrics.collect()
                if self._system_metrics is not None
                else None
            )
            progress = progress_override or (
                ScreenerProgress(
                    stage=self._active_progress_stage,
                    started_at=self._job_started_at,
                )
                if state == "screening"
                and self._active_progress_stage is not None
                and self._job_started_at is not None
                else None
            )
            signature = sign_heartbeat(
                self._keypair,
                screener_hotkey=self._config.screener_hotkey,
                software_version=__version__,
                protocol_version=_HEARTBEAT_PROTOCOL_VERSION,
                policy_version=SCREENING_POLICY_VERSION,
                state=state,
                active_agent_id=self._active_agent_id,
                progress=progress,
                system_metrics=metrics,
                timestamp=timestamp,
            )
            request = ScreenerHeartbeatRequest(
                screener_hotkey=self._config.screener_hotkey,
                software_version=__version__,
                protocol_version=_HEARTBEAT_PROTOCOL_VERSION,
                policy_version=SCREENING_POLICY_VERSION,
                state=state,
                active_agent_id=self._active_agent_id,
                progress=progress,
                system_metrics=metrics,
                timestamp=timestamp,
                signature=signature,
            )
            await self._platform.submit_heartbeat(request)
        except Exception as error:  # noqa: BLE001 - observability is best effort
            logger.warning("screener heartbeat failed (screening continues): %s", error)
        finally:
            # Throttle an older platform that has not deployed the optional
            # heartbeat endpoint yet; mixed deployment states remain safe.
            self._last_heartbeat_monotonic = now_monotonic
            self._last_heartbeat_state = state

    async def _heartbeat_while_active(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=_ACTIVE_HEARTBEAT_SECONDS)
            except TimeoutError:
                await self._report_heartbeat("screening", force=True)

    async def _sweep(self, stop: asyncio.Event) -> int:
        """Lease and screen the next eligible agent; return how many were done."""
        required_policy = await self._platform.get_required_policy_version()
        if required_policy != SCREENING_POLICY_VERSION:
            raise PlatformError(
                "screening policy mismatch before claim: platform requires "
                f"{required_policy}, worker supports {SCREENING_POLICY_VERSION}"
            )
        queue = await self._platform.claim_next(policy_version=SCREENING_POLICY_VERSION)
        if queue.required_policy_version != required_policy:
            raise PlatformError(
                "platform changed screening policy during claim: expected "
                f"{required_policy}, received {queue.required_policy_version}"
            )
        if not queue.items:
            return 0
        logger.info("screener sweep: %d agent(s) to screen", len(queue.items))
        done = 0
        for item in queue.items:
            if stop.is_set():
                break
            await self._screen_one(item, policy_version=required_policy)
            done += 1
        return done

    async def _screen_one(
        self, item: ScreenerQueueItem, *, policy_version: int
    ) -> None:
        """Gate one agent and post its signed verdict. Never raises."""
        agent_id = item.agent_id
        if item.attempt_id is None:
            logger.error("claimed agent_id=%s without a screening attempt id", agent_id)
            return
        self._active_agent_id = agent_id
        self._job_started_at = int(time.time())
        self._set_progress("preparing")
        heartbeat_stop = asyncio.Event()
        heartbeat_task = asyncio.create_task(
            self._heartbeat_while_active(heartbeat_stop)
        )
        try:
            if item.precheck_reason_code is not None:
                if item.precheck_reason_code != EXACT_CROSS_MINER_DUPLICATE:
                    raise PlatformError(
                        "unsupported platform precheck disposition: "
                        f"{item.precheck_reason_code}"
                    )
                result = core_decision(
                    ScreeningOutcome.DETERMINISTIC_REJECT,
                    code=EXACT_CROSS_MINER_DUPLICATE,
                    summary="artifact is an exact cross-miner duplicate",
                    detail="exact cross-miner duplicate",
                )
            else:
                screen_deadline = self._screen_deadline(item.lease_deadline)
                if (
                    screen_deadline is not None
                    and screen_deadline <= asyncio.get_running_loop().time()
                ):
                    logger.warning(
                        "agent_id=%s claimed with insufficient lease budget; "
                        "reporting retryable so the platform re-queues promptly",
                        agent_id,
                    )
                    result = core_decision(
                        ScreeningOutcome.RETRYABLE_INFRA,
                        code="lease-budget-exhausted",
                        summary="insufficient screening lease budget at claim",
                        detail="screener error: insufficient lease budget at claim",
                    )
                else:
                    artifact = await self._platform.get_artifact(agent_id)
                    result = await self._gate.screen(
                        agent_id=agent_id,
                        attempt_id=item.attempt_id,
                        miner_hotkey=item.miner_hotkey,
                        sha256=item.sha256,
                        download_url=str(artifact.download_url),
                        progress=self._set_progress,
                        deadline=screen_deadline,
                    )
            # INCONCLUSIVE is a NON-verdict by platform contract: the result
            # endpoint rejects a submitted inconclusive outcome and expects the
            # worker to post nothing and let the lease expire as the backoff
            # ("we could not tell; try again later"). Reporting it as
            # retryable_infra instead re-queues the agent immediately and hot-
            # loops as a mislabeled "Screening infrastructure error", so we honor
            # the contract and stay silent. QUARANTINE is the only non-boolean
            # outcome that still submits.
            submits_result = (
                result.submits_verdict or result.outcome.value == "quarantine"
            )
            if not submits_result:
                logger.warning(
                    "screening agent_id=%s outcome=%s manifest=%s; "
                    "no public verdict submitted and lease remains authoritative",
                    agent_id,
                    result.outcome,
                    result.manifest_digest,
                )
                return
            self._set_progress("submitting")
            typed_outcome = ScreenResultOutcome(result.outcome.value)
            passed = typed_outcome == ScreenResultOutcome.PASS
            is_quarantine = typed_outcome == ScreenResultOutcome.QUARANTINE
            reason_code = result.evidence[-1].code if result.evidence else None
            # The bounded review payloads ride along on quarantine so the
            # operator sees WHY, not just a digest. When a source-review
            # finding exists, the signed finding_digest binds that finding;
            # otherwise it anchors the last module evidence digest as before.
            finding = (
                SourceReviewFinding.model_validate(result.finding)
                if is_quarantine and result.finding is not None
                else None
            )
            evidence = (
                [
                    ScreenEvidenceItem(
                        module_id=item.module_id,
                        code=item.code,
                        summary=item.summary,
                        digest=item.digest,
                    )
                    for item in result.evidence
                ]
                if is_quarantine and result.evidence
                else None
            )
            finding_digest = (
                finding.canonical_digest()
                if finding is not None
                else next(
                    (item.digest for item in reversed(result.evidence) if item.digest),
                    None,
                )
                if is_quarantine
                else None
            )
            signature = sign_verdict(
                self._keypair,
                screener_hotkey=self._config.screener_hotkey,
                agent_id=agent_id,
                passed=passed,
                policy_version=policy_version,
                attempt_id=item.attempt_id,
                outcome=typed_outcome,
                manifest_digest=result.manifest_digest if is_quarantine else None,
                finding_digest=finding_digest,
                reason_code=reason_code,
            )
            resp = await self._platform.submit_result(
                agent_id,
                signature=signature,
                passed=passed,
                policy_version=policy_version,
                detail=result.detail,
                attempt_id=item.attempt_id,
                outcome=typed_outcome,
                manifest_digest=result.manifest_digest if is_quarantine else None,
                finding_digest=finding_digest,
                reason_code=reason_code,
                evidence=evidence,
                finding=finding,
            )
            logger.info(
                "screened agent_id=%s miner=%s outcome=%s passed=%s -> %s%s",
                agent_id,
                item.miner_hotkey,
                result.outcome,
                passed,
                resp.status,
                f" detail={result.detail!r}" if result.detail else "",
            )
        except PlatformError as e:
            # A late/conflicting verdict (409) or transient error: log + move on.
            logger.warning("verdict for agent_id=%s not applied: %s", agent_id, e)
        finally:
            heartbeat_stop.set()
            await heartbeat_task
            progress_tasks = tuple(self._progress_heartbeat_tasks)
            for task in progress_tasks:
                task.cancel()
            await asyncio.gather(*progress_tasks, return_exceptions=True)
            self._progress_heartbeat_tasks.clear()
            self._active_agent_id = None
            self._active_progress_stage = None
            self._job_started_at = None
            await self._report_heartbeat("polling", force=True)

    async def _sleep_or_stop(self, stop: asyncio.Event, seconds: float) -> None:
        """Sleep up to ``seconds``, waking early if ``stop`` is set."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=seconds)
