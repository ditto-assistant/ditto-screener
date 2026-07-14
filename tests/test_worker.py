"""Tests for the screener sweep loop (fakes for platform + gate)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from ditto_screener.config import ScreenerConfig
from ditto_screener.errors import PlatformError
from ditto_screener.policy import ScreeningDecision, ScreeningOutcome, core_decision
from ditto_screener.worker import ScreenerWorker
from ditto_screening_protocol import (
    SCREENING_POLICY_VERSION,
    AgentStatus,
    ArtifactResponse,
    ScreenerQueueItem,
    ScreenerQueueResponse,
)

_MINER = "5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm"


def _item(agent_id: UUID) -> ScreenerQueueItem:
    return ScreenerQueueItem(
        agent_id=agent_id,
        miner_hotkey=_MINER,
        name="a",
        sha256="de" * 32,
        status=AgentStatus.SCREENING,
        created_at=datetime.now(UTC),
        attempt_id=uuid4(),
        lease_deadline=datetime.now(UTC),
    )


class _FakeKeypair:
    def sign(self, _message: bytes) -> bytes:
        return b"\xcd" * 64


def _decision(outcome: ScreeningOutcome, detail: str = "") -> ScreeningDecision:
    return core_decision(
        outcome,
        code="test",
        summary="test decision",
        detail=detail,
    )


class _FakeGate:
    def __init__(self, result: ScreeningDecision) -> None:
        self.result = result
        self.calls: list[UUID] = []

    async def screen(self, *, agent_id: UUID, **_: Any) -> ScreeningDecision:
        self.calls.append(agent_id)
        return self.result


class _FakePlatform:
    def __init__(self, queues: list[list[ScreenerQueueItem]]) -> None:
        self._queues = queues
        self.verdicts: list[dict] = []
        self.submit_error: Exception | None = None
        self.stop_after_queue: asyncio.Event | None = None
        self.required_policy_version = SCREENING_POLICY_VERSION
        self.claim_calls = 0
        self.heartbeats: list[Any] = []
        self.heartbeat_error: Exception | None = None

    async def submit_heartbeat(self, request: Any) -> Any:
        if self.heartbeat_error is not None:
            raise self.heartbeat_error
        self.heartbeats.append(request)
        return object()

    async def get_required_policy_version(self) -> int:
        return self.required_policy_version

    async def claim_next(self, *, policy_version: int) -> ScreenerQueueResponse:
        self.claim_calls += 1
        items = self._queues.pop(0) if self._queues else []
        # Signal the loop to stop once the queue has drained (first empty sweep),
        # AFTER the item-bearing sweeps have been served + processed.
        if self.stop_after_queue is not None and not items:
            self.stop_after_queue.set()
        return ScreenerQueueResponse(
            items=items,
            count=len(items),
            required_policy_version=policy_version,
        )

    async def get_artifact(self, agent_id: UUID) -> ArtifactResponse:
        return ArtifactResponse(
            agent_id=agent_id,
            sha256="de" * 32,
            download_url="https://storage.test/a.tar.gz",
            expires_at=datetime.now(UTC),
        )

    async def submit_result(  # type: ignore[no-untyped-def]
        self,
        agent_id,
        *,
        signature,
        passed,
        policy_version,
        detail="",
        attempt_id,
    ):
        if self.submit_error is not None:
            raise self.submit_error
        self.verdicts.append(
            {
                "agent_id": agent_id,
                "signature": signature,
                "passed": passed,
                "policy_version": policy_version,
                "detail": detail,
                "attempt_id": attempt_id,
            }
        )

        class _R:
            status = type(
                "S", (), {"value": "evaluating" if passed else "screening_failed"}
            )()

        return _R()


def _worker(cfg: ScreenerConfig, platform, gate) -> ScreenerWorker:  # type: ignore[no-untyped-def]
    return ScreenerWorker(
        config=cfg, platform=platform, gate=gate, keypair=_FakeKeypair()
    )


async def test_screen_one_pass_posts_signed_pass_verdict(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    agent = uuid4()
    platform = _FakePlatform([])
    gate = _FakeGate(_decision(ScreeningOutcome.PASS))
    worker = _worker(make_config(), platform, gate)
    await worker._screen_one(_item(agent), policy_version=SCREENING_POLICY_VERSION)
    assert gate.calls == [agent]
    assert len(platform.verdicts) == 1
    v = platform.verdicts[0]
    assert v["passed"] is True and v["signature"] == "cd" * 64 and v["detail"] == ""
    assert v["policy_version"] == SCREENING_POLICY_VERSION
    assert v["attempt_id"] is not None
    assert platform.heartbeats[0].state == "screening"
    assert platform.heartbeats[0].progress.stage == "preparing"
    assert platform.heartbeats[-1].state == "polling"
    assert platform.heartbeats[-1].progress is None


async def test_screen_one_fail_forwards_detail(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([])
    gate = _FakeGate(
        _decision(ScreeningOutcome.DETERMINISTIC_REJECT, "build failed: E0432")
    )
    worker = _worker(make_config(), platform, gate)
    await worker._screen_one(_item(uuid4()), policy_version=SCREENING_POLICY_VERSION)
    v = platform.verdicts[0]
    assert v["passed"] is False and "E0432" in v["detail"]


async def test_screen_one_retryable_failure_preserves_v6_screening_failed_verdict(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([])
    gate = _FakeGate(
        _decision(
            ScreeningOutcome.RETRYABLE_INFRA,
            "screener error: Docker daemon temporarily unavailable",
        )
    )
    worker = _worker(make_config(), platform, gate)
    await worker._screen_one(_item(uuid4()), policy_version=SCREENING_POLICY_VERSION)
    assert len(platform.verdicts) == 1
    assert platform.verdicts[0]["passed"] is False
    assert platform.verdicts[0]["detail"].startswith("screener error:")


async def test_quarantine_submits_no_public_verdict(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([])
    gate = _FakeGate(
        _decision(
            ScreeningOutcome.QUARANTINE,
            "private policy quarantine pending operator review",
        )
    )
    worker = _worker(make_config(), platform, gate)
    await worker._screen_one(_item(uuid4()), policy_version=SCREENING_POLICY_VERSION)
    assert platform.verdicts == []


async def test_verdict_platform_error_swallowed(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([])
    platform.submit_error = PlatformError("409 conflict")
    gate = _FakeGate(_decision(ScreeningOutcome.PASS))
    worker = _worker(make_config(), platform, gate)
    # Must not raise (a 409/late verdict is logged and skipped).
    await worker._screen_one(_item(uuid4()), policy_version=SCREENING_POLICY_VERSION)
    assert platform.verdicts == []


async def test_heartbeat_failure_never_blocks_screening_or_verdict(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([])
    platform.heartbeat_error = PlatformError("heartbeat unavailable")
    gate = _FakeGate(_decision(ScreeningOutcome.PASS))
    worker = _worker(make_config(), platform, gate)
    await worker._screen_one(_item(uuid4()), policy_version=SCREENING_POLICY_VERSION)
    assert len(platform.verdicts) == 1
    assert gate.calls
    assert worker._active_agent_id is None
    assert worker._active_progress_stage is None
    assert worker._job_started_at is None


async def test_run_forever_drains_queue_then_stops(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    a1, a2 = uuid4(), uuid4()
    # First sweep has two agents; the second (empty) sweep trips the stop.
    platform = _FakePlatform([[_item(a1), _item(a2)], []])
    stop = asyncio.Event()
    platform.stop_after_queue = stop  # set on the first empty sweep
    gate = _FakeGate(_decision(ScreeningOutcome.PASS))
    worker = _worker(make_config(), platform, gate)
    await asyncio.wait_for(worker.run_forever(stop), timeout=2.0)
    assert gate.calls == [a1, a2]
    assert {v["agent_id"] for v in platform.verdicts} == {a1, a2}


async def test_run_forever_exits_immediately_when_stopped(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([])
    gate = _FakeGate(_decision(ScreeningOutcome.PASS))
    worker = _worker(make_config(), platform, gate)
    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(worker.run_forever(stop), timeout=2.0)


async def test_policy_mismatch_does_not_claim(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([[_item(uuid4())]])
    platform.required_policy_version = SCREENING_POLICY_VERSION - 2
    gate = _FakeGate(_decision(ScreeningOutcome.PASS))
    worker = _worker(make_config(), platform, gate)

    try:
        await worker._sweep(asyncio.Event())
    except PlatformError as exc:
        assert "policy mismatch before claim" in str(exc)
    else:
        raise AssertionError("policy mismatch must stop before claiming")

    assert platform.claim_calls == 0
    assert gate.calls == []


async def test_policy_six_claims_and_signs_policy_six(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    platform = _FakePlatform([[_item(uuid4())]])
    platform.required_policy_version = 6
    gate = _FakeGate(_decision(ScreeningOutcome.PASS))
    worker = _worker(make_config(), platform, gate)

    assert await worker._sweep(asyncio.Event()) == 1
    assert platform.verdicts[0]["policy_version"] == 6
