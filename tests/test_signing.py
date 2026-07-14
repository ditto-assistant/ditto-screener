"""Tests for screener verdict signing (message format + delegation)."""

from __future__ import annotations

from uuid import UUID

from ditto_screener.heartbeat import DockerHealth, SystemMetrics
from ditto_screener.signing import (
    heartbeat_signing_message,
    sign_verdict,
    verdict_signing_message,
)
from ditto_screening_protocol import SCREENING_POLICY_VERSION

_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
_AGENT = UUID("550e8400-e29b-41d4-a716-446655440000")
_ATTEMPT = UUID("776a3bb8-5847-40db-b2af-42f93f20233c")


def test_message_matches_platform_format() -> None:
    # Must byte-for-byte match the platform's
    # f"{screener_hotkey}:{agent_id}:{passed}".encode() — including Python's
    # bool str form ("True"/"False").
    msg = verdict_signing_message(screener_hotkey=_HOTKEY, agent_id=_AGENT, passed=True)
    assert msg == f"{_HOTKEY}:{_AGENT}:True:{SCREENING_POLICY_VERSION}".encode()
    assert msg.endswith(f":True:{SCREENING_POLICY_VERSION}".encode())

    msg_false = verdict_signing_message(
        screener_hotkey=_HOTKEY, agent_id=_AGENT, passed=False
    )
    assert msg_false.endswith(f":False:{SCREENING_POLICY_VERSION}".encode())


class _FakeKeypair:
    """Records what it was asked to sign; returns deterministic bytes."""

    def __init__(self) -> None:
        self.signed: bytes | None = None

    def sign(self, message: bytes) -> bytes:
        self.signed = message
        return b"\xab" * 64


def test_sign_verdict_signs_canonical_message() -> None:
    kp = _FakeKeypair()
    sig = sign_verdict(kp, screener_hotkey=_HOTKEY, agent_id=_AGENT, passed=False)
    assert sig == ("ab" * 64)
    assert kp.signed == f"{_HOTKEY}:{_AGENT}:False:{SCREENING_POLICY_VERSION}".encode()


def test_attempt_signature_binds_exact_lease() -> None:
    kp = _FakeKeypair()
    sign_verdict(
        kp,
        screener_hotkey=_HOTKEY,
        agent_id=_AGENT,
        attempt_id=_ATTEMPT,
        passed=True,
    )
    assert (
        kp.signed
        == (
            "ditto-screen-verdict:v2:"
            f"{_HOTKEY}:{_AGENT}:{_ATTEMPT}:True:{SCREENING_POLICY_VERSION}"
        ).encode()
    )


def test_heartbeat_signature_binds_allowlisted_coarse_metrics() -> None:
    metrics = SystemMetrics(
        collected_at=123,
        cpu_percent=15,
        memory_percent=40,
        disk_percent=55,
        docker=DockerHealth(
            status="healthy", running_containers=3, unhealthy_containers=0
        ),
    )
    assert (
        heartbeat_signing_message(
            screener_hotkey=_HOTKEY,
            software_version="0.1.0",
            protocol_version=1,
            policy_version=6,
            state="screening",
            active_agent_id=_AGENT,
            system_metrics=metrics,
            timestamp=456,
        )
        == (
            "ditto-screener-heartbeat:v1:"
            f"{_HOTKEY}:0.1.0:1:6:screening:{_AGENT}:"
            "123,15,40,55,healthy,3,0:456"
        ).encode()
    )
