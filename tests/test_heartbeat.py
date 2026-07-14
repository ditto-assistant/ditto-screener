"""Privacy and bounds for optional fleet-health reporting."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from ditto_screener.heartbeat import (
    DockerHealth,
    ScreenerHeartbeatRequest,
    SystemMetricsCollector,
)


def test_collector_rounds_and_caches_without_identifying_metadata() -> None:
    times = iter((10.0, 20.0, 200.0))
    collector = SystemMetricsCollector(
        monotonic=lambda: next(times),
        wall_clock=lambda: 123.0,
        cpu_percent=lambda: 12.6,
        virtual_memory=lambda: SimpleNamespace(percent=41.9),
        disk_usage=lambda _path: SimpleNamespace(percent=57.4),
        docker_probe=lambda: DockerHealth(
            status="healthy", running_containers=4, unhealthy_containers=0
        ),
    )
    first = collector.collect()
    assert collector.collect() is first
    refreshed = collector.collect()
    assert (first.cpu_percent, first.memory_percent, first.disk_percent) == (
        15,
        40,
        55,
    )
    assert refreshed.model_dump() == first.model_dump()
    assert set(first.model_dump()) == {
        "collected_at",
        "cpu_percent",
        "memory_percent",
        "disk_percent",
        "docker",
    }


def test_heartbeat_rejects_arbitrary_private_host_fields() -> None:
    with pytest.raises(ValidationError):
        ScreenerHeartbeatRequest.model_validate(
            {
                "screener_hotkey": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
                "software_version": "0.1.0",
                "protocol_version": 1,
                "policy_version": 6,
                "state": "polling",
                "timestamp": 1,
                "signature": "ab" * 64,
                "hostname": "must-not-leave-the-host",
            }
        )
