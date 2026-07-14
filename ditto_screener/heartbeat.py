"""Privacy-bounded screener fleet heartbeat models and host sampling."""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

import psutil
from pydantic import BaseModel, ConfigDict, Field, model_validator

DockerHealthStatus = Literal["healthy", "degraded", "unavailable"]
ScreenerRuntimeState = Literal["polling", "screening", "error", "paused"]
_SS58_PATTERN = r"^[1-9A-HJ-NP-Za-km-z]{47,48}$"
_SIGNATURE_HEX_PATTERN = r"^[0-9a-fA-F]{128}$"
_SOFTWARE_VERSION_PATTERN = r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$"
_SYSTEM_METRICS_SAMPLE_SECONDS = 120.0


class DockerHealth(BaseModel):
    """Aggregate Docker health without names or image metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: DockerHealthStatus
    running_containers: Annotated[int, Field(ge=0, le=1000)]
    unhealthy_containers: Annotated[int, Field(ge=0, le=1000)]

    @model_validator(mode="after")
    def validate_counts(self) -> DockerHealth:
        if self.unhealthy_containers > self.running_containers:
            raise ValueError("unhealthy containers cannot exceed running containers")
        if self.status == "healthy" and self.unhealthy_containers:
            raise ValueError("healthy Docker cannot report unhealthy containers")
        if self.status == "degraded" and not self.unhealthy_containers:
            raise ValueError("degraded Docker requires an unhealthy container")
        if self.status == "unavailable" and (
            self.running_containers or self.unhealthy_containers
        ):
            raise ValueError("unavailable Docker cannot report container counts")
        return self


class SystemMetrics(BaseModel):
    """One bounded and intentionally coarse host-health sample."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    collected_at: Annotated[int, Field(ge=0)]
    cpu_percent: Annotated[int, Field(ge=0, le=100, multiple_of=5)]
    memory_percent: Annotated[int, Field(ge=0, le=100, multiple_of=5)]
    disk_percent: Annotated[int, Field(ge=0, le=100, multiple_of=5)]
    docker: DockerHealth


class ScreenerHeartbeatRequest(BaseModel):
    """Dedicated screener identity, work, and optional coarse host health."""

    model_config = ConfigDict(extra="forbid")

    screener_hotkey: Annotated[str, Field(pattern=_SS58_PATTERN)]
    software_version: Annotated[str, Field(pattern=_SOFTWARE_VERSION_PATTERN)]
    protocol_version: Annotated[int, Field(ge=1, le=2**31 - 1)]
    policy_version: Annotated[int, Field(ge=1, le=2**31 - 1)]
    state: ScreenerRuntimeState
    active_agent_id: UUID | None = None
    system_metrics: SystemMetrics | None = None
    timestamp: Annotated[int, Field(ge=0)]
    signature: Annotated[str, Field(pattern=_SIGNATURE_HEX_PATTERN)]


class ScreenerHeartbeatResponse(BaseModel):
    accepted: bool
    seen_at: datetime


def system_metrics_signing_token(metrics: SystemMetrics | None) -> str:
    """Return the exact bounded token used by platform PR #74."""
    if metrics is None:
        return "-"
    docker = metrics.docker
    return ",".join(
        str(value)
        for value in (
            metrics.collected_at,
            metrics.cpu_percent,
            metrics.memory_percent,
            metrics.disk_percent,
            docker.status,
            docker.running_containers,
            docker.unhealthy_containers,
        )
    )


def _coarse_percent(value: float) -> int:
    bounded = min(100.0, max(0.0, float(value)))
    return min(100, int((bounded + 2.5) // 5) * 5)


def probe_docker_health() -> DockerHealth:
    """Read aggregate running-container health without identifying metadata."""
    try:
        result = subprocess.run(
            [
                "docker",
                "container",
                "ls",
                "--filter",
                "status=running",
                "--format",
                "{{.Status}}",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return DockerHealth(
            status="unavailable", running_containers=0, unhealthy_containers=0
        )
    if result.returncode != 0:
        return DockerHealth(
            status="unavailable", running_containers=0, unhealthy_containers=0
        )
    statuses = result.stdout.splitlines()[:1000]
    unhealthy = sum("(unhealthy)" in status.lower() for status in statuses)
    return DockerHealth(
        status="degraded" if unhealthy else "healthy",
        running_containers=len(statuses),
        unhealthy_containers=unhealthy,
    )


class SystemMetricsCollector:
    """Cache an allowlisted five-point sample for two minutes."""

    def __init__(
        self,
        *,
        sample_seconds: float = _SYSTEM_METRICS_SAMPLE_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        cpu_percent: Callable[[], float] | None = None,
        virtual_memory: Callable[[], Any] = psutil.virtual_memory,
        disk_usage: Callable[[str], Any] = psutil.disk_usage,
        docker_probe: Callable[[], DockerHealth] = probe_docker_health,
    ) -> None:
        self._sample_seconds = sample_seconds
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._cpu_percent = cpu_percent or (lambda: psutil.cpu_percent(interval=0.1))
        self._virtual_memory = virtual_memory
        self._disk_usage = disk_usage
        self._docker_probe = docker_probe
        self._last_sampled = float("-inf")
        self._cached: SystemMetrics | None = None

    def collect(self) -> SystemMetrics:
        now = self._monotonic()
        if self._cached is not None and now - self._last_sampled < self._sample_seconds:
            return self._cached
        sample = SystemMetrics(
            collected_at=int(self._wall_clock()),
            cpu_percent=_coarse_percent(self._cpu_percent()),
            memory_percent=_coarse_percent(self._virtual_memory().percent),
            disk_percent=_coarse_percent(self._disk_usage("/").percent),
            docker=self._docker_probe(),
        )
        self._cached = sample
        self._last_sampled = now
        return sample


__all__ = [
    "DockerHealth",
    "ScreenerHeartbeatRequest",
    "ScreenerHeartbeatResponse",
    "ScreenerRuntimeState",
    "SystemMetrics",
    "SystemMetricsCollector",
    "system_metrics_signing_token",
]
