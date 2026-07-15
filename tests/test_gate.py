"""Stable-core tests for bounded artifact, build, health, and teardown behavior."""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest

from ditto_screener.config import ScreenerConfig
from ditto_screener.gate import BuildGate, _detail_tail, _log_tail, dockerfile_at_root
from ditto_screener.policy import (
    CORE_ONLY_MANIFEST,
    PolicyEngine,
    ReviewJournal,
    ScreeningOutcome,
)

_AGENT = UUID("550e8400-e29b-41d4-a716-446655440000")
_ATTEMPT = UUID("7c5df3f9-3ea7-47ba-92d1-1bbcf4c5f300")
_MINER = "5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm"
_URL = "https://storage.test/agent.tar.gz"


def _make_tar(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _valid_tar(**overrides: bytes) -> bytes:
    files = {
        "Dockerfile": b"FROM scratch\n",
        "Cargo.toml": b'[package]\nname = "agent"\nversion = "0.1.0"\n',
        "src/main.rs": b"fn main() {}\n",
    }
    files.update(overrides)
    return _make_tar(files)


def _gate_with(
    config: ScreenerConfig,
    run_stub: Callable[..., Any],
    *,
    tarball: bytes,
) -> BuildGate:
    def artifact(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(_URL)
        return httpx.Response(200, content=tarball)

    client = httpx.AsyncClient(transport=httpx.MockTransport(artifact))
    gate = BuildGate(
        config,
        client,
        policy=PolicyEngine(CORE_ONLY_MANIFEST),
        journal=ReviewJournal(None),
    )
    gate._run = run_stub  # type: ignore[method-assign]
    return gate


def _ok_run(calls: list[list[str]] | None = None) -> Callable[..., Any]:
    async def run(args: list[str], *, stdin: Any = None, **_: Any) -> tuple[int, str]:
        if calls is not None:
            calls.append(args)
        if args[0] == "build" and stdin is not None:
            stdin.read()
        return 0, ""

    return run


async def _screen(  # type: ignore[no-untyped-def]
    gate: BuildGate, sha256: str, *, progress=None
):
    return await gate.screen(
        agent_id=_AGENT,
        attempt_id=_ATTEMPT,
        miner_hotkey=_MINER,
        sha256=sha256,
        download_url=_URL,
        progress=progress,
    )


def test_root_and_log_helpers() -> None:
    assert dockerfile_at_root(["Dockerfile", "src/lib.rs"])
    assert dockerfile_at_root(["./Dockerfile", "Cargo.toml"])
    assert not dockerfile_at_root(["sub/Dockerfile"])
    assert _log_tail("  hi  ") == "hi"
    assert len(_detail_tail("x" * 5000)) == 3900


async def test_default_v6_builds_and_health_checks_without_run(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()
    calls: list[list[str]] = []
    gate = _gate_with(make_config(), _ok_run(calls), tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())

    assert result.outcome == ScreeningOutcome.PASS
    assert result.manifest_digest == CORE_ONLY_MANIFEST.digest
    assert any("http://harness:8080/health" in arg for call in calls for arg in call)
    assert not any("http://harness:8080/run" in arg for call in calls for arg in call)


async def test_reports_only_coarse_pipeline_stages(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()
    stages: list[str] = []
    gate = _gate_with(make_config(), _ok_run(), tarball=tarball)
    async with gate._client:
        result = await _screen(
            gate,
            hashlib.sha256(tarball).hexdigest(),
            progress=stages.append,
        )
    assert result.outcome == ScreeningOutcome.PASS
    assert stages == [
        "downloading",
        "validating",
        "building",
        "starting",
        "health_check",
        "validating",
    ]


async def test_progress_callback_failure_does_not_change_screening(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()
    gate = _gate_with(make_config(), _ok_run(), tarball=tarball)

    def fail_progress(_stage: str) -> None:
        raise RuntimeError("telemetry unavailable")

    async with gate._client:
        result = await _screen(
            gate,
            hashlib.sha256(tarball).hexdigest(),
            progress=fail_progress,
        )
    assert result.outcome == ScreeningOutcome.PASS


async def test_fake_gateway_is_internal_and_resource_capped(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()
    calls: list[list[str]] = []
    config = make_config(smoke_env=(("OPENROUTER_API_KEY", "dummy"),))
    gate = _gate_with(config, _ok_run(calls), tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())

    assert result.passed
    network = next(call for call in calls if call[:2] == ["network", "create"])
    assert "--internal" in network
    gateway = next(
        call
        for call in calls
        if call[0] == "run" and "DITTO_FAKE_GATEWAY_RESPONSE=" in " ".join(call)
    )
    assert {"--read-only", "--cap-drop", "no-new-privileges"} <= set(gateway)
    harness = next(
        call
        for call in calls
        if call[0] == "run" and call[-1].startswith("ditto-screen/")
    )
    assert "CHUTES_BASE_URL=http://fake-gateway:8080/v1" in harness
    assert "--memory" in harness and "--pids-limit" in harness


async def test_sha_mismatch_is_deterministic_and_cleans_temp_file(
    make_config: Callable[..., ScreenerConfig],
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    tarball = _valid_tar()
    calls: list[list[str]] = []
    artifact_path = tmp_path / "failed-download.tar.gz"

    def mkstemp(*_: Any, **__: Any) -> tuple[int, str]:
        fd = os.open(artifact_path, os.O_CREAT | os.O_TRUNC | os.O_RDWR, 0o600)
        return fd, str(artifact_path)

    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    gate = _gate_with(make_config(), _ok_run(calls), tarball=tarball)
    async with gate._client:
        result = await _screen(gate, "00" * 32)
    assert result.outcome == ScreeningOutcome.DETERMINISTIC_REJECT
    assert "sha256 mismatch" in result.detail
    assert not any(call[0] == "build" for call in calls)
    assert not artifact_path.exists()


async def test_rust_contract_failure_is_terminal_reject(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _make_tar({"Dockerfile": b"FROM scratch\n", "solver.py": b"pass\n"})
    calls: list[list[str]] = []
    gate = _gate_with(make_config(), _ok_run(calls), tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())
    assert result.outcome == ScreeningOutcome.DETERMINISTIC_REJECT
    assert result.detail.startswith(
        "error[SCR-RUST-006]: Cargo.toml is missing from the archive root"
    )
    assert "help:" in result.detail
    assert not any(call[0] == "build" for call in calls)


async def test_build_and_health_failures_are_deterministic(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()

    async def build_failure(
        args: list[str], *, stdin: Any = None, **_: Any
    ) -> tuple[int, str]:
        if args[0] == "build":
            if stdin is not None:
                stdin.read()
            return 1, "error[E0432]: unresolved import"
        return 0, ""

    gate = _gate_with(make_config(), build_failure, tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())
    assert result.outcome == ScreeningOutcome.DETERMINISTIC_REJECT
    assert "unresolved import" in result.detail

    async def unhealthy(
        args: list[str], *, stdin: Any = None, **_: Any
    ) -> tuple[int, str]:
        if args[0] == "build" and stdin is not None:
            stdin.read()
        if args[0] == "exec" and any("http://harness:" in arg for arg in args):
            return 1, "HTTP 503"
        return 0, ""

    gate = _gate_with(make_config(run_timeout_seconds=0.05), unhealthy, tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())
    assert result.outcome == ScreeningOutcome.DETERMINISTIC_REJECT
    assert "never healthy" in result.detail


async def test_gateway_start_failure_is_retryable_infrastructure(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()

    async def no_daemon(
        args: list[str], *, stdin: Any = None, **_: Any
    ) -> tuple[int, str]:
        if args[0] == "build" and stdin is not None:
            stdin.read()
        if args[:2] == ["network", "create"]:
            return 1, "Cannot connect to the Docker daemon"
        return 0, ""

    gate = _gate_with(make_config(), no_daemon, tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())
    assert result.outcome == ScreeningOutcome.RETRYABLE_INFRA
    assert result.detail.startswith("screener error:")


async def test_docker_daemon_build_failure_is_retryable_infrastructure(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()

    async def no_daemon(
        args: list[str], *, stdin: Any = None, **_: Any
    ) -> tuple[int, str]:
        if args[0] == "build":
            if stdin is not None:
                stdin.read()
            return 1, "Cannot connect to the Docker daemon"
        return 0, ""

    gate = _gate_with(make_config(), no_daemon, tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())
    assert result.outcome == ScreeningOutcome.RETRYABLE_INFRA
    assert result.detail.startswith("screener error:")


@pytest.mark.parametrize(
    "failure",
    [
        "no space left on device",
        "failed to solve: failed to mount buildkit snapshot",
        "TLS handshake timeout fetching registry layer",
        "secret gh_token: not found",
        "process was killed: out of memory",
    ],
)
async def test_transient_build_failures_are_retryable_infrastructure(
    make_config: Callable[..., ScreenerConfig], failure: str
) -> None:
    tarball = _valid_tar()

    async def transient_failure(
        args: list[str], *, stdin: Any = None, **_: Any
    ) -> tuple[int, str]:
        if args[0] == "build":
            if stdin is not None:
                stdin.read()
            return 1, failure
        return 0, ""

    gate = _gate_with(make_config(), transient_failure, tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())
    assert result.outcome == ScreeningOutcome.RETRYABLE_INFRA
    assert result.detail.startswith("screener error:")


async def test_signal_interrupted_build_is_retryable_infrastructure(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    tarball = _valid_tar()

    async def interrupted(
        args: list[str], *, stdin: Any = None, **_: Any
    ) -> tuple[int, str]:
        if args[0] == "build":
            if stdin is not None:
                stdin.read()
            return -15, ""
        return 0, ""

    gate = _gate_with(make_config(), interrupted, tarball=tarball)
    async with gate._client:
        result = await _screen(gate, hashlib.sha256(tarball).hexdigest())
    assert result.outcome == ScreeningOutcome.RETRYABLE_INFRA
    assert "SIGTERM" in result.detail


async def test_failure_diagnostics_are_bounded(
    make_config: Callable[..., ScreenerConfig],
) -> None:
    gate = _gate_with(make_config(), _ok_run(), tarball=_valid_tar())

    async def logs(args: list[str], **_: Any) -> tuple[int, str]:
        if args == ["logs", "harness"]:
            return 0, "harness error body"
        if args == ["logs", "gateway"]:
            return 0, "gateway request log"
        return 0, ""

    gate._run = logs  # type: ignore[method-assign]
    detail = await gate._with_container_logs(
        "health failed",
        harness_container="harness",
        gateway_container="gateway",
    )
    await gate._client.aclose()
    assert "harness error body" in detail
    assert "gateway request log" in detail


async def test_private_challenge_observes_isolated_gateway_dataflow(
    make_config: Callable[..., ScreenerConfig], tmp_path: Path
) -> None:
    gate = _gate_with(make_config(), _ok_run(), tarball=_valid_tar())
    state = tmp_path / "gateway-calls"
    token = "ephemeral-audit-output"

    async def request(*_: Any, **__: Any) -> tuple[int, str]:
        state.write_text("1\n")
        return 0, '{"final_text":"prefix ephemeral-audit-output suffix"}'

    gate._request_from_sidecar = request  # type: ignore[method-assign]
    observation = await gate._run_private_challenge(
        "rotating-control",
        {"case_id": "private-control"},
        5,
        harness_base="http://harness:8080",
        probe_container="probe",
        gateway_response_token=token,
        gateway_state_file=str(state),
    )
    await gate._client.aclose()

    assert observation.ok
    assert observation.gateway_calls == 1
    assert observation.gateway_token_observed
    assert observation.json_keys == ("final_text",)
