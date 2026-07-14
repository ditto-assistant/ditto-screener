"""Stable v6 screening core plus an optional private policy boundary.

The gate is deliberately cheaper than a full DittoBench run. It verifies the
image and service contract before a submission can consume a scoring run.

Flow for one agent:

1. **Download + verify.** Stream the presigned tarball to a temp file, bounded by
   ``max_tarball_bytes``, and re-check its SHA-256 against the queue value (the
   URL is presigned but the bytes are still attacker-controlled).
2. **Contract check.** Reject unsafe archive entries and require a root Rust
   crate before any build is attempted. The crate may use, fork, or replace
   ``ditto-harness``.
3. **Build.** ``docker build`` reads the *tarball itself* as the build context on
   stdin: Docker unpacks it inside its own build sandbox, so the screener never
   re-implements safe tar extraction. BuildKit is used with an optional
   ``gh_token`` secret for a private build dependency, when configured. Bounded by
   ``build_timeout_seconds``.
4. **Serve smoke.** Run the image detached with a memory + pids cap and poll
   ``GET /health`` until it returns 2xx.
5. **Private policy.** The default v6 manifest stops after health. A rotating
   private manifest may use timing, random-control, fingerprint, and behavioral
   audit modules. Those signals can only pass or route to review; they cannot
   produce a deterministic rejection.
6. **Teardown.** The container + image are always removed.

A pass is "built and served" under the default production-v6 manifest.
Deterministic contract violations fail; infrastructure failures are retryable.
Failures include a short ``detail``
(response body, container-log tail, or failing stage) for the miner and operator.
Every stage is best-effort and never raises into the worker loop: an
infrastructure error (Docker down) is reported as a non-pass with detail, so a
flaky host does not silently promote or wrongly reject.

Trust posture: the build runs on the host Docker daemon, same as dittobench's;
wall-time is bounded by the timeout. Deeper isolation (rootless/gVisor) and an
egress allowlist are out of scope for this gate.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import io
import json
import logging
import os
import secrets
import shutil
import tarfile
import tempfile
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING
from uuid import UUID

import httpx

from ditto_screener.fake_gateway import LOCKED_HARNESS_MODEL
from ditto_screener.heartbeat import (
    ScreenerProgressStage,
    source_review_progress_stage,
)
from ditto_screener.policy import (
    ChallengeObservation,
    PolicyContext,
    PolicyEngine,
    ReviewJournal,
    ScreeningDecision,
    ScreeningOutcome,
    core_decision,
)
from ditto_screener.source_review import OpenRouterSourceReviewAgent

if TYPE_CHECKING:
    from ditto_screener.config import ScreenerConfig

logger = logging.getLogger(__name__)

# Bytes of a failing build log to attach to the verdict detail.
_LOG_TAIL_BYTES = 2000
_MAX_GATE_DETAIL_CHARS = 3900
# How long to wait between /health probes while the container boots.
_PROBE_INTERVAL_SECONDS = 1.0
_MAX_UNPACKED_BYTES = 64 * 1024 * 1024
_MAX_CANARY_RESPONSE_BYTES = 64 * 1024
_CANARY_IMAGE = (
    "python:3.12-alpine@sha256:"
    "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
)
_GATEWAY_ALIAS = "fake-gateway"
_HARNESS_ALIAS = "harness"
_DOCKER_INFRASTRUCTURE_MARKERS = (
    "cannot connect to the docker daemon",
    "error during connect",
    "docker daemon is not running",
    "connection refused",
)


@dataclass(frozen=True)
class _StageResult:
    """Internal stable-core stage result."""

    passed: bool
    detail: str
    retryable: bool = False

    def __post_init__(self) -> None:
        if self.passed and self.retryable:
            raise ValueError("a passing stage result cannot be retryable")


@dataclass(frozen=True)
class _AuditRuntime:
    """Ephemeral values used only while a selected private audit runs."""

    harness_base: str
    gateway_response_token: str
    gateway_state_file: str


def dockerfile_at_root(member_names: list[str]) -> bool:
    """Whether the tar has a ``Dockerfile`` at its root.

    Accepts the bare ``Dockerfile`` and a leading ``./`` (tar writers differ).
    The submission contract fixes the Dockerfile at the tarball root, so a
    Dockerfile only in a subdirectory does not satisfy the gate.
    """
    return any(name in ("Dockerfile", "./Dockerfile") for name in member_names)


def _rust_diagnostic(code: str, message: str, help_text: str) -> str:
    """Return a rustc-style contract diagnostic without source excerpts."""
    return f"error[{code}]: {message}\n\nhelp: {help_text}"


def _gateway_call_count(path: str) -> int:
    """Count bounded call markers written by one isolated fake gateway."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return 0
    if len(data) > 64 * 1024:
        raise ValueError("fake gateway call state exceeded safety cap")
    return data.count(b"1\n")


def _contains_string(value: object, needle: str) -> bool:
    """Whether a JSON value contains the exact ephemeral gateway token."""
    if isinstance(value, str):
        return needle in value
    if isinstance(value, list):
        return any(_contains_string(item, needle) for item in value)
    if isinstance(value, dict):
        return any(_contains_string(item, needle) for item in value.values())
    return False


def _log_tail(text: str) -> str:
    """Last chunk of a build log, trimmed for the verdict detail field."""
    trimmed = text.strip()
    if len(trimmed) <= _LOG_TAIL_BYTES:
        return trimmed
    return "…" + trimmed[-_LOG_TAIL_BYTES:]


def _detail_tail(text: str) -> str:
    """Keep a result detail below the shared protocol's 4,000-char cap."""
    trimmed = text.strip()
    if len(trimmed) <= _MAX_GATE_DETAIL_CHARS:
        return trimmed
    return "…" + trimmed[-(_MAX_GATE_DETAIL_CHARS - 1) :]


def _docker_infrastructure_failure(text: str) -> bool:
    normalized = text.casefold()
    return any(marker in normalized for marker in _DOCKER_INFRASTRUCTURE_MARKERS)


class BuildGate:
    """Runs the build, serve, and model-call checks for one agent at a time.

    Docker CLI calls are funnelled through :meth:`_run` so tests can stub the
    subprocess layer; HTTP (download + health probe) uses the injected client.
    """

    def __init__(
        self,
        config: ScreenerConfig,
        client: httpx.AsyncClient,
        *,
        policy: PolicyEngine,
        journal: ReviewJournal,
    ) -> None:
        self._config = config
        self._client = client
        self._policy = policy
        self._journal = journal
        self._source_reviewer = OpenRouterSourceReviewAgent(
            api_key_file=config.source_review_api_key_file,
            model=config.source_review_model,
            base_url=config.source_review_base_url,
            timeout_seconds=config.source_review_timeout_seconds,
            max_steps=config.source_review_max_steps,
        )

    async def screen(
        self,
        *,
        agent_id: UUID,
        attempt_id: UUID,
        miner_hotkey: str,
        sha256: str,
        download_url: str,
        progress: Callable[[ScreenerProgressStage], None] | None = None,
    ) -> ScreeningDecision:
        """Screen one agent end-to-end; never raises."""

        def report(stage: ScreenerProgressStage) -> None:
            try:
                if progress is not None:
                    progress(stage)
            except Exception:  # noqa: BLE001 - telemetry cannot affect screening
                logger.warning("screener progress callback failed; screening continues")

        tag = f"ditto-screen/{agent_id}:latest"
        container = f"ditto-screen-{agent_id}"
        gateway_container = f"ditto-gateway-{agent_id}"
        network = f"ditto-screen-{agent_id}"
        gateway_state_dir = tempfile.mkdtemp(prefix="ditto-gateway-state-")
        os.chmod(gateway_state_dir, 0o755)
        tmp_path: str | None = None
        try:
            report("downloading")
            tmp_path, dl_detail = await self._download_verified(download_url, sha256)
            if tmp_path is None:
                outcome = (
                    ScreeningOutcome.RETRYABLE_INFRA
                    if dl_detail.startswith("artifact download")
                    else ScreeningOutcome.DETERMINISTIC_REJECT
                )
                detail = (
                    f"screener error: {dl_detail}"
                    if outcome == ScreeningOutcome.RETRYABLE_INFRA
                    else dl_detail
                )
                return core_decision(
                    outcome,
                    code="artifact-download"
                    if outcome == ScreeningOutcome.RETRYABLE_INFRA
                    else "artifact-invalid",
                    summary="artifact download infrastructure failed"
                    if outcome == ScreeningOutcome.RETRYABLE_INFRA
                    else "artifact violated the bounded download contract",
                    detail=detail,
                )
            report("validating")
            contract_error = self._contract_error(tmp_path)
            if contract_error is not None:
                return core_decision(
                    ScreeningOutcome.DETERMINISTIC_REJECT,
                    code="rust-harness-contract",
                    summary="artifact does not satisfy the Rust harness contract",
                    detail=contract_error,
                )
            source_digest, source_paths = self._source_metadata(tmp_path)

            report("building")
            started = asyncio.get_running_loop().time()
            built, build_detail = await self._build(tmp_path, tag)
            build_elapsed_ms = round(
                (asyncio.get_running_loop().time() - started) * 1000
            )
            if not built:
                retryable = _docker_infrastructure_failure(build_detail)
                return core_decision(
                    ScreeningOutcome.RETRYABLE_INFRA
                    if retryable
                    else ScreeningOutcome.DETERMINISTIC_REJECT,
                    code=(
                        "docker-build-infrastructure" if retryable else "docker-build"
                    ),
                    summary=(
                        "Docker build infrastructure failed"
                        if retryable
                        else "artifact Docker image did not build"
                    ),
                    detail=(
                        f"screener error: Docker build infrastructure: {build_detail}"
                        if retryable
                        else f"build failed: {build_detail}"
                    ),
                )

            report("starting")
            started = asyncio.get_running_loop().time()
            serve_result, audit_runtime = await self._run_and_probe(
                tag,
                container,
                gateway_container=gateway_container,
                network=network,
                gateway_state_dir=gateway_state_dir,
                progress=report,
            )
            health_elapsed_ms = round(
                (asyncio.get_running_loop().time() - started) * 1000
            )
            if not serve_result.passed:
                outcome = (
                    ScreeningOutcome.RETRYABLE_INFRA
                    if serve_result.retryable
                    else ScreeningOutcome.DETERMINISTIC_REJECT
                )
                prefix = (
                    "screener error" if serve_result.retryable else "serve check failed"
                )
                return core_decision(
                    outcome,
                    code="serve-infrastructure"
                    if serve_result.retryable
                    else "health-contract",
                    summary="screening runtime infrastructure failed"
                    if serve_result.retryable
                    else "container did not satisfy the health contract",
                    detail=f"{prefix}: {serve_result.detail}",
                )
            if audit_runtime is None:
                raise RuntimeError("healthy harness has no isolated audit runtime")

            async def run_challenge(
                challenge_id: str, request: Mapping[str, object], timeout: float
            ) -> ChallengeObservation:
                return await self._run_private_challenge(
                    challenge_id,
                    request,
                    timeout,
                    harness_base=audit_runtime.harness_base,
                    probe_container=gateway_container,
                    gateway_response_token=audit_runtime.gateway_response_token,
                    gateway_state_file=audit_runtime.gateway_state_file,
                )

            async def review_source():  # type: ignore[no-untyped-def]
                return await self._source_reviewer.review(
                    tmp_path,
                    artifact_sha256=sha256.lower(),
                    progress=lambda completed, total: report(
                        source_review_progress_stage(completed, total)
                    ),
                )

            context = PolicyContext(
                agent_id=agent_id,
                attempt_id=attempt_id,
                miner_hotkey=miner_hotkey,
                artifact_sha256=sha256.lower(),
                source_digest=source_digest,
                source_paths=source_paths,
                build_elapsed_ms=build_elapsed_ms,
                health_elapsed_ms=health_elapsed_ms,
                run_challenge=run_challenge,
                review_source=review_source,
            )
            report("validating")
            decision = await self._policy.evaluate(context)
            self._journal.record(context=context, decision=decision)
            return decision
        except Exception as e:  # noqa: BLE001 - the loop must never die on one agent
            logger.exception("gate error for agent_id=%s", agent_id)
            return core_decision(
                ScreeningOutcome.RETRYABLE_INFRA,
                code="unexpected-infrastructure",
                summary="unexpected screening infrastructure failure",
                detail=f"screener error: {type(e).__name__}: {e}",
            )
        finally:
            await self._teardown(
                container,
                tag,
                gateway_container=gateway_container,
                network=network,
            )
            shutil.rmtree(gateway_state_dir, ignore_errors=True)
            if tmp_path is not None:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)

    # --- stages -----------------------------------------------------------

    async def _download_verified(
        self, url: str, expected_sha256: str
    ) -> tuple[str | None, str]:
        """Stream the tarball to a temp file, size-bounded + sha256-checked.

        Returns ``(path, "")`` on success or ``(None, reason)`` on a cap breach,
        digest mismatch, or transport error.
        """
        cap = self._config.max_tarball_bytes
        hasher = hashlib.sha256()
        total = 0
        fd, path = tempfile.mkstemp(prefix="ditto-screen-", suffix=".tar.gz")
        keep_path = False
        try:
            with os.fdopen(fd, "wb") as fh:
                async with self._client.stream("GET", url) as resp:
                    if resp.status_code != 200:
                        return None, f"artifact download HTTP {resp.status_code}"
                    async for chunk in resp.aiter_bytes():
                        total += len(chunk)
                        if total > cap:
                            return None, f"tarball exceeds {cap} byte cap"
                        hasher.update(chunk)
                        fh.write(chunk)
            digest = hasher.hexdigest()
            if digest != expected_sha256.lower():
                return None, f"sha256 mismatch (got {digest[:12]}…)"
            keep_path = True
            return path, ""
        except httpx.HTTPError as e:
            return None, f"artifact download failed: {e}"
        finally:
            if not keep_path:
                with contextlib.suppress(OSError):
                    os.unlink(path)

    def _contract_error(self, tar_path: str) -> str | None:
        """Validate the archive and Rust harness contract without extracting it."""
        try:
            with tarfile.open(tar_path, mode="r:gz") as tar:
                members: dict[str, tarfile.TarInfo] = {}
                unpacked = 0
                for member in tar.getmembers():
                    name = member.name.removeprefix("./")
                    if not name and member.isdir():
                        continue
                    path = PurePosixPath(name)
                    if (
                        not name
                        or name.startswith("/")
                        or "\\" in name
                        or (path.parts and path.parts[0].endswith(":"))
                        or ".." in path.parts
                    ):
                        return _rust_diagnostic(
                            "SCR-RUST-001",
                            "archive contains an unsafe path",
                            "remove absolute paths, parent traversals, backslashes, "
                            "and drive-prefixed entries",
                        )
                    if name in members:
                        return _rust_diagnostic(
                            "SCR-RUST-002",
                            "archive contains a duplicate path",
                            "package each path exactly once",
                        )
                    if not (member.isfile() or member.isdir()):
                        return _rust_diagnostic(
                            "SCR-RUST-003",
                            "archive contains a link or special file",
                            "package only regular files and directories",
                        )
                    unpacked += member.size
                    if unpacked > _MAX_UNPACKED_BYTES:
                        return _rust_diagnostic(
                            "SCR-RUST-004",
                            "archive expands beyond the safety limit",
                            "remove generated assets and build output before packaging",
                        )
                    members[name] = member

                if "Dockerfile" not in members or not members["Dockerfile"].isfile():
                    return _rust_diagnostic(
                        "SCR-RUST-005",
                        "Dockerfile is missing from the archive root",
                        "package the crate contents so Dockerfile is at the top level",
                    )
                manifest_member = members.get("Cargo.toml")
                if manifest_member is None or not manifest_member.isfile():
                    return _rust_diagnostic(
                        "SCR-RUST-006",
                        "Cargo.toml is missing from the archive root",
                        "package the crate contents, not the directory containing "
                        "the crate",
                    )
                if not any(
                    name.startswith("src/") and name.endswith(".rs") and member.isfile()
                    for name, member in members.items()
                ):
                    return _rust_diagnostic(
                        "SCR-RUST-007",
                        "no Rust source file was found under src/",
                        "include at least one .rs source file below src/",
                    )

                manifest_file = tar.extractfile(manifest_member)
                if manifest_file is None:
                    return _rust_diagnostic(
                        "SCR-RUST-008",
                        "Cargo.toml could not be read",
                        "recreate the archive from a readable UTF-8 crate manifest",
                    )
                try:
                    manifest = tomllib.loads(manifest_file.read().decode("utf-8"))
                except (UnicodeDecodeError, tomllib.TOMLDecodeError):
                    return _rust_diagnostic(
                        "SCR-RUST-009",
                        "Cargo.toml is not valid UTF-8 TOML",
                        "run cargo metadata locally and fix the first manifest error",
                    )
                if not isinstance(manifest.get("package"), dict):
                    return _rust_diagnostic(
                        "SCR-RUST-010",
                        "Cargo.toml has no [package] table",
                        "submit a runnable Rust package rather than a virtual "
                        "workspace",
                    )
                return None
        except (tarfile.TarError, OSError) as e:
            logger.warning("could not read tar %s: %s", tar_path, e)
            return _rust_diagnostic(
                "SCR-RUST-011",
                "archive is not a readable gzip-compressed tar",
                "recreate it as a .tar.gz archive and retry",
            )

    def _source_metadata(self, tar_path: str) -> tuple[str, tuple[str, ...]]:
        """Return a canonical content digest and bounded normalized path list."""
        digest = hashlib.sha256()
        paths: list[str] = []
        with tarfile.open(tar_path, mode="r:gz") as tar:
            members = sorted(
                (member for member in tar.getmembers() if member.isfile()),
                key=lambda member: member.name.removeprefix("./"),
            )
            for member in members:
                name = member.name.removeprefix("./")
                digest.update(name.encode("utf-8"))
                digest.update(b"\0")
                digest.update(str(member.size).encode("ascii"))
                digest.update(b"\0")
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise ValueError(f"archive member {name!r} is unreadable")
                while chunk := extracted.read(64 * 1024):
                    digest.update(chunk)
                digest.update(b"\0")
                if len(paths) < 256:
                    paths.append(name)
        return digest.hexdigest(), tuple(paths)

    async def _build(self, tar_path: str, tag: str) -> tuple[bool, str]:
        """``docker build`` from the tarball-on-stdin; returns (ok, log_tail)."""
        args = ["build", "-t", tag, "-f", "Dockerfile"]
        env = dict(os.environ)
        env["DOCKER_BUILDKIT"] = "1"
        gh_file = self._config.gh_token_file
        if gh_file and os.path.exists(gh_file):
            args += ["--secret", f"id=gh_token,src={gh_file}"]
        args.append("-")  # build context comes from stdin
        with open(tar_path, "rb") as stdin_f:
            code, out = await self._run(
                args, stdin=stdin_f, timeout=self._config.build_timeout_seconds, env=env
            )
        if code == 0:
            return True, ""
        return False, _log_tail(out)

    async def _run_and_probe(
        self,
        tag: str,
        container: str,
        *,
        gateway_container: str,
        network: str,
        gateway_state_dir: str,
        progress: Callable[[ScreenerProgressStage], None] | None = None,
    ) -> tuple[_StageResult, _AuditRuntime | None]:
        """Run the image and await health against the isolated fake gateway."""
        port = self._config.container_port
        response_text = f"ditto-fake-gateway-{secrets.token_hex(16)}"
        started, detail = await self._start_fake_gateway(
            gateway_container=gateway_container,
            network=network,
            response_text=response_text,
            state_dir=gateway_state_dir,
        )
        if not started:
            return _StageResult(False, detail, retryable=True), None

        gateway = f"http://{_GATEWAY_ALIAS}:8080"
        run_args = [
            "run",
            "-d",
            "--rm",
            "--name",
            container,
            "--network",
            network,
            "--network-alias",
            _HARNESS_ALIAS,
            "--memory",
            self._config.build_memory,
            "--pids-limit",
            str(self._config.pids_limit),
        ]
        for key, value in self._config.smoke_env:
            run_args += ["-e", f"{key}={value}"]
        # Mirror the production scorer's locked provider contract. These are
        # appended last so an operator's legacy smoke env cannot bypass the
        # fake gateway.
        gateway_env = {
            "DITTOBENCH_PROVIDER": "chutes",
            "DITTOBENCH_MODEL": LOCKED_HARNESS_MODEL,
            "CHUTES_BASE_URL": f"{gateway}/v1",
            "CHUTES_API_KEY": "relay",
            "OPENAI_BASE_URL": f"{gateway}/v1",
            "OPENAI_API_KEY": "relay",
            "OLLAMA_BASE_URL": gateway,
        }
        for key, value in gateway_env.items():
            run_args += ["-e", f"{key}={value}"]
        run_args.append(tag)
        code, out = await self._run(run_args, timeout=self._config.run_timeout_seconds)
        if code != 0:
            return (
                _StageResult(
                    False,
                    f"container did not start: {_log_tail(out)}",
                    retryable=_docker_infrastructure_failure(out),
                ),
                None,
            )

        harness_base = f"http://{_HARNESS_ALIAS}:{port}"
        if progress is not None:
            progress("health_check")
        healthy, detail = await self._wait_healthy(
            harness_base, probe_container=gateway_container
        )
        if not healthy:
            return (
                _StageResult(
                    False,
                    await self._with_container_logs(
                        detail,
                        harness_container=container,
                        gateway_container=gateway_container,
                    ),
                ),
                None,
            )
        # Production v6 intentionally stops here. No synthetic POST /run is
        # issued unless a private policy selector explicitly chooses an audit.
        return (
            _StageResult(True, ""),
            _AuditRuntime(
                harness_base=harness_base,
                gateway_response_token=response_text,
                gateway_state_file=str(Path(gateway_state_dir) / "model-called"),
            ),
        )

    async def _start_fake_gateway(
        self,
        *,
        gateway_container: str,
        network: str,
        response_text: str,
        state_dir: str,
    ) -> tuple[bool, str]:
        """Start the fake gateway beside the harness on an internal network."""
        code, out = await self._run(
            ["network", "create", "--internal", network], timeout=30.0
        )
        if code != 0:
            return False, f"could not create isolated network: {_log_tail(out)}"

        script = str(Path(__file__).with_name("fake_gateway.py").resolve())
        code, out = await self._run(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                gateway_container,
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--network",
                network,
                "--network-alias",
                _GATEWAY_ALIAS,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--memory",
                "64m",
                "--pids-limit",
                "32",
                "-e",
                f"DITTO_FAKE_GATEWAY_RESPONSE={response_text}",
                "-e",
                "DITTO_FAKE_GATEWAY_STATE_FILE=/state/model-called",
                "-v",
                f"{script}:/app/fake_gateway.py:ro",
                "-v",
                f"{state_dir}:/state",
                _CANARY_IMAGE,
                "python",
                "/app/fake_gateway.py",
            ],
            timeout=self._config.run_timeout_seconds,
        )
        if code != 0:
            return False, f"fake gateway did not start: {_log_tail(out)}"

        probe = (
            "import socket; socket.create_connection(('127.0.0.1', 8080), 2).close()"
        )
        for _ in range(20):
            code, _ = await self._run(
                ["exec", gateway_container, "python", "-c", probe], timeout=5.0
            )
            if code == 0:
                return True, ""
            await asyncio.sleep(0.1)
        return False, "fake gateway did not become ready"

    async def _wait_healthy(
        self, harness_base: str, *, probe_container: str | None = None
    ) -> tuple[bool, str]:
        """Poll the submitted container's health endpoint until the deadline."""
        url = f"{harness_base}{self._config.health_path}"
        deadline = self._config.run_timeout_seconds
        waited = 0.0
        last = "no response"
        while waited < deadline:
            if probe_container is not None:
                code, out = await self._request_from_sidecar(
                    probe_container, url, timeout=5.0
                )
                if code == 0:
                    return True, ""
                last = _log_tail(out) or "unreachable"
            else:
                try:
                    resp = await self._client.get(url, timeout=5.0)
                    if 200 <= resp.status_code < 300:
                        return True, ""
                    last = f"HTTP {resp.status_code}"
                except httpx.HTTPError as e:
                    last = type(e).__name__
            await asyncio.sleep(_PROBE_INTERVAL_SECONDS)
            waited += _PROBE_INTERVAL_SECONDS
        return False, f"/health never healthy within {deadline:g}s ({last})"

    async def _run_private_challenge(
        self,
        challenge_id: str,
        request: Mapping[str, object],
        timeout: float,
        *,
        harness_base: str,
        probe_container: str,
        gateway_response_token: str,
        gateway_state_file: str,
    ) -> ChallengeObservation:
        """Run one selected private challenge and retain only bounded evidence.

        This is observational triage. A response shape or timing can route to
        review, but it is never interpreted as proof of causal model use.
        """
        calls_before = _gateway_call_count(gateway_state_file)
        started = asyncio.get_running_loop().time()
        code, out = await self._request_from_sidecar(
            probe_container,
            f"{harness_base}/run",
            payload=request,
            timeout=min(timeout, self._config.run_timeout_seconds),
        )
        elapsed_ms = round((asyncio.get_running_loop().time() - started) * 1000)
        gateway_calls = max(0, _gateway_call_count(gateway_state_file) - calls_before)
        if code != 0:
            return ChallengeObservation(
                challenge_id=challenge_id,
                ok=False,
                response_digest=None,
                elapsed_ms=elapsed_ms,
                error_code="challenge-http-failure",
                gateway_calls=gateway_calls,
            )
        body = out.encode()
        response_digest = hashlib.sha256(body).hexdigest()
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return ChallengeObservation(
                challenge_id=challenge_id,
                ok=False,
                response_digest=response_digest,
                elapsed_ms=elapsed_ms,
                error_code="challenge-invalid-json",
                gateway_calls=gateway_calls,
            )
        if not isinstance(payload, dict):
            return ChallengeObservation(
                challenge_id=challenge_id,
                ok=False,
                response_digest=response_digest,
                elapsed_ms=elapsed_ms,
                error_code="challenge-invalid-shape",
                gateway_calls=gateway_calls,
            )
        return ChallengeObservation(
            challenge_id=challenge_id,
            ok=True,
            response_digest=response_digest,
            elapsed_ms=elapsed_ms,
            json_keys=tuple(sorted(str(key) for key in payload)[:64]),
            gateway_calls=gateway_calls,
            gateway_token_observed=_contains_string(payload, gateway_response_token),
        )

    async def _request_from_sidecar(
        self,
        container: str,
        url: str,
        *,
        payload: Mapping[str, object] | None = None,
        timeout: float,
    ) -> tuple[int, str]:
        """Make an HTTP request from inside the isolated Docker network."""
        encoded = ""
        method = "GET"
        if payload is not None:
            encoded = base64.b64encode(json.dumps(payload).encode()).decode()
            method = "POST"
        script = f"""\
import base64
import sys
import urllib.error
import urllib.request

url, method, data, timeout_raw = sys.argv[1:5]
body = base64.b64decode(data) if data else None
request = urllib.request.Request(
    url, data=body, method=method, headers={{"Content-Type": "application/json"}}
)
try:
    response = urllib.request.urlopen(request, timeout=float(timeout_raw))
except urllib.error.HTTPError as error:
    response = error
output = response.read({_MAX_CANARY_RESPONSE_BYTES + 1})
if len(output) > {_MAX_CANARY_RESPONSE_BYTES}:
    sys.stdout.write("response exceeded safety cap")
    raise SystemExit(23)
if not 200 <= response.status < 300:
    sys.stdout.buffer.write(f"HTTP {{response.status}}: ".encode() + output)
    raise SystemExit(22)
sys.stdout.buffer.write(output)
"""
        return await self._run(
            [
                "exec",
                container,
                "python",
                "-c",
                script,
                url,
                method,
                encoded,
                str(timeout),
            ],
            timeout=timeout,
        )

    async def _with_container_logs(
        self,
        detail: str,
        *,
        harness_container: str,
        gateway_container: str,
    ) -> str:
        """Attach bounded Docker logs before teardown removes the containers."""
        sections: list[str] = []
        for label, container in (
            ("harness", harness_container),
            ("fake-gateway", gateway_container),
        ):
            _code, output = await self._run(["logs", container], timeout=15.0)
            if output.strip():
                sections.append(f"{label} logs:\n{_log_tail(output)}")
        if not sections:
            return detail
        diagnostics = _log_tail("\n".join(sections))
        logger.warning("screener container diagnostics: %s", diagnostics)
        return _detail_tail(f"{detail}\n{diagnostics}")

    async def _teardown(
        self,
        container: str,
        tag: str,
        *,
        gateway_container: str,
        network: str,
    ) -> None:
        """Best-effort removal of the container + image; never raises."""
        try:
            await self._run(["rm", "-f", container], timeout=30.0)
            await self._run(["rm", "-f", gateway_container], timeout=30.0)
            await self._run(["network", "rm", network], timeout=30.0)
            await self._run(["rmi", "-f", tag], timeout=30.0)
        except Exception:  # noqa: BLE001 - teardown must never mask a result
            logger.warning("teardown issue for %s / %s", container, tag, exc_info=True)

    # --- subprocess -------------------------------------------------------

    async def _run(
        self,
        args: list[str],
        *,
        stdin: io.BufferedReader | None = None,
        timeout: float,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str]:
        """Run ``docker <args>`` with a hard timeout; return (returncode, output).

        stdout+stderr are merged. On timeout the process is killed and a
        non-zero code with a ``[timeout]`` marker is returned.
        """
        proc = await asyncio.create_subprocess_exec(
            self._config.docker_bin,
            *args,
            stdin=stdin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            with contextlib.suppress(Exception):
                await proc.wait()
            return 124, f"[timeout after {timeout:g}s]"
        return proc.returncode or 0, out.decode("utf-8", errors="replace")
