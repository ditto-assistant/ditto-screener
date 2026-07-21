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
5. **Private policy.** The default v8 manifest performs bounded Luna source
   review after health. A rotating
   private manifest may use timing, random-control, fingerprint, and behavioral
   audit modules. Those signals can only pass or route to review; they cannot
   produce a deterministic rejection.
6. **Teardown.** The container + image are always removed.

A pass is "built, served, and cleared by bounded source review" under the
default production-v8 manifest.
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
import re
import secrets
import shutil
import signal
import tarfile
import tempfile
import tomllib
from collections.abc import Awaitable, Callable, Mapping, Sequence
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
from ditto_screener.l2_review import (
    IsolatedCodingHarness,
    KimiSolSourceReviewAgent,
    L2AuditJournal,
    LayeredSourceReviewAgent,
)
from ditto_screener.policy import (
    ChallengeObservation,
    PolicyContext,
    PolicyEngine,
    PolicyEvidence,
    ReviewJournal,
    ScreeningDecision,
    ScreeningOutcome,
    core_decision,
)
from ditto_screener.source_review import (
    OpenRouterSourceReviewAgent,
    SourceReviewObservation,
    TarSourceRepository,
)

if TYPE_CHECKING:
    from ditto_screener.config import ScreenerConfig

logger = logging.getLogger(__name__)

# Bytes of a failing build log to attach to the verdict detail.
_LOG_TAIL_BYTES = 2000
_MAX_GATE_DETAIL_CHARS = 3900
# How long to wait between /health probes while the container boots.
_PROBE_INTERVAL_SECONDS = 1.0
# Refuse to begin a screening stage that cannot plausibly finish and still leave
# the worker time to sign and post a verdict before the lease deadline. A stage
# entered with less than this many seconds of lease budget is abandoned as
# retryable-infra so the platform re-queues promptly instead of the loop burning
# the whole lease on work whose verdict would arrive after expiry.
_LEASE_MIN_STAGE_SECONDS = 5.0
_MAX_UNPACKED_BYTES = 64 * 1024 * 1024
_MAX_SCREENED_IMAGE_BYTES = 8 * 1024**3
_IMAGE_EXPORT_DISK_RESERVE_BYTES = 256 * 1024**2
_IMAGE_HASH_CHUNK_BYTES = 8 * 1024**2
_MAX_CANARY_RESPONSE_BYTES = 64 * 1024
_CANARY_IMAGE = (
    "python:3.12-alpine@sha256:"
    "6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
)
_GATEWAY_ALIAS = "fake-gateway"
_HARNESS_ALIAS = "harness"
_VALIDATOR_SANDBOX_USER = "65532:65532"
_VALIDATOR_SANDBOX_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=512m"
_VALIDATOR_SANDBOX_MEMORY = "3g"
_VALIDATOR_SANDBOX_CPUS = "2"
_VALIDATOR_SANDBOX_PIDS = "512"
_VALIDATOR_SANDBOX_DB = "/tmp/dittobench.db"
_DOCKER_INFRASTRUCTURE_MARKERS = (
    "cannot connect to the docker daemon",
    "error during connect",
    "docker daemon is not running",
    "connection refused",
    "no space left on device",
    "out of memory",
    "cannot allocate memory",
    "killed",
    "docker command exited with signal",
    "signal sigterm",
    "signal sigkill",
    # A build the daemon or worker was restarted out from under (deploy /
    # `systemctl restart docker`) aborts with BuildKit's cancellation marker.
    # That is our own interruption, never the miner's crate failing to compile,
    # so it must requeue as retryable-infra rather than terminally reject.
    "context canceled",
    "context cancelled",
    "buildkit",
    "snapshotter",
    "failed to mount",
    "secret gh_token",
    "secret id=gh_token",
    "temporary failure in name resolution",
    "could not resolve host",
    "tls handshake timeout",
    "i/o timeout",
    "connection reset by peer",
    "unexpected eof",
    "too many requests",
    "service unavailable",
    "bad gateway",
    "gateway timeout",
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
class BuiltImageArtifact:
    """A locally exported, content-addressed Docker image archive."""

    path: str
    sha256: str
    size_bytes: int
    image_id: str
    image_ref: str


class _ScreenedImageTooLargeError(ValueError):
    """The miner-controlled image deterministically exceeds the archive cap."""


class _ScreenedImageExportError(RuntimeError):
    """The host could not export an otherwise passing screened image."""


class _LeaseDeadlineError(TimeoutError):
    """An image export/publication operation exhausted the screening lease."""


@dataclass(frozen=True)
class _AuditRuntime:
    """Ephemeral values used only while a selected private audit runs."""

    harness_base: str
    gateway_response_token: str
    oracle_answer: str
    gateway_state_file: str


# The fake gateway serves a benign `/tool` sink at the same host-container alias
# the harness already uses for the model, so a tool-shaped challenge's
# `tool_endpoint` is reachable from inside the harness network and carries no
# screener-specific tell (it is the same host:port the model calls go to).
_TOOL_ENDPOINT = f"http://{_GATEWAY_ALIAS}:8080/tool"


def _with_tool_endpoint(request: Mapping[str, object]) -> dict[str, object]:
    """Fill a reachable ``tool_endpoint`` for a tool-declaring challenge request.

    Returns a copy so the caller's mapping is not mutated. A request that
    already carries a ``tool_endpoint``, or declares no ``tools``, is returned
    unchanged (aside from the copy).

    This applies to any tool-declaring private challenge, not only the oracle.
    An explicit ``tool_endpoint`` is always preserved, so a challenge pack that
    deliberately wants a different endpoint — including an unreachable one, to
    observe whether the harness fabricates tool results with no live endpoint —
    sets its own and is never overridden by the gateway sink.
    """
    payload = dict(request)
    if payload.get("tools") and not payload.get("tool_endpoint"):
        payload["tool_endpoint"] = _TOOL_ENDPOINT
    return payload


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


# Rust/native build indicators. If none appear, the image cannot be compiling
# the committed crate, so whatever it runs is not the reviewed source.
_BUILD_STEP_RE = re.compile(r"\b(cargo|rustc|make|cmake)\b", re.IGNORECASE)


def _dockerfile_instructions(text: str) -> list[tuple[str, str]]:
    """Parse a Dockerfile into (INSTRUCTION, remainder) pairs.

    Line continuations are joined and standalone comment lines are dropped.
    This is a bounded static parse, not a full Dockerfile grammar.
    """
    logical: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        buffer = f"{buffer} {stripped}".strip() if buffer else stripped
        if buffer.endswith("\\"):
            buffer = buffer[:-1].rstrip()
            continue
        logical.append(buffer)
        buffer = ""
    if buffer:
        logical.append(buffer)
    instructions: list[tuple[str, str]] = []
    for line in logical:
        parts = line.split(None, 1)
        if parts:
            instructions.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return instructions


def image_binding_advisory(dockerfile_text: str) -> str | None:
    """Flag a Dockerfile that LOOKS like it ships a prebuilt binary.

    This is a bounded static text heuristic, so it is ADVISORY ONLY and routes
    to operator-reviewed quarantine, never to a deterministic rejection: a
    legitimate wrapper (``RUN ./build.sh`` that calls cargo) would otherwise
    be falsely rejected, while ``RUN echo cargo`` would falsely pass — text
    matching can neither prove nor disprove provenance. Fully binding
    provenance needs the build to emit, and the gate to verify, a hash of the
    entrypoint's origin against the reviewed crate.
    """
    has_build_step = False
    has_context_copy = False
    has_entrypoint = False
    for keyword, rest in _dockerfile_instructions(dockerfile_text):
        if keyword == "RUN" and _BUILD_STEP_RE.search(rest):
            has_build_step = True
        elif keyword in {"COPY", "ADD"} and "--from=" not in rest.casefold():
            has_context_copy = True
        elif keyword in {"ENTRYPOINT", "CMD"}:
            has_entrypoint = True
    if has_entrypoint and has_context_copy and not has_build_step:
        return (
            "Dockerfile copies build-context files and sets an entrypoint "
            "without a recognizable crate build step; the running image may "
            "not be the reviewed source"
        )
    return None


def _with_image_binding_advisory(
    decision: ScreeningDecision, advisory: str | None
) -> ScreeningDecision:
    """Escalate a passing decision to operator review on a provenance warning.

    The heuristic is text matching, so it can neither prove nor disprove that
    the image runs the reviewed crate. It therefore never rejects: a PASS
    becomes an operator-reviewed QUARANTINE and an existing QUARANTINE gains
    the evidence item; terminal rejections and retryable failures are
    untouched.
    """
    if advisory is None or decision.outcome not in {
        ScreeningOutcome.PASS,
        ScreeningOutcome.QUARANTINE,
    }:
        return decision
    evidence = (
        *decision.evidence[:15],
        PolicyEvidence("stable-core", "image-binding-heuristic", advisory[:240]),
    )
    return ScreeningDecision(
        outcome=ScreeningOutcome.QUARANTINE,
        detail="private policy quarantine pending operator review",
        manifest_digest=decision.manifest_digest,
        evidence=evidence,
        finding=decision.finding,
    )


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


def _format_stage_timings(history: Sequence[tuple[str, float]], *, end: float) -> str:
    """Fold progress transitions into ``stage=<ms>`` pairs, in order.

    Each stage's duration runs until the next transition (the last until
    ``end``). The per-percent ``source_review_NN`` stages collapse into one
    ``source_review`` bucket, and a revisited stage name accumulates.
    """
    durations: dict[str, int] = {}
    for index, (stage, entered) in enumerate(history):
        exited = history[index + 1][1] if index + 1 < len(history) else end
        name = "source_review" if stage.startswith("source_review_") else str(stage)
        durations[name] = durations.get(name, 0) + round(
            max(0.0, exited - entered) * 1000
        )
    return " ".join(f"{name}_ms={ms}" for name, ms in durations.items())


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
        l1_reviewer = OpenRouterSourceReviewAgent(
            api_key_file=config.source_review_api_key_file,
            model=config.source_review_model,
            base_url=config.source_review_base_url,
            timeout_seconds=config.source_review_timeout_seconds,
            max_steps=config.source_review_max_steps,
        )
        l2_reviewer = KimiSolSourceReviewAgent(
            api_key_file=config.source_review_api_key_file,
            base_url=config.source_review_base_url,
            harness=IsolatedCodingHarness(
                docker_bin=config.docker_bin,
                image=config.l2_analyzer_image,
            ),
            cache_dir=config.l2_cache_dir,
            audit_journal=L2AuditJournal(
                config.l2_audit_journal_file,
                retention_days=config.l2_audit_retention_days,
            ),
            timeout_seconds=config.l2_timeout_seconds,
            max_steps=config.l2_max_steps,
            max_input_tokens=config.l2_max_input_tokens,
            max_output_tokens=config.l2_max_output_tokens,
            max_completion_tokens=config.l2_max_completion_tokens,
            max_cost_usd=config.l2_max_cost_usd,
            analyst_reasoning_effort=config.l2_analyst_reasoning_effort,
            critic_reasoning_effort=config.l2_critic_reasoning_effort,
            cache_ttl_seconds=config.l2_cache_ttl_seconds,
            model=config.l2_review_model,
            fallback_models=config.l2_fallback_models,
            critic_model=config.l3_review_model,
            critic_provider=config.l3_review_provider,
        )
        self._source_reviewer = LayeredSourceReviewAgent(
            l1=l1_reviewer,
            l2=l2_reviewer,
            mode=config.l2_review_mode,
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
        deadline: float | None = None,
        publish_image: Callable[[BuiltImageArtifact], Awaitable[None]] | None = None,
        build_only: bool = False,
    ) -> ScreeningDecision:
        """Screen one agent end-to-end; never raises.

        ``deadline`` is an optional monotonic-clock (``loop.time()``) bound for
        the whole screen, derived by the worker from the platform's lease. When
        set, each heavy stage is clamped to the remaining budget and refuses to
        start once the budget is spent, so a slow build or source review can no
        longer run past the lease and have its verdict rejected as expired.

        ``build_only`` marks a submission that has already cleared anti-cheat
        review under the current policy and is missing only its built
        prerequisites. It skips the entire source / pre-execution anti-cheat
        review and runs only the mechanical build, serve, behavioral-oracle,
        and image-export work. A build-only screen can only pass, report a
        genuine build/serve/infra failure, or run out of lease budget; it can
        never quarantine.
        """

        loop = asyncio.get_running_loop()
        screen_started = loop.time()
        # (stage, entered_at) transitions; folded into one per-stage timing
        # log line when the screen ends, so operators can see where each
        # screening spent its wall clock without any external tooling.
        stage_history: list[tuple[str, float]] = []

        def report(stage: ScreenerProgressStage) -> None:
            stage_history.append((stage, loop.time()))
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
        review_task: asyncio.Task[SourceReviewObservation] | None = None
        try:
            report("downloading")
            if (exhausted := self._lease_exhausted(deadline, "download")) is not None:
                return exhausted
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

            # The agentic source review reads only the validated tarball, so
            # it can run CONCURRENTLY with the docker build + serve + oracle
            # stages instead of serially after them (prod baseline: ~430s
            # review after a ~214s build; overlapping removes the build from
            # the critical path of every passing screen). Its per-percent
            # progress is muted until the policy phase so heartbeat stages
            # keep their sequential meaning for operators.
            in_policy_phase = False

            def report_review_progress(completed: int, total: int) -> None:
                if in_policy_phase:
                    report(source_review_progress_stage(completed, total))

            # A build-only submission has ALREADY cleared anti-cheat review
            # under the current policy and is here only to have its screened
            # image built. Skip the entire source / pre-execution anti-cheat
            # review (the static malicious-preflight lead AND the agentic
            # reviewer): no lead is resolved, no reviewer is launched, and the
            # policy is given no source-review source below, so only the
            # mechanical build + serve + behavioral-oracle stages run and the
            # run can never quarantine on review.
            if not build_only:
                # Static rules run before any submission-controlled Dockerfile or
                # image, but they are routing leads rather than proof. Resolve an
                # elevated lead with the inert L2/L3 harness before deciding
                # whether untrusted build execution may start.
                preflight = TarSourceRepository(tmp_path).malicious_preflight(
                    artifact_sha256=sha256.lower()
                )
                preflight_clearance: SourceReviewObservation | None = None
                if preflight is not None:
                    logger.warning(
                        "static-source review lead agent_id=%s attempt_id=%s "
                        "categories=%s execution_started=false",
                        agent_id,
                        attempt_id,
                        ",".join(preflight.categories),
                    )
                    resolved_preflight = await self._source_reviewer.resolve_lead(
                        tmp_path,
                        artifact_sha256=sha256.lower(),
                        attempt_id=attempt_id,
                        l1_observation=preflight,
                        progress=(
                            lambda completed, total: report(
                                source_review_progress_stage(completed, total)
                            )
                        ),
                        deadline=deadline,
                    )
                    if resolved_preflight.ok and resolved_preflight.risk_level == "low":
                        preflight_clearance = resolved_preflight
                    else:
                        decision = self._policy.preexecution_source_decision(
                            resolved_preflight
                        )

                        async def unreachable_challenge(
                            _challenge_id: str,
                            _request: Mapping[str, object],
                            _timeout: float,
                        ) -> ChallengeObservation:
                            raise RuntimeError(
                                "unresolved pre-execution review never starts a "
                                "challenge"
                            )

                        context = PolicyContext(
                            agent_id=agent_id,
                            attempt_id=attempt_id,
                            miner_hotkey=miner_hotkey,
                            artifact_sha256=sha256.lower(),
                            source_digest=source_digest,
                            source_paths=source_paths,
                            build_elapsed_ms=0,
                            health_elapsed_ms=0,
                            run_challenge=unreachable_challenge,
                            review_source=None,
                        )
                        self._journal.record(context=context, decision=decision)
                        return decision

                if preflight_clearance is None:
                    review_task = asyncio.create_task(
                        self._source_reviewer.review(
                            tmp_path,
                            artifact_sha256=sha256.lower(),
                            attempt_id=attempt_id,
                            progress=report_review_progress,
                            deadline=deadline,
                        )
                    )
                else:

                    async def cleared_preflight() -> SourceReviewObservation:
                        assert preflight_clearance is not None
                        return preflight_clearance

                    review_task = asyncio.create_task(cleared_preflight())

            report("building")
            if (exhausted := self._lease_exhausted(deadline, "build")) is not None:
                return exhausted
            build_timeout = self._config.build_timeout_seconds
            remaining = self._lease_remaining(deadline)
            if remaining is not None:
                build_timeout = min(build_timeout, remaining)
            started = asyncio.get_running_loop().time()
            built, build_detail, built_image_id = await self._build(
                tmp_path, tag, timeout=build_timeout
            )
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
            if built_image_id is None:
                raise RuntimeError("successful Docker build did not return an image id")

            report("starting")
            exhausted = self._lease_exhausted(deadline, "serve check")
            if exhausted is not None:
                return exhausted
            started = asyncio.get_running_loop().time()
            serve_result, audit_runtime = await self._run_and_probe(
                built_image_id,
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
                    oracle_answer=audit_runtime.oracle_answer,
                    gateway_state_file=audit_runtime.gateway_state_file,
                )

            async def review_source():  # type: ignore[no-untyped-def]
                nonlocal in_policy_phase
                in_policy_phase = True
                assert review_task is not None
                return await review_task

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
                # A build-only pass skipped source review, so the policy is
                # given no source-review source and never runs the selector
                # (anti-cheat) phase.
                review_source=None if build_only else review_source,
            )
            report("validating")
            exhausted = self._lease_exhausted(deadline, "policy review")
            if exhausted is not None:
                return exhausted
            decision = await self._policy.evaluate(context, build_only=build_only)
            decision = _with_image_binding_advisory(
                decision, self._image_binding_advisory(tmp_path)
            )
            self._journal.record(context=context, decision=decision)
            if decision.outcome == ScreeningOutcome.PASS and publish_image is not None:
                report("submitting")
                if (
                    exhausted := self._lease_exhausted(deadline, "image export")
                ) is not None:
                    return exhausted
                try:
                    image = await self._export_image(
                        built_image_id,
                        image_ref=tag,
                        deadline=deadline,
                    )
                except _ScreenedImageTooLargeError as error:
                    return core_decision(
                        ScreeningOutcome.DETERMINISTIC_REJECT,
                        code="screened-image-too-large",
                        summary="screened Docker image exceeded the archive size limit",
                        detail=str(error),
                    )
                except _LeaseDeadlineError:
                    return self._lease_exhausted(
                        deadline, "image export"
                    ) or core_decision(
                        ScreeningOutcome.RETRYABLE_INFRA,
                        code="lease-budget-exhausted",
                        summary="screening lease budget exhausted before completion",
                        detail=(
                            "screener error: lease budget exhausted during image export"
                        ),
                    )
                except Exception as error:  # noqa: BLE001 - classify export infra
                    return core_decision(
                        ScreeningOutcome.RETRYABLE_INFRA,
                        code="screened-image-export-failed",
                        summary="screened Docker image export failed",
                        detail=f"screener error: image export failed: {error}",
                    )
                try:
                    remaining = self._lease_remaining(deadline)
                    if remaining is None:
                        await publish_image(image)
                    elif remaining <= 0:
                        raise _LeaseDeadlineError
                    else:
                        async with asyncio.timeout(remaining):
                            await publish_image(image)
                except (TimeoutError, _LeaseDeadlineError):
                    return core_decision(
                        ScreeningOutcome.RETRYABLE_INFRA,
                        code="lease-budget-exhausted",
                        summary="screening lease budget exhausted before completion",
                        detail=(
                            "screener error: lease budget exhausted during image upload"
                        ),
                    )
                except Exception as error:  # noqa: BLE001 - publish is retryable infra
                    return core_decision(
                        ScreeningOutcome.RETRYABLE_INFRA,
                        code="image-upload-failed",
                        summary="screened Docker image upload failed",
                        detail=f"screener error: image upload failed: {error}",
                    )
                finally:
                    with contextlib.suppress(OSError):
                        os.unlink(image.path)
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
            if review_task is not None and not review_task.done():
                # The run is over without needing the review (build failure,
                # lease exhaustion, core reject): stop spending LLM tokens.
                review_task.cancel()
            if review_task is not None:
                # Drain so a failed review never surfaces as "exception was
                # never retrieved" noise after the decision is already made.
                with contextlib.suppress(BaseException):
                    await review_task
            teardown_started = loop.time()
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
            logger.info(
                "screen timing agent_id=%s total_ms=%d teardown_ms=%d %s",
                agent_id,
                round((loop.time() - screen_started) * 1000),
                round((loop.time() - teardown_started) * 1000),
                _format_stage_timings(stage_history, end=teardown_started),
            )

    # --- lease budget -----------------------------------------------------

    @staticmethod
    def _lease_remaining(deadline: float | None) -> float | None:
        """Seconds of lease budget left, or ``None`` when no deadline is set."""
        if deadline is None:
            return None
        return deadline - asyncio.get_running_loop().time()

    def _lease_exhausted(
        self, deadline: float | None, stage: str
    ) -> ScreeningDecision | None:
        """A retryable decision when too little lease remains to run ``stage``."""
        remaining = self._lease_remaining(deadline)
        if remaining is not None and remaining <= _LEASE_MIN_STAGE_SECONDS:
            logger.warning(
                "screening lease budget exhausted before %s (%.1fs left); "
                "reporting retryable so the platform re-queues",
                stage,
                remaining,
            )
            return core_decision(
                ScreeningOutcome.RETRYABLE_INFRA,
                code="lease-budget-exhausted",
                summary="screening lease budget exhausted before completion",
                detail=f"screener error: lease budget exhausted before {stage}",
            )
        return None

    # --- stages -----------------------------------------------------------

    async def _export_image(
        self,
        image_id: str,
        *,
        image_ref: str,
        deadline: float | None,
    ) -> BuiltImageArtifact:
        """Export the exact screened image before teardown and hash its bytes."""
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise _ScreenedImageExportError("Docker returned an invalid image id")
        path: str | None = None
        try:
            inspect_timeout = self._lease_timeout(deadline, 30.0, "image inspection")
            code, raw_size = await self._run(
                ["image", "inspect", "--format", "{{.Size}}", image_id],
                timeout=inspect_timeout,
            )
            if code != 0:
                raise _ScreenedImageExportError(
                    f"docker image inspect failed: {_log_tail(raw_size)}"
                )
            try:
                image_size = int(raw_size.strip())
            except ValueError as error:
                raise _ScreenedImageExportError(
                    "docker returned an invalid image size"
                ) from error
            if image_size > _MAX_SCREENED_IMAGE_BYTES:
                raise _ScreenedImageTooLargeError(
                    f"screened image exceeds {_MAX_SCREENED_IMAGE_BYTES} byte cap"
                )

            fd, path = tempfile.mkstemp(prefix="ditto-screened-image-", suffix=".tar")
            os.close(fd)
            free_bytes = shutil.disk_usage(Path(path).parent).free
            required_bytes = image_size + _IMAGE_EXPORT_DISK_RESERVE_BYTES
            if free_bytes < required_bytes:
                raise _ScreenedImageExportError(
                    "insufficient temporary disk for screened image export "
                    f"(need {required_bytes} bytes, have {free_bytes})"
                )
            export_timeout = self._lease_timeout(deadline, 600.0, "image export")
            code, output = await self._run(
                ["image", "save", "--output", path, image_id],
                timeout=export_timeout,
            )
            if code != 0:
                raise _ScreenedImageExportError(
                    f"docker image export failed: {_log_tail(output)}"
                )
            size_bytes = os.path.getsize(path)
            if size_bytes > _MAX_SCREENED_IMAGE_BYTES:
                raise _ScreenedImageTooLargeError(
                    "screened image archive exceeds "
                    f"{_MAX_SCREENED_IMAGE_BYTES} byte cap"
                )
            sha256 = await self._hash_image_archive(path, deadline=deadline)
            return BuiltImageArtifact(
                path=path,
                sha256=sha256,
                size_bytes=size_bytes,
                image_id=image_id,
                image_ref=image_ref,
            )
        except BaseException:
            if path is not None:
                with contextlib.suppress(OSError):
                    os.unlink(path)
            raise

    def _lease_timeout(self, deadline: float | None, cap: float, stage: str) -> float:
        """Clamp one operation to remaining lease time without post-expiry grace."""
        remaining = self._lease_remaining(deadline)
        if remaining is None:
            return cap
        if remaining <= 0:
            raise _LeaseDeadlineError(f"lease expired before {stage}")
        return min(cap, remaining)

    async def _hash_image_archive(self, path: str, *, deadline: float | None) -> str:
        """Hash the archive incrementally while enforcing the lease deadline."""
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                timeout = self._lease_timeout(deadline, 30.0, "image hashing")
                try:
                    chunk = await asyncio.wait_for(
                        asyncio.to_thread(handle.read, _IMAGE_HASH_CHUNK_BYTES),
                        timeout=timeout,
                    )
                except TimeoutError as error:
                    raise _LeaseDeadlineError(
                        "lease expired during image hashing"
                    ) from error
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

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

    def _image_binding_advisory(self, tar_path: str) -> str | None:
        """Run the advisory image/crate binding heuristic over the Dockerfile."""
        try:
            with tarfile.open(tar_path, mode="r:gz") as tar:
                for name in ("Dockerfile", "./Dockerfile"):
                    try:
                        member = tar.getmember(name)
                    except KeyError:
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        return None
                    text = extracted.read(1024 * 1024).decode("utf-8", "replace")
                    return image_binding_advisory(text)
        except (tarfile.TarError, OSError):
            return None
        return None

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

                dockerfile_file = tar.extractfile(members["Dockerfile"])
                if dockerfile_file is not None:
                    try:
                        dockerfile_file.read().decode("utf-8")
                    except UnicodeDecodeError:
                        return _rust_diagnostic(
                            "SCR-RUST-012",
                            "Dockerfile is not valid UTF-8 text",
                            "commit a readable UTF-8 Dockerfile that builds the crate",
                        )
                # Image/crate binding is a text heuristic, so it is applied as
                # advisory quarantine evidence after policy evaluation (see
                # _image_binding_advisory), never as a contract rejection.
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

    async def _build(
        self, tar_path: str, tag: str, *, timeout: float | None = None
    ) -> tuple[bool, str, str | None]:
        """``docker build`` from the tarball-on-stdin; returns (ok, log_tail).

        ``timeout`` overrides the configured build cap so the worker can clamp a
        build to the remaining lease budget; it defaults to the full cap.
        """
        fd, iid_path = tempfile.mkstemp(prefix="ditto-screen-iid-")
        os.close(fd)
        os.unlink(iid_path)
        args = ["build", "--iidfile", iid_path, "-t", tag, "-f", "Dockerfile"]
        env = dict(os.environ)
        env["DOCKER_BUILDKIT"] = "1"
        # No build-time credential is mounted. The build context (a
        # submission-controlled Dockerfile) runs with network access, so any
        # secret exposed here — a BuildKit secret, or the GCE metadata SA token
        # reachable at 169.254.169.254 — is exfiltratable by a hostile RUN step.
        # The only former consumer, the private ``ditto-harness`` dep, is now
        # public and fetches over anonymous HTTPS, so the ``gh_token`` mount was
        # removed. Metadata access is additionally blocked at the host firewall
        # (see the IMDS guard in scripts/bootstrap-screener.sh) as defense in
        # depth for the shared runtime SA.
        args.append("-")  # build context comes from stdin
        if timeout is None:
            timeout = self._config.build_timeout_seconds
        try:
            with open(tar_path, "rb") as stdin_f:
                code, out = await self._run(
                    args, stdin=stdin_f, timeout=timeout, env=env
                )
            if code == 0:
                try:
                    image_id = Path(iid_path).read_text().strip()
                except OSError as error:
                    return False, f"Docker did not write iidfile: {error}", None
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                    return False, "Docker wrote an invalid image id", None
                return True, "", image_id
        finally:
            with contextlib.suppress(OSError):
                os.unlink(iid_path)
        if code < 0:
            signal_name = signal.Signals(-code).name
            return (
                False,
                (f"docker command exited with signal {signal_name}: {_log_tail(out)}"),
                None,
            )
        if code in {137, 143}:
            return (
                False,
                (f"docker command exited after signal ({code}): {_log_tail(out)}"),
                None,
            )
        return False, _log_tail(out), None

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
        # High-entropy, opaque tokens with no ``ditto``/``fake``/``screening``
        # marker: the first is the per-container nonce the gateway returns, the
        # second is the answer it returns only once the nonce is fed back on a
        # second round-trip (the gateway-encoded correctness oracle).
        response_text = secrets.token_hex(16)
        oracle_answer = secrets.token_hex(16)
        started, detail = await self._start_fake_gateway(
            gateway_container=gateway_container,
            network=network,
            response_text=response_text,
            oracle_answer=oracle_answer,
            state_dir=gateway_state_dir,
        )
        if not started:
            return _StageResult(False, detail, retryable=True), None

        gateway = f"http://{_GATEWAY_ALIAS}:8080"
        run_args = [
            "run",
            "-d",
            "--rm",
            "--init",
            "--name",
            container,
            "--user",
            _VALIDATOR_SANDBOX_USER,
            "--read-only",
            "--tmpfs",
            _VALIDATOR_SANDBOX_TMPFS,
            "--network",
            network,
            "--network-alias",
            _HARNESS_ALIAS,
            "--memory",
            _VALIDATOR_SANDBOX_MEMORY,
            "--cpus",
            _VALIDATOR_SANDBOX_CPUS,
            "--pids-limit",
            _VALIDATOR_SANDBOX_PIDS,
            "--ulimit",
            "nofile=1024:1024",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
        ]
        for key, value in self._config.smoke_env:
            if key == "DITTOBENCH_DB":
                continue
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
            # The validator root filesystem is read-only. Its bounded /tmp
            # tmpfs is the canonical writable location for the harness DB.
            "DITTOBENCH_DB": _VALIDATOR_SANDBOX_DB,
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
                oracle_answer=oracle_answer,
                gateway_state_file=str(Path(gateway_state_dir) / "model-called"),
            ),
        )

    async def _start_fake_gateway(
        self,
        *,
        gateway_container: str,
        network: str,
        response_text: str,
        oracle_answer: str,
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
                f"DITTO_FAKE_GATEWAY_ORACLE_ANSWER={oracle_answer}",
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
        oracle_answer: str | None = None,
    ) -> ChallengeObservation:
        """Run one selected private challenge and retain only bounded evidence.

        Timing and gateway-call counts are objective, reproducible facts about
        the isolated round-trip. ``oracle_answer_correct`` is likewise objective:
        the harness can only surface ``oracle_answer`` by feeding the gateway
        nonce back through a second turn, which a static table cannot do.
        """
        # A tool-shaped challenge (non-empty `tools`) needs a reachable
        # `tool_endpoint` so the harness's agent loop can execute the tool call
        # the model returns and proceed to the second model turn. Filled here
        # (not in the policy module) because only the gate knows the network
        # topology.
        payload = _with_tool_endpoint(request)
        calls_before = _gateway_call_count(gateway_state_file)
        started = asyncio.get_running_loop().time()
        code, out = await self._request_from_sidecar(
            probe_container,
            f"{harness_base}/run",
            payload=payload,
            timeout=min(timeout, self._config.run_timeout_seconds),
        )
        elapsed_ms = round((asyncio.get_running_loop().time() - started) * 1000)
        gateway_calls = max(0, _gateway_call_count(gateway_state_file) - calls_before)
        if code != 0:
            # The probe output carries the concrete failure ("HTTP 422: ...",
            # a timeout traceback, ...). Log it bounded: a silent discard here
            # previously hid a request-contract break behind an opaque
            # "challenge-http-failure" for every screening.
            logger.warning(
                "private challenge %s HTTP failure: exit=%d detail=%.400s",
                challenge_id,
                code,
                out,
            )
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
            # Either token proves binding to THIS container's ephemeral
            # gateway: with the tool-call first turn the nonce is consumed
            # inside the transcript and the surfaced final text is the oracle
            # answer, so both must count.
            gateway_token_observed=(
                _contains_string(payload, gateway_response_token)
                or (
                    oracle_answer is not None
                    and _contains_string(payload, oracle_answer)
                )
            ),
            oracle_answer_correct=(
                oracle_answer is not None and _contains_string(payload, oracle_answer)
            ),
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
            # Both containers can be removed concurrently; the network can
            # only go once its endpoints are gone, and the image untag is
            # independent of the network.
            await asyncio.gather(
                self._run(["rm", "-f", container], timeout=30.0),
                self._run(["rm", "-f", gateway_container], timeout=30.0),
            )
            await asyncio.gather(
                self._run(["network", "rm", network], timeout=30.0),
                self._run(["rmi", "-f", tag], timeout=30.0),
            )
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
