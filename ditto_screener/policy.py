"""Typed, rotating private policy boundary for screening.

The stable build gate owns objective artifact/build/serve checks.  Only that
stable core may produce a terminal deterministic rejection.  Private modules
are deliberately weaker signals: they may select an audit, clear it, request a
retry, or route it to quarantine/inconclusive review.  No module result is
treated as proof that a black-box harness causally used a model.

The default manifest has no private modules and exactly reproduces production
policy v6: build + health, with no synthetic ``POST /run`` assertion.  A private
JSON manifest can rotate modules and challenge packs without changing
``SCREENING_POLICY_VERSION`` or the canonical verdict-signing bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar, Protocol
from uuid import UUID

from ditto_screening_protocol import SCREENING_POLICY_VERSION

logger = logging.getLogger(__name__)

_MAX_MANIFEST_BYTES = 128 * 1024
_MAX_FEED_BYTES = 256 * 1024
_MAX_MODULES = 16
_MAX_EVIDENCE = 16
_MAX_CHALLENGES = 8
_MAX_ID = 64
_MAX_CODE = 64
_MAX_SUMMARY = 240
_MAX_FINDING_BYTES = 8 * 1024
_SHA256_HEX = frozenset("0123456789abcdef")
_PRIVATE_CHALLENGE_CATEGORIES = frozenset(
    {
        "benchmark_emulation",
        "embedded_evaluator_logic",
        "fabricated_tool_trajectory",
        "hidden_value_leakage",
        "provider_bypass",
        "scorer_contract_manipulation",
        "seed_state_shortcut",
        "suspicious_static_tables",
    }
)
_MALICIOUS_SOURCE_CATEGORIES = frozenset(
    {
        "credential_access",
        "cross_user_access",
        "data_exfiltration",
        "embedded_secret",
        "malicious_build",
        "prompt_injection",
    }
)
_ORIGINALITY_CATEGORIES = frozenset({"duplicate_submission"})
_ADVISORY_SOURCE_CATEGORIES = frozenset(
    {"external_build_dependency", "user_isolation_correctness"}
)


class ScreeningOutcome(StrEnum):
    """Final typed result at the private policy boundary."""

    PASS = "pass"
    DETERMINISTIC_REJECT = "deterministic_reject"
    RETRYABLE_INFRA = "retryable_infra"
    QUARANTINE = "quarantine"
    INCONCLUSIVE = "inconclusive"


class ModuleDisposition(StrEnum):
    """Non-terminal result emitted by one private module."""

    CLEAR = "clear"
    TRIPWIRE = "tripwire"
    RETRYABLE_INFRA = "retryable_infra"
    QUARANTINE = "quarantine"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class PolicyEvidence:
    """One bounded, public-safe evidence summary.

    Raw challenge prompts, responses, private rules, credentials, and artifact
    source never belong here.  Modules record stable codes and digests only.
    """

    module_id: str
    code: str
    summary: str
    digest: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= len(self.module_id) <= _MAX_ID:
            raise ValueError("evidence module_id is empty or too long")
        if not 1 <= len(self.code) <= _MAX_CODE:
            raise ValueError("evidence code is empty or too long")
        if not 1 <= len(self.summary) <= _MAX_SUMMARY:
            raise ValueError("evidence summary is empty or too long")
        if self.digest is not None and not _is_sha256(self.digest):
            raise ValueError("evidence digest must be lowercase SHA-256 hex")


@dataclass(frozen=True)
class ScreeningDecision:
    """Outcome returned by the stable core plus private policy engine."""

    outcome: ScreeningOutcome
    detail: str
    manifest_digest: str
    evidence: tuple[PolicyEvidence, ...] = ()
    policy_version: int = SCREENING_POLICY_VERSION
    finding: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        if self.policy_version != SCREENING_POLICY_VERSION:
            raise ValueError("decision policy version does not match worker policy")
        if len(self.detail) > 3900:
            raise ValueError("decision detail exceeds protocol bound")
        if not _is_sha256(self.manifest_digest):
            raise ValueError("manifest_digest must be lowercase SHA-256 hex")
        if len(self.evidence) > _MAX_EVIDENCE:
            raise ValueError("too many evidence entries")
        if (
            self.finding is not None
            and len(json.dumps(self.finding, sort_keys=True, separators=(",", ":")))
            > _MAX_FINDING_BYTES
        ):
            raise ValueError("finding exceeds bounded size")

    @property
    def submits_verdict(self) -> bool:
        """Whether this result maps to the unchanged v6 boolean verdict."""
        return self.outcome in {
            ScreeningOutcome.PASS,
            ScreeningOutcome.DETERMINISTIC_REJECT,
            ScreeningOutcome.RETRYABLE_INFRA,
        }

    @property
    def passed(self) -> bool:
        """Boolean bound by the unchanged canonical verdict signature."""
        if not self.submits_verdict:
            raise ValueError(f"{self.outcome} is not a verdict")
        return self.outcome == ScreeningOutcome.PASS


@dataclass(frozen=True)
class ChallengeObservation:
    """Sanitized observation from one private behavioral challenge."""

    challenge_id: str
    ok: bool
    response_digest: str | None
    elapsed_ms: int
    json_keys: tuple[str, ...] = ()
    error_code: str | None = None
    gateway_calls: int = 0
    gateway_token_observed: bool = False
    oracle_answer_correct: bool = False


@dataclass(frozen=True)
class SourceReviewObservation:
    """Sanitized result from the private read-only source-review agent.

    ``finding`` is the bounded canonical payload (risk, confidence, categories,
    flagged path/line evidence, and a generic summary) whose canonical JSON
    hashes to ``finding_digest``. It never contains source text, prompts, or
    fixtures; it exists so a quarantine reaches the operator with reviewable
    context instead of a bare digest.
    """

    ok: bool
    risk_level: str | None
    finding_digest: str | None
    categories: tuple[str, ...]
    error_code: str | None = None
    finding: Mapping[str, object] | None = None


ChallengeRunner = Callable[
    [str, Mapping[str, object], float], Awaitable[ChallengeObservation]
]
SourceReviewRunner = Callable[[], Awaitable[SourceReviewObservation]]


@dataclass(frozen=True)
class PolicyContext:
    """Bounded inputs available to private policy modules."""

    agent_id: UUID
    attempt_id: UUID
    miner_hotkey: str
    artifact_sha256: str
    source_digest: str
    source_paths: tuple[str, ...]
    build_elapsed_ms: int
    health_elapsed_ms: int
    run_challenge: ChallengeRunner
    review_source: SourceReviewRunner | None = None


@dataclass(frozen=True)
class ModuleResult:
    disposition: ModuleDisposition
    evidence: tuple[PolicyEvidence, ...] = ()
    finding: Mapping[str, object] | None = None


class PolicyModule(Protocol):
    """Private module interface; implementations cannot terminally reject."""

    @property
    def module_id(self) -> str: ...

    @property
    def phase(self) -> str: ...

    @property
    def clears_selection(self) -> bool: ...

    async def evaluate(self, context: PolicyContext) -> ModuleResult: ...


@dataclass(frozen=True)
class PolicyManifest:
    """Canonical description of one daily private module rotation."""

    rotation_id: str
    module_specs: tuple[Mapping[str, object], ...] = ()
    policy_version: int = SCREENING_POLICY_VERSION

    def __post_init__(self) -> None:
        if not 1 <= len(self.rotation_id) <= _MAX_ID:
            raise ValueError("rotation_id is empty or too long")
        if self.policy_version != SCREENING_POLICY_VERSION:
            raise ValueError("rotating manifest cannot change production policy")
        if len(self.module_specs) > _MAX_MODULES:
            raise ValueError("too many policy modules")

    @property
    def digest(self) -> str:
        payload = {
            "policy_version": self.policy_version,
            "rotation_id": self.rotation_id,
            "modules": list(self.module_specs),
        }
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        return hashlib.sha256(canonical).hexdigest()


CORE_ONLY_MANIFEST = PolicyManifest(rotation_id="v8-core-build-health-no-run")
DEFAULT_V8_MANIFEST = PolicyManifest(
    rotation_id="v8-luna-source-review-behavioral-oracle",
    module_specs=(
        {"kind": "agentic_source_review", "id": "luna-source-review"},
        {"kind": "behavioral_oracle", "id": "v8-behavioral-oracle"},
    ),
)


def core_decision(
    outcome: ScreeningOutcome,
    *,
    code: str,
    summary: str,
    detail: str,
) -> ScreeningDecision:
    """Build an objective stable-core result under the current policy."""
    return ScreeningDecision(
        outcome=outcome,
        detail=detail,
        manifest_digest=CORE_ONLY_MANIFEST.digest,
        evidence=(PolicyEvidence("stable-core", code, summary),),
    )


@dataclass(frozen=True)
class _BaseModule:
    module_id: str
    phase: str = field(init=False, default="selector")
    # Whether a CLEAR from this module may release a selector tripwire.
    # Only the dedicated, rotating private audit packs earn that power; a
    # generic always-on challenge passing must never clear a medium/high
    # source finding, or a harness that implements the generic exchange
    # while cheating elsewhere silently self-clears its own audit.
    clears_selection: ClassVar[bool] = False

    def __post_init__(self) -> None:
        if not 1 <= len(self.module_id) <= _MAX_ID:
            raise ValueError("module id is empty or too long")


@dataclass(frozen=True)
class TimingRelayRiskModule(_BaseModule):
    """Tripwire from private aggregate timing/score/relay observations.

    Crossing a threshold only selects a private audit.  It never rejects.
    """

    feed_path: Path = Path("/nonexistent")
    min_composite: float = 0.98
    max_median_ms: int = 500

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0 <= self.min_composite <= 1:
            raise ValueError("min_composite must be between 0 and 1")
        if self.max_median_ms < 0:
            raise ValueError("max_median_ms must be non-negative")

    async def evaluate(self, context: PolicyContext) -> ModuleResult:
        try:
            feed = _read_json(self.feed_path, max_bytes=_MAX_FEED_BYTES)
        except (OSError, ValueError, json.JSONDecodeError):
            return ModuleResult(
                ModuleDisposition.RETRYABLE_INFRA,
                (
                    PolicyEvidence(
                        self.module_id,
                        "risk-feed-unavailable",
                        "private timing and relay feed was unavailable",
                    ),
                ),
            )
        if not isinstance(feed, dict):
            return ModuleResult(
                ModuleDisposition.RETRYABLE_INFRA,
                (
                    PolicyEvidence(
                        self.module_id,
                        "risk-feed-invalid",
                        "private timing and relay feed was invalid",
                    ),
                ),
            )
        record = feed.get(str(context.agent_id), feed.get(context.miner_hotkey, {}))
        if not isinstance(record, dict):
            return ModuleResult(ModuleDisposition.CLEAR)
        composite = record.get("composite")
        median_ms = record.get("median_ms")
        relay_flags = record.get("relay_flags", [])
        fast_high = (
            isinstance(composite, (int, float))
            and not isinstance(composite, bool)
            and isinstance(median_ms, int)
            and not isinstance(median_ms, bool)
            and float(composite) >= self.min_composite
            and median_ms <= self.max_median_ms
        )
        relayed = isinstance(relay_flags, list) and any(
            isinstance(flag, str) and flag for flag in relay_flags
        )
        if not (fast_high or relayed):
            return ModuleResult(ModuleDisposition.CLEAR)
        digest = hashlib.sha256(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return ModuleResult(
            ModuleDisposition.TRIPWIRE,
            (
                PolicyEvidence(
                    self.module_id,
                    "timing-relay-tripwire",
                    "aggregate timing, score, or relay risk selected a private audit",
                    digest,
                ),
            ),
        )


@dataclass(frozen=True)
class RandomAuditModule(_BaseModule):
    """Private deterministic random-control selector, rotated by secret seed."""

    rate_basis_points: int = 500
    seed_env: str = "SCREENER_AUDIT_SEED"

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 0 <= self.rate_basis_points <= 10_000:
            raise ValueError("rate_basis_points must be between 0 and 10000")

    async def evaluate(self, context: PolicyContext) -> ModuleResult:
        seed = os.environ.get(self.seed_env, "").encode()
        if len(seed) < 16:
            return ModuleResult(
                ModuleDisposition.RETRYABLE_INFRA,
                (
                    PolicyEvidence(
                        self.module_id,
                        "audit-seed-unavailable",
                        "private random-audit seed was unavailable",
                    ),
                ),
            )
        draw = (
            int.from_bytes(
                hmac.digest(seed, context.agent_id.bytes, "sha256")[:8], "big"
            )
            % 10_000
        )
        if draw >= self.rate_basis_points:
            return ModuleResult(ModuleDisposition.CLEAR)
        return ModuleResult(
            ModuleDisposition.TRIPWIRE,
            (
                PolicyEvidence(
                    self.module_id,
                    "random-control-selected",
                    "submission was selected for the private random control sample",
                ),
            ),
        )


@dataclass(frozen=True)
class SourceFingerprintTriageModule(_BaseModule):
    """Tripwire for private known-source fingerprints; never a rejection."""

    known_source_digests: frozenset[str] = frozenset()
    suspicious_path_suffixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        super().__post_init__()
        if any(not _is_sha256(value) for value in self.known_source_digests):
            raise ValueError("known source fingerprints must be SHA-256 hex")

    async def evaluate(self, context: PolicyContext) -> ModuleResult:
        digest_match = context.source_digest in self.known_source_digests
        path_match = any(
            path.endswith(suffix)
            for path in context.source_paths
            for suffix in self.suspicious_path_suffixes
            if suffix
        )
        if not (digest_match or path_match):
            return ModuleResult(ModuleDisposition.CLEAR)
        return ModuleResult(
            ModuleDisposition.TRIPWIRE,
            (
                PolicyEvidence(
                    self.module_id,
                    "source-fingerprint-tripwire",
                    "private source or layout fingerprint selected a deeper audit",
                    context.source_digest,
                ),
            ),
        )


@dataclass(frozen=True)
class AgenticSourceReviewModule(_BaseModule):
    """Use private read-only source analysis as a quarantine selector only."""

    async def evaluate(self, context: PolicyContext) -> ModuleResult:
        if context.review_source is None:
            return ModuleResult(
                ModuleDisposition.RETRYABLE_INFRA,
                (
                    PolicyEvidence(
                        self.module_id,
                        "source-review-unavailable",
                        "private source-review infrastructure was unavailable",
                    ),
                ),
            )
        observation = await context.review_source()
        if not observation.ok:
            return ModuleResult(
                ModuleDisposition.RETRYABLE_INFRA,
                (
                    PolicyEvidence(
                        self.module_id,
                        observation.error_code or "source-review-inconclusive",
                        "private source review did not produce a usable result",
                    ),
                ),
            )
        if observation.risk_level == "low" and set(observation.categories) <= (
            {"none"} | _ADVISORY_SOURCE_CATEGORIES
        ):
            # Keep the low-risk finding: if another module later quarantines,
            # clean or advisory-only source review is useful operator context.
            # Advisory correctness/build observations are not anti-cheat
            # tripwires by themselves.
            return ModuleResult(ModuleDisposition.CLEAR, finding=observation.finding)
        if observation.risk_level not in {"low", "medium", "high"}:
            return ModuleResult(
                ModuleDisposition.INCONCLUSIVE,
                (
                    PolicyEvidence(
                        self.module_id,
                        "source-review-invalid-risk",
                        "private source review returned an invalid risk level",
                    ),
                ),
            )
        code, summary = _source_review_reason(observation.categories)
        return ModuleResult(
            ModuleDisposition.TRIPWIRE,
            (
                PolicyEvidence(
                    self.module_id,
                    code,
                    summary,
                    observation.finding_digest,
                ),
            ),
            finding=observation.finding,
        )


@dataclass(frozen=True)
class BehavioralChallengePackModule(_BaseModule):
    """Run a rotating private black-box pack as observational evidence only."""

    pack_path: Path = Path("/nonexistent")
    phase: str = field(init=False, default="challenge")
    # Packs are rotated privately per suspicion class, so a full pack CLEAR
    # is allowed to release the tripwire that selected the audit.
    clears_selection: ClassVar[bool] = True

    async def evaluate(self, context: PolicyContext) -> ModuleResult:
        try:
            pack = _read_json(self.pack_path, max_bytes=_MAX_MANIFEST_BYTES)
            challenges = _parse_challenges(pack)
        except (OSError, ValueError, json.JSONDecodeError):
            return ModuleResult(
                ModuleDisposition.RETRYABLE_INFRA,
                (
                    PolicyEvidence(
                        self.module_id,
                        "challenge-pack-unavailable",
                        "private behavioral challenge pack was unavailable",
                    ),
                ),
            )
        evidence: list[PolicyEvidence] = []
        for (
            challenge_id,
            request,
            timeout,
            required_keys,
            require_model_call,
            require_gateway_token,
        ) in challenges:
            observation = await context.run_challenge(challenge_id, request, timeout)
            if not observation.ok:
                evidence.append(
                    PolicyEvidence(
                        self.module_id,
                        observation.error_code or "challenge-inconclusive",
                        "private behavioral challenge was inconclusive",
                    )
                )
                return ModuleResult(ModuleDisposition.INCONCLUSIVE, tuple(evidence))
            if require_model_call and observation.gateway_calls < 1:
                evidence.append(
                    PolicyEvidence(
                        self.module_id,
                        "challenge-model-call-missing",
                        "private challenge returned without an observed model call",
                        observation.response_digest,
                    )
                )
                return ModuleResult(ModuleDisposition.QUARANTINE, tuple(evidence))
            if require_gateway_token and not observation.gateway_token_observed:
                evidence.append(
                    PolicyEvidence(
                        self.module_id,
                        "challenge-gateway-token-missing",
                        "private challenge response was not bound to the "
                        "ephemeral model output",
                        observation.response_digest,
                    )
                )
                return ModuleResult(ModuleDisposition.QUARANTINE, tuple(evidence))
            missing = set(required_keys).difference(observation.json_keys)
            if missing:
                evidence.append(
                    PolicyEvidence(
                        self.module_id,
                        "challenge-shape-anomaly",
                        "private challenge response shape requires operator review",
                        observation.response_digest,
                    )
                )
                return ModuleResult(ModuleDisposition.QUARANTINE, tuple(evidence))
            evidence.append(
                PolicyEvidence(
                    self.module_id,
                    "challenge-observed",
                    "private challenge completed; this is not proof of "
                    "causal model use",
                    observation.response_digest,
                )
            )
        return ModuleResult(ModuleDisposition.CLEAR, tuple(evidence))


# Generic, benchmark-plausible system prompts for the oracle's RunRequest.
# Several phrasings (picked per request) so no single fixed string becomes a
# fingerprint, while each reads like an ordinary validator case.
_ORACLE_SYSTEM_PROMPTS: tuple[str, ...] = (
    "You are a helpful personal assistant with access to the user's saved "
    "notes and memories.",
    "You are the user's personal assistant. Use their stored notes to answer "
    "accurately and concisely.",
    "Answer the user using their previously saved information. Be brief and factual.",
    "You are an assistant that recalls the user's stored notes to answer "
    "questions concisely.",
)


@dataclass(frozen=True)
class BehavioralOracleModule(_BaseModule):
    """Always-on gateway-encoded correctness oracle with timing thresholds.

    Unlike the selector-gated packs, this challenge runs on every submission.
    It is built in (no external pack file), so it works in the default v8
    manifest out of the box. The oracle is objective and reproducible: the
    isolated fake gateway returns a per-container nonce, and the harness can
    only surface the gateway's ``oracle_answer`` by feeding that nonce back
    through a second gateway turn. A static lookup table that never performs
    the round-trip cannot produce the right final answer, returns in ~1 call,
    and answers in milliseconds.

    TRUST-BOUNDARY NOTE: a wrong gateway-encoded answer, insufficient call
    count, or implausibly fast round-trip is reproducible escalation evidence,
    but it is not sole terminal proof. Provider behavior, retries, caching, and
    harness architecture can produce legitimate anomalies. The PolicyEngine
    therefore routes these observations to ``QUARANTINE`` and reserves
    ``deterministic_reject`` for stable-core artifact/build/serve failures.
    """

    phase: str = field(init=False, default="challenge")
    challenge_id: str = "v8-behavioral-oracle"
    timeout_seconds: float = 20.0
    min_gateway_calls: int = 2
    min_elapsed_ms: int = 250

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.min_gateway_calls < 1:
            raise ValueError("min_gateway_calls must be at least 1")
        if self.min_elapsed_ms < 0:
            raise ValueError("min_elapsed_ms must be non-negative")
        if not 1 <= self.timeout_seconds <= 60:
            raise ValueError("timeout_seconds must be between 1 and 60")

    async def evaluate(self, context: PolicyContext) -> ModuleResult:
        # Shaped like an ordinary benchmark case, with randomized identifiers
        # and phrasing: no fixed case id and no protocol marker, so a harness
        # cannot fingerprint the oracle request and behave honestly only for
        # it. The correctness signal comes entirely from the per-container
        # gateway nonce round-trip — the gateway's first turn is a normal
        # tool_calls completion (against the harness's own declared tools)
        # carrying the nonce, so any honest agent loop naturally makes the
        # second model call the oracle scores, while a static lookup that
        # skips the gateway cannot know the nonce and cannot answer.
        subject = secrets.token_hex(4)
        # The payload must deserialize as the harness contract's RunRequest
        # (dittobench-starter-kit src/protocol.rs): `case_id`, `system_prompt`
        # and `user_input` are REQUIRED fields with no serde default, so an
        # honest axum harness rejects a request missing any of them with 422
        # before the handler runs. `tools`/`tool_endpoint`/`user_id` default.
        # The system prompt is drawn from generic assistant phrasings so the
        # request still carries no fixed marker a harness could branch on.
        request: Mapping[str, object] = {
            "case_id": secrets.token_hex(16),
            "system_prompt": random.choice(_ORACLE_SYSTEM_PROMPTS),
            "user_input": (
                f"Look up what I previously noted about item {subject} "
                "and summarize it in one sentence."
            ),
        }
        observation = await context.run_challenge(
            self.challenge_id, request, self.timeout_seconds
        )
        if not observation.ok:
            logger.warning(
                "behavioral oracle inconclusive: error_code=%s elapsed_ms=%s "
                "gateway_calls=%s",
                observation.error_code,
                observation.elapsed_ms,
                observation.gateway_calls,
            )
            return ModuleResult(
                ModuleDisposition.INCONCLUSIVE,
                (
                    PolicyEvidence(
                        self.module_id,
                        observation.error_code or "behavioral-oracle-inconclusive",
                        "always-on behavioral oracle did not produce a usable result",
                        observation.response_digest,
                    ),
                ),
            )
        if observation.gateway_calls < self.min_gateway_calls:
            # Too few calls is a strong shortcut signal, but alternate honest
            # provider loops can differ, so it remains operator escalation.
            return ModuleResult(
                ModuleDisposition.QUARANTINE,
                (
                    PolicyEvidence(
                        self.module_id,
                        "behavioral-oracle-insufficient-round-trips",
                        "behavioral oracle observed too few gateway round-trips",
                        observation.response_digest,
                    ),
                ),
            )
        if not observation.oracle_answer_correct:
            # Objective: the gateway-encoded answer is deterministically known
            # to the screener; a wrong final answer is a checkable failure.
            return ModuleResult(
                ModuleDisposition.QUARANTINE,
                (
                    PolicyEvidence(
                        self.module_id,
                        "behavioral-oracle-wrong-answer",
                        "behavioral oracle final answer did not match the "
                        "gateway-encoded value",
                        observation.response_digest,
                    ),
                ),
            )
        if observation.elapsed_ms < self.min_elapsed_ms:
            # Very low latency is a tripwire, not causal proof of a table.
            return ModuleResult(
                ModuleDisposition.QUARANTINE,
                (
                    PolicyEvidence(
                        self.module_id,
                        "behavioral-oracle-implausibly-fast",
                        "behavioral oracle round-trip returned faster than any "
                        "genuine model call",
                        observation.response_digest,
                    ),
                ),
            )
        return ModuleResult(
            ModuleDisposition.CLEAR,
            (
                PolicyEvidence(
                    self.module_id,
                    "behavioral-oracle-passed",
                    "behavioral oracle round-trip returned the gateway-encoded value",
                    observation.response_digest,
                ),
            ),
        )


class PolicyEngine:
    """Evaluate selectors, optional challenges, and typed review routing."""

    def __init__(
        self, manifest: PolicyManifest, modules: Sequence[PolicyModule] = ()
    ) -> None:
        self.manifest = manifest
        self.modules = tuple(modules)
        if len(self.modules) != len(manifest.module_specs):
            raise ValueError("manifest/module count mismatch")
        if len(self.modules) > _MAX_MODULES:
            raise ValueError("too many modules")

    async def evaluate(self, context: PolicyContext) -> ScreeningDecision:
        evidence: list[PolicyEvidence] = []
        finding: Mapping[str, object] | None = None
        selected = False
        for module in (m for m in self.modules if m.phase == "selector"):
            result = await module.evaluate(context)
            evidence.extend(result.evidence)
            finding = result.finding or finding
            terminal = _module_terminal(result.disposition)
            if terminal is not None:
                return self._decision(terminal, evidence, finding)
            selected = selected or result.disposition == ModuleDisposition.TRIPWIRE

        # Challenge-phase modules run on EVERY submission, decoupled from the
        # selector tripwire. The always-on behavioral oracle lives here so a
        # harness cannot behave only during a ~5% audit.
        challenges = tuple(m for m in self.modules if m.phase == "challenge")
        cleared = False
        for module in challenges:
            result = await module.evaluate(context)
            evidence.extend(result.evidence)
            finding = result.finding or finding
            terminal = _module_terminal(result.disposition)
            if terminal is not None:
                return self._decision(terminal, evidence, finding)
            cleared = cleared or (
                module.clears_selection
                and result.disposition == ModuleDisposition.CLEAR
            )

        # A selector tripwire (e.g. a medium/high source-review finding) is
        # released only by a dedicated selected-audit pack CLEAR. Passing the
        # generic always-on oracle proves one compliant exchange, not that the
        # flagged behavior is absent, so it must not self-clear the audit.
        if selected and not cleared:
            if not evidence:
                evidence.append(
                    PolicyEvidence(
                        "policy-engine",
                        "audit-awaiting-private-challenge",
                        "tripwire selected quarantine until a private challenge "
                        "is available",
                    )
                )
            return self._decision(ScreeningOutcome.QUARANTINE, evidence, finding)

        return self._decision(ScreeningOutcome.PASS, evidence, finding)

    def _decision(
        self,
        outcome: ScreeningOutcome,
        evidence: Sequence[PolicyEvidence],
        finding: Mapping[str, object] | None = None,
    ) -> ScreeningDecision:
        bounded = tuple(evidence[:_MAX_EVIDENCE])
        detail = ""
        if outcome == ScreeningOutcome.RETRYABLE_INFRA:
            detail = "screener error: private policy infrastructure unavailable"
        elif outcome == ScreeningOutcome.QUARANTINE:
            detail = "private policy quarantine pending operator review"
        elif outcome == ScreeningOutcome.INCONCLUSIVE:
            detail = "private policy audit inconclusive"
        return ScreeningDecision(
            outcome=outcome,
            detail=detail,
            manifest_digest=self.manifest.digest,
            evidence=bounded,
            finding=finding,
        )


def load_policy_engine(manifest_path: str | None) -> PolicyEngine:
    """Load a strict private manifest, or production v8 Luna source review."""
    if manifest_path is None:
        return PolicyEngine(
            DEFAULT_V8_MANIFEST,
            (
                AgenticSourceReviewModule(module_id="luna-source-review"),
                BehavioralOracleModule(module_id="v8-behavioral-oracle"),
            ),
        )
    raw = _read_json(Path(manifest_path), max_bytes=_MAX_MANIFEST_BYTES)
    if not isinstance(raw, dict) or set(raw) != {
        "policy_version",
        "rotation_id",
        "modules",
    }:
        raise ValueError("policy manifest has unexpected fields")
    if raw["policy_version"] != SCREENING_POLICY_VERSION:
        raise ValueError("policy manifest may not change SCREENING_POLICY_VERSION")
    rotation_id = raw["rotation_id"]
    specs = raw["modules"]
    if not isinstance(rotation_id, str) or not isinstance(specs, list):
        raise ValueError("policy manifest fields have invalid types")
    normalized: list[Mapping[str, object]] = []
    modules: list[PolicyModule] = []
    for spec in specs:
        if not isinstance(spec, dict):
            raise ValueError("policy module spec must be an object")
        normalized_spec = _normalize_spec(spec)
        normalized.append(normalized_spec)
        modules.append(_build_module(normalized_spec))
    manifest = PolicyManifest(rotation_id=rotation_id, module_specs=tuple(normalized))
    return PolicyEngine(manifest, modules)


class ReviewJournal:
    """Append-only, mode-0600 private journal for non-verdict outcomes."""

    def __init__(self, path: str | None) -> None:
        self._path = Path(path) if path else None

    def record(
        self,
        *,
        context: PolicyContext,
        decision: ScreeningDecision,
    ) -> None:
        if self._path is None:
            return
        if decision.outcome not in {
            ScreeningOutcome.QUARANTINE,
            ScreeningOutcome.INCONCLUSIVE,
        }:
            return
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = {
            "agent_id": str(context.agent_id),
            "attempt_id": str(context.attempt_id),
            "miner_hotkey": context.miner_hotkey,
            "outcome": decision.outcome,
            "policy_version": decision.policy_version,
            "manifest_digest": decision.manifest_digest,
            "evidence": [
                {
                    "module_id": item.module_id,
                    "code": item.code,
                    "summary": item.summary,
                    "digest": item.digest,
                }
                for item in decision.evidence
            ],
            "finding": decision.finding,
        }
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        fd = os.open(self._path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)


def _module_terminal(disposition: ModuleDisposition) -> ScreeningOutcome | None:
    return {
        ModuleDisposition.RETRYABLE_INFRA: ScreeningOutcome.RETRYABLE_INFRA,
        ModuleDisposition.QUARANTINE: ScreeningOutcome.QUARANTINE,
        ModuleDisposition.INCONCLUSIVE: ScreeningOutcome.INCONCLUSIVE,
    }.get(disposition)


def _source_review_reason(categories: Sequence[str]) -> tuple[str, str]:
    category_set = set(categories)
    if category_set & _MALICIOUS_SOURCE_CATEGORIES:
        return (
            "source-safety-malicious-risk",
            "private source analysis found malicious-source safety risk",
        )
    if category_set & _PRIVATE_CHALLENGE_CATEGORIES:
        return (
            "source-safety-private-challenge-risk",
            "private source analysis found private-challenge safety risk",
        )
    if category_set & _ORIGINALITY_CATEGORIES:
        return (
            "originality-duplicate-risk",
            "cross-submission evidence found exact-artifact originality risk",
        )
    if category_set & _ADVISORY_SOURCE_CATEGORIES:
        return (
            "source-correctness-review",
            "private source analysis found correctness or reviewability risk, "
            "not terminal anti-cheat proof",
        )
    return (
        "source-safety-behavioral-risk",
        "private source analysis selected a bounded behavioral audit",
    )


def _read_json(path: Path, *, max_bytes: int) -> Any:
    data = path.read_bytes()
    if len(data) > max_bytes:
        raise ValueError(f"JSON file exceeds {max_bytes} byte cap")
    return json.loads(data)


def _parse_challenges(
    pack: object,
) -> tuple[tuple[str, Mapping[str, object], float, tuple[str, ...], bool, bool], ...]:
    if not isinstance(pack, dict) or set(pack) != {"challenges"}:
        raise ValueError("challenge pack has unexpected fields")
    raw = pack["challenges"]
    if not isinstance(raw, list) or not 1 <= len(raw) <= _MAX_CHALLENGES:
        raise ValueError("challenge pack size is invalid")
    parsed: list[
        tuple[str, Mapping[str, object], float, tuple[str, ...], bool, bool]
    ] = []
    for item in raw:
        required_fields = {
            "id",
            "request",
            "timeout_seconds",
            "required_response_keys",
        }
        optional_fields = {"require_model_call", "require_gateway_token"}
        if (
            not isinstance(item, dict)
            or not required_fields.issubset(item)
            or not set(item).issubset(required_fields | optional_fields)
        ):
            raise ValueError("challenge has unexpected fields")
        challenge_id = item["id"]
        request = item["request"]
        timeout = item["timeout_seconds"]
        required = item["required_response_keys"]
        require_model_call = item.get("require_model_call", False)
        require_gateway_token = item.get("require_gateway_token", False)
        if (
            not isinstance(challenge_id, str)
            or not 1 <= len(challenge_id) <= _MAX_ID
            or not isinstance(request, dict)
            or not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 1 <= float(timeout) <= 60
            or not isinstance(required, list)
            or any(not isinstance(key, str) or not key for key in required)
            or not isinstance(require_model_call, bool)
            or not isinstance(require_gateway_token, bool)
            or (require_gateway_token and not require_model_call)
        ):
            raise ValueError("challenge fields have invalid types")
        parsed.append(
            (
                challenge_id,
                request,
                float(timeout),
                tuple(sorted(set(required))),
                require_model_call,
                require_gateway_token,
            )
        )
    return tuple(parsed)


def _normalize_spec(spec: Mapping[str, object]) -> Mapping[str, object]:
    try:
        encoded = json.dumps(spec, sort_keys=True, separators=(",", ":"))
        normalized = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise ValueError("module spec must be canonical JSON") from error
    if not isinstance(normalized, dict):
        raise ValueError("module spec must be an object")
    return normalized


def _build_module(spec: Mapping[str, object]) -> PolicyModule:
    kind = spec.get("kind")
    module_id = spec.get("id")
    if not isinstance(kind, str) or not isinstance(module_id, str):
        raise ValueError("module kind and id are required strings")
    if kind == "timing_relay_risk":
        _expect_keys(
            spec, {"kind", "id", "feed_path", "min_composite", "max_median_ms"}
        )
        return TimingRelayRiskModule(
            module_id=module_id,
            feed_path=Path(_string(spec, "feed_path")),
            min_composite=_number(spec, "min_composite"),
            max_median_ms=_integer(spec, "max_median_ms"),
        )
    if kind == "random_audit":
        _expect_keys(spec, {"kind", "id", "rate_basis_points", "seed_env"})
        return RandomAuditModule(
            module_id=module_id,
            rate_basis_points=_integer(spec, "rate_basis_points"),
            seed_env=_string(spec, "seed_env"),
        )
    if kind == "source_fingerprint":
        _expect_keys(
            spec,
            {"kind", "id", "known_source_digests", "suspicious_path_suffixes"},
        )
        return SourceFingerprintTriageModule(
            module_id=module_id,
            known_source_digests=frozenset(_string_list(spec, "known_source_digests")),
            suspicious_path_suffixes=tuple(
                _string_list(spec, "suspicious_path_suffixes")
            ),
        )
    if kind == "agentic_source_review":
        _expect_keys(spec, {"kind", "id"})
        return AgenticSourceReviewModule(module_id=module_id)
    if kind == "behavioral_challenge_pack":
        _expect_keys(spec, {"kind", "id", "pack_path"})
        return BehavioralChallengePackModule(
            module_id=module_id, pack_path=Path(_string(spec, "pack_path"))
        )
    if kind == "behavioral_oracle":
        _expect_keys(spec, {"kind", "id"})
        return BehavioralOracleModule(module_id=module_id)
    raise ValueError(f"unsupported policy module kind {kind!r}")


def _expect_keys(spec: Mapping[str, object], expected: set[str]) -> None:
    if set(spec) != expected:
        raise ValueError("module spec has unexpected fields")


def _string(spec: Mapping[str, object], key: str) -> str:
    value = spec.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _integer(spec: Mapping[str, object], key: str) -> int:
    value = spec.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{key} must be an integer")
    return value


def _number(spec: Mapping[str, object], key: str) -> float:
    value = spec.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{key} must be a number")
    return float(value)


def _string_list(spec: Mapping[str, object], key: str) -> list[str]:
    value = spec.get(key)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"{key} must be a list of non-empty strings")
    return value


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and set(value) <= _SHA256_HEX


__all__ = [
    "CORE_ONLY_MANIFEST",
    "DEFAULT_V8_MANIFEST",
    "ChallengeObservation",
    "PolicyContext",
    "PolicyEngine",
    "PolicyEvidence",
    "PolicyManifest",
    "ReviewJournal",
    "SourceReviewObservation",
    "ScreeningDecision",
    "ScreeningOutcome",
    "core_decision",
    "load_policy_engine",
]
