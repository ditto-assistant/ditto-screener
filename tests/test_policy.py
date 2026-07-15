"""Contract tests for typed private outcomes and daily module rotations."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID

import pytest

from ditto_screener.policy import (
    CORE_ONLY_MANIFEST,
    AgenticSourceReviewModule,
    BehavioralChallengePackModule,
    ChallengeObservation,
    PolicyContext,
    PolicyEngine,
    PolicyManifest,
    ReviewJournal,
    ScreeningOutcome,
    SourceFingerprintTriageModule,
    SourceReviewObservation,
    TimingRelayRiskModule,
    core_decision,
    load_policy_engine,
)
from ditto_screening_protocol import SCREENING_POLICY_VERSION

_AGENT = UUID("4f2a1309-f763-4d40-9326-9eb7d13339e8")
_ATTEMPT = UUID("7c5df3f9-3ea7-47ba-92d1-1bbcf4c5f300")
_DIGEST = "de" * 32


def _context(  # type: ignore[no-untyped-def]
    challenge,
    review_source=None,
) -> PolicyContext:
    return PolicyContext(
        agent_id=_AGENT,
        attempt_id=_ATTEMPT,
        miner_hotkey="5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm",
        artifact_sha256=_DIGEST,
        source_digest=_DIGEST,
        source_paths=("Cargo.toml", "Dockerfile", "src/main.rs"),
        build_elapsed_ms=100,
        health_elapsed_ms=20,
        run_challenge=challenge,
        review_source=review_source,
    )


def _model_binding_engine(tmp_path: Path) -> PolicyEngine:
    pack = tmp_path / "rotating-pack.json"
    pack.write_text(
        json.dumps(
            {
                "challenges": [
                    {
                        "id": "rotating-private-control",
                        "request": {"case_id": "private-control"},
                        "timeout_seconds": 10,
                        "required_response_keys": ["final_text", "tool_calls"],
                        "require_model_call": True,
                        "require_gateway_token": True,
                    }
                ]
            }
        )
    )
    selector = SourceFingerprintTriageModule(
        module_id="private-selector",
        known_source_digests=frozenset({_DIGEST}),
    )
    challenge = BehavioralChallengePackModule(module_id="model-binding", pack_path=pack)
    manifest = PolicyManifest(
        rotation_id="private-control",
        module_specs=(
            {"kind": "source_fingerprint"},
            {"kind": "behavioral_challenge_pack"},
        ),
    )
    return PolicyEngine(manifest, (selector, challenge))


async def test_core_only_pass_never_calls_run() -> None:
    calls = 0

    async def challenge(*_):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        raise AssertionError("core-only policy must not call /run")

    decision = await PolicyEngine(CORE_ONLY_MANIFEST).evaluate(_context(challenge))
    assert decision.outcome == ScreeningOutcome.PASS
    assert decision.submits_verdict and decision.passed
    assert calls == 0


async def test_default_v7_runs_luna_review_and_passes_low_risk() -> None:
    reviews = 0

    async def challenge(*_):  # type: ignore[no-untyped-def]
        raise AssertionError("default v7 must not call /run")

    async def review() -> SourceReviewObservation:
        nonlocal reviews
        reviews += 1
        return SourceReviewObservation(
            ok=True,
            risk_level="low",
            finding_digest=None,
            categories=("none",),
        )

    engine = load_policy_engine(None)
    decision = await engine.evaluate(_context(challenge, review))

    assert engine.manifest.rotation_id == "v7-luna-source-review"
    assert decision.outcome == ScreeningOutcome.PASS
    assert reviews == 1


async def test_timing_is_only_a_tripwire_and_routes_to_quarantine(
    tmp_path: Path,
) -> None:
    feed = tmp_path / "risk.json"
    feed.write_text(json.dumps({str(_AGENT): {"composite": 0.999, "median_ms": 3}}))
    module = TimingRelayRiskModule(module_id="timing", feed_path=feed)
    manifest = PolicyManifest(
        rotation_id="daily-1",
        module_specs=({"kind": "timing_relay_risk"},),
    )
    engine = PolicyEngine(manifest, (module,))

    async def no_challenge(*_):  # type: ignore[no-untyped-def]
        raise AssertionError

    decision = await engine.evaluate(_context(no_challenge))
    assert decision.outcome == ScreeningOutcome.QUARANTINE
    assert not decision.submits_verdict
    assert all(item.code != "deterministic_reject" for item in decision.evidence)


async def test_agentic_source_review_can_only_select_quarantine() -> None:
    async def challenge(*_):  # type: ignore[no-untyped-def]
        raise AssertionError("no behavioral pack is configured")

    async def review() -> SourceReviewObservation:
        return SourceReviewObservation(
            ok=True,
            risk_level="high",
            finding_digest="ab" * 32,
            categories=("provider_bypass",),
        )

    module = AgenticSourceReviewModule(module_id="private-source-review")
    engine = PolicyEngine(
        PolicyManifest(
            rotation_id="source-review",
            module_specs=({"kind": "agentic_source_review"},),
        ),
        (module,),
    )
    decision = await engine.evaluate(_context(challenge, review))
    assert decision.outcome == ScreeningOutcome.QUARANTINE
    assert not decision.submits_verdict
    assert decision.evidence[0].code == "source-safety-private-challenge-risk"


@pytest.mark.parametrize(
    ("category", "expected_code"),
    [
        ("hidden_value_leakage", "source-safety-private-challenge-risk"),
        ("embedded_secret", "source-safety-malicious-risk"),
        ("data_exfiltration", "source-safety-malicious-risk"),
        ("malicious_build", "source-safety-malicious-risk"),
        ("cross_user_access", "source-safety-malicious-risk"),
        ("duplicate_submission", "originality-duplicate-risk"),
    ],
)
async def test_adversarial_and_originality_risks_remain_quarantined(
    category: str, expected_code: str
) -> None:
    async def challenge(*_):  # type: ignore[no-untyped-def]
        raise AssertionError("no private challenge is required to retain the hold")

    async def review() -> SourceReviewObservation:
        return SourceReviewObservation(
            ok=True,
            risk_level="high",
            finding_digest="ab" * 32,
            categories=(category,),
        )

    engine = PolicyEngine(
        PolicyManifest(
            rotation_id="risk-domain-regression",
            module_specs=({"kind": "agentic_source_review"},),
        ),
        (AgenticSourceReviewModule(module_id="private-source-review"),),
    )
    decision = await engine.evaluate(_context(challenge, review))

    assert decision.outcome == ScreeningOutcome.QUARANTINE
    assert decision.evidence[-1].code == expected_code
    assert all(
        item.code != "audit-awaiting-private-challenge" for item in decision.evidence
    )


async def test_low_risk_label_cannot_clear_a_malicious_category() -> None:
    async def challenge(*_):  # type: ignore[no-untyped-def]
        raise AssertionError

    async def review() -> SourceReviewObservation:
        return SourceReviewObservation(
            ok=True,
            risk_level="low",
            finding_digest="ab" * 32,
            categories=("embedded_secret",),
        )

    engine = PolicyEngine(
        PolicyManifest(
            rotation_id="inconsistent-review-regression",
            module_specs=({"kind": "agentic_source_review"},),
        ),
        (AgenticSourceReviewModule(module_id="private-source-review"),),
    )
    decision = await engine.evaluate(_context(challenge, review))

    assert decision.outcome == ScreeningOutcome.QUARANTINE
    assert decision.evidence[-1].code == "source-safety-malicious-risk"


async def test_tripwire_plus_behavioral_shape_anomaly_stays_quarantine(
    tmp_path: Path,
) -> None:
    pack = tmp_path / "pack.json"
    pack.write_text(
        json.dumps(
            {
                "challenges": [
                    {
                        "id": "rotating-private-case",
                        "request": {"case_id": "private"},
                        "timeout_seconds": 10,
                        "required_response_keys": ["final_text", "tool_calls"],
                    }
                ]
            }
        )
    )
    selector = SourceFingerprintTriageModule(
        module_id="fingerprint", known_source_digests=frozenset({_DIGEST})
    )
    challenge_module = BehavioralChallengePackModule(
        module_id="behavior", pack_path=pack
    )
    manifest = PolicyManifest(
        rotation_id="daily-2",
        module_specs=(
            {"kind": "source_fingerprint"},
            {"kind": "behavioral_challenge_pack"},
        ),
    )
    engine = PolicyEngine(manifest, (selector, challenge_module))

    async def observe(challenge_id, request, timeout):  # type: ignore[no-untyped-def]
        assert challenge_id == "rotating-private-case"
        assert request == {"case_id": "private"} and timeout == 10
        return ChallengeObservation(
            challenge_id=challenge_id,
            ok=True,
            response_digest="ab" * 32,
            elapsed_ms=2,
            json_keys=("final_text",),
        )

    decision = await engine.evaluate(_context(observe))
    assert decision.outcome == ScreeningOutcome.QUARANTINE
    assert not decision.submits_verdict
    assert any(item.code == "challenge-shape-anomaly" for item in decision.evidence)


async def test_inconclusive_challenge_is_not_a_rejection(tmp_path: Path) -> None:
    pack = tmp_path / "pack.json"
    pack.write_text(
        json.dumps(
            {
                "challenges": [
                    {
                        "id": "case",
                        "request": {},
                        "timeout_seconds": 5,
                        "required_response_keys": [],
                    }
                ]
            }
        )
    )
    selector = SourceFingerprintTriageModule(
        module_id="fingerprint", known_source_digests=frozenset({_DIGEST})
    )
    challenge_module = BehavioralChallengePackModule(
        module_id="behavior", pack_path=pack
    )
    manifest = PolicyManifest(
        rotation_id="daily-3", module_specs=({"kind": "x"}, {"kind": "y"})
    )

    async def observe(*_):  # type: ignore[no-untyped-def]
        return ChallengeObservation("case", False, None, 100, error_code="timeout")

    decision = await PolicyEngine(manifest, (selector, challenge_module)).evaluate(
        _context(observe)
    )
    assert decision.outcome == ScreeningOutcome.INCONCLUSIVE
    assert not decision.submits_verdict


async def test_canonical_starter_control_clears_ephemeral_model_binding(
    tmp_path: Path,
) -> None:
    """Model a canonical kit response that propagates the fake gateway output."""

    async def observe(*_):  # type: ignore[no-untyped-def]
        return ChallengeObservation(
            "rotating-private-control",
            True,
            "ab" * 32,
            75,
            json_keys=("final_text", "tool_calls"),
            gateway_calls=1,
            gateway_token_observed=True,
        )

    decision = await _model_binding_engine(tmp_path).evaluate(_context(observe))
    assert decision.outcome == ScreeningOutcome.PASS
    assert decision.submits_verdict and decision.passed


async def test_benchmark_shortcut_fixture_is_quarantined_not_rejected(
    tmp_path: Path,
) -> None:
    """A valid-looking hardcoded response without a model call is review evidence."""

    async def observe(*_):  # type: ignore[no-untyped-def]
        return ChallengeObservation(
            "rotating-private-control",
            True,
            "cd" * 32,
            1,
            json_keys=("final_text", "tool_calls"),
            gateway_calls=0,
            gateway_token_observed=False,
        )

    decision = await _model_binding_engine(tmp_path).evaluate(_context(observe))
    assert decision.outcome == ScreeningOutcome.QUARANTINE
    assert not decision.submits_verdict
    assert any(
        item.code == "challenge-model-call-missing" for item in decision.evidence
    )


async def test_dummy_model_call_without_dataflow_is_quarantined(
    tmp_path: Path,
) -> None:
    async def observe(*_):  # type: ignore[no-untyped-def]
        return ChallengeObservation(
            "rotating-private-control",
            True,
            "ef" * 32,
            2,
            json_keys=("final_text", "tool_calls"),
            gateway_calls=1,
            gateway_token_observed=False,
        )

    decision = await _model_binding_engine(tmp_path).evaluate(_context(observe))
    assert decision.outcome == ScreeningOutcome.QUARANTINE
    assert any(
        item.code == "challenge-gateway-token-missing" for item in decision.evidence
    )


async def test_shape_only_pack_preserves_non_model_harness_compatibility(
    tmp_path: Path,
) -> None:
    """Legacy/private audits opt into model binding explicitly."""
    pack = tmp_path / "shape-only.json"
    pack.write_text(
        json.dumps(
            {
                "challenges": [
                    {
                        "id": "shape",
                        "request": {},
                        "timeout_seconds": 5,
                        "required_response_keys": ["final_text"],
                    }
                ]
            }
        )
    )
    selector = SourceFingerprintTriageModule(
        module_id="selector", known_source_digests=frozenset({_DIGEST})
    )
    challenge = BehavioralChallengePackModule(module_id="shape", pack_path=pack)
    engine = PolicyEngine(
        PolicyManifest(rotation_id="shape", module_specs=({"a": 1}, {"b": 2})),
        (selector, challenge),
    )

    async def observe(*_):  # type: ignore[no-untyped-def]
        return ChallengeObservation(
            "shape",
            True,
            "12" * 32,
            1,
            json_keys=("final_text",),
        )

    decision = await engine.evaluate(_context(observe))
    assert decision.outcome == ScreeningOutcome.PASS


def test_manifest_rotation_changes_digest_not_policy_or_signature_contract(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "policy_version": 7,
                "rotation_id": "2026-07-14-private",
                "modules": [
                    {
                        "kind": "random_audit",
                        "id": "controls",
                        "rate_basis_points": 500,
                        "seed_env": "SCREENER_AUDIT_SEED",
                    }
                ],
            }
        )
    )
    engine = load_policy_engine(str(manifest))
    assert engine.manifest.policy_version == SCREENING_POLICY_VERSION == 7
    assert engine.manifest.digest != CORE_ONLY_MANIFEST.digest


def test_review_journal_is_bounded_private_and_mode_0600(tmp_path: Path) -> None:
    journal_path = tmp_path / "private" / "review.jsonl"
    journal = ReviewJournal(str(journal_path))

    async def challenge(*_):  # type: ignore[no-untyped-def]
        raise AssertionError

    context = _context(challenge)
    decision = core_decision(
        ScreeningOutcome.QUARANTINE,
        code="private-review",
        summary="operator review required",
        detail="private policy quarantine pending operator review",
    )
    journal.record(context=context, decision=decision)
    row = json.loads(journal_path.read_text())
    assert row["agent_id"] == str(_AGENT)
    assert row["attempt_id"] == str(_ATTEMPT)
    assert row["outcome"] == "quarantine"
    assert not os.stat(journal_path).st_mode & 0o077


def test_live_v6_snapshot_is_an_acceptance_fixture() -> None:
    fixture = Path(__file__).parent / "fixtures" / "production-v6-snapshot.json"
    snapshot = json.loads(fixture.read_text())
    assert snapshot["screening_policy_version"] == 6
    assert SCREENING_POLICY_VERSION == 7
    assert snapshot["queue"]["waiting_validator"] == 9
    assert snapshot["queue"]["evaluating"] == 1
    assert len(snapshot["rust_contract_rejections"]) == 6
    assert "not evidence" in snapshot["interpretation"].lower()
    decision = core_decision(
        ScreeningOutcome.DETERMINISTIC_REJECT,
        code="rust-harness-contract",
        summary="artifact does not satisfy the Rust harness contract",
        detail="contract failed: no Cargo.toml at tarball root",
    )
    assert decision.submits_verdict and not decision.passed
