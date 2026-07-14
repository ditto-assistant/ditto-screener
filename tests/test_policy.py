"""Contract tests for typed private outcomes and daily module rotations."""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID

from ditto_screener.policy import (
    CORE_V6_MANIFEST,
    BehavioralChallengePackModule,
    ChallengeObservation,
    PolicyContext,
    PolicyEngine,
    PolicyManifest,
    ReviewJournal,
    ScreeningOutcome,
    SourceFingerprintTriageModule,
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
    )


async def test_core_v6_pass_never_calls_run() -> None:
    calls = 0

    async def challenge(*_):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        raise AssertionError("core-only v6 must not call /run")

    decision = await PolicyEngine(CORE_V6_MANIFEST).evaluate(_context(challenge))
    assert decision.outcome == ScreeningOutcome.PASS
    assert decision.submits_verdict and decision.passed
    assert calls == 0


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


def test_manifest_rotation_changes_digest_not_policy_or_signature_contract(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "policy_version": 6,
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
    assert engine.manifest.policy_version == SCREENING_POLICY_VERSION == 6
    assert engine.manifest.digest != CORE_V6_MANIFEST.digest


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
    assert snapshot["screening_policy_version"] == SCREENING_POLICY_VERSION == 6
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
