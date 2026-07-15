"""Bounds and digest-binding for the quarantine review wire payloads."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from ditto_screening_protocol import (
    SCREENING_POLICY_VERSION,
    ScreenEvidenceItem,
    ScreenResultOutcome,
    ScreenResultRequest,
    SourceReviewFinding,
)

_HOTKEY = "5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm"


def _finding() -> SourceReviewFinding:
    return SourceReviewFinding(
        artifact_sha256="de" * 32,
        prompt_revision="source-review-v2",
        risk_level="medium",
        confidence=0.8,
        categories=["suspicious_static_tables"],
        evidence=[
            {"path": "src/table.rs", "line": 3, "category": "suspicious_static_tables"}
        ],
        summary="Large static answer table shapes the response path.",
    )


def _request(**overrides: object) -> ScreenResultRequest:
    finding = _finding()
    base: dict[str, object] = {
        "screener_hotkey": _HOTKEY,
        "attempt_id": uuid4(),
        "signature": "ab" * 64,
        "passed": False,
        "outcome": ScreenResultOutcome.QUARANTINE,
        "policy_version": SCREENING_POLICY_VERSION,
        "manifest_digest": "ab" * 32,
        "finding_digest": finding.canonical_digest(),
        "reason_code": "agentic-source-review-tripwire",
        "evidence": [
            ScreenEvidenceItem(
                module_id="luna-source-review",
                code="agentic-source-review-tripwire",
                summary="private source analysis selected a behavioral audit",
                digest=finding.canonical_digest(),
            )
        ],
        "finding": finding,
    }
    base.update(overrides)
    return ScreenResultRequest.model_validate(base)


def test_canonical_digest_is_stable_and_order_insensitive() -> None:
    one = _finding()
    two = SourceReviewFinding.model_validate(one.model_dump(mode="json"))
    assert one.canonical_digest() == two.canonical_digest()
    reordered = one.model_copy(
        update={"categories": list(reversed([*one.categories, "prompt_injection"]))}
    )
    rebuilt = one.model_copy(
        update={"categories": [*one.categories, "prompt_injection"]}
    )
    assert reordered.canonical_digest() == rebuilt.canonical_digest()


def test_quarantine_request_accepts_digest_bound_finding() -> None:
    request = _request()
    assert request.finding is not None
    assert request.finding.canonical_digest() == request.finding_digest


def test_finding_digest_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError, match="does not match finding_digest"):
        _request(finding_digest="ef" * 32)


def test_finding_without_digest_is_rejected() -> None:
    with pytest.raises(ValidationError, match="finding requires finding_digest"):
        _request(finding_digest=None)


def test_review_payloads_require_review_outcome() -> None:
    with pytest.raises(ValidationError, match="require a review outcome"):
        _request(
            passed=True,
            outcome=ScreenResultOutcome.PASS,
            manifest_digest=None,
            reason_code=None,
            finding=None,
        )


def test_evidence_list_is_bounded() -> None:
    item = ScreenEvidenceItem(
        module_id="m", code="c", summary="bounded public-safe summary"
    )
    with pytest.raises(ValidationError):
        _request(evidence=[item] * 17)
