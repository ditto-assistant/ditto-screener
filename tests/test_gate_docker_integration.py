"""Real-Docker core-v6 coverage for build, isolated startup, and health."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest

from ditto_screener.config import ScreenerConfig
from ditto_screener.gate import BuildGate
from ditto_screener.policy import (
    CORE_ONLY_MANIFEST,
    BehavioralChallengePackModule,
    PolicyEngine,
    PolicyManifest,
    ReviewJournal,
    SourceFingerprintTriageModule,
    load_policy_engine,
)


@pytest.mark.integration
async def test_current_starter_kit_builds_and_health_checks_without_run(
    make_config: Any, tmp_path: Path
) -> None:
    archive_raw = os.environ.get("DITTO_STARTER_KIT_ARCHIVE")
    starter_dir_raw = os.environ.get("DITTO_STARTER_KIT_DIR")
    if archive_raw:
        tarball = Path(archive_raw).resolve().read_bytes()
    else:
        if not starter_dir_raw:
            pytest.skip("set DITTO_STARTER_KIT_DIR to a current canonical checkout")
        starter_dir = Path(starter_dir_raw).resolve()
        archive = tmp_path / "dittobench-starter-kit.tar.gz"
        with archive.open("wb") as output:
            subprocess.run(
                ["git", "-C", str(starter_dir), "archive", "--format=tar.gz", "HEAD"],
                check=True,
                stdout=output,
            )
        tarball = archive.read_bytes()

    def artifact(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://artifact.test/starter-kit.tar.gz")
        return httpx.Response(200, content=tarball)

    config: ScreenerConfig = make_config(
        build_timeout_seconds=1200.0,
        run_timeout_seconds=120.0,
        max_tarball_bytes=20 * 1024 * 1024,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(artifact))
    gate = BuildGate(
        config,
        client,
        policy=PolicyEngine(CORE_ONLY_MANIFEST),
        journal=ReviewJournal(None),
    )
    challenge_calls = 0
    real_challenge = gate._run_private_challenge

    async def observed_challenge(*args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
        nonlocal challenge_calls
        challenge_calls += 1
        return await real_challenge(*args, **kwargs)

    gate._run_private_challenge = observed_challenge  # type: ignore[method-assign]
    async with client:
        result = await gate.screen(
            agent_id=uuid4(),
            attempt_id=uuid4(),
            miner_hotkey="5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm",
            sha256=hashlib.sha256(tarball).hexdigest(),
            download_url="https://artifact.test/starter-kit.tar.gz",
        )

    assert result.passed, result.detail
    assert challenge_calls == 0


@pytest.mark.integration
async def test_current_starter_kit_clears_model_binding_audit(
    make_config: Any, tmp_path: Path
) -> None:
    starter_dir_raw = os.environ.get("DITTO_STARTER_KIT_DIR")
    if not starter_dir_raw:
        pytest.skip("set DITTO_STARTER_KIT_DIR to a current canonical checkout")
    starter_dir = Path(starter_dir_raw).resolve()
    archive = tmp_path / "dittobench-starter-kit-audit.tar.gz"
    with archive.open("wb") as output:
        subprocess.run(
            ["git", "-C", str(starter_dir), "archive", "--format=tar.gz", "HEAD"],
            check=True,
            stdout=output,
        )
    tarball = archive.read_bytes()
    pack = tmp_path / "private-control-pack.json"
    pack.write_text(
        json.dumps(
            {
                "challenges": [
                    {
                        "id": "rotating-private-control",
                        "request": {
                            "case_id": "private-control",
                            "system_prompt": "Answer the user concisely.",
                            "user_input": "Return a short acknowledgement.",
                            "tools": [],
                        },
                        "timeout_seconds": 60,
                        "required_response_keys": ["final_text", "tool_calls"],
                        "require_model_call": True,
                        "require_gateway_token": True,
                    }
                ]
            }
        )
    )
    selector = SourceFingerprintTriageModule(
        module_id="starter-control-selector",
        suspicious_path_suffixes=("src/baseline.rs",),
    )
    challenge = BehavioralChallengePackModule(
        module_id="model-binding-control", pack_path=pack
    )
    manifest = PolicyManifest(
        rotation_id="integration-control",
        module_specs=(
            {"kind": "source_fingerprint"},
            {"kind": "behavioral_challenge_pack"},
        ),
    )

    def artifact(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://artifact.test/starter-kit.tar.gz")
        return httpx.Response(200, content=tarball)

    config: ScreenerConfig = make_config(
        build_timeout_seconds=1200.0,
        run_timeout_seconds=120.0,
        max_tarball_bytes=20 * 1024 * 1024,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(artifact))
    gate = BuildGate(
        config,
        client,
        policy=PolicyEngine(manifest, (selector, challenge)),
        journal=ReviewJournal(None),
    )
    async with client:
        result = await gate.screen(
            agent_id=uuid4(),
            attempt_id=uuid4(),
            miner_hotkey="5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm",
            sha256=hashlib.sha256(tarball).hexdigest(),
            download_url="https://artifact.test/starter-kit.tar.gz",
        )

    assert result.passed, result.detail
    assert any(item.code == "challenge-observed" for item in result.evidence)


@pytest.mark.integration
async def test_current_starter_kit_passes_real_default_v7_luna_review(
    make_config: Any, tmp_path: Path
) -> None:
    starter_dir_raw = os.environ.get("DITTO_STARTER_KIT_DIR")
    key_file = os.environ.get("SCREENER_SOURCE_REVIEW_API_KEY_FILE")
    if not starter_dir_raw or not key_file:
        pytest.skip("set starter-kit directory and protected source-review key")
    archive = tmp_path / "dittobench-starter-kit-v7.tar.gz"
    with archive.open("wb") as output:
        subprocess.run(
            [
                "git",
                "-C",
                str(Path(starter_dir_raw).resolve()),
                "archive",
                "--format=tar.gz",
                "HEAD",
            ],
            check=True,
            stdout=output,
        )
    tarball = archive.read_bytes()

    def artifact(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://artifact.test/starter-kit.tar.gz")
        return httpx.Response(200, content=tarball)

    config: ScreenerConfig = make_config(
        build_timeout_seconds=1200.0,
        run_timeout_seconds=120.0,
        max_tarball_bytes=20 * 1024 * 1024,
        source_review_api_key_file=key_file,
    )
    client = httpx.AsyncClient(transport=httpx.MockTransport(artifact))
    gate = BuildGate(
        config,
        client,
        policy=load_policy_engine(None),
        journal=ReviewJournal(None),
    )
    async with client:
        result = await gate.screen(
            agent_id=uuid4(),
            attempt_id=uuid4(),
            miner_hotkey="5DhaT8U7LVwnnJNUU8VL1XEipicatoaDVVq7cHo227gogVZm",
            sha256=hashlib.sha256(tarball).hexdigest(),
            download_url="https://artifact.test/starter-kit.tar.gz",
        )

    assert result.passed, result.detail
