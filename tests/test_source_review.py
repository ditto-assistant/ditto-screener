"""Agentic source-review controls for untrusted submission crates."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import IO

import httpx
import pytest

from ditto_screener import binary_analysis as binary_analysis_module
from ditto_screener import source_review as source_review_module
from ditto_screener.binary_analysis import BinarySample
from ditto_screener.source_review import (
    OpenRouterSourceReviewAgent,
    TarSourceRepository,
)
from ditto_screener.source_signals import find_source_review_leads
from ditto_screening_protocol import SourceReviewFinding

_SHA = "ab" * 32


def _archive(tmp_path: Path, source: str) -> Path:
    path = tmp_path / "agent.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, value in {
            "Cargo.toml": '[package]\nname="agent"\nversion="0.1.0"\n',
            "Dockerfile": "FROM scratch\n",
            "src/main.rs": source,
        }.items():
            raw = value.encode()
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return path


def _archive_files(tmp_path: Path, files: dict[str, bytes]) -> Path:
    path = tmp_path / "files.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return path


def _tool(call_id: str, name: str, arguments: dict[str, object]) -> dict[str, object]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def _transport(final: dict[str, object], seen: list[dict[str, object]]):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        payload = json.loads(request.content)
        seen.append(payload)
        assert request.headers["authorization"] == "Bearer sk-test-private-review"
        assert request.headers["http-referer"] == "https://heyditto.ai"
        assert request.headers["x-openrouter-title"] == "Ditto"
        if calls == 0:
            tool_calls = [
                _tool(
                    "read-1",
                    "read_file",
                    {"path": "src/main.rs", "start_line": 1, "end_line": 400},
                )
            ]
        else:
            tool_calls = [_tool("submit-1", "submit_review", final)]
        calls += 1
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": tool_calls,
                        }
                    }
                ]
            },
        )

    return httpx.MockTransport(handler)


def _agent(
    key_file: Path, transport: httpx.AsyncBaseTransport
) -> OpenRouterSourceReviewAgent:
    return OpenRouterSourceReviewAgent(
        api_key_file=str(key_file),
        model="openai/gpt-5.6-luna",
        base_url="https://openrouter.test/api/v1",
        timeout_seconds=10,
        max_steps=4,
        transport=transport,
    )


def _archive_with(tmp_path: Path, extra: dict[str, bytes]) -> Path:
    path = tmp_path / "agent.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        base = {
            "Cargo.toml": b'[package]\nname="agent"\nversion="0.1.0"\n',
            "Dockerfile": b"FROM scratch\n",
            "src/main.rs": b"fn main() {}\n",
        }
        base.update(extra)
        for name, raw in base.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    return path


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _pb_varint(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def _pb_bytes(field: int, value: bytes) -> bytes:
    return _varint((field << 3) | 2) + _varint(len(value)) + value


def _minimal_onnx() -> bytes:
    # ONNX ModelProto -> GraphProto -> NodeProto/TensorProto/ValueInfoProto.
    node = _pb_bytes(4, b"MatMul")
    tensor = (
        _pb_varint(2, 1)
        + _pb_bytes(8, b"reranker.weight")
        + _pb_bytes(9, b"\x00\xff\x02\x03")
    )
    value_info = _pb_bytes(1, b"embedding")
    graph = b"".join(
        [
            _pb_bytes(1, node),
            _pb_bytes(2, b"reranker"),
            _pb_bytes(5, tensor),
            _pb_bytes(11, value_info),
            _pb_bytes(12, value_info),
        ]
    )
    opset = _pb_bytes(1, b"") + _pb_varint(2, 18)
    return _pb_varint(1, 9) + _pb_bytes(7, graph) + _pb_bytes(8, opset)


def test_opaque_binary_blob_is_surfaced_in_inventory(tmp_path: Path) -> None:
    blob = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00secret-string-table\x00" * 8
    repo = TarSourceRepository(str(_archive_with(tmp_path, {"assets/table.bin": blob})))
    inventory = json.loads(repo.inventory())
    opaque = {entry["path"]: entry for entry in inventory["opaque_blobs"]}
    assert "assets/table.bin" in opaque
    assert opaque["assets/table.bin"]["reason"] == "non_utf8"
    assert opaque["assets/table.bin"]["bytes"] == len(blob)
    # A normal UTF-8 source file is not surfaced as opaque.
    assert "src/main.rs" not in opaque


def test_valid_onnx_is_structurally_analyzed_without_extension_trust(
    tmp_path: Path,
) -> None:
    model = _minimal_onnx()
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/reranker.bin": model}))
    )

    inventory = json.loads(repo.inventory())
    assert [item["path"] for item in inventory["opaque_blobs"]] == [
        "models/reranker.bin"
    ]
    assert inventory["binary_analysis"][0]["path"] == "models/reranker.bin"
    assert inventory["binary_analysis"][0]["format"] == "onnx"
    assert inventory["binary_analysis"][0]["details"]["operator_types"] == ["MatMul"]
    analysis = json.loads(repo.analyze_binary("models/reranker.bin"))

    assert analysis["format"] == "onnx"
    assert analysis["format_confidence"] == "high"
    assert analysis["details"]["graph_complete"] is True
    assert analysis["details"]["graph_parse_status"] == "complete"
    assert analysis["details"]["graph_name"] == "reranker"
    assert analysis["details"]["ir_version"] == 9
    assert analysis["details"]["node_count"] == 1
    assert analysis["details"]["initializer_count"] == 1
    assert analysis["details"]["initializer_bytes"] == 4
    assert analysis["details"]["input_count"] == 1
    assert analysis["details"]["output_count"] == 1
    assert analysis["details"]["operator_types"] == ["MatMul"]
    assert analysis["details"]["opsets"] == [{"domain": "", "version": 18}]
    assert analysis["details"]["external_data_references"] == 0
    assert analysis["details"]["metadata_complete"] is True
    assert analysis["details"]["model_parse_status"] == "complete"
    assert analysis["benchmark_schema_markers"] == []
    assert analysis["safety"] == {
        "decompressed_payloads": False,
        "executed": False,
        "external_data_loaded": False,
    }


def test_onnx_suffix_does_not_hide_renamed_answer_registry(tmp_path: Path) -> None:
    registry = (
        b"\xff\x00expected_answer\x00answer_items\x00forbidden_answer\x00"
        b"memory_cases\x00run_after_wave\x00tool_cases\x00"
    )
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/answers.onnx": registry}))
    )

    analysis = json.loads(repo.analyze_binary("models/answers.onnx"))

    assert analysis["format"] == "binary-data"
    assert analysis["benchmark_schema_markers"] == [
        "answer_items",
        "expected_answer",
        "forbidden_answer",
        "memory_cases",
        "run_after_wave",
        "tool_cases",
    ]
    inventory = json.loads(repo.inventory())
    assert any(
        item["path"] == "models/answers.onnx" for item in inventory["opaque_blobs"]
    )
    assert inventory["binary_analysis"][0]["format"] == "binary-data"
    assert inventory["binary_analysis"][0]["benchmark_schema_markers"] == [
        "answer_items",
        "expected_answer",
        "forbidden_answer",
        "memory_cases",
        "run_after_wave",
        "tool_cases",
    ]


def test_analyze_binary_reports_executable_and_archive_structure(
    tmp_path: Path,
) -> None:
    elf = bytearray(64)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    elf[16:20] = struct.pack("<HH", 2, 62)
    elf[24:32] = struct.pack("<Q", 0x401000)
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("dataset/memory_cases.json", b'{"expected_answer":"x"}')

    repo = TarSourceRepository(
        str(
            _archive_with(
                tmp_path,
                {
                    "bin/agent": bytes(elf),
                    "fixtures/public-dataset.zip": archive_buffer.getvalue(),
                },
            )
        )
    )

    executable = json.loads(repo.analyze_binary("bin/agent"))
    bundled = json.loads(repo.analyze_binary("fixtures/public-dataset.zip"))

    assert executable["format"] == "elf"
    assert executable["details"] == {
        "bits": 64,
        "byte_order": "little",
        "entrypoint": 0x401000,
        "machine": 62,
        "os_abi": 0,
        "type": 2,
    }
    assert bundled["format"] == "zip"
    assert bundled["details"]["entry_count"] == 1
    assert bundled["details"]["entries"][0]["path"] == ("dataset/memory_cases.json")
    assert bundled["safety"]["decompressed_payloads"] is False


def test_analyze_binary_reports_safetensors_without_loading_weights(
    tmp_path: Path,
) -> None:
    header = json.dumps(
        {
            "reranker.weight": {
                "dtype": "F32",
                "shape": [2, 2],
                "data_offsets": [0, 16],
            },
            "__metadata__": {"framework": "competition-reranker"},
        },
        separators=(",", ":"),
    ).encode()
    model = len(header).to_bytes(8, "little") + header + b"\xff" * 16
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/reranker.weights": model}))
    )

    analysis = json.loads(repo.analyze_binary("models/reranker.weights"))

    assert analysis["format"] == "safetensors"
    assert analysis["details"]["tensor_count"] == 1
    assert analysis["details"]["tensor_bytes"] == 16
    assert analysis["details"]["tensors"] == [
        {
            "bytes": 16,
            "dtype": "F32",
            "name": "reranker.weight",
            "shape": [2, 2],
        }
    ]
    assert analysis["safety"]["external_data_loaded"] is False


def test_safetensors_rejects_invalid_and_overlapping_payload_ranges(
    tmp_path: Path,
) -> None:
    header = json.dumps(
        {
            "valid": {"dtype": "U8", "shape": [8], "data_offsets": [0, 8]},
            "negative": {"dtype": "U8", "shape": [1], "data_offsets": [-1, 0]},
            "descending": {
                "dtype": "U8",
                "shape": [1],
                "data_offsets": [9, 8],
            },
            "outside": {"dtype": "U8", "shape": [1], "data_offsets": [16, 17]},
            "overlap": {"dtype": "U8", "shape": [8], "data_offsets": [4, 12]},
            "boolean": {"dtype": "U8", "shape": [1], "data_offsets": [False, 1]},
        },
        separators=(",", ":"),
    ).encode()
    model = len(header).to_bytes(8, "little") + header + b"\xff" * 16
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/untrusted.weights": model}))
    )

    analysis = json.loads(repo.analyze_binary("models/untrusted.weights"))

    assert analysis["format"] == "safetensors"
    assert analysis["format_confidence"] == "medium"
    assert analysis["details"]["tensor_count"] == 1
    assert analysis["details"]["tensor_bytes"] == 8
    assert analysis["details"]["invalid_tensor_ranges"] == 5
    assert analysis["details"]["payload_available"] is False


def test_safetensors_without_declared_payload_is_not_high_confidence(
    tmp_path: Path,
) -> None:
    header = json.dumps(
        {
            "missing": {
                "dtype": "F32",
                "shape": [2, 2],
                "data_offsets": [0, 16],
            }
        },
        separators=(",", ":"),
    ).encode()
    model = len(header).to_bytes(8, "little") + header
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/missing-payload.weights": model}))
    )

    analysis = json.loads(repo.analyze_binary("models/missing-payload.weights"))

    assert analysis["format"] != "safetensors"
    assert analysis["format_confidence"] != "high"


def test_onnx_truncated_top_level_parse_is_partial(tmp_path: Path) -> None:
    model = _minimal_onnx() + _pb_varint(2, 128)[:-1]
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/truncated.onnx": model}))
    )

    analysis = json.loads(repo.analyze_binary("models/truncated.onnx"))

    assert analysis["format"] == "onnx"
    assert analysis["format_confidence"] == "medium"
    assert analysis["details"]["model_parse_status"] == "truncated"
    assert analysis["details"]["metadata_complete"] is False


def test_onnx_field_cap_is_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(binary_analysis_module, "_MAX_PROTO_FIELDS", 2)
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/capped.onnx": _minimal_onnx()}))
    )

    analysis = json.loads(repo.analyze_binary("models/capped.onnx"))

    assert analysis["format"] == "onnx"
    assert analysis["format_confidence"] == "medium"
    assert analysis["details"]["model_parse_status"] == "field_limit"
    assert analysis["details"]["metadata_complete"] is False


def test_onnx_truncated_nested_graph_is_partial(tmp_path: Path) -> None:
    graph = _pb_bytes(1, _pb_bytes(4, b"MatMul")) + b"\x10\x80"
    model = _pb_varint(1, 9) + _pb_bytes(7, graph)
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/partial-graph.onnx": model}))
    )

    analysis = json.loads(repo.analyze_binary("models/partial-graph.onnx"))

    assert analysis["format"] == "onnx"
    assert analysis["format_confidence"] == "medium"
    assert analysis["details"]["graph_parse_status"] == "truncated"
    assert analysis["details"]["graph_complete"] is False
    assert analysis["details"]["metadata_complete"] is False


def test_analyze_binary_surfaces_datagen_schema_inside_sqlite(tmp_path: Path) -> None:
    database = tmp_path / "answers.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE memory_cases "
        "(expected_answer TEXT, answer_items TEXT, forbidden_answer TEXT)"
    )
    connection.commit()
    connection.close()
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"cache/retrieval.db": database.read_bytes()}))
    )

    analysis = json.loads(repo.analyze_binary("cache/retrieval.db"))

    assert analysis["format"] == "sqlite3"
    assert analysis["details"]["page_size"] == 4096
    assert analysis["benchmark_schema_markers"] == [
        "answer_items",
        "expected_answer",
        "forbidden_answer",
        "memory_cases",
    ]


def test_analyze_binary_is_bounded_and_labels_partial_analysis(tmp_path: Path) -> None:
    oversized = b"\xff" + b"x" * (8 * 1024 * 1024 + 1)
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/large.weights": oversized}))
    )

    analysis = json.loads(repo.analyze_binary("models/large.weights"))

    assert analysis["bytes"] == len(oversized)
    assert analysis["analyzed_bytes"] == 8 * 1024 * 1024
    assert analysis["analysis_truncated"] is True
    assert len(analysis["sha256"]) == 64
    assert analysis["sha256_complete"] is True
    assert analysis["sha256_bytes"] == len(oversized)


def test_binary_hashing_has_an_expanded_member_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(binary_analysis_module, "_MAX_HASHED_BYTES", 16)

    sample = binary_analysis_module.sample_stream(io.BytesIO(b"x" * 64), size=64)
    analysis = binary_analysis_module.analyze_binary(sample, path="data/bomb.bin")

    assert sample.hashed_bytes == 16
    assert sample.hash_complete is False
    assert analysis["sha256_bytes"] == 16
    assert analysis["sha256_complete"] is False
    assert analysis["analysis_truncated"] is True


def test_analyze_binary_rejects_missing_member(tmp_path: Path) -> None:
    repo = TarSourceRepository(str(_archive_with(tmp_path, {})))
    assert json.loads(repo.analyze_binary("missing.onnx")) == {
        "error": "file-not-found"
    }


def test_inventory_preanalysis_is_reused_by_agent_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0
    original = source_review_module.sample_stream

    def counting_sample_stream(stream: IO[bytes], *, size: int) -> BinarySample:
        nonlocal calls
        calls += 1
        return original(stream, size=size)

    monkeypatch.setattr(source_review_module, "sample_stream", counting_sample_stream)
    repo = TarSourceRepository(
        str(_archive_with(tmp_path, {"models/reranker.onnx": _minimal_onnx()}))
    )

    inventory = json.loads(repo.inventory())
    detailed = json.loads(repo.analyze_binary("models/reranker.onnx"))

    assert inventory["binary_analysis"][0]["sha256"] == detailed["sha256"]
    assert calls == 1


def test_oversized_file_is_surfaced_as_opaque(tmp_path: Path) -> None:
    big = b"a" * (2 * 1024 * 1024 + 16)
    repo = TarSourceRepository(str(_archive_with(tmp_path, {"data/big.txt": big})))
    opaque = json.loads(repo.inventory())["opaque_blobs"]
    assert any(
        entry["path"] == "data/big.txt" and entry["reason"] == "oversized"
        for entry in opaque
    )


def test_utf8_only_crate_reports_no_opaque_blobs(tmp_path: Path) -> None:
    repo = TarSourceRepository(str(_archive_with(tmp_path, {})))
    inventory = json.loads(repo.inventory())
    assert inventory["opaque_blobs"] == []
    assert inventory["binary_analysis"] == []


async def test_benign_control_clears_with_zdr_and_read_only_tools(
    tmp_path: Path,
) -> None:
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)
    seen: list[dict[str, object]] = []
    final = {
        "risk_level": "low",
        "confidence": 0.9,
        "categories": ["none"],
        "evidence": [],
        "summary": "General model-backed request path.",
    }
    progress: list[tuple[int, int]] = []
    observation = await _agent(key, _transport(final, seen)).review(
        str(_archive(tmp_path, "fn main() { call_model(); }")),
        artifact_sha256=_SHA,
        progress=lambda completed, total: progress.append((completed, total)),
    )

    assert observation.ok and observation.risk_level == "low"
    assert progress == [(0, 4), (1, 4), (2, 4)]
    assert all(
        tool["function"]["name"]
        in {"analyze_binary", "list_files", "read_file", "search", "submit_review"}
        for request in seen
        for tool in request["tools"]
    )
    assert seen[0]["provider"] == {
        "zdr": True,
        "data_collection": "deny",
        "require_parameters": True,
    }
    prompt = seen[0]["messages"][0]["content"]
    assert "Public availability is not a safe harbor" in prompt
    assert "BuildKit secret mount" in prompt
    assert "abstention or retrieval side probe" in prompt
    assert "BERT/ONNX cross-encoder" in prompt
    assert "scorer_contract_manipulation" in prompt
    assert "user_isolation_correctness" in prompt
    assert "external_build_dependency" in prompt
    assert 'location-only "review_leads"' in prompt
    assert observation.finding is not None
    assert "use\nanalyze_binary only when" in prompt
    assert 'compact, precomputed\n"binary_analysis"' in prompt
    assert observation.finding["prompt_revision"] == "source-review-v6"


def test_review_leads_surface_compound_behavior_without_source_text() -> None:
    source = """\
fn run(req: Request) {
    if detect_rare_code_canary(&req.text) {
        let records = search_all(req.user_id);
        return force_inject(records, req.text);
    }
    if grader_scores_only_one_half(&req) {
        let tool = synthesize_tool_answer();
        let memory = synthesize_memory_abstain();
        return emit_both(tool, memory);
    }
}
"""

    leads = find_source_review_leads([("src/agent.rs", source)])

    assert {lead["kind"] for lead in leads} >= {
        "challenge-shaped-retrieval-override",
        "scorer-contract-manipulation",
    }
    encoded = json.dumps(leads)
    assert "detect_rare_code_canary" not in encoded
    assert "grader_scores_only_one_half" not in encoded
    assert all(
        set(location) == {"path", "line", "role"}
        for lead in leads
        for location in lead["locations"]
    )


def test_review_leads_cover_instruction_envelope_rewrites() -> None:
    source = """\
fn preprocess(req: Request) {
    if detect_exact_response_override_envelope(&req.user_input) {
        return sanitize_strip_prefix_keep_trailing_question(req);
    }
    req
}
"""

    leads = find_source_review_leads([("src/input_guard.rs", source)])

    assert "instruction-envelope-rewrite" in {lead["kind"] for lead in leads}


def test_review_leads_surface_audit_gated_model_routing() -> None:
    # The case-study bypass: recognize a watched request by its envelope, run the
    # real model only then, and route scored traffic to a deterministic solver.
    source = """\
fn answer(req: Request) {
    if tool_endpoint_present(&req) || is_probe(req.case_id) {
        return call_model(req);
    }
    return deterministic_solver_lookup(req);
}
"""

    leads = find_source_review_leads([("src/agent.rs", source)])

    assert "audit-gated-model-routing" in {lead["kind"] for lead in leads}
    encoded = json.dumps(leads)
    assert "deterministic_solver_lookup" not in encoded
    assert "case_id" not in encoded


def test_review_leads_do_not_flag_model_use_gated_by_tool_presence_alone() -> None:
    # A harness that runs the real model always and merely uses tools when the
    # request carries them has no deterministic route, so it is not the bypass.
    source = """\
fn answer(req: Request) {
    let facts = retrieve(req.user_id);
    let model = call_model(req.question, facts);
    if !req.tools.is_empty() {
        return run_tools(model, req.tools);
    }
    model.into_response()
}
"""

    leads = find_source_review_leads([("src/agent.rs", source)])

    assert "audit-gated-model-routing" not in {lead["kind"] for lead in leads}


def test_review_leads_distinguish_legitimate_near_neighbors() -> None:
    source = """\
fn answer(req: Request) {
    let records = retrieve(req.user_id);
    let visible = records.before(req.as_of);
    let exact = visible.exact_match(req.product_code);
    let result = call_model(req.question, exact);
    Response {
        tool: result.tool_output,
        memory: result.memory_output,
        answer: result.answer,
    }
}
fn preprocess(req: Request) { sanitize_untrusted_content(req.user_input); }
"""

    leads = find_source_review_leads([("src/agent.rs", source)])

    assert not {
        "challenge-shaped-retrieval-override",
        "deterministic-challenge-resolver",
        "scorer-contract-manipulation",
        "challenge-template-rewrite",
        "instruction-envelope-rewrite",
    } & {lead["kind"] for lead in leads}


def test_inventory_surfaces_review_leads_as_non_verdict_locations(
    tmp_path: Path,
) -> None:
    source = """\
fn answer(req: Request) {
    if TEMPORAL_COUNT_TEMPLATE.is_match(&req.text) {
        return resolve_as_of_count(&req.text);
    }
    general_agent(req)
}
"""
    inventory = json.loads(
        TarSourceRepository(str(_archive(tmp_path, source))).inventory()
    )

    assert inventory["review_leads"]["items"]
    assert inventory["review_leads"]["truncated"] is False
    assert "TEMPORAL_COUNT_TEMPLATE" not in json.dumps(inventory["review_leads"])


async def test_agent_can_analyze_binary_before_submitting_review(
    tmp_path: Path,
) -> None:
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        payload = json.loads(request.content)
        if calls == 0:
            tool_calls = [
                _tool("binary-1", "analyze_binary", {"path": "models/answers.onnx"})
            ]
        else:
            tool_result = json.loads(payload["messages"][-1]["content"])
            assert tool_result["format"] == "binary-data"
            assert tool_result["benchmark_schema_markers"] == ["expected_answer"]
            tool_calls = [
                _tool(
                    "submit-1",
                    "submit_review",
                    {
                        "risk_level": "medium",
                        "confidence": 0.8,
                        "categories": ["suspicious_static_tables"],
                        "evidence": [
                            {
                                "path": "models/answers.onnx",
                                "line": 1,
                                "category": "suspicious_static_tables",
                            }
                        ],
                        "summary": "Opaque runtime artifact needs operator review.",
                    },
                )
            ]
        calls += 1
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": tool_calls,
                        }
                    }
                ]
            },
        )

    archive = _archive_with(
        tmp_path, {"models/answers.onnx": b"\xffexpected_answer\x00known-value"}
    )
    observation = await _agent(key, httpx.MockTransport(handler)).review(
        str(archive), artifact_sha256=_SHA
    )

    assert observation.ok and observation.risk_level == "medium"
    assert calls == 2


async def test_synthetic_legitimate_patterns_clear_source_safety(
    tmp_path: Path,
) -> None:
    cases = json.loads(
        (
            Path(__file__).parent / "fixtures" / "source-review-regressions.json"
        ).read_text()
    )["legitimate"]
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)

    for index, case in enumerate(cases):
        final = {
            "risk_level": "low",
            "confidence": 0.95,
            "categories": ["none"],
            "evidence": [],
            "summary": "Allowed public-benchmark mechanism with user-scoped data.",
        }
        observation = await _agent(key, _transport(final, [])).review(
            str(_archive(tmp_path, f"// synthetic case {index}\n{case['source']}")),
            artifact_sha256=_SHA,
        )
        assert observation.ok and observation.risk_level == "low", case["name"]


async def test_synthetic_prohibited_patterns_retain_source_safety_enforcement(
    tmp_path: Path,
) -> None:
    cases = json.loads(
        (
            Path(__file__).parent / "fixtures" / "source-review-regressions.json"
        ).read_text()
    )["prohibited"]
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)

    for index, case in enumerate(cases):
        category = case["category"]
        evidence = [
            {"path": "src/main.rs", "line": 1, "category": category},
        ]
        if category in {
            "benchmark_emulation",
            "scorer_contract_manipulation",
        }:
            evidence.append({"path": "src/main.rs", "line": 2, "category": category})
        final = {
            "risk_level": "high",
            "confidence": 0.95,
            "categories": [category],
            "evidence": evidence,
            "summary": "Reachable prohibited behavior in the substantive path.",
        }
        observation = await _agent(key, _transport(final, [])).review(
            str(
                _archive(
                    tmp_path, f"fn serve() {{ route(); }} // {index}\n{case['source']}"
                )
            ),
            artifact_sha256=_SHA,
        )
        assert observation.ok and observation.risk_level == "high", case["name"]
        assert observation.categories == (category,), case["name"]


async def test_synthetic_advisory_patterns_are_classified_separately(
    tmp_path: Path,
) -> None:
    cases = json.loads(
        (
            Path(__file__).parent / "fixtures" / "source-review-regressions.json"
        ).read_text()
    )["advisory"]
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)

    for index, case in enumerate(cases):
        final = {
            "risk_level": "low",
            "confidence": 0.9,
            "categories": [case["category"]],
            "evidence": [
                {
                    "path": "src/main.rs",
                    "line": 2,
                    "category": case["category"],
                }
            ],
            "summary": "Advisory reviewability or correctness evidence only.",
        }
        observation = await _agent(key, _transport(final, [])).review(
            str(_archive(tmp_path, f"// advisory case {index}\n{case['source']}")),
            artifact_sha256=_SHA,
        )

        assert observation.ok and observation.risk_level == "low", case["name"]
        assert observation.categories == (case["category"],), case["name"]


def test_regression_fixture_quantifies_the_tradeoff() -> None:
    replay = json.loads(
        (
            Path(__file__).parent / "fixtures" / "source-review-regressions.json"
        ).read_text()
    )["production_replay"]

    assert replay == {
        "unique_source_safe_patterns": 8,
        "held_submissions": 6,
        "old_generic_source_safety_holds": 6,
        "new_source_safety_holds": 0,
        "new_originality_holds": 2,
    }


def test_regression_fixture_covers_allowed_and_prohibited_boundary() -> None:
    fixture = json.loads(
        (
            Path(__file__).parent / "fixtures" / "source-review-regressions.json"
        ).read_text()
    )

    legitimate = {case["name"] for case in fixture["legitimate"]}
    prohibited = {case["name"] for case in fixture["prohibited"]}

    assert {
        "locked-public-git-build-with-unused-optional-secret",
        "fixed-user-abstention-side-probe-with-request-scoped-main-path",
        "modified-onnx-cross-encoder-only-reranks-live-memory",
        "request-grounded-temporal-filter",
        "generic-rare-identifier-retrieval",
        "genuine-tool-and-memory-result-serialization",
        "generic-prompt-injection-defense",
    } <= legitimate
    assert prohibited == {
        "case-or-private-challenge-dispatch",
        "deterministic-benchmark-answer-table",
        "expected-answer-trained-runtime",
        "model-output-replacement",
        "audit-environment-fingerprint",
        "credential-or-private-challenge-embedding",
        "cross-user-content-access-and-exfiltration",
        "challenge-shaped-retrieval-injection",
        "deterministic-temporal-count-resolver",
        "scorer-contract-parallel-response-halves",
        "instruction-envelope-request-rewrite",
        "audit-gated-model-routing",
    }
    assert legitimate.isdisjoint(prohibited)


def test_latest_backroom_safe_batch_is_fully_represented() -> None:
    fixture = json.loads(
        (
            Path(__file__).parent / "fixtures" / "source-review-regressions.json"
        ).read_text()
    )

    assert fixture["latest_backroom_safe_batch"] == {
        "false_positive_classes": 3,
        "false_positive_submissions": 5,
    }
    assert fixture["recent_review_gaps"] == {
        "false_negative_families": 4,
        "advisory_classes": 2,
    }


def test_exact_official_provenance_does_not_whitelist_derivatives(
    tmp_path: Path,
) -> None:
    official = b"official public fixture"
    modified = b"official public fixture plus hidden derivative"
    manifest = tmp_path / "provenance.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "origin": "public/starter",
                "revision": "abc123",
                "files": {
                    "fixtures/models/official.bin": hashlib.sha256(
                        official
                    ).hexdigest(),
                    "fixtures/seed-user/official.json": hashlib.sha256(
                        official
                    ).hexdigest(),
                },
            }
        )
    )
    archive = _archive_files(
        tmp_path,
        {
            "fixtures/models/official.bin": official,
            "fixtures/seed-user/official.json": modified,
            "fixtures/models/derivative.bin": official,
        },
    )

    provenance = json.loads(
        TarSourceRepository(str(archive)).trusted_provenance(str(manifest))
    )

    assert provenance["matched_exact_files"] == ["fixtures/models/official.bin"]
    assert provenance["tracked_but_modified_files"] == [
        "fixtures/seed-user/official.json"
    ]
    assert "fixtures/models/derivative.bin" not in json.dumps(provenance)


async def test_sanitized_shortcut_fixture_produces_bounded_risk_digest(
    tmp_path: Path,
) -> None:
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)
    final = {
        "risk_level": "high",
        "confidence": 0.98,
        "categories": ["benchmark_emulation", "provider_bypass"],
        "evidence": [
            {"path": "src/main.rs", "line": 1, "category": "benchmark_emulation"},
            {"path": "src/main.rs", "line": 2, "category": "benchmark_emulation"},
            {"path": "src/main.rs", "line": 2, "category": "provider_bypass"},
        ],
        "summary": "Deterministic shortcut bypasses the general provider path.",
    }
    source = "fn serve() { run(); }\nfn run() { fast_path(); }"
    observation = await _agent(key, _transport(final, [])).review(
        str(_archive(tmp_path, source)), artifact_sha256=_SHA
    )

    assert observation.ok and observation.risk_level == "high"
    assert observation.categories == ("benchmark_emulation", "provider_bypass")
    assert observation.finding_digest is not None
    assert len(observation.finding_digest) == 64

    # The bounded finding rides along for the operator console and hashes to
    # the digest that the signed verdict binds.
    assert observation.finding is not None
    parsed = SourceReviewFinding.model_validate(observation.finding)
    assert parsed.canonical_digest() == observation.finding_digest
    assert parsed.risk_level == "high"
    assert parsed.summary == final["summary"]
    assert [item.model_dump() for item in parsed.evidence] == final["evidence"]
    # Nothing beyond the sanitized, bounded fields is retained.
    assert set(observation.finding) == {
        "artifact_sha256",
        "prompt_revision",
        "risk_level",
        "confidence",
        "categories",
        "evidence",
        "summary",
    }


async def test_malformed_or_unavailable_reviewer_is_retryable_not_reject(
    tmp_path: Path,
) -> None:
    key = tmp_path / "key"
    key.write_text("short")
    os.chmod(key, 0o600)
    observation = await _agent(
        key, httpx.MockTransport(lambda _: httpx.Response(500))
    ).review(str(_archive(tmp_path, "fn main() {}")), artifact_sha256=_SHA)

    assert not observation.ok
    assert observation.risk_level is None
    assert observation.error_code == "source-review-oserror"


@pytest.mark.parametrize(
    "final",
    [
        {
            "risk_level": "low",
            "confidence": 0.9,
            "categories": ["benchmark_emulation"],
            "evidence": [
                {
                    "path": "src/main.rs",
                    "line": 1,
                    "category": "benchmark_emulation",
                }
            ],
            "summary": "Low risk despite a prohibited category.",
        },
        {
            "risk_level": "high",
            "confidence": 0.9,
            "categories": ["benchmark_emulation"],
            "evidence": [
                {
                    "path": "src/main.rs",
                    "line": 1,
                    "category": "benchmark_emulation",
                }
            ],
            "summary": "High risk without a separate causal source location.",
        },
        {
            "risk_level": "high",
            "confidence": 0.9,
            "categories": ["benchmark_emulation", "none"],
            "evidence": [
                {
                    "path": "src/main.rs",
                    "line": 1,
                    "category": "benchmark_emulation",
                },
                {
                    "path": "src/main.rs",
                    "line": 2,
                    "category": "benchmark_emulation",
                },
            ],
            "summary": "None cannot hide an elevated category.",
        },
    ],
)
async def test_internally_inconsistent_review_is_retryable_not_a_weak_finding(
    tmp_path: Path, final: dict[str, object]
) -> None:
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)

    observation = await _agent(key, _transport(final, [])).review(
        str(_archive(tmp_path, "fn serve() { route(); }\nfn route() {}")),
        artifact_sha256=_SHA,
    )

    assert not observation.ok
    assert observation.error_code == "source-review-valueerror"


async def test_expired_lease_deadline_stops_review_before_first_call(
    tmp_path: Path,
) -> None:
    import asyncio

    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"choices": []})

    loop = asyncio.get_running_loop()
    observation = await _agent(key, httpx.MockTransport(handler)).review(
        str(_archive(tmp_path, "fn main() {}")),
        artifact_sha256=_SHA,
        deadline=loop.time() - 1.0,
    )
    # An exhausted lease aborts the review before any model turn and surfaces a
    # retryable (ok=False) observation rather than burning the per-request
    # timeout on every step.
    assert calls == 0
    assert not observation.ok
    assert observation.error_code == "source-review-valueerror"


async def test_transient_openrouter_failure_is_retried(
    tmp_path: Path, monkeypatch
) -> None:
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(503, request=request)
        return httpx.Response(
            200,
            request=request,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                _tool(
                                    "submit-1",
                                    "submit_review",
                                    {
                                        "risk_level": "low",
                                        "confidence": 0.9,
                                        "categories": ["none"],
                                        "evidence": [],
                                        "summary": "General model-backed path.",
                                    },
                                )
                            ],
                        }
                    }
                ]
            },
        )

    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("ditto_screener.source_review.asyncio.sleep", no_sleep)
    observation = await _agent(key, httpx.MockTransport(handler)).review(
        str(_archive(tmp_path, "fn main() { call_model(); }")),
        artifact_sha256=_SHA,
    )

    assert observation.ok
    assert calls == 2


async def test_hallucinated_citations_are_dropped_before_digest_binding(
    tmp_path: Path,
) -> None:
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)
    final = {
        "risk_level": "high",
        "confidence": 0.9,
        "categories": ["benchmark_emulation"],
        "evidence": [
            # Real file, real line: kept.
            {"path": "src/main.rs", "line": 1, "category": "benchmark_emulation"},
            {"path": "src/main.rs", "line": 2, "category": "benchmark_emulation"},
            # Nonexistent file: dropped.
            {"path": "src/ghost.rs", "line": 3, "category": "benchmark_emulation"},
            # Real file, impossible line: dropped.
            {"path": "src/main.rs", "line": 9999, "category": "benchmark_emulation"},
        ],
        "summary": "Deterministic shortcut bypasses the general provider path.",
    }
    observation = await _agent(key, _transport(final, [])).review(
        str(_archive(tmp_path, "fn run() { fast_path(); }\nfn fast_path() {}")),
        artifact_sha256=_SHA,
    )

    assert observation.ok and observation.finding is not None
    parsed = SourceReviewFinding.model_validate(observation.finding)
    assert [(item.path, item.line) for item in parsed.evidence] == [
        ("src/main.rs", 1),
        ("src/main.rs", 2),
    ]
    # The digest binds the VALIDATED evidence set.
    assert parsed.canonical_digest() == observation.finding_digest


def test_inventory_degrades_partially_with_truncation_metadata(
    tmp_path: Path,
) -> None:
    # Many files with long names would previously collapse the whole
    # inventory into a truncation error; now the listing shrinks but the
    # counts and flags survive.
    files = {
        f"src/module_{index:04d}/{'x' * 120}.rs": b"fn f() {}\n" for index in range(700)
    }
    files["assets/table.bin"] = b"\xff\xfe\x00binary" * 4
    repo = TarSourceRepository(str(_archive_files(tmp_path, files)))
    inventory = json.loads(repo.inventory())

    assert "error" not in inventory
    assert inventory["file_count"] == len(files)
    assert inventory["truncated"] is True
    assert inventory["files_listed"] == len(inventory["largest_files"])
    assert inventory["opaque_total"] == 1
    assert inventory["opaque_blobs"][0]["path"] == "assets/table.bin"
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":"))
    assert len(encoded) <= 48_000
