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
from ditto_screener.source_signals import (
    find_decisive_malicious_source,
    find_source_review_leads,
)
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
                ),
                _tool("search-1", "search", {"query": "call_model"}),
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


def test_generator_mirroring_constellation_supports_auditable_finding(
    tmp_path: Path,
) -> None:
    source = b"""\
const ATTRS: &[&str] = &["city", "employer", "car", "university", "instrument",
    "project", "trip", "pet", "cuisine", "diet", "color", "hobby"];
const QUESTIONS: &[&str] = &[
    "What city do I live in?", "Where do I work now?",
    "Which university did I attend?", "How many projects did I mention?",
    "List every trip I described.", "What did I use to drive before?",
];
const FACTS: &[&str] = &[
    "I moved to Northport.", "I work at Example Labs.", "I drive a hatchback.",
    "I studied at Northport College.", "I play an instrument.",
    "My project is Atlas.", "My favorite cuisine changed recently.",
];
const EVENT_LABELS: &[&str] = &["moved", "started", "switched", "changed"];
fn bridge_question_to_fact(question: &str, query: &str, fact: &str, memory: &str,
    attribute: &str, value: &str) {
    let _ = (extract(question), retrieve(query, memory), match_fact(fact),
        keyword(attribute), value);
}
fn deterministic_response() -> Option<String> { return Some(answer()); }
fn run() -> String {
    if let Some(answer) = deterministic_response() { return answer; }
    otherwise_call_model_inference_provider()
}
"""
    repo = TarSourceRepository(
        str(_archive_files(tmp_path, {"src/memory_solver.rs": source}))
    )

    analysis = repo.review_leads()["generator_mirroring"]

    assert analysis["aggregate_candidate"] is True
    assert analysis["served_runtime_candidate"] is True
    assert {
        location["dimension"] for location in analysis["served_runtime_locations"]
    } == {
        "question_templates",
        "retrieval_vocabulary_bridge",
        "deterministic_answer_path",
    }
    assert analysis["matched_dimensions"] == [
        "attribute_ontology",
        "question_templates",
        "fact_update_frames",
        "event_label_frames",
        "retrieval_vocabulary_bridge",
        "deterministic_answer_path",
    ]
    dimensions = analysis["dimensions"]
    assert all(
        location["path"] == "src/memory_solver.rs"
        and isinstance(location["line"], int)
        and location["line"] > 0
        for dimension in dimensions.values()
        for location in dimension["locations"]
    )
    assert analysis["disposition"] == "requires-runtime-causal-review"
    assert "text" not in json.dumps(analysis)

    observation = source_review_module._parse_review(
        {
            "risk_level": "high",
            "confidence": 0.96,
            "categories": ["benchmark_emulation"],
            "evidence": [
                {
                    "path": "src/memory_solver.rs",
                    "line": line,
                    "category": "benchmark_emulation",
                }
                for line in (1, 4, 8, 13, 21, 22)
            ],
            "summary": (
                "Coordinated public-generator mirror returns deterministic answers "
                "before inference."
            ),
        },
        artifact_sha256=_SHA,
        repository=repo,
    )
    assert observation.risk_level == "high"
    assert observation.categories == ("benchmark_emulation",)
    assert observation.finding is not None
    assert observation.finding["prompt_revision"] == "source-review-v11"
    assert observation.finding["evidence"] == [
        {
            "path": "src/memory_solver.rs",
            "line": line,
            "category": "benchmark_emulation",
        }
        for line in (1, 4, 8, 13, 21, 22)
    ]


def test_served_generator_candidate_ignores_one_generic_task_prompt(
    tmp_path: Path,
) -> None:
    source = b"""\
const PROMPT: &str = "How many projects should I list?";
pub async fn run(question: &str) -> RunResponse {
    let memory = retrieve(question);
    let answer = model(memory).await;
    RunResponse { final_text: answer, answer: None, abstain: None }
}
"""
    repo = TarSourceRepository(str(_archive_files(tmp_path, {"src/agent.rs": source})))

    analysis = repo.review_leads()["generator_mirroring"]

    assert analysis["served_runtime_candidate"] is False
    assert analysis["served_runtime_locations"] == []


def test_generator_scan_prioritizes_runtime_source_over_decoy_files(
    tmp_path: Path,
) -> None:
    runtime = b"""\
const ATTRS: &[&str] = &["city", "employer", "car", "university", "instrument",
    "project", "trip", "pet", "cuisine", "diet", "color", "hobby"];
const QUESTIONS: &[&str] = &["What city?", "Where work?", "Which project?",
    "How many trips?", "List pets", "What was used before?"];
const FACTS: &[&str] = &["I moved city", "I work company", "I drive car",
    "I studied university", "I play instrument", "My project changed"];
const EVENTS: &[&str] = &["moved", "started", "switched", "changed"];
fn bridge(question: Query, query: Query, fact: Fact, memory: Memory,
    attribute: Attr, value: Value) { extract(question); retrieve(query, memory);
    match_fact(fact); keyword(attribute); use_value(value); }
fn direct_answer() -> Answer { return deterministic_answer(); }
fn run() -> Answer { if ready() { return direct_answer(); } call_model_inference(); }
"""
    files = {
        **{f"docs/decoy-{index:04}.md": b"irrelevant" for index in range(2048)},
        "src/runtime.rs": runtime,
    }
    repo = TarSourceRepository(str(_archive_files(tmp_path, files)))

    analysis = repo.review_leads()["generator_mirroring"]

    assert analysis["aggregate_candidate"] is True
    assert analysis["scanned_runtime_source_files"] == 1


@pytest.mark.parametrize(
    "name,source",
    [
        (
            "ordinary-schema",
            "struct Profile { city: String, employer: String, car: String, "
            "university: String, instrument: String, projects: Vec<String>, "
            "trips: Vec<String>, pets: Vec<String>, cuisine: String, color: String }",
        ),
        (
            "generic-retrieval",
            "fn retrieve(question: Query, memory: Memory) -> Fact { "
            "extract(question.value); match_fact(memory.attribute); keyword_search() }",
        ),
        (
            "public-benchmark-comment",
            "// DittoBench uses scalar and list attributes, question templates, "
            "// fact updates, event labels, and retrieval.\nfn call_model() {}",
        ),
        (
            "generic-direct-answer",
            "fn run() { if let Some(answer) = deterministic_response() "
            "{ return answer; } "
            "otherwise_call_model_provider(); }",
        ),
    ],
)
def test_isolated_schema_retrieval_or_benchmark_mentions_do_not_form_candidate(
    tmp_path: Path, name: str, source: str
) -> None:
    repo = TarSourceRepository(
        str(_archive_files(tmp_path, {f"src/{name}.rs": source.encode()}))
    )

    analysis = repo.review_leads()["generator_mirroring"]

    assert analysis["aggregate_candidate"] is False
    assert analysis["disposition"] == "no-aggregate-candidate"


@pytest.mark.parametrize(
    ("expected_category", "source"),
    [
        (
            "malicious_build",
            'let endpoint = "/var/run/docker.sock";\nconnect_control_socket(endpoint);',
        ),
        (
            "malicious_build",
            'let boundary = "/proc/1/root";\nmount_host_boundary(boundary);',
        ),
        (
            "credential_access",
            'let path = "/proc/1/environ";\nlet data = read_secret_path(path);',
        ),
        (
            "cross_user_access",
            'let home = "/root/.config";\nscan_cross_user_home(home);',
        ),
        (
            "data_exfiltration",
            "let secret = os.environ.clone();\nhttp_client.post(callback, secret);",
        ),
    ],
)
def test_decisive_malicious_preflight_categories(
    expected_category: str, source: str
) -> None:
    findings = find_decisive_malicious_source([("src/runtime.rs", source)])
    assert expected_category in {item["category"] for item in findings}


def test_decisive_malicious_preflight_ignores_inert_regression_material() -> None:
    findings = find_decisive_malicious_source(
        [
            (
                "tests/security_canary.rs",
                'assert_blocked("/var/run/docker.sock"); read_fixture(".env");',
            ),
            (
                "docs/security.md",
                "Never mount the host root or upload a credential.",
            ),
            (
                "src/agent.rs",
                "// /var/run/docker.sock connect mount host\n"
                "fn run() { call_model(); }",
            ),
            (
                "src/prompt.rs",
                'let security_prompt = r#"Never read, open, scan, or copy\n'
                "/proc/1/environ or credential files.\n"
                'Do not upload them."#;',
            ),
        ]
    )
    assert findings == []


def test_decisive_preflight_ignores_nested_inert_regression_material() -> None:
    findings = find_decisive_malicious_source(
        [
            (
                "vendor/dependency/tests/security_canary.rs",
                'assert_blocked("/var/run/docker.sock"); read_fixture(".env");',
            ),
            (
                "dependency/docs/security_example.py",
                'connect_control_socket("/var/run/docker.sock")',
            ),
        ]
    )

    assert findings == []


def test_decisive_preflight_keeps_runtime_beside_nested_inert_material() -> None:
    findings = find_decisive_malicious_source(
        [
            (
                "vendor/dependency/tests/security_canary.rs",
                'assert_blocked("/var/run/docker.sock");',
            ),
            (
                "vendor/dependency/src/runtime.rs",
                'let endpoint = "/var/run/docker.sock";\n'
                "connect_control_socket(endpoint);",
            ),
        ]
    )

    assert "malicious_build" in {item["category"] for item in findings}


def test_decisive_preflight_keeps_runtime_under_src_named_tests() -> None:
    findings = find_decisive_malicious_source(
        [
            (
                "src/tests/runtime.rs",
                'let endpoint = "/var/run/docker.sock";\n'
                "connect_control_socket(endpoint);",
            )
        ]
    )

    assert "malicious_build" in {item["category"] for item in findings}


def test_decisive_malicious_preflight_keeps_real_effect_beside_prompt() -> None:
    findings = find_decisive_malicious_source(
        [
            (
                "src/runtime.rs",
                'let security_prompt = "Never read /proc/1/environ";\n'
                'let stolen = read_secret_path("/proc/1/environ");',
            )
        ]
    )

    assert "credential_access" in {item["category"] for item in findings}


def test_decisive_malicious_preflight_masks_strings_after_triple_quotes() -> None:
    findings = find_decisive_malicious_source(
        [
            (
                "scripts/local-lab.py",
                '"""Local development helper."""\n'
                "def child_environment(pass_env):\n"
                "    safe = {name for name in os.environ if name.startswith('LC_')}\n"
                "    for name in pass_env:\n"
                "        if name not in os.environ:\n"
                '            raise ValueError(f"requested environment variable '
                'is not set: {name}")\n'
                "    return {name: os.environ[name] for name in safe}\n",
            )
        ]
    )

    assert findings == []


def test_decisive_malicious_preflight_detects_effect_after_triple_quotes() -> None:
    findings = find_decisive_malicious_source(
        [
            (
                "src/runtime.py",
                '"""Runtime entrypoint."""\n'
                "secret = os.environ.copy()\n"
                "http_client.post(callback, secret)\n",
            )
        ]
    )

    assert "data_exfiltration" in {item["category"] for item in findings}


def test_repository_preflight_emits_digest_bound_location_only_finding(
    tmp_path: Path,
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/runtime.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    )
                },
            )
        )
    )
    observation = repo.malicious_preflight(artifact_sha256="a" * 64)
    assert observation is not None
    assert observation.risk_level == "high"
    assert observation.finding_digest
    serialized = json.dumps(observation.finding)
    assert "docker-control-plane" in serialized
    assert "/var/run/docker.sock" not in serialized


def test_repository_preflight_prioritizes_runtime_over_archive_padding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(source_review_module, "_MAX_LEAD_SCAN_FILES", 2)
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "000-docs.md": b"ordinary documentation",
                    "001-notes.md": b"ordinary notes",
                    "src/runtime.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert observation is not None
    assert observation.categories == ("malicious_build",)


def test_repository_preflight_scans_custom_cargo_build_path(tmp_path: Path) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "Cargo.toml": (
                        b'[package]\nname = "agent"\nversion = "0.1.0"\n'
                        b'build = "vendor/dependency/tests/payload.rs"\n'
                    ),
                    "vendor/dependency/tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert observation is not None
    assert observation.categories == ("malicious_build",)


def test_repository_preflight_follows_rust_include_into_nested_test_path(
    tmp_path: Path,
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/main.rs": (
                        b'include!("../vendor/dependency/tests/payload.rs");\n'
                    ),
                    "vendor/dependency/tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                    "vendor/dependency/tests/inert.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    runtime_paths = repo._explicit_runtime_paths()
    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert "vendor/dependency/tests/payload.rs" in runtime_paths
    assert "vendor/dependency/tests/inert.rs" not in runtime_paths
    assert observation is not None
    assert observation.categories == ("malicious_build",)


@pytest.mark.parametrize("target_kind", ["example", "test", "bench"])
def test_repository_preflight_ignores_inert_cargo_targets(
    tmp_path: Path, target_kind: str
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "Cargo.toml": (
                        b'[package]\nname = "agent"\nversion = "0.1.0"\n'
                        + f'[[{target_kind}]]\nname = "fixture"\n'.encode()
                        + b'path = "tests/payload.rs"\n'
                    ),
                    "src/main.rs": b"fn main() {}\n",
                    "tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    runtime_paths = repo._explicit_runtime_paths()
    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert "tests/payload.rs" not in runtime_paths
    assert observation is None


def test_repository_preflight_ignores_dev_dependency_build_script(
    tmp_path: Path,
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "Cargo.toml": (
                        b'[package]\nname = "agent"\nversion = "0.1.0"\n'
                        b"[dev-dependencies]\n"
                        b'fixture = { path = "tests/fixture" }\n'
                    ),
                    "src/main.rs": b"fn main() {}\n",
                    "tests/fixture/Cargo.toml": (
                        b'[package]\nname = "fixture"\nversion = "0.1.0"\n'
                        b'build = "payload.rs"\n'
                    ),
                    "tests/fixture/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    runtime_paths = repo._explicit_runtime_paths()
    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert "tests/fixture/payload.rs" not in runtime_paths
    assert observation is None


@pytest.mark.parametrize(
    "runtime_source",
    [
        ('#[cfg(test)]\n#[path = "../tests/payload.rs"]\nmod policy_fixture;\n'),
        '#[cfg(test)]\ninclude!("../tests/payload.rs");\n',
    ],
)
def test_repository_preflight_ignores_test_only_rust_indirections(
    tmp_path: Path, runtime_source: str
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/main.rs": runtime_source.encode(),
                    "tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    runtime_paths = repo._explicit_runtime_paths()
    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert "tests/payload.rs" not in runtime_paths
    assert observation is None


def test_repository_preflight_follows_unguarded_rust_path_attribute(
    tmp_path: Path,
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/main.rs": (
                        b'#[path = "../tests/payload.rs"]\nmod production_module;\n'
                    ),
                    "tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    runtime_paths = repo._explicit_runtime_paths()
    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert "tests/payload.rs" in runtime_paths
    assert observation is not None
    assert observation.categories == ("malicious_build",)


@pytest.mark.parametrize(
    "root_manifest,dependency_manifest",
    [
        (
            b'[workspace]\nmembers = ["vendor/dependency"]\n',
            b'[package]\nname = "dependency"\nversion = "0.1.0"\n'
            b'build = "tests/payload.rs"\n',
        ),
        (
            b'[package]\nname = "agent"\nversion = "0.1.0"\n'
            b'[dependencies]\ndependency = { path = "vendor/dependency" }\n',
            b'[package]\nname = "dependency"\nversion = "0.1.0"\n'
            b'build = "tests/payload.rs"\n',
        ),
    ],
)
def test_repository_preflight_scans_reachable_cargo_package_targets(
    tmp_path: Path, root_manifest: bytes, dependency_manifest: bytes
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "Cargo.toml": root_manifest,
                    "vendor/dependency/Cargo.toml": dependency_manifest,
                    "vendor/dependency/tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert observation is not None
    assert observation.categories == ("malicious_build",)


@pytest.mark.parametrize(
    "include_expression",
    [
        'include!(r#"../vendor/dependency/tests/payload.rs"#);',
        'include!(concat!("../vendor/", "dependency/tests/payload.rs"));',
        "fn borrow<'a>(value: &'a str) { let _ = value; }\n"
        'include!("../vendor/dependency/tests/payload.rs");',
        'include!("\\x2e\\x2e/vendor/dependency/tests/payload.rs");',
    ],
)
def test_repository_preflight_resolves_rust_literal_include_forms(
    tmp_path: Path, include_expression: str
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/main.rs": include_expression.encode(),
                    "vendor/dependency/tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert observation is not None
    assert observation.categories == ("malicious_build",)


def test_repository_preflight_ignores_include_examples_in_comments_and_strings(
    tmp_path: Path,
) -> None:
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/main.rs": (
                        b'// include!("../vendor/dependency/tests/payload.rs");\n'
                        b'let example = r#"include!("../vendor/dependency/tests/'
                        b'payload.rs")"#;\n'
                    ),
                    "vendor/dependency/tests/payload.rs": (
                        b'let endpoint = "/var/run/docker.sock";\n'
                        b"connect_control_socket(endpoint);\n"
                    ),
                },
            )
        )
    )

    assert repo.malicious_preflight(artifact_sha256="a" * 64) is None


def test_repository_preflight_skips_oversized_member_without_stopping_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dangerous = (
        b'let endpoint = "/var/run/docker.sock";\nconnect_control_socket(endpoint);\n'
    )
    monkeypatch.setattr(
        source_review_module, "_MAX_LEAD_SCAN_BYTES", len(dangerous) + 8
    )
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/a_large.rs": b"x" * (len(dangerous) + 16),
                    "src/z_runtime.rs": dangerous,
                },
            )
        )
    )

    observation = repo.malicious_preflight(artifact_sha256="a" * 64)

    assert observation is not None
    assert observation.categories == ("malicious_build",)


def test_repository_preflight_trusts_only_exact_pinned_starter_file(
    tmp_path: Path,
) -> None:
    official = (
        b'let endpoint = "/var/run/docker.sock";\nconnect_control_socket(endpoint);\n'
    )
    manifest = tmp_path / "provenance.json"
    manifest.write_text(
        json.dumps(
            {
                "version": 1,
                "origin": "public/starter",
                "revision": "reviewed",
                "files": {"scripts/official.py": hashlib.sha256(official).hexdigest()},
            }
        )
    )
    exact = TarSourceRepository(
        str(_archive_files(tmp_path, {"scripts/official.py": official}))
    )

    assert (
        exact.malicious_preflight(
            artifact_sha256="a" * 64,
            provenance_manifest_paths=(str(manifest),),
        )
        is None
    )

    modified = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {"scripts/official.py": official + b"// miner change\n"},
            )
        )
    )
    observation = modified.malicious_preflight(
        artifact_sha256="b" * 64,
        provenance_manifest_paths=(str(manifest),),
    )

    assert observation is not None
    assert observation.categories == ("malicious_build",)


def test_repository_rejects_noncanonical_source_alias(tmp_path: Path) -> None:
    archive = _archive_files(
        tmp_path,
        {
            "src/main.rs": b"fn original() {}",
            "src/./main.rs": b"fn replacement() {}",
        },
    )

    with pytest.raises(ValueError, match="non-canonical path"):
        TarSourceRepository(str(archive))


def test_all_generator_grammar_without_answer_path_is_not_candidate(
    tmp_path: Path,
) -> None:
    source = b"""\
const ATTRS: &[&str] = &["city", "employer", "car", "university", "instrument",
    "project", "trip", "pet", "cuisine", "diet", "color", "hobby"];
const QUESTIONS: &[&str] = &[
    "What city do I live in?", "Where do I work now?",
    "Which university did I attend?", "How many projects did I mention?",
    "List every trip I described.", "What did I use to drive before?",
];
const FACTS: &[&str] = &[
    "I moved to Northport.", "I work at Example Labs.", "I drive a hatchback.",
    "I studied at Northport College.", "I play an instrument.",
    "My project is Atlas.", "My favorite cuisine changed recently.",
];
const EVENT_LABELS: &[&str] = &["moved", "started", "switched", "changed"];
fn bridge_question_to_fact(question: &str, query: &str, fact: &str, memory: &str,
    attribute: &str, value: &str) {
    let _ = (extract(question), retrieve(query, memory), match_fact(fact),
        keyword(attribute), value);
}
"""
    repo = TarSourceRepository(
        str(_archive_files(tmp_path, {"src/grammar_only.rs": source}))
    )

    analysis = repo.review_leads()["generator_mirroring"]

    assert set(analysis["matched_dimensions"]) == {
        "attribute_ontology",
        "question_templates",
        "fact_update_frames",
        "event_label_frames",
        "retrieval_vocabulary_bridge",
    }
    assert analysis["aggregate_candidate"] is False
    assert analysis["disposition"] == "no-aggregate-candidate"


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
    assert observation.clearance_certified
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
    assert "genuine model generation" in prompt
    assert "Current-user facts remain legitimate agent context" in prompt
    assert "behavioral-\noracle failures" in prompt
    assert "user_isolation_correctness" in prompt
    assert "external_build_dependency" in prompt
    assert 'location-only "review_leads"' in prompt
    assert "coordinated constellation" in prompt
    assert "literal expected answers or hidden values" in prompt
    assert observation.finding is not None
    assert "use\nanalyze_binary only when" in prompt
    assert 'compact, precomputed\n"binary_analysis"' in prompt
    assert observation.finding["prompt_revision"] == "source-review-v11"
    initial_inventory = json.loads(
        seen[0]["messages"][1]["content"]
        .split("\nExact-file trusted provenance:\n", 1)[0]
        .removeprefix("Review this untrusted crate. Initial inventory:\n")
    )
    mirroring = initial_inventory["review_leads"]["generator_mirroring"]
    assert mirroring["aggregate_candidate"] is False


async def test_first_turn_low_result_is_not_a_clearance_certificate(
    tmp_path: Path,
) -> None:
    key = tmp_path / "key"
    key.write_text("sk-test-private-review")
    os.chmod(key, 0o600)
    final = {
        "risk_level": "low",
        "confidence": 0.99,
        "categories": ["none"],
        "evidence": [],
        "summary": "Inventory-only result.",
    }

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [_tool("submit-1", "submit_review", final)],
                        }
                    }
                ]
            },
        )

    observation = await _agent(key, httpx.MockTransport(handler)).review(
        str(_archive(tmp_path, "fn main() { call_model(); }")),
        artifact_sha256=_SHA,
    )

    assert observation.ok and observation.risk_level == "low"
    assert not observation.clearance_certified


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


def test_review_leads_surface_review_adaptive_model_routing(tmp_path: Path) -> None:
    source = """\
fn answer(req: Request) {
    // The audit oracle quarantines a single call on an empty transcript.
    // Always make a second model call that carries the first call's nonce.
    let notes = chat(req.question);
    let answer = chat(notes);
    return_response(answer)
}
"""
    repo = TarSourceRepository(str(_archive(tmp_path, source)))

    analysis = repo.review_leads()["review_adaptive_model_routing"]

    assert analysis["candidate"] is True
    locations = analysis["constellations"][0]["locations"]
    assert {location["role"] for location in locations} == {
        "review_channel",
        "probe_shape",
        "model_effect",
    }
    assert "nonce" not in json.dumps(analysis)


def test_review_adaptation_requires_probe_claim_and_runtime_effect(
    tmp_path: Path,
) -> None:
    benign = """\
fn answer(req: Request) {
    // Retry an empty response so ordinary users get a useful answer.
    let notes = chat(req.question);
    if notes.is_empty() { return chat(req.question); }
    return_response(notes)
}
"""
    decoy = """\
// The audit oracle quarantines a single call on an empty transcript.
// Always make a second model call that carries the first call's nonce.
fn example(req: Request) { chat(req.question); }
"""
    repo = TarSourceRepository(
        str(
            _archive_files(
                tmp_path,
                {
                    "src/main.rs": benign.encode(),
                    "docs/reviewer-example.rs": decoy.encode(),
                },
            )
        )
    )

    analysis = repo.review_leads()["review_adaptive_model_routing"]

    assert analysis["candidate"] is False


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
        "dittobench-v3-required-reachability-preflight",
        "dittobench-v3-best-effort-reachability-preflight",
    } <= legitimate
    assert {
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
        "post-generation-nonce-scrub-and-answer-clear",
        "scored-family-answer-and-abstain-synthesis",
        "grader-specific-prose-and-field-overwrite",
        "fabricated-tool-arguments-and-lifecycle",
        "exact-banned-cross-miner-artifact",
        "preflight-near-miss-prefix-dispatch",
        "preflight-wrong-tool-reported-as-search-web",
        "preflight-no-endpoint-execution",
        "preflight-fabricated-observed-call",
        "preflight-branch-leaks-into-scored-requests",
    } <= prohibited
    assert legitimate.isdisjoint(prohibited)


def test_dittobench_preflight_prompt_keeps_the_false_positive_boundary_narrow() -> None:
    from ditto_screener.source_review import _SYSTEM_PROMPT

    required = {
        "reserved `preflight:`",
        "exact supplied endpoint",
        "incoming case_id",
        "name `search_web`",
        "JSON-object args",
        "hop 0",
        "actually attempts that POST",
        "ignore or discard the",
        "validator-side endpoint observation is authoritative",
        "self-report cannot make the preflight pass",
        "ordinary scored request",
        "near-miss prefixes",
        "wrong tools",
        "no actual POST attempt",
        "self-reported preflight call with no matching POST",
        "self-report paired with the required best-effort",
    }

    assert all(marker in _SYSTEM_PROMPT for marker in required)


def test_latest_backroom_safe_batch_is_fully_represented() -> None:
    fixture = json.loads(
        (
            Path(__file__).parent / "fixtures" / "source-review-regressions.json"
        ).read_text()
    )

    assert fixture["latest_backroom_safe_batch"] == {
        "false_positive_classes": 5,
        "false_positive_submissions": 7,
        "correct_rejections": 6,
        "infrastructure_rescreens": 1,
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


def test_closest_official_provenance_uses_exact_supported_revision(
    tmp_path: Path,
) -> None:
    older = tmp_path / "older.json"
    current = tmp_path / "current.json"
    files = {"src/main.rs": b"current", "README.md": b"shared"}
    for path, revision, main_digest in (
        (older, "older", hashlib.sha256(b"older").hexdigest()),
        (current, "current", hashlib.sha256(b"current").hexdigest()),
    ):
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "origin": "public/starter",
                    "revision": revision,
                    "files": {
                        "src/main.rs": main_digest,
                        "README.md": hashlib.sha256(b"shared").hexdigest(),
                    },
                }
            )
        )
    archive = _archive_files(tmp_path, files)

    provenance = json.loads(
        TarSourceRepository(str(archive)).closest_trusted_provenance(
            (str(older), str(current))
        )
    )

    assert provenance["revision"] == "current"
    assert provenance["matched_exact_files"] == ["README.md", "src/main.rs"]
    assert provenance["tracked_but_modified_files"] == []
    assert provenance["supported_revisions"] == ["current", "older"]
    assert provenance["candidate_revisions"] == ["current"]
    assert provenance["selection"] == "unique-closest-supported-revision"
    assert provenance["scope"] == "exact-path-and-sha256-only"


def test_closest_official_provenance_reports_ambiguous_exact_tie(
    tmp_path: Path,
) -> None:
    shared = b"shared"
    manifests: list[str] = []
    for revision in ("older", "newer"):
        manifest = tmp_path / f"{revision}.json"
        manifest.write_text(
            json.dumps(
                {
                    "version": 1,
                    "origin": "public/starter",
                    "revision": revision,
                    "files": {"README.md": hashlib.sha256(shared).hexdigest()},
                }
            )
        )
        manifests.append(str(manifest))
    archive = _archive_files(tmp_path, {"README.md": shared})

    provenance = json.loads(
        TarSourceRepository(str(archive)).closest_trusted_provenance(tuple(manifests))
    )

    assert provenance["revision"] is None
    assert provenance["candidate_revisions"] == ["newer", "older"]
    assert provenance["selection"] == "ambiguous-closest-supported-revisions"
    assert provenance["matched_exact_files"] == ["README.md"]


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
