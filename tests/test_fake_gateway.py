"""Tests for the host-side fake OpenAI-compatible screening gateway."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ditto_screener.fake_gateway import FakeModelGateway


async def test_chat_completion_is_counted_and_returns_offline_response(
    tmp_path: Path,
) -> None:
    state = tmp_path / "calls"
    async with FakeModelGateway(state_file=str(state)) as gateway:
        local_url = gateway.gateway_url.replace("host.docker.internal", "127.0.0.1")
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{local_url}/v1/chat/completions",
                json={
                    "model": "acme/reasoner-v3",
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )
        assert response.status_code == 200
        body = response.json()
        assert body["choices"][0]["message"]["content"] == gateway.response_text
        # The response must echo the caller's model, use a random id, and a real
        # timestamp so the container cannot fingerprint the screener.
        assert body["model"] == "acme/reasoner-v3"
        assert body["id"].startswith("chatcmpl-")
        assert body["id"] != "chatcmpl-ditto-screening-fake"
        assert body["created"] > 0
        assert gateway.model_calls == 1
        assert state.read_text() == "1\n"
        assert not state.stat().st_mode & 0o077


async def test_no_screening_fingerprints_leak_in_any_response() -> None:
    """No ``ditto``/``fake``/``screening``/locked-model tell reaches the container."""
    async with FakeModelGateway() as gateway:
        local_url = gateway.gateway_url.replace("host.docker.internal", "127.0.0.1")
        async with httpx.AsyncClient() as client:
            chat = await client.post(
                f"{local_url}/v1/chat/completions",
                json={"model": "acme/x", "messages": []},
            )
            responses = await client.post(
                f"{local_url}/v1/responses", json={"model": "acme/x", "input": "hi"}
            )
            not_found = await client.post(f"{local_url}/v1/unknown", json={})
            bad = await client.post(
                f"{local_url}/v1/chat/completions", content=b"{not-json"
            )
    for raw in (chat.text.lower(), responses.text.lower(), not_found.text.lower()):
        assert "ditto" not in raw
        assert "fake" not in raw
        assert "screening" not in raw
        assert "qwen" not in raw
    # Even the 404/400 error bodies the container can probe must not tell.
    assert "fake" not in bad.text.lower() and "ditto" not in bad.text.lower()


async def test_model_round_trip_oracle_returns_answer_only_after_nonce() -> None:
    """A second turn carrying the nonce yields the answer; a first turn does not."""
    async with FakeModelGateway(
        response_text="nonce-token-abc", oracle_answer="answer-token-xyz"
    ) as gateway:
        local_url = gateway.gateway_url.replace("host.docker.internal", "127.0.0.1")
        async with httpx.AsyncClient() as client:
            first = await client.post(
                f"{local_url}/v1/chat/completions",
                json={"model": "m", "messages": [{"role": "user", "content": "go"}]},
            )
            second = await client.post(
                f"{local_url}/v1/chat/completions",
                json={
                    "model": "m",
                    "messages": [
                        {"role": "assistant", "content": "nonce-token-abc"},
                        {"role": "user", "content": "return that value"},
                    ],
                },
            )
    assert first.json()["choices"][0]["message"]["content"] == "nonce-token-abc"
    assert second.json()["choices"][0]["message"]["content"] == "answer-token-xyz"


async def test_configured_latency_delays_a_model_call() -> None:
    async with FakeModelGateway(latency_range=(0.05, 0.05)) as gateway:
        local_url = gateway.gateway_url.replace("host.docker.internal", "127.0.0.1")
        async with httpx.AsyncClient() as client:
            start = asyncio.get_running_loop().time()
            await client.post(
                f"{local_url}/v1/chat/completions",
                json={"model": "m", "messages": []},
            )
            elapsed = asyncio.get_running_loop().time() - start
    assert elapsed >= 0.05


async def test_concurrent_gateways_keep_call_evidence_isolated(
    tmp_path: Path,
) -> None:
    state_a = tmp_path / "a"
    state_b = tmp_path / "b"
    async with (
        FakeModelGateway(state_file=str(state_a)) as gateway_a,
        FakeModelGateway(state_file=str(state_b)) as gateway_b,
    ):
        urls = [
            gateway_a.gateway_url.replace("host.docker.internal", "127.0.0.1"),
            gateway_b.gateway_url.replace("host.docker.internal", "127.0.0.1"),
        ]
        async with httpx.AsyncClient() as client:
            await asyncio.gather(
                client.post(
                    f"{urls[0]}/v1/chat/completions",
                    json={"model": "x", "messages": []},
                ),
                client.post(
                    f"{urls[1]}/v1/chat/completions",
                    json={"model": "x", "messages": []},
                ),
            )
    assert state_a.read_text() == "1\n"
    assert state_b.read_text() == "1\n"


async def test_embedding_request_does_not_count_as_model_call() -> None:
    async with FakeModelGateway() as gateway:
        local_url = gateway.gateway_url.replace("host.docker.internal", "127.0.0.1")
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{local_url}/api/embed", json={"model": "x", "input": "hello"}
            )
        assert response.status_code == 200
        assert response.json()["embeddings"]
        assert gateway.model_calls == 0


async def test_chunked_chat_completion_is_accepted() -> None:
    async with FakeModelGateway() as gateway:
        port = urlsplit(gateway.gateway_url).port
        assert port is not None
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(
            b"POST /v1/chat/completions HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/json\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b'9;client=test\r\n{"model":\r\n'
            b'4\r\n"x"}\r\n'
            b"0\r\nX-Request-Trailer: accepted\r\n\r\n"
        )
        await writer.drain()
        raw_response = await reader.read()
        writer.close()
        await writer.wait_closed()

        raw_headers, raw_body = raw_response.split(b"\r\n\r\n", 1)
        assert b" 200 OK\r\n" in raw_headers + b"\r\n"
        assert (
            json.loads(raw_body)["choices"][0]["message"]["content"]
            == gateway.response_text
        )
        assert gateway.model_calls == 1


async def test_tool_declaring_caller_gets_a_protocol_natural_round_trip() -> None:
    """First turn is a tool call against the caller's own tools; the nonce is
    inside its arguments, so an honest agent loop naturally feeds it back and
    unlocks the oracle answer on the second turn."""
    async with FakeModelGateway(oracle_answer="oracle-token-xyz") as gateway:
        local_url = gateway.gateway_url.replace("host.docker.internal", "127.0.0.1")
        async with httpx.AsyncClient() as client:
            first = await client.post(
                f"{local_url}/v1/chat/completions",
                json={
                    "model": "acme/reasoner-v3",
                    "messages": [{"role": "user", "content": "look this up"}],
                    "tools": [
                        {
                            "type": "function",
                            "function": {"name": "search_memory", "parameters": {}},
                        }
                    ],
                },
            )
            message = first.json()["choices"][0]["message"]
            assert message["content"] is None
            call = message["tool_calls"][0]
            assert call["function"]["name"] == "search_memory"
            arguments = json.loads(call["function"]["arguments"])
            assert gateway.response_text in arguments.values()
            assert first.json()["choices"][0]["finish_reason"] == "tool_calls"

            # The honest second turn carries the transcript (with the nonce).
            second = await client.post(
                f"{local_url}/v1/chat/completions",
                json={
                    "model": "acme/reasoner-v3",
                    "messages": [
                        {"role": "user", "content": "look this up"},
                        message,
                        {
                            "role": "tool",
                            "tool_call_id": call["id"],
                            "content": "no results",
                        },
                    ],
                },
            )
            final = second.json()["choices"][0]["message"]
            assert final["content"] == "oracle-token-xyz"
            assert second.json()["choices"][0]["finish_reason"] == "stop"
        assert gateway.model_calls == 2


async def test_text_only_caller_still_gets_a_plain_completion() -> None:
    """No declared tools means no un-executable tool call is forced."""
    async with FakeModelGateway(oracle_answer="oracle-token-xyz") as gateway:
        local_url = gateway.gateway_url.replace("host.docker.internal", "127.0.0.1")
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{local_url}/v1/chat/completions",
                json={
                    "model": "acme/reasoner-v3",
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )
        message = response.json()["choices"][0]["message"]
        assert message["content"] == gateway.response_text
        assert "tool_calls" not in message
