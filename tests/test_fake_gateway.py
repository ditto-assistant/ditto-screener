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
                    "model": "ignored",
                    "messages": [{"role": "user", "content": "hello"}],
                },
            )
        assert response.status_code == 200
        assert (
            response.json()["choices"][0]["message"]["content"] == gateway.response_text
        )
        assert gateway.model_calls == 1
        assert state.read_text() == "1\n"
        assert not state.stat().st_mode & 0o077


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
