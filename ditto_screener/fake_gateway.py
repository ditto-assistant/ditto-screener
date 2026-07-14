"""Ephemeral fake model gateway for isolated harness startup and private audits.

The server runs in a locked-down sidecar on the harness's isolated Docker
network and implements the small OpenAI-compatible surface a harness needs for
optional private behavioral challenge. The public v6 build gate never calls
``POST /run`` and never treats this server as proof of causal model use.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
from pathlib import Path
from types import TracebackType

_MAX_HEADER_BYTES = 64 * 1024
_MAX_BODY_BYTES = 1024 * 1024
_EMBED_DIMENSIONS = 768
LOCKED_HARNESS_MODEL = "qwen/qwen3-32b"


class FakeModelGateway:
    """Short-lived OpenAI-compatible HTTP server with observable call state."""

    def __init__(
        self,
        *,
        response_text: str | None = None,
        host: str = "0.0.0.0",
        port: int = 0,
        state_file: str | None = None,
    ) -> None:
        self.response_text = response_text or f"ditto-fake-{secrets.token_hex(16)}"
        self.model_calls = 0
        self._host = host
        self._port = port
        self._state_file = state_file
        self._server: asyncio.Server | None = None

    @property
    def gateway_url(self) -> str:
        """URL the Docker container can use for this host-side server."""
        if self._server is None or not self._server.sockets:
            raise RuntimeError("fake model gateway is not running")
        port = int(self._server.sockets[0].getsockname()[1])
        return f"http://host.docker.internal:{port}"

    async def __aenter__(self) -> FakeModelGateway:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)
        return self

    def _record_model_call(self) -> None:
        self.model_calls += 1
        if self._state_file is not None:
            path = Path(self._state_file)
            fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                os.fchmod(fd, 0o600)
                os.write(fd, b"1\n")
            finally:
                os.close(fd)

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _tb: TracebackType | None,
    ) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        status = "200 OK"
        payload: dict[str, object]
        try:
            raw_headers = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=5
            )
            if len(raw_headers) > _MAX_HEADER_BYTES:
                raise ValueError("headers too large")
            lines = raw_headers.decode("latin-1").split("\r\n")
            method, path, _version = lines[0].split(" ", 2)
            headers = {
                key.strip().casefold(): value.strip()
                for line in lines[1:]
                if ":" in line
                for key, value in [line.split(":", 1)]
            }
            if headers.get("expect", "").casefold() == "100-continue":
                writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
                await writer.drain()
            # The gateway only supplies an offline-compatible model surface.
            # Some compatible clients stream chunked bodies differently across
            # architectures, so tolerate body framing quirks here.
            # Drain a well-formed body when possible, but do not turn a body
            # framing quirk into a permanent miner rejection.
            try:
                await self._read_request_body(reader, headers)
            except (
                TimeoutError,
                ValueError,
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
            ) as error:
                print(
                    f"fake gateway ignored request-body framing error: {error}",
                    flush=True,
                )

            if method == "POST" and path.rstrip("/") in {
                "/v1/chat/completions",
                "/chat/completions",
            }:
                self._record_model_call()
                payload = {
                    "id": "chatcmpl-ditto-screening-fake",
                    "object": "chat.completion",
                    "created": 0,
                    "model": LOCKED_HARNESS_MODEL,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": self.response_text,
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                    },
                }
            elif method == "POST" and path.rstrip("/") in {
                "/v1/responses",
                "/responses",
            }:
                self._record_model_call()
                payload = {
                    "id": "resp_ditto_screening_fake",
                    "object": "response",
                    "status": "completed",
                    "model": LOCKED_HARNESS_MODEL,
                    "output": [
                        {
                            "type": "message",
                            "role": "assistant",
                            "content": [
                                {"type": "output_text", "text": self.response_text}
                            ],
                        }
                    ],
                    "output_text": self.response_text,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            elif method == "POST" and path.rstrip("/") in {
                "/api/embed",
                "/api/embeddings",
                "/v1/embeddings",
            }:
                vector = [0.0] * _EMBED_DIMENSIONS
                vector[0] = 1.0
                payload = {
                    "model": LOCKED_HARNESS_MODEL,
                    "embeddings": [vector],
                    "data": [{"index": 0, "embedding": vector}],
                }
            else:
                status = "404 Not Found"
                payload = {"error": {"message": "unsupported fake gateway endpoint"}}
        except (
            TimeoutError,
            ValueError,
            UnicodeError,
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            OSError,
        ) as error:
            print(f"fake gateway rejected malformed request: {error}", flush=True)
            status = "400 Bad Request"
            payload = {"error": {"message": "malformed fake gateway request"}}

        body = json.dumps(payload, separators=(",", ":")).encode()
        writer.write(
            f"HTTP/1.1 {status}\r\n".encode()
            + b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        writer.close()
        with contextlib.suppress(ConnectionError):
            await writer.wait_closed()

    @staticmethod
    async def _read_request_body(
        reader: asyncio.StreamReader, headers: dict[str, str]
    ) -> bytes:
        """Read a bounded fixed-length or chunked HTTP request body."""
        transfer_encodings = {
            value.strip().casefold()
            for value in headers.get("transfer-encoding", "").split(",")
            if value.strip()
        }
        if transfer_encodings and transfer_encodings != {"chunked"}:
            raise ValueError("unsupported transfer encoding")
        if transfer_encodings:
            return await FakeModelGateway._read_chunked_body(reader)

        length = int(headers.get("content-length", "0"))
        if length < 0 or length > _MAX_BODY_BYTES:
            raise ValueError("body too large")
        if not length:
            return b""
        return await asyncio.wait_for(reader.readexactly(length), timeout=5)

    @staticmethod
    async def _read_chunked_body(reader: asyncio.StreamReader) -> bytes:
        body = bytearray()
        while True:
            raw_size = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=5)
            size_text = raw_size[:-2].split(b";", 1)[0].strip()
            if not size_text:
                raise ValueError("missing chunk size")
            size = int(size_text, 16)
            if size < 0 or len(body) + size > _MAX_BODY_BYTES:
                raise ValueError("body too large")
            if size == 0:
                while True:
                    trailer = await asyncio.wait_for(
                        reader.readuntil(b"\r\n"), timeout=5
                    )
                    if trailer == b"\r\n":
                        return bytes(body)
            body.extend(await asyncio.wait_for(reader.readexactly(size), timeout=5))
            if await asyncio.wait_for(reader.readexactly(2), timeout=5) != b"\r\n":
                raise ValueError("malformed chunk terminator")


async def _serve_sidecar() -> None:
    """Run the fixed-port server used by the isolated Docker sidecar."""
    response_text = os.environ["DITTO_FAKE_GATEWAY_RESPONSE"]
    state_file = os.environ.get("DITTO_FAKE_GATEWAY_STATE_FILE")
    async with FakeModelGateway(
        response_text=response_text,
        host="0.0.0.0",
        port=8080,
        state_file=state_file,
    ):
        await asyncio.Event().wait()


if __name__ == "__main__":  # pragma: no cover - exercised in Docker E2E
    asyncio.run(_serve_sidecar())
