# Ditto Screener

Private, platform-operated screening worker for Ditto SN118 submissions.

The worker leases one submission at a time from `ditto-platform`, downloads and
verifies its tarball, checks the archive contract, builds the Docker image,
waits for `/health`, runs a hidden model-response canary, and submits a
lease-bound sr25519 verdict. It never reads or writes the platform database.

The only shared application boundary is the dependency-light
`packages/ditto-screening-protocol` package. It owns the request and response
models, `AgentStatus`, `SCREENING_POLICY_VERSION`, artifact metadata, and the
canonical verdict-signing message. The worker does not import the platform or
subnet application packages.

## Local development

```bash
uv sync --group dev
uv run ruff format --check .
uv run ruff check .
uv run mypy ditto_screener
uv run pytest -m "not integration"
docker build -t ditto-screener:local .
```

The real Docker canary smoke test needs a canonical starter-kit checkout:

```bash
DITTO_STARTER_KIT_DIR=/path/to/dittobench-starter-kit \
  uv run pytest -m integration tests/test_gate_docker_integration.py -vv
```

## Runtime configuration

Required values are supplied through the production host's protected
`screener.env` file:

- `SCREENER_PLATFORM_API_URL`: platform API base URL.
- `SCREENER_API_TOKEN`: dedicated bearer token, at least 32 characters.
- `SCREENER_HOTKEY`: allowlisted public screener SS58 address.
- `SCREENER_WALLET_NAME` and `SCREENER_WALLET_HOTKEY`, or
  `SCREENER_MNEMONIC`: signing-key source. Prefer the host wallet.
- `SCREENER_GH_TOKEN_FILE`: optional path to a read-only GitHub token used only
  as a BuildKit secret for private harness dependencies.

See [docs/deployment.md](docs/deployment.md) for deployment secrets, health
checks, cache maintenance, and the compatible rollout sequence.
