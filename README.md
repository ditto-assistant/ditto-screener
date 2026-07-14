# Ditto Screener

Private, platform-operated screening worker for Ditto SN118 submissions.

The stable v6 core leases one submission at a time from `ditto-platform`,
downloads and verifies its tarball, enforces safe archive and root Rust package
rules, builds the Docker image, starts it with resource caps and an internal fake
gateway, waits for `/health`, and submits a lease-bound sr25519 verdict. The
default manifest never calls `POST /run`. It never reads or writes the platform
database.

The only shared application boundary is the dependency-light
`packages/ditto-screening-protocol` package. It owns request/response models,
`AgentStatus`, `SCREENING_POLICY_VERSION`, artifact metadata, and the canonical
verdict-signing message. The worker does not import platform or subnet
application packages.

Private modules can rotate timing and relay tripwires, randomized controls,
source/fingerprint triage, and behavioral challenge packs without changing the
public v6 protocol or signing bytes. No private signal proves causal model use.
Modules can pass or route to `retryable_infra`, `quarantine`, or `inconclusive`;
only the objective stable core can return `deterministic_reject`.

The worker also sends the optional signed, privacy-bounded fleet heartbeat
defined by the open platform fleet-health work. It reports only five-point
CPU/memory/disk buckets, aggregate Docker health/counts, worker state, and the
active agent ID. An older platform can reject the optional endpoint without
blocking or changing screening.

## Local development

```bash
uv sync --group dev
uv run ruff format --check .
uv run ruff check .
uv run mypy ditto_screener packages/ditto-screening-protocol
uv run pytest -m "not integration"
docker build -t ditto-screener:local .
```

The real Docker core smoke test needs a canonical starter-kit checkout:

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
- `SCREENER_GH_TOKEN_FILE`: optional path to a read-only token used only as a
  BuildKit secret for a private harness dependency.
- `SCREENER_POLICY_MANIFEST_FILE`: optional protected private manifest. When
  absent, the worker runs core-only v6 with no `/run` call.
- `SCREENER_REVIEW_JOURNAL_FILE`: optional protected append-only journal path
  for quarantine and inconclusive evidence.
- `SCREENER_AUDIT_SEED`: secret seed read only when a configured random-control
  module names this environment variable.

See [docs/policy-modules.md](docs/policy-modules.md) for the private module
boundary and [docs/deployment.md](docs/deployment.md) for deployment secrets,
health checks, cache maintenance, and the compatible rollout sequence.
