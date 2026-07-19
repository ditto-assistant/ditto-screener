# Ditto Screener

Platform-operated screening worker for Ditto SN118 submissions.

The stable core leases one submission at a time from `ditto-platform`,
downloads and verifies its tarball, enforces safe archive and root Rust package
rules, builds the Docker image, starts it with resource caps and an internal fake
gateway, waits for `/health`, then performs a bounded, read-only Luna source
review before submitting a lease-bound sr25519 result. Medium- and high-risk
results are quarantined for operator review, never automatically rejected. The
default manifest never calls `POST /run`. It never reads or writes the platform
database.

The health smoke mirrors the validator runtime contract: UID/GID 65532, a
read-only root filesystem, a bounded noexec `/tmp` tmpfs, dropped capabilities,
and a locked `DITTOBENCH_DB=/tmp/dittobench.db`. An image is never exported if
it only boots as root or depends on writing elsewhere in its root filesystem.

On a pass, the worker exports the exact verified image with `docker image save`,
hashes the archive, and uploads it sequentially in bounded multipart chunks.
Each storage request has a finite timeout and bounded retry policy; failures
trigger a best-effort multipart abort and the local archive is always removed.
The platform streams the completed object to verify the full archive SHA-256
before acknowledging it. The worker then binds that verified upload ID, archive
digest, byte size, immutable Docker image ID, and image reference into the
canonical signed verdict. Validators can therefore load the screened image
instead of repeating the Rust build.

The only shared application boundary is the dependency-light
`packages/ditto-screening-protocol` package. It owns request/response models,
`AgentStatus`, `SCREENING_POLICY_VERSION`, artifact metadata, and the canonical
verdict-signing message. The worker does not import platform or subnet
application packages.

Private modules can rotate timing and relay tripwires, randomized controls,
source/fingerprint triage, and behavioral challenge packs without changing the
v9 protocol or signing bytes. No private signal proves causal model use.
Modules can pass or route to `retryable_infra`, `quarantine`, or `inconclusive`;
only the objective stable core can return `deterministic_reject`.

The worker also sends the optional signed, privacy-bounded fleet heartbeat
defined by the open platform fleet-health work. It reports only five-point
CPU/memory/disk buckets, aggregate Docker health/counts, worker state, and the
active agent ID. Heartbeat protocol v2 may also include one allowlisted stage
(`preparing`, `downloading`, `validating`, `building`, `starting`,
`health_check`, or `submitting`) and the current job's signed start time. It
never includes artifact contents, build output, dependency or image metadata,
policy internals, paths, prompts, evidence, or secrets. An older platform can
reject the optional endpoint without blocking or changing screening.

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

Set `DITTOBENCH_API_DIR=/path/to/dittobench-api` as well to pass that exact
export through the real validator-side image loader during the integration test.

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
  absent, the worker runs the production v8 Luna policy with no `/run` call.
- `SCREENER_REVIEW_JOURNAL_FILE`: optional protected append-only journal path
  for quarantine and inconclusive evidence.
- `SCREENER_AUDIT_SEED`: secret seed read only when a configured random-control
  module names this environment variable.
- `SCREENER_SOURCE_REVIEW_API_KEY_FILE`: required mode-0400 OpenRouter key file
  for the private read-only source reviewer. The default model is
  `openai/gpt-5.6-luna`.

Source-review requests follow OpenRouter's app-attribution contract with
`HTTP-Referer: https://heyditto.ai` and `X-OpenRouter-Title: Ditto`.

See [docs/policy-modules.md](docs/policy-modules.md) for the private module
boundary, [docs/source-review-policy.md](docs/source-review-policy.md) for the
allowed-optimization and benchmark-emulation boundary,
[docs/binary-analysis.md](docs/binary-analysis.md) for the bounded opaque-file
inspection contract, and
[docs/deployment.md](docs/deployment.md) for deployment secrets, health checks,
cache maintenance, and the compatible rollout sequence.
