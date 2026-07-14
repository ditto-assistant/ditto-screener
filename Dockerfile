FROM python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3

RUN apt-get update \
    && apt-get install --no-install-recommends -y docker-cli git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv@sha256:0f36cb9361a3346885ca3677e3767016687b5a170c1a6b88465ec14aefec90aa /uv /uvx /bin/

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY packages/ditto-screening-protocol ./packages/ditto-screening-protocol
COPY ditto_screener ./ditto_screener
RUN uv sync --frozen --no-dev

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["uv", "run", "--no-sync", "python", "-m", "ditto_screener.health"]

CMD ["uv", "run", "--no-sync", "python", "-m", "ditto_screener"]
