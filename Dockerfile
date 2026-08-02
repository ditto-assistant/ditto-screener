FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de

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
