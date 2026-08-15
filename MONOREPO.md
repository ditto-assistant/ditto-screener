# Moved to ditto-subnet

Active screener development, releases, fleet bakes, and exact-release deploys
now live in
[`ditto-assistant/ditto-subnet/workers/screener`](https://github.com/ditto-assistant/ditto-subnet/tree/main/workers/screener).

The monorepo owns the production entry points:

- [component-gated releases](https://github.com/ditto-assistant/ditto-subnet/blob/main/.github/workflows/release.yml)
- [exact-release screener deploys](https://github.com/ditto-assistant/ditto-subnet/blob/main/.github/workflows/screener-deploy.yml)
- [fleet image bakes](https://github.com/ditto-assistant/ditto-subnet/blob/main/.github/workflows/screener-bake.yml)

This cutover removes the old standalone release and production mutations. The
monorepo owns one Targon-first capacity controller, GCE scale-to-zero fallback,
and a separate trusted-image builder. Hostile Targon execution remains disabled
until its capability gate passes.

Merge this only after the destination and infra stacks are ready. This
repository remains readable for history.
