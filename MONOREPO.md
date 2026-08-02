# Moved to ditto-subnet

Active screener development, releases, fleet bakes, and exact-release deploys
now live in
[`ditto-assistant/ditto-subnet/workers/screener`](https://github.com/ditto-assistant/ditto-subnet/tree/main/workers/screener).

This cutover removes the old standalone release and production mutations. The
monorepo owns one Targon-first capacity controller, GCE scale-to-zero fallback,
and a separate trusted-image builder. Hostile Targon execution remains disabled
until its capability gate passes.

Merge this only after the destination and infra stacks are ready. This
repository remains readable for history.
