# Private policy modules

The policy boundary separates stable public-v6 enforcement from rotating
private triage. Daily rotations replace a protected JSON manifest and restart
the worker. They do not change `SCREENING_POLICY_VERSION`, API models, database
state, or canonical verdict-signing bytes.

## Typed outcomes

| Outcome | Source | Public behavior |
| --- | --- | --- |
| `pass` | Stable core passed; selected private audit, if any, cleared | Signed `passed=true`; existing promotion applies |
| `deterministic_reject` | Objective stable-core archive, Rust package, build, or health failure | Signed `passed=false`; terminal `rejected` |
| `retryable_infra` | Download, Docker host, policy feed/pack, or other infrastructure failure | Signed `passed=false` with the existing `screener error:` marker; retryable `screening_failed` |
| `quarantine` | Private tripwire or behavioral shape needs review | No public verdict; bounded private journal entry; lease remains authoritative |
| `inconclusive` | Selected private challenge could not yield usable evidence | No public verdict; bounded private journal entry; lease remains authoritative |

Only `deterministic_reject` is a terminal failure, and private modules cannot
emit it. Timing, score, relay, source, and response-shape observations are risk
signals, not proof that a harness did or did not causally use a model. Fast,
high-scoring submissions and a randomized control sample can both enter the
same rotating challenges, so fixed sleeps or dummy calls do not form the policy.

## Manifest boundary

The strict manifest contains exactly `policy_version`, `rotation_id`, and
`modules`. Supported module kinds are:

- `timing_relay_risk`: reads a bounded private aggregate feed and emits only a
  tripwire or retryable infrastructure outcome.
- `random_audit`: uses HMAC with the named secret seed environment variable to
  select a deterministic private control sample for that rotation.
- `source_fingerprint`: compares bounded canonical source/layout fingerprints
  and emits only a tripwire.
- `behavioral_challenge_pack`: runs bounded private `/run` requests only after a
  selector trips. It records response digests, elapsed time, and JSON keys, not
  private prompts or response bodies. An anomaly becomes quarantine and an
  unusable observation becomes inconclusive.

The worker logs the manifest digest and rotation ID at startup. Quarantine and
inconclusive journal records contain agent/attempt IDs, outcome, manifest
digest, and bounded public-safe evidence codes. The journal is created mode
`0600`; its parent is mode `0700`. Operators must rotate, retain, and inspect it
as private security data.
