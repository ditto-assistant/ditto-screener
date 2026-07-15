# Private policy modules

The policy boundary separates stable public-v7 enforcement from rotating
private triage. Daily rotations replace a protected JSON manifest and restart
the worker. They do not change `SCREENING_POLICY_VERSION`.

## Typed outcomes

| Outcome | Source | Public behavior |
| --- | --- | --- |
| `pass` | Stable core passed; selected private audit, if any, cleared | Signed `passed=true`; existing promotion applies |
| `deterministic_reject` | Objective stable-core archive, Rust package, build, or health failure | Signed `passed=false`; terminal `rejected` |
| `retryable_infra` | Download, Docker host, policy feed/pack, or other infrastructure failure | Signed `passed=false` with the existing `screener error:` marker; retryable `screening_failed` |
| `quarantine` | Private source review or behavioral audit needs review | Signed attempt-bound quarantine result; platform persists a non-scoreable hold |
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
- `agentic_source_review`: gives GPT-5.6 Luna bounded read/list/literal-search
  tools over the verified archive. Source is treated as adversarial data; the
  reviewer has no shell, edits, execution, web, external-directory, or secret
  tools. Medium/high risk can only select quarantine or a behavioral audit.
  Exact SHA-256 provenance for named official starter-kit fixture/model files
  prevents unchanged binaries and seed data from being mistaken for suspicious
  static tables. Trust never extends to a changed path or derivative file.
- `behavioral_challenge_pack`: runs bounded private `/run` requests only after a
  selector trips. It records response digests, elapsed time, and JSON keys, not
  private prompts or response bodies. An anomaly becomes quarantine and an
  unusable observation becomes inconclusive.

A challenge can opt into `require_model_call` and
`require_gateway_token`. The first requires at least one chat/responses call
to the isolated fake OpenAI-compatible gateway during that challenge. The
second additionally requires the harness response to carry the gateway's
per-container random output, establishing bounded request-to-response dataflow.
A missing call or missing dataflow token quarantines the attempt; it never
creates a deterministic rejection. Embedding-only traffic does not satisfy the
model-call check.

Challenge packs and selectors remain protected operator inputs. Rotate request
shapes, identifiers, and audit sampling together; do not commit a production
pack or a known-source digest. Separate workers use separate Docker networks,
container names, gateway tokens, and state files, so horizontal concurrency
cannot mix audit evidence.

The worker logs the manifest digest and rotation ID at startup. Quarantine and
inconclusive journal records contain agent/attempt IDs, outcome, manifest
digest, and bounded public-safe evidence codes. The journal is created mode
`0600`; its parent is mode `0700`. Operators must rotate, retain, and inspect it
as private security data.

Source review uses `provider.zdr=true` and `data_collection=deny` on every
OpenRouter request. Tool output and step counts are bounded. The API key is read
from the mode-0400 file named by `SCREENER_SOURCE_REVIEW_API_KEY_FILE`; it is
never injected into a submitted container or written to the review journal.

Source-review holds use public-safe risk-domain reason codes. Private-challenge
risk, malicious-source risk, and exact-artifact originality risk are distinct;
raw categories, paths, prompts, and evidence stay private. A source-safe exact
duplicate must still be held by the originality guard and must not be relabeled
as private-challenge leakage.
