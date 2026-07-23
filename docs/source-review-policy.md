# Source-review decision policy

The source reviewer identifies submissions that replace a general agent with
benchmark-, scorer-, or audit-specific behavior. Its findings select operator
quarantine; they never create an automatic terminal rejection.

## Allowed optimization

Miners may tune candidate profiles, prompts, model settings, retrieval and
reranking, context construction, memory lifecycle behavior, and tool routing.
They may use documented protocol fields, including answer and abstain fields,
when those fields faithfully serialize a genuine model or tool result. Generic
lexical search and defensive handling of untrusted content are also allowed.

Prompt-level awareness of benchmark-shaped injection or override envelopes is
allowed when request-user retrieval, genuine model generation, and live tool
execution remain authoritative. General temporal, count, ordering, and list
facts may be computed from current user-scoped memories and supplied as context
to that model. Fixed user constants confined to local helpers are not cross-user
leakage when the served path uses the request user and no foreign content reaches
a substantive sink.

None of these mechanisms is suspicious merely because it improves a public
benchmark. Mentioning benchmark terminology, keeping local evaluation tools, or
shipping byte-identical official starter-kit fixtures is not evidence of
cheating. Modified code still needs a causal runtime connection to a prohibited
behavior before it is reported.

Opaque artifacts receive the same treatment. The reviewer can inspect bounded
binary structure, strings, and public benchmark-schema markers without
executing the file. A changed model is not suspicious solely because its
weights differ, and a model filename or valid container is not a safe harbor.
The finding must connect the artifact to prohibited runtime behavior.

That rule includes build inputs and learned artifacts. A checksum-pinned public
Git dependency, lockfile checksums, ordinary CI, and an optional unused
BuildKit secret are normal locked-build mechanisms. A modified opaque ONNX/BERT
cross-encoder used only to rerank live query-memory candidates is also allowed
unless its contents or behavior show answer tables, challenge strings,
deterministic dispatch, or an executable bypass.

User scoping is judged across the substantive request -> retrieval -> model ->
tool -> response path. A fixed-user bug in an abstention-only side probe remains
a correctness defect, but it is not malicious cross-user access when no other
user's content reaches model context, tool execution, the response, a log, or
an outbound sink and the probe cannot replace the request-user path.

Reachable fixed-user writes, cross-user lifecycle maps, and global lifecycle
state are classified as `user_isolation_correctness` when they do not carry
another user's content into the substantive path. That category may justify a
correctness review, but it is not benchmark-emulation or malicious-source proof
and does not justify an anti-cheat rejection by itself.

Likewise, an external or pinned input may be recorded as
`external_build_dependency` when it expands the review surface without concrete
malicious behavior. Only an effective build that reads or leaks credentials,
executes mutable unreviewed logic, installs a backdoor, or replaces the reviewed
runtime qualifies as `malicious_build`.

## Benchmark emulation

Quarantine for `benchmark_emulation` when evidence from the effective build or
runtime path shows at least one of these behaviors:

- exact generator, scorer, canary, challenge, or audit token/template
  recognition that changes runtime behavior;
- deterministic solvers or phrase tables for scored question families that
  bypass the claimed general model/tool path;
- training or runtime selection based on expected answers, answer items,
  evaluator/grader implementations, or private challenge outcomes;
- scorer-aware answer or abstain rewriting that is not derived from the genuine
  model/tool result, including inserting served grading needles;
- fabricated tool trajectories or calls made only to satisfy the evaluator;
- screening-environment fingerprinting that presents different audit behavior.

Use `scorer_contract_manipulation` as an additional category when reachable
code exploits which response half or field the grader observes, emits parallel
tool and memory answers because only one is scored, or synthesizes answer and
abstain fields outside the genuine agent result.

Public source code or documentation for a benchmark does not make these runtime
shortcuts acceptable.

### DittoBench v3 reachability preflight

DittoBench v3 reserves one exact, non-scored transport handshake. A `/run`
request whose case-sensitive `case_id` starts with `preflight:` asks the harness
to prove that the validator-supplied `tool_endpoint` is reachable from the
harness network namespace. The handler is required to bypass model inference,
POST exactly one real `ToolExecRequest` to that request's endpoint, and then
return the mechanical acknowledgement.

That branch is protocol compliance, not benchmark emulation, only when the
source proves the complete boundary:

- the exact reserved `preflight:` prefix is checked;
- the endpoint is the nonempty value supplied on the same request;
- the posted body preserves the incoming case ID and request user (or protocol
  default), names `search_web`, carries JSON-object arguments, and uses hop 0;
- an actual POST is attempted. The handler may ignore or discard the client-side
  response and may return the matching self-reported `ObservedToolCall`, because
  validator-side endpoint observation—not that untrusted report—decides whether
  the probe passed or the run fails and retries;
- acknowledgement or error prose is not an observed call. A handler may append
  the reported call only after a successful POST and otherwise return prose
  with an empty call list;
- the response is only the required acknowledgement and cannot affect an
  ordinary scored request.

The exception does not cover near-miss prefixes, substring or general probe
detection, other tools, fixed or substituted endpoints, no actual POST attempt,
scored answers, or a preflight branch that leaks into normal case handling. A
self-reported call with no matching POST attempt remains suspicious. The same
report paired with the required best-effort POST cannot fabricate authoritative
success and is allowed. Other paths remain subject to the ordinary
benchmark-emulation, scorer-contract, and tool-fidelity rules.

Generator mirroring may be distributed rather than expressed as one obvious
answer table. Source review therefore surfaces an aggregate routing signal for
coordinated overlap across attribute ontologies, question templates, fact and
update frames, event labels, retrieval vocabulary, and deterministic answer
paths. The signal is not itself a finding. Reviewers must cite exact runtime
locations and connect multiple mirrored dimensions to a served answer that
bypasses model inference. Request-user grounding does not make a proven model
bypass general-purpose, and literal answer keys are not required. Conversely,
grounding plus an authoritative real model call is not a bypass.

## Evidence threshold

A finding should identify the relevant `path:line` evidence and explain the
causal path from recognized input to changed output, tool trajectory, or model
bypass. Medium/high findings require evidence for every category. Benchmark
emulation and scorer-contract manipulation require at least two distinct,
validated source locations covering the trigger and effect. Location-only
review leads in the initial inventory are search prompts, not findings; the
reviewer must prove they are reachable before citing them. The following are
insufficient on their own:

- tuned parameters or multiple candidate profiles;
- generic answer-slot parsing;
- generic lexical retrieval of user-owned values;
- benchmark words in prose, comments, tests, or filenames;
- unchanged official fixtures recognized by exact provenance;
- local evaluation helpers that are unreachable from the submitted service.
- local Docker launchers are not part of the screened image merely because they
  are present in the archive. Require a Dockerfile build/runtime instruction to
  invoke the script; `COPY` or permission changes alone are not execution.
- opacity or divergence from a starter model blob without content or behavioral
  evidence of prohibited logic;
- pinned dependency, lockfile, CI, or optional-secret syntax without evidence
  that the effective build reads credentials or replaces reviewed behavior;
- a metadata-only fixed-user side-probe bug that cannot expose content or alter
  the substantive model/tool result.
- an external or pinned build input without concrete execution, credential,
  exfiltration, backdoor, or runtime-replacement behavior.
- one generator-mirroring dimension, ordinary schema/retrieval vocabulary, or
  an aggregate candidate with no reachable pre-model response path.
- prompt-level injection or benchmark awareness followed by authoritative
  request-user retrieval, genuine model generation, and live tool execution;
- temporal, count, ordering, or list context derived from current user memories
  and supplied to a real model;
- insufficient behavioral-oracle round trips or infrastructure failures.

When the causal connection is ambiguous, quarantine evidence may describe the
uncertainty, but operators should not reject solely on terminology, timing,
score, or a single fingerprint signal.

## Operator outcomes

- **Release** when the implementation is a general reusable agent and the
  evidence is ordinary optimization or a false positive.
- **Rescreen** when evidence is incomplete because of screener or review
  infrastructure, or when a corrected artifact should receive a fresh policy
  run.
- **Reject** when source evidence establishes benchmark emulation, hidden-value
  leakage, fabricated execution, cross-user access, credential/exfiltration
  behavior, malicious build behavior, or another documented policy violation.

`user_isolation_correctness` and `external_build_dependency` are advisory
categories. They may support hardening, rescreening, or a separate correctness
review, but are not terminal anti-cheat grounds by themselves.

Every operator action must record a miner-visible reason describing the actual
evidence. Avoid conclusions based only on labels such as "optimized" or
"benchmark-aware."

### Historical preflight-only holds

Past quarantines can be selected as *rescreen candidates* without changing
review state by filtering for source-review findings whose only cited causal
path is the reserved preflight handler. Re-open the exact digest-bound artifact
offline and verify every condition above, including the real endpoint POST and
isolation from ordinary scored requests. Exclude any hold with another category,
another causal path, ambiguous execution, or missing source evidence.

Do not bulk-release candidates from metadata alone. After the new policy is
deployed, use the normal guarded rescreen workflow with a fresh identity/status
check so each artifact receives the current complete review. This PR performs
no production query, rescreen, release, rejection, or verdict mutation.
