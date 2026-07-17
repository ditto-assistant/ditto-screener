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

Public source code or documentation for a benchmark does not make these runtime
shortcuts acceptable.

## Evidence threshold

A finding should identify the relevant `path:line` evidence and explain the
causal path from recognized input to changed output, tool trajectory, or model
bypass. The following are insufficient on their own:

- tuned parameters or multiple candidate profiles;
- generic answer-slot parsing;
- generic lexical retrieval of user-owned values;
- benchmark words in prose, comments, tests, or filenames;
- unchanged official fixtures recognized by exact provenance;
- local evaluation helpers that are unreachable from the submitted service.
- opacity or divergence from a starter model blob without content or behavioral
  evidence of prohibited logic;
- pinned dependency, lockfile, CI, or optional-secret syntax without evidence
  that the effective build reads credentials or replaces reviewed behavior;
- a metadata-only fixed-user side-probe bug that cannot expose content or alter
  the substantive model/tool result.

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

Every operator action must record a miner-visible reason describing the actual
evidence. Avoid conclusions based only on labels such as "optimized" or
"benchmark-aware."
