"""Bounded semantic leads for the agentic source reviewer.

These rules do not decide policy. They identify nearby combinations of generic
source concepts that deserve an explicit reachability check by the reviewer.
Only locations and semantic roles are returned; source text and matched values
never leave the archive through this module.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

_MAX_LEADS = 32
_MAX_LEADS_PER_RULE_FILE = 4
_WINDOW_LINES = 18
_MAX_STATIC_FINDINGS = 16
_COMMAND_EXECUTION_EFFECT = re.compile(
    r"\b(?:Command::new|subprocess\.|os\.system|child_process\.|execFile|spawn)\b"
)


@dataclass(frozen=True)
class _Role:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class _Rule:
    kind: str
    roles: tuple[_Role, ...]
    build_files_only: bool = False


@dataclass(frozen=True)
class _StaticRule:
    category: str
    kind: str
    roles: tuple[_Role, ...]


def _words(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


_RULES = (
    _Rule(
        "challenge-shaped-retrieval-override",
        (
            _Role(
                "challenge-shape",
                _words(
                    r"\b(?:canary|rare[-_ ]?code|challenge[-_ ]?(?:token|value)|"
                    r"grader[-_ ]?slot|scorer[-_ ]?slot)\b"
                ),
            ),
            _Role(
                "input-recognition",
                _words(
                    r"\b(?:contains|starts_with|ends_with|matches|regex|parse|"
                    r"detect|recogniz(?:e|es|ed|ing))\b"
                ),
            ),
            _Role(
                "retrieval-override",
                _words(
                    r"\b(?:inject|force|must[-_ ]?include|broaden|search[-_ ]?all|"
                    r"scan[-_ ]?all|push_front|override)\b"
                ),
            ),
        ),
    ),
    _Rule(
        "deterministic-challenge-resolver",
        (
            _Role(
                "question-family",
                _words(
                    r"\b(?:as[-_ ]?of|temporal|count|ordering|latest[-_ ]?before|"
                    r"grader[-_ ]?slot)\b"
                ),
            ),
            _Role(
                "template-recognition",
                _words(r"\b(?:template|regex|contains|starts_with|token)\b"),
            ),
            _Role(
                "answer-synthesis",
                _words(
                    r"\b(?:resolve|synthesi[sz]e|construct|return|answer|abstain)\b"
                ),
            ),
        ),
    ),
    _Rule(
        "scorer-contract-manipulation",
        (
            _Role(
                "scorer-contract",
                _words(
                    r"\b(?:scorer|grader|scored|unscored|ignored|score[-_ ]?only)\b"
                ),
            ),
            _Role("tool-half", _words(r"\btool(?:s|_calls?|[-_ ]?response)?\b")),
            _Role("memory-half", _words(r"\bmemor(?:y|ies|y[-_ ]?response)\b")),
            _Role(
                "response-synthesis",
                _words(r"\b(?:answer|abstain|synthesi[sz]e|emit|construct|override)\b"),
            ),
        ),
    ),
    _Rule(
        "challenge-template-rewrite",
        (
            _Role(
                "challenge-shape",
                _words(r"\b(?:challenge|exam|audit|grader|scorer)\b"),
            ),
            _Role(
                "input-rewrite",
                _words(
                    r"\b(?:strip|drop|remove|trailing[-_ ]?question|exact[-_ ]?reply|"
                    r"override|rewrite)\b"
                ),
            ),
            _Role(
                "request-preprocessor",
                _words(r"\b(?:saniti[sz]e|guard|preprocess|normalize|rewrite)\b"),
            ),
        ),
    ),
    _Rule(
        "instruction-envelope-rewrite",
        (
            _Role(
                "instruction-envelope",
                _words(
                    r"\b(?:override|exact[-_ ]?(?:reply|response)|"
                    r"opaque[-_ ]?(?:payload|token)|response[-_ ]?constraint)\b"
                ),
            ),
            _Role(
                "prefix-or-payload-removal",
                _words(
                    r"\b(?:strip|drop|remove|retain|prefix|trailing[-_ ]?question)\b"
                ),
            ),
            _Role(
                "request-preprocessor",
                _words(r"\b(?:saniti[sz]e|guard|preprocess|normalize|rewrite)\b"),
            ),
        ),
    ),
    _Rule(
        "audit-gated-model-routing",
        (
            _Role(
                "audit-envelope-signal",
                _words(
                    r"\b(?:case[-_ ]?id|tool[-_ ]?endpoint|tools?[-_ ]?present|"
                    r"has[-_ ]?tools?|memory[-_ ]?empty|empty[-_ ]?memory|"
                    r"is[-_ ]?probe|is[-_ ]?audit|"
                    r"being[-_ ]?(?:scored|graded|watched)|watched|"
                    r"observed|preceded[-_ ]?by[-_ ]?seed)\b"
                ),
            ),
            _Role(
                "genuine-model-route",
                _words(
                    r"\b(?:call[-_ ]?model|invoke[-_ ]?model|real[-_ ]?model|"
                    r"run[-_ ]?model|llm|inference|general[-_ ]?agent|"
                    r"agent[-_ ]?path)\b"
                ),
            ),
            _Role(
                "deterministic-route",
                _words(
                    r"\b(?:deterministic|solver|solve[-_ ]?(?:known|case)|lookup|"
                    r"answer[-_ ]?table|phrase[-_ ]?table|precomputed|hard[-_ ]?coded|"
                    r"canned|shortcut|fast[-_ ]?path)\b"
                ),
            ),
        ),
    ),
    _Rule(
        "user-isolation-correctness",
        (
            _Role(
                "fixed-or-global-user-state",
                _words(
                    r"\b(?:default[-_ ]?user|fixed[-_ ]?user|global[-_ ]?(?:state|map)|"
                    r"static[-_ ]?(?:state|map))\b"
                ),
            ),
            _Role(
                "lifecycle-access",
                _words(
                    r"\b(?:lifecycle|abstain|seed|retriev|write|insert|upsert|store)\w*\b"
                ),
            ),
        ),
    ),
    _Rule(
        "external-build-input",
        (
            _Role(
                "external-input",
                _words(
                    r"(?:https?://|git\+|\bcurl\b|\bwget\b|\bgit\s+clone\b|"
                    r"mount=type=secret)"
                ),
            ),
        ),
        build_files_only=True,
    ),
)


# These preflight rules are deliberately narrower than the advisory leads
# above. Each requires a dangerous target plus an operational effect in nearby
# executable source. Matches stop the artifact before any Docker build or run;
# documentation, tests, examples, and comments on their own never qualify.
_STATIC_MALICIOUS_RULES = (
    _StaticRule(
        "malicious_build",
        "docker-control-plane",
        (
            _Role(
                "docker-endpoint",
                _words(
                    r"(?:/var/run/docker\.sock|/run/(?:user/[0-9]+/)?docker\.sock|"
                    r"\bDOCKER_HOST\b|tcp://[^\s]+:237[56]|/v1\.[0-9]+/(?:containers|images|volumes))"
                ),
            ),
            _Role(
                "control-effect",
                _words(
                    r"\b(?:connect|request|post|create|start|exec|build|mount|"
                    r"run|socket|client|daemon)\w*\b"
                ),
            ),
        ),
    ),
    _StaticRule(
        "malicious_build",
        "host-mount-or-namespace",
        (
            _Role(
                "host-boundary",
                _words(
                    r"(?:--privileged\b|--(?:pid|ipc|network)(?:=|\s+)host\b|"
                    r"(?:source|src)(?:=|:)\s*/(?:\s|[,\"'])|"
                    r"(?:-v|--volume)\s+/(?:\s*):|/proc/1/root)"
                ),
            ),
            _Role(
                "boundary-effect",
                _words(
                    r"\b(?:mount|bind|volume|namespace|container|docker|podman)\w*\b"
                ),
            ),
        ),
    ),
    _StaticRule(
        "credential_access",
        "credential-discovery",
        (
            _Role(
                "credential-path",
                _words(
                    r"(?:/proc/(?:1|self)/environ|(?:^|[/\\])\.env\b|"
                    r"(?:^|[/\\])\.(?:ssh|aws|azure)(?:[/\\]|\b)|"
                    r"\.config[/\\]gcloud|\.bittensor[/\\]wallets|"
                    r"credentials?(?:\.json|[/\\]))"
                ),
            ),
            _Role(
                "read-effect",
                _words(r"\b(?:read|open|cat|load|scan|walk|glob|copy|collect)\w*\b"),
            ),
        ),
    ),
    _StaticRule(
        "cross_user_access",
        "cross-user-host-access",
        (
            _Role(
                "cross-user-path",
                _words(r"(?:/root(?:/|\b)|/home/|/Users/|/proc/1/root|/host(?:/|\b))"),
            ),
            _Role(
                "access-effect",
                _words(r"\b(?:read|open|scan|walk|glob|copy|write|remove|upload)\w*\b"),
            ),
        ),
    ),
    _StaticRule(
        "data_exfiltration",
        "sensitive-data-exfiltration",
        (
            _Role(
                "sensitive-source",
                _words(
                    r"(?:/proc/(?:1|self)/environ|(?:^|[/\\])\.env\b|"
                    r"(?:^|[/\\])\.(?:ssh|aws|azure)(?:[/\\]|\b)|"
                    r"\.config[/\\]gcloud|\.bittensor[/\\]wallets|"
                    r"std::env::vars|env::vars|os\.environ|"
                    r"GetEnvironmentVariables|private[-_ ]?key|mnemonic)"
                ),
            ),
            _Role(
                "outbound-effect",
                _words(
                    r"\b(?:upload|exfiltrat|webhook|callback|send|post|put|"
                    r"curl|wget|http[-_ ]?client|reqwest|requests?)\w*\b"
                ),
            ),
        ),
    ),
)


def find_source_review_leads(
    files: Iterable[tuple[str, str]],
) -> list[dict[str, object]]:
    """Return bounded location-only review leads from readable source files."""
    leads: list[dict[str, object]] = []
    for path, text in sorted(files, key=lambda item: _path_priority(item[0])):
        lines = text.splitlines()
        if not lines:
            continue
        for rule in _RULES:
            if rule.build_files_only and not _is_build_file(path):
                continue
            role_hits = {
                role.name: [
                    line_number
                    for line_number, line in enumerate(lines, 1)
                    if role.pattern.search(
                        line[:4096].replace("_", " ").replace("-", " ")
                    )
                ]
                for role in rule.roles
            }
            if any(not hits for hits in role_hits.values()):
                continue
            seen: set[tuple[tuple[str, int], ...]] = set()
            anchors = sorted({line for hits in role_hits.values() for line in hits})
            for anchor in anchors:
                locations: list[dict[str, object]] = []
                signature: list[tuple[str, int]] = []
                for role in rule.roles:
                    nearby = min(
                        role_hits[role.name],
                        key=lambda line: (abs(line - anchor), line),
                    )
                    if abs(nearby - anchor) > _WINDOW_LINES:
                        break
                    signature.append((role.name, nearby))
                    locations.append({"path": path, "line": nearby, "role": role.name})
                else:
                    normalized = tuple(signature)
                    if normalized in seen:
                        continue
                    seen.add(normalized)
                    leads.append({"kind": rule.kind, "locations": locations})
                    if len(leads) >= _MAX_LEADS:
                        return leads
                    if len(seen) >= _MAX_LEADS_PER_RULE_FILE:
                        break
    return leads


def find_decisive_malicious_source(
    files: Iterable[tuple[str, str]],
) -> list[dict[str, object]]:
    """Return high-confidence, location-only findings for pre-build quarantine."""
    findings: list[dict[str, object]] = []
    for path, text in sorted(files, key=lambda item: _path_priority(item[0])):
        if not _is_executable_source_path(path):
            continue
        lines = text.splitlines()
        if not lines:
            continue
        executable_lines = _mask_string_literals(text).splitlines()
        for rule in _STATIC_MALICIOUS_RULES:
            role_hits = {
                role.name: [
                    line_number
                    for line_number, line in enumerate(lines, 1)
                    if role.pattern.search(
                        _static_role_search_text(
                            role.name,
                            line[:4096],
                            executable_lines[line_number - 1][:4096],
                        )
                    )
                    and not line.lstrip().startswith(("//", "#", "/*", "*"))
                ]
                for role in rule.roles
            }
            if any(not hits for hits in role_hits.values()):
                continue
            for anchor in sorted(
                {line for hits in role_hits.values() for line in hits}
            ):
                locations: list[dict[str, object]] = []
                for role in rule.roles:
                    nearby = min(
                        role_hits[role.name],
                        key=lambda line: (abs(line - anchor), line),
                    )
                    if abs(nearby - anchor) > _WINDOW_LINES:
                        break
                    locations.append({"path": path, "line": nearby, "role": role.name})
                else:
                    finding: dict[str, object] = {
                        "category": rule.category,
                        "kind": rule.kind,
                        "locations": locations,
                    }
                    if finding not in findings:
                        findings.append(finding)
                    break
            if len(findings) >= _MAX_STATIC_FINDINGS:
                return findings
    return findings


def _static_role_search_text(
    role_name: str, source_line: str, executable_line: str
) -> str:
    """Keep dangerous targets visible while requiring effects to be executable.

    Paths and secret names normally appear in string literals, so target roles
    inspect the original source line. Operational verbs inside an ordinary
    prompt or response literal are inert, however, and must not turn a static
    lead into a 100%-confidence pre-build quarantine. Preserve command payloads
    only when the surrounding line invokes a process-execution API.
    """
    if not role_name.endswith("effect") or _COMMAND_EXECUTION_EFFECT.search(
        source_line
    ):
        return source_line
    return executable_line


def _mask_string_literals(text: str) -> str:
    """Replace quoted source text with spaces while preserving source layout."""
    chars = list(text)
    index = 0
    quote: str | None = None
    quote_width = 0
    escaped = False
    while index < len(chars):
        char = chars[index]
        if quote is None:
            if char in {'"', "'", "`"}:
                quote = char
                quote_width = (
                    3 if char != "`" and text[index : index + 3] == char * 3 else 1
                )
                for offset in range(quote_width):
                    chars[index + offset] = " "
                index += quote_width
                escaped = False
                continue
            index += 1
            continue
        if quote_width == 3 and text[index : index + 3] == quote * 3:
            chars[index : index + 3] = [" ", " ", " "]
            quote = None
            quote_width = 0
            escaped = False
            index += 3
            continue
        if char not in {"\r", "\n"}:
            chars[index] = " "
        if escaped:
            escaped = False
        elif char == "\\" and quote != "`" and quote_width == 1:
            escaped = True
        elif quote_width == 1 and char == quote:
            quote = None
            quote_width = 0
        index += 1
    return "".join(chars)


def _is_build_file(path: str) -> bool:
    normalized = path.casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        name in {"dockerfile", "cargo.toml", "cargo.lock", "build.rs"}
        or name.endswith((".sh", ".bash", ".zsh"))
        or normalized.startswith(".github/workflows/")
    )


def _is_non_runtime_path(path: str) -> bool:
    normalized = path.casefold().removeprefix("./")
    return normalized.startswith(
        ("tests/", "test/", "docs/", "examples/", "benches/", ".github/")
    ) or normalized.rsplit("/", 1)[-1] in {
        "readme",
        "readme.md",
        "security.md",
        "license",
    }


def _is_executable_source_path(path: str) -> bool:
    normalized = path.casefold().removeprefix("./")
    if _is_non_runtime_path(normalized):
        return False
    name = normalized.rsplit("/", 1)[-1]
    return (
        normalized.startswith("src/")
        or name == "build.rs"
        or name.startswith("dockerfile")
        or name.endswith((".rs", ".py", ".go", ".js", ".ts", ".sh", ".bash", ".zsh"))
    )


def _path_priority(path: str) -> tuple[int, str]:
    normalized = path.casefold().removeprefix("./")
    if normalized.startswith("src/"):
        return (0, normalized)
    if _is_build_file(normalized):
        return (1, normalized)
    if normalized.startswith(("tests/", "test/", "docs/", "examples/", "benches/")):
        return (3, normalized)
    return (2, normalized)


__all__ = ["find_decisive_malicious_source", "find_source_review_leads"]
