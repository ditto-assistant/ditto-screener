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


@dataclass(frozen=True)
class _Role:
    name: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class _Rule:
    kind: str
    roles: tuple[_Role, ...]
    build_files_only: bool = False


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


def _is_build_file(path: str) -> bool:
    normalized = path.casefold()
    name = normalized.rsplit("/", 1)[-1]
    return (
        name in {"dockerfile", "cargo.toml", "cargo.lock", "build.rs"}
        or name.endswith((".sh", ".bash", ".zsh"))
        or normalized.startswith(".github/workflows/")
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


__all__ = ["find_source_review_leads"]
