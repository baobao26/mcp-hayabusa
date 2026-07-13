#!/usr/bin/env python3
"""Validate a Sigma rule file against this project's detection-engineering standards.

Checks (see ../SKILL.md):
  1. At least one ATT&CK technique tag (attack.tXXXX or attack.tXXXX.XXX)
  2. A level: field with a value from ALLOWED_LEVELS
  3. A non-empty falsepositives: section
  4. At least one "# Test case:"-style comment

Sigma rules are YAML, but this parses with a line-scan/regex approach rather than
PyYAML, matching server.py's _parse_rule_summary() convention (stdlib only, no
added dependency for a lint-style check).

Usage: python validate-rule.py <path-to-rule.yml>
Prints a JSON validation report to stdout and exits 0 if valid, 1 if not.
"""

import json
import re
import sys
from pathlib import Path

ALLOWED_LEVELS = ["low", "medium", "high", "critical"]

_LEVEL_RE = re.compile(r"^level:\s*(\S+)")
_TAGS_RE = re.compile(r"^tags:\s*$")
_LIST_ITEM_RE = re.compile(r"^\s*-\s*(.+)$")
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_FALSEPOSITIVES_RE = re.compile(r"^falsepositives:\s*(.*)$")
_TEST_CASE_RE = re.compile(r"^\s*#.*test case", re.IGNORECASE)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def _find_attack_tags(lines: list[str]) -> list[str]:
    tags: list[str] = []
    in_tags = False
    for line in lines:
        if in_tags:
            if match := _LIST_ITEM_RE.match(line):
                tags.append(_strip_quotes(match.group(1)))
                continue
            in_tags = False
        if _TAGS_RE.match(line):
            in_tags = True
    return [t for t in tags if _TECHNIQUE_TAG_RE.match(t)]


def _find_level(lines: list[str]) -> str | None:
    for line in lines:
        if match := _LEVEL_RE.match(line):
            return _strip_quotes(match.group(1))
    return None


def _has_falsepositives(lines: list[str]) -> bool:
    for i, line in enumerate(lines):
        match = _FALSEPOSITIVES_RE.match(line)
        if not match:
            continue
        inline = match.group(1).strip()
        if inline and inline != "[]":
            return True
        for follow in lines[i + 1:]:
            if _LIST_ITEM_RE.match(follow):
                return True
            if follow.strip() == "" or follow.startswith(" "):
                continue
            break
        return False
    return False


def _has_test_case(lines: list[str]) -> bool:
    return any(_TEST_CASE_RE.match(line) for line in lines)


def validate_rule(rule_path: Path) -> dict:
    try:
        lines = rule_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {"file": str(rule_path), "valid": False, "checks": {}, "issues": [f"could not read file: {exc}"]}

    technique_tags = _find_attack_tags(lines)
    level = _find_level(lines)
    fp_present = _has_falsepositives(lines)
    test_case_present = _has_test_case(lines)

    checks = {
        "attack_tags_present": bool(technique_tags),
        "valid_severity": level in ALLOWED_LEVELS,
        "falsepositives_present": fp_present,
        "test_case_present": test_case_present,
    }

    issues = []
    if not technique_tags:
        issues.append("no ATT&CK technique tag found under tags: (expected attack.tXXXX or attack.tXXXX.XXX)")
    if level is None:
        issues.append("no level: field found")
    elif level not in ALLOWED_LEVELS:
        issues.append(f"level '{level}' is not one of {ALLOWED_LEVELS}")
    if not fp_present:
        issues.append("falsepositives: section is missing or empty")
    if not test_case_present:
        issues.append("no test case comment found (expected a '# Test case:' comment)")

    return {
        "file": str(rule_path),
        "valid": all(checks.values()),
        "checks": checks,
        "attack_tags": technique_tags,
        "level": level,
        "issues": issues,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"error": "usage: validate-rule.py <path-to-sigma-rule.yml>"}))
        return 2

    rule_path = Path(sys.argv[1])
    if not rule_path.is_file():
        print(json.dumps({"error": f"file not found: {rule_path}"}))
        return 2

    result = validate_rule(rule_path)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
