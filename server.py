"""MCP server that wraps Hayabusa for EVTX analysis."""

import json
import platform
import re
import subprocess
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hayabusa")

HAYABUSA_DIR = Path(__file__).resolve().parent / "hayabusa"
SEVERITY_LEVELS = ["informational", "low", "medium", "high", "critical"]
SCAN_TIMEOUT_SECONDS = 300


def _find_hayabusa_binary() -> Path | None:
    """Locate the Hayabusa executable inside ./hayabusa/."""
    if not HAYABUSA_DIR.is_dir():
        return None

    is_windows = platform.system() == "Windows"
    pattern = "hayabusa*.exe" if is_windows else "hayabusa*"
    default_name = "hayabusa.exe" if is_windows else "hayabusa"

    candidates = [HAYABUSA_DIR / default_name]
    candidates += sorted(HAYABUSA_DIR.glob(pattern))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


SUMMARY_FIELDS = ("Timestamp", "RuleTitle", "Level", "Computer", "EventID", "RecordID")
OUTPUT_FORMATS = ["summary", "full"]

RULES_DIR = HAYABUSA_DIR / "rules"

_TITLE_RE = re.compile(r"^title:\s*(.+)$")
_ID_RE = re.compile(r"^id:\s*(\S+)")
_LEVEL_RE = re.compile(r"^level:\s*(\S+)")
_STATUS_RE = re.compile(r"^status:\s*(\S+)")
_DESCRIPTION_RE = re.compile(r"^description:\s*(.*)$")
_TAGS_RE = re.compile(r"^tags:\s*$")
_TAG_ITEM_RE = re.compile(r"^\s*-\s*(.+)$")


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return value


def _parse_rule_summary(rule_path: Path) -> dict | None:
    """Extract title/id/level/status/tags/description from a rule file.

    Sigma/Hayabusa rules are YAML, but their top-level scalar fields (title,
    id, level, status, tags, description) are always unindented, regardless
    of whether they appear before or after the (indented) `detection:`
    block, so a line scan anchored to column 0 avoids taking a PyYAML
    dependency for a fuzzy listing tool.
    """
    title = None
    rule_id = None
    level = None
    status = None
    description = None
    tags: list[str] = []
    in_tags = False
    in_description_block = False

    try:
        lines = rule_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    for line in lines:
        if in_description_block:
            if line.startswith(" ") and line.strip():
                if not description:
                    description = line.strip()
                continue
            in_description_block = False

        if in_tags:
            if match := _TAG_ITEM_RE.match(line):
                tags.append(_strip_quotes(match.group(1)))
                continue
            in_tags = False

        if match := _TITLE_RE.match(line):
            title = _strip_quotes(match.group(1))
        elif match := _ID_RE.match(line):
            rule_id = match.group(1)
        elif match := _LEVEL_RE.match(line):
            level = match.group(1)
        elif match := _STATUS_RE.match(line):
            status = match.group(1)
        elif match := _DESCRIPTION_RE.match(line):
            raw = match.group(1).strip()
            if raw in ("|", ">", "|-", ">-"):
                in_description_block = True
            else:
                description = _strip_quotes(raw)
        elif _TAGS_RE.match(line):
            in_tags = True

    if title is None:
        return None

    try:
        rel_parts = rule_path.relative_to(RULES_DIR).parts
    except ValueError:
        rel_parts = rule_path.parts
    ruletype = rel_parts[0] if rel_parts else "unknown"

    return {
        "title": title,
        "id": rule_id,
        "level": level,
        "status": status,
        "ruletype": ruletype,
        "tags": tags,
        "description": description,
    }


@mcp.tool()
def scan_evtx(
    file_path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict:
    """Scan an EVTX file with Hayabusa and return structured results.

    Args:
        file_path: Path to the EVTX file to scan.
        min_severity: Optional minimum severity level to include
            (one of: informational, low, medium, high, critical).
        rule_filter: Optional case-insensitive substring to match against
            each finding's rule title (e.g. "lateral" or "mimikatz").
            Only matching findings are returned.
        output_format: "summary" (default) returns a trimmed set of fields
            per finding; "full" returns every field Hayabusa produced.
        max_results: Optional cap on the number of findings returned.
    """
    evtx_path = Path(file_path)
    if not evtx_path.is_file():
        return {"error": f"EVTX file not found: {file_path}"}

    if min_severity is not None and min_severity.lower() not in SEVERITY_LEVELS:
        return {
            "error": (
                f"Invalid min_severity '{min_severity}'. "
                f"Must be one of: {', '.join(SEVERITY_LEVELS)}"
            )
        }

    if output_format not in OUTPUT_FORMATS:
        return {
            "error": (
                f"Invalid output_format '{output_format}'. "
                f"Must be one of: {', '.join(OUTPUT_FORMATS)}"
            )
        }

    if max_results is not None and max_results < 0:
        return {"error": f"Invalid max_results '{max_results}'. Must be >= 0."}

    hayabusa_bin = _find_hayabusa_binary()
    if hayabusa_bin is None:
        return {"error": f"Hayabusa executable not found in {HAYABUSA_DIR}"}

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "results.jsonl"
        cmd = [
            str(hayabusa_bin),
            "json-timeline",
            "-f", str(evtx_path),
            "-o", str(output_path),
            "-L",  # JSONL-output: one JSON object per line
            "-w",  # no-wizard: scan for all events/alerts without prompting
            "-q",  # quiet: skip the launch banner
            "-Q",  # quiet-errors: don't write error log files
        ]
        if min_severity is not None:
            cmd += ["-m", min_severity.lower()]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"error": f"Hayabusa scan timed out after {SCAN_TIMEOUT_SECONDS}s"}
        except OSError as exc:
            return {"error": f"Failed to run Hayabusa: {exc}"}

        if result.returncode != 0:
            return {
                "error": "Hayabusa scan failed",
                "returncode": result.returncode,
                "stderr": result.stderr.strip(),
            }

        if not output_path.exists():
            return {
                "error": "Hayabusa did not produce an output file",
                "stderr": result.stderr.strip(),
            }

        try:
            with open(output_path, encoding="utf-8") as f:
                findings = [json.loads(line) for line in f if line.strip()]
        except json.JSONDecodeError as exc:
            return {"error": f"Failed to parse Hayabusa output: {exc}"}

    if rule_filter is not None:
        needle = rule_filter.lower()
        findings = [
            f for f in findings if needle in f.get("RuleTitle", "").lower()
        ]

    count = len(findings)

    if output_format == "summary":
        findings = [
            {field: f.get(field) for field in SUMMARY_FIELDS} for f in findings
        ]

    truncated = max_results is not None and max_results < count
    if max_results is not None:
        findings = findings[:max_results]

    return {
        "file": str(evtx_path),
        "min_severity": min_severity,
        "rule_filter": rule_filter,
        "output_format": output_format,
        "count": count,
        "returned": len(findings),
        "truncated": truncated,
        "findings": findings,
    }


@mcp.tool()
def get_hayabusa_rules(keyword: str | None = None, max_results: int | None = 50) -> dict:
    """List available Hayabusa detection rules, optionally filtered by keyword.

    Useful for discovering what rules exist (and their exact titles/tags)
    before scanning, e.g. to pick a value for scan_evtx's rule_filter.

    Args:
        keyword: Optional case-insensitive substring matched against each
            rule's title, description, and tags.
        max_results: Optional cap on the number of rules returned
            (default 50; pass null for unlimited).
    """
    if not RULES_DIR.is_dir():
        return {"error": f"Hayabusa rules directory not found: {RULES_DIR}"}

    if max_results is not None and max_results < 0:
        return {"error": f"Invalid max_results '{max_results}'. Must be >= 0."}

    needle = keyword.lower() if keyword else None
    matches = []
    count = 0
    for rule_path in RULES_DIR.rglob("*.yml"):
        if ".git" in rule_path.parts:
            continue
        rule = _parse_rule_summary(rule_path)
        if rule is None:
            continue
        if needle is not None:
            haystack = " ".join(
                [rule["title"], rule["description"] or "", " ".join(rule["tags"])]
            ).lower()
            if needle not in haystack:
                continue
        count += 1
        matches.append(rule)

    truncated = max_results is not None and max_results < count
    if max_results is not None:
        matches = matches[:max_results]

    return {
        "keyword": keyword,
        "count": count,
        "returned": len(matches),
        "truncated": truncated,
        "rules": matches,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
