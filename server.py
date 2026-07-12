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
SIGMA_RULES_DIR = Path(__file__).resolve().parent / "rules"
ATTACK_DATA_PATH = Path(__file__).resolve().parent / "attack" / "enterprise-attack.json"

_TITLE_RE = re.compile(r"^title:\s*(.+)$")
_ID_RE = re.compile(r"^id:\s*(\S+)")
_LEVEL_RE = re.compile(r"^level:\s*(\S+)")
_STATUS_RE = re.compile(r"^status:\s*(\S+)")
_DESCRIPTION_RE = re.compile(r"^description:\s*(.*)$")
_TAGS_RE = re.compile(r"^tags:\s*$")
_TAG_ITEM_RE = re.compile(r"^\s*-\s*(.+)$")
_TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_TECHNIQUE_ID_RE = re.compile(r"^t?\d{4}(?:\.\d{3})?$", re.IGNORECASE)


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


def _list_sigma_rule_files() -> list[Path]:
    """List curated Sigma rule files in ./rules/ (flat, non-recursive)."""
    if not SIGMA_RULES_DIR.is_dir():
        return []
    return sorted(SIGMA_RULES_DIR.glob("*.yml"))


def _find_sigma_rule_file(rule_name: str) -> Path | None:
    """Resolve a rule_name (with or without a .yml/.yaml suffix) to a file in ./rules/."""
    stem = rule_name
    for suffix in (".yml", ".yaml"):
        if stem.lower().endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    needle = stem.lower()
    for path in _list_sigma_rule_files():
        if path.stem.lower() == needle:
            return path
    return None


def _technique_ids_from_tags(tags: list[str]) -> list[str]:
    """Extract ATT&CK technique IDs (e.g. 'T1003.001') from a rule's Sigma tags."""
    techniques = []
    for tag in tags:
        if match := _TECHNIQUE_TAG_RE.match(tag):
            techniques.append(match.group(1).upper())
    return techniques


def _sigma_rule_summary(rule_path: Path) -> dict | None:
    """Summarize a curated Sigma rule for the detection:// resources."""
    summary = _parse_rule_summary(rule_path)
    if summary is None:
        return None
    return {
        "rule_name": rule_path.stem,
        "title": summary["title"],
        "id": summary["id"],
        "level": summary["level"],
        "status": summary["status"],
        "tags": summary["tags"],
        "techniques": _technique_ids_from_tags(summary["tags"]),
        "description": summary["description"],
    }


@mcp.resource("detection://rules", mime_type="application/json")
def list_detection_rules() -> dict:
    """List all curated Sigma detection rules in ./rules/."""
    rules = [
        summary
        for path in _list_sigma_rule_files()
        if (summary := _sigma_rule_summary(path)) is not None
    ]
    return {"count": len(rules), "rules": rules}


@mcp.resource("detection://rules/{rule_name}", mime_type="application/x-yaml")
def get_detection_rule(rule_name: str) -> str:
    """Get a specific Sigma rule's raw YAML content by its file name (with or without extension)."""
    rule_path = _find_sigma_rule_file(rule_name)
    if rule_path is None:
        raise ValueError(f"Rule not found: {rule_name}")
    return rule_path.read_text(encoding="utf-8")


def _normalize_technique_id(technique_id: str) -> str:
    """Normalize a technique ID to canonical 'T####' / 'T####.###' form."""
    needle = technique_id.strip().upper()
    if not needle.startswith("T"):
        needle = f"T{needle}"
    return needle


def _normalize_tactic_name(tactic_name: str) -> str:
    """Normalize a tactic name to its ATT&CK shortname (e.g. 'Credential Access' -> 'credential-access')."""
    return re.sub(r"\s+", "-", tactic_name.strip().lower())


@mcp.resource("detection://rules/by-technique/{technique_id}", mime_type="application/json")
def list_rules_by_technique(technique_id: str) -> dict:
    """List curated Sigma rules tagged with a given ATT&CK technique ID (e.g. 'T1003.001')."""
    needle = _normalize_technique_id(technique_id)

    rules = [
        summary
        for path in _list_sigma_rule_files()
        if (summary := _sigma_rule_summary(path)) is not None and needle in summary["techniques"]
    ]

    return {"technique_id": needle, "count": len(rules), "rules": rules}


_attack_techniques_cache: dict[str, dict] | None = None


def _load_attack_techniques() -> dict[str, dict]:
    """Load and cache ATT&CK technique name/description/url, keyed by technique ID.

    Parses the MITRE ATT&CK Enterprise STIX bundle once per server process —
    it's tens of MB, too expensive to re-parse on every resource read, and
    static for the process lifetime (re-run scripts/download_attack_data.py
    and restart the server to pick up a newer ATT&CK release).
    """
    global _attack_techniques_cache
    if _attack_techniques_cache is not None:
        return _attack_techniques_cache

    if not ATTACK_DATA_PATH.is_file():
        raise FileNotFoundError(
            f"ATT&CK data not found at {ATTACK_DATA_PATH}. "
            "Run scripts/download_attack_data.py first."
        )

    with open(ATTACK_DATA_PATH, encoding="utf-8") as f:
        bundle = json.load(f)

    techniques: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        external_id = None
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                external_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not external_id:
            continue

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques[external_id.upper()] = {
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "url": url,
            "tactics": tactics,
        }

    _attack_techniques_cache = techniques
    return techniques


_attack_tactics_cache: dict[str, str] | None = None


def _load_attack_tactics() -> dict[str, str]:
    """Load and cache ATT&CK tactic shortname -> display name (e.g. 'credential-access' -> 'Credential Access').

    Parsed once per server process from the same STIX bundle as
    _load_attack_techniques, for the same reasons (large file, static
    for the process lifetime).
    """
    global _attack_tactics_cache
    if _attack_tactics_cache is not None:
        return _attack_tactics_cache

    if not ATTACK_DATA_PATH.is_file():
        raise FileNotFoundError(
            f"ATT&CK data not found at {ATTACK_DATA_PATH}. "
            "Run scripts/download_attack_data.py first."
        )

    with open(ATTACK_DATA_PATH, encoding="utf-8") as f:
        bundle = json.load(f)

    tactics: dict[str, str] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "x-mitre-tactic":
            continue
        shortname = obj.get("x_mitre_shortname")
        if shortname:
            tactics[shortname] = obj.get("name", shortname)

    _attack_tactics_cache = tactics
    return tactics


def _assess_technique_coverage(
    technique_id: str, matching_rules: list[dict], all_rules: list[dict]
) -> str:
    """Rate detection coverage for a technique against the curated rule set.

    "covered": at least one rule is tagged with this exact technique ID.
    "partial": no exact-match rule, but a parent technique (for a
        sub-technique ID) or a sub-technique (for a parent ID) is covered —
        related detection logic likely catches some, not all, of this
        technique's variants.
    "gap": nothing in the curated rule set references this technique at all.
    """
    if matching_rules:
        return "covered"

    all_covered = {t for rule in all_rules for t in rule["techniques"]}
    parent = technique_id.split(".")[0] if "." in technique_id else None
    has_parent_coverage = parent is not None and parent in all_covered
    has_child_coverage = any(t.startswith(f"{technique_id}.") for t in all_covered)

    return "partial" if (has_parent_coverage or has_child_coverage) else "gap"


@mcp.resource("detection://attack/techniques/{technique_id}", mime_type="application/json")
def get_attack_technique(technique_id: str) -> dict:
    """Look up an ATT&CK technique and assess our curated rule set's coverage of it.

    Combines MITRE's ATT&CK STIX data (name/description) with the ATT&CK tags
    parsed from ./rules/ to answer "what is this technique, do we detect it,
    and how well?" in one lookup.
    """
    needle = _normalize_technique_id(technique_id)

    techniques = _load_attack_techniques()
    technique = techniques.get(needle)
    if technique is None:
        raise ValueError(f"Unknown ATT&CK technique: {technique_id}")

    all_rules = [
        summary for path in _list_sigma_rule_files() if (summary := _sigma_rule_summary(path))
    ]
    matching_rules = [rule for rule in all_rules if needle in rule["techniques"]]

    return {
        "technique_id": needle,
        "name": technique["name"],
        "description": technique["description"],
        "is_subtechnique": technique["is_subtechnique"],
        "url": technique["url"],
        "rules": matching_rules,
        "rule_count": len(matching_rules),
        "coverage": _assess_technique_coverage(needle, matching_rules, all_rules),
    }


@mcp.tool()
def analyze_coverage(target: str) -> dict:
    """Analyze curated detection coverage for an ATT&CK technique or tactic.

    Combines the ATT&CK STIX data with the ./rules/ Sigma rule set (the same
    sources behind the detection:// resources) into a single coverage report,
    either for one technique or for every technique in a tactic.

    Args:
        target: An ATT&CK technique ID (e.g. "T1003.001" or "T1003"), or a
            tactic name/shortname (e.g. "Credential Access" or
            "credential-access").
    """
    stripped = target.strip() if target else ""
    if not stripped:
        return {"error": "target must be a non-empty technique ID or tactic name."}

    try:
        techniques = _load_attack_techniques()
    except FileNotFoundError as exc:
        return {"error": str(exc)}

    all_rules = [
        summary for path in _list_sigma_rule_files() if (summary := _sigma_rule_summary(path))
    ]

    if _TECHNIQUE_ID_RE.match(stripped):
        needle = _normalize_technique_id(stripped)
        technique = techniques.get(needle)
        if technique is None:
            return {"error": f"Unknown ATT&CK technique: {target}"}

        matching_rules = [rule for rule in all_rules if needle in rule["techniques"]]
        return {
            "target_type": "technique",
            "technique_id": needle,
            "name": technique["name"],
            "tactics": technique["tactics"],
            "coverage": _assess_technique_coverage(needle, matching_rules, all_rules),
            "rule_count": len(matching_rules),
            "rules": matching_rules,
        }

    try:
        tactics = _load_attack_tactics()
    except FileNotFoundError as exc:
        return {"error": str(exc)}

    tactic_shortname = _normalize_tactic_name(stripped)
    if tactic_shortname not in tactics:
        return {
            "error": (
                f"Unknown tactic '{target}'. Known tactics: "
                f"{', '.join(sorted(tactics.values()))}"
            )
        }

    tactic_techniques = {
        tid: t for tid, t in techniques.items() if tactic_shortname in t["tactics"]
    }

    covered, partial, gaps = [], [], []
    for tid, t in sorted(tactic_techniques.items()):
        matching_rules = [rule for rule in all_rules if tid in rule["techniques"]]
        entry = {"technique_id": tid, "name": t["name"], "rule_count": len(matching_rules)}
        status = _assess_technique_coverage(tid, matching_rules, all_rules)
        {"covered": covered, "partial": partial, "gap": gaps}[status].append(entry)

    return {
        "target_type": "tactic",
        "tactic": tactics[tactic_shortname],
        "technique_count": len(tactic_techniques),
        "covered_count": len(covered),
        "partial_count": len(partial),
        "gap_count": len(gaps),
        "covered": covered,
        "partial": partial,
        "gaps": gaps,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
