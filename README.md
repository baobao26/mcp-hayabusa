# mcp-hayabusa

An MCP server with two layers: it wraps the [Hayabusa](https://github.com/Yamato-Security/hayabusa) CLI, exposing a `scan_evtx` tool for analyzing Windows EVTX event log files and a `get_hayabusa_rules` tool for browsing its detection rule set; and it doubles as a detection-engineering knowledge base, exposing a curated Sigma rule set and MITRE ATT&CK technique/coverage lookups as `detection://` resources.

## Requirements

- Python 3.10+ (uses the `X | None` type-hint syntax)
- The `mcp` library (`pip install -r requirements.txt`)
- The Hayabusa CLI, extracted to `./hayabusa/` (see Setup below)
- The MITRE ATT&CK Enterprise STIX bundle, extracted to `./attack/` (see Setup below) — only required for the `detection://attack/techniques/{technique_id}` resource

## Setup

```
pip install -r requirements.txt
python scripts/download_hayabusa.py
```

`download_hayabusa.py` detects your OS/architecture, downloads the matching release asset from Hayabusa's latest GitHub release, and extracts it into `./hayabusa/` (binary, `rules/`, `config/`). This directory is gitignored — re-run the script after cloning, or whenever you want to pick up a newer Hayabusa release.

Optional, for manual testing:

```
python scripts/download_sample_evtx.py
```

Downloads one real attack-technique sample (`4794_DSRM_password_change_t1098.evtx`) from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) into `./samples/` (also gitignored).

Required for the `detection://attack/techniques/{technique_id}` resource:

```
python scripts/download_attack_data.py
```

Downloads the MITRE ATT&CK Enterprise STIX bundle (~50MB) from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) into `./attack/enterprise-attack.json` (gitignored). Re-run it whenever you want to pick up a newer ATT&CK release — the server caches the parsed data in memory for the life of the process, so restart `server.py` afterward to pick up the change.

## Running the server

```
python server.py
```

The server communicates over stdio, so it's meant to be launched by an MCP client (e.g. Claude Code), not run interactively. With no client attached, it reads EOF from stdin and exits immediately — that's expected, not a bug.

To register it with Claude Code locally, add it to `.mcp.json` at the project root:

```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "python",
      "args": ["server.py"],
      "cwd": "C:/path/to/mcp-hayabusa"
    }
  }
}
```

MCP server definitions aren't read from `settings.json`/`settings.local.json` (those are for permissions/hooks/env) — `.mcp.json` is the file Claude Code actually checks. It's gitignored here because `cwd` is an absolute, machine-specific path; each collaborator creates their own.

### Registering with Claude Desktop

Claude Desktop uses a separate config file from `.mcp.json`, and doesn't support a `cwd` key, so pass an absolute path to `server.py` in `args` instead:

```json
{
  "mcpServers": {
    "hayabusa": {
      "command": "python",
      "args": ["C:/path/to/mcp-hayabusa/server.py"]
    }
  }
}
```

Finding the right file to edit takes a bit of care on Windows:

- On a standard (non-Store) install, it's `%APPDATA%\Claude\claude_desktop_config.json`.
- On the MSIX-packaged Store build, Windows redirects the app's `%APPDATA%` to a virtualized path — editing `%APPDATA%\Claude\...` from outside the app (e.g. a terminal) touches an inert file the app never reads. The real file is `%LOCALAPPDATA%\Packages\<Claude package ID>\LocalCache\Roaming\Claude\claude_desktop_config.json`. Check `%LOCALAPPDATA%\Packages` for a folder starting with `Claude_` if you're not sure which build you have.

Fully quit and relaunch Claude Desktop after editing (not just close the window). Per-server connection logs land in `logs\mcp-server-hayabusa.log` next to the config file — check there first if a server shows as disconnected; it logs the exact command/args/cwd used to launch it and any stderr from the process.

## The `scan_evtx` tool

```
scan_evtx(
    file_path: str,
    min_severity: str | None = None,
    rule_filter: str | None = None,
    output_format: str = "summary",
    max_results: int | None = None,
) -> dict
```

| Parameter | Required | Description |
| --- | --- | --- |
| `file_path` | yes | Path to the `.evtx` file to scan |
| `min_severity` | no | Minimum severity to include: `informational`, `low`, `medium`, `high`, or `critical`. Filtering happens inside Hayabusa itself (`--min-level`). |
| `rule_filter` | no | Case-insensitive substring matched against each finding's rule title (e.g. `"lateral"` or `"mimikatz"`). Only matching findings are returned. |
| `output_format` | no | `"summary"` (default) returns a trimmed set of fields per finding; `"full"` returns every field Hayabusa produced. |
| `max_results` | no | Caps the number of findings returned. |

### Success response

```json
{
  "file": "samples/4794_DSRM_password_change_t1098.evtx",
  "min_severity": null,
  "rule_filter": null,
  "output_format": "summary",
  "count": 1,
  "returned": 1,
  "truncated": false,
  "findings": [
    {
      "Timestamp": "2017-06-09 15:21:26.968 -04:00",
      "RuleTitle": "Password Change on Directory Service Restore Mode (DSRM) Account",
      "Level": "high",
      "Computer": "2016dc.hqcorp.local",
      "EventID": 4794,
      "RecordID": 3139859
    }
  ]
}
```

`count` is the total matching findings after `rule_filter` (before any `max_results` cap); `returned` is how many are actually in `findings`; `truncated` is `true` if `max_results` cut the list short. Pass `output_format="full"` to get every field Hayabusa produced (`Channel`, `Details`, `ExtraFieldInfo`, `RuleID`, etc.) instead of the trimmed summary shape shown above.

### Error response

Every failure mode returns `{"error": "..."}` (plus `stderr`/`returncode` where applicable) instead of raising:

| Situation | Example error |
| --- | --- |
| File doesn't exist | `EVTX file not found: <path>` |
| Invalid `min_severity` | `Invalid min_severity 'bogus'. Must be one of: informational, low, medium, high, critical` |
| Invalid `output_format` | `Invalid output_format 'bogus'. Must be one of: summary, full` |
| Invalid `max_results` | `Invalid max_results '-1'. Must be >= 0.` |
| Hayabusa binary missing | `Hayabusa executable not found in <dir>` |
| Hayabusa exits non-zero | `Hayabusa scan failed` (with `returncode`, `stderr`) |
| Scan takes too long | `Hayabusa scan timed out after 300s` |
| Output unparseable | `Failed to parse Hayabusa output: ...` |

## The `get_hayabusa_rules` tool

```
get_hayabusa_rules(keyword: str | None = None, max_results: int | None = 50) -> dict
```

Lists detection rules from the local `./hayabusa/rules/` checkout (~5,000 Sigma + Hayabusa-native rules) — useful for discovering what rules exist, and their exact titles/tags, before scanning (e.g. to pick a value for `scan_evtx`'s `rule_filter`).

| Parameter | Required | Description |
| --- | --- | --- |
| `keyword` | no | Case-insensitive substring matched against each rule's title, description, and tags. |
| `max_results` | no | Caps the number of rules returned. Defaults to `50`; pass `null` for unlimited. |

### Success response

```json
{
  "keyword": "mimikatz",
  "count": 24,
  "returned": 24,
  "truncated": false,
  "rules": [
    {
      "title": "Mimikatz Use",
      "id": "06d71506-7beb-4f22-8888-e2e5e2ca7fd8",
      "level": null,
      "status": "test",
      "ruletype": "sigma",
      "tags": ["attack.s0002", "attack.lateral-movement", "attack.t1003.002"],
      "description": "This method detects mimikatz keywords in different Eventlogs..."
    }
  ]
}
```

Rule fields are extracted with a lightweight line-scan, not a full YAML parser (see Notes below), so `level`/`status`/`tags`/`description` are `null`/empty when a given rule doesn't define that field at the top level.

### Error response

| Situation | Example error |
| --- | --- |
| Rules directory missing | `Hayabusa rules directory not found: <dir>` |
| Invalid `max_results` | `Invalid max_results '-1'. Must be >= 0.` |

## Detection engineering knowledge base resources

Alongside the two tools above, the server exposes a curated Sigma rule set (`./rules/`, checked into git — distinct from the full `./hayabusa/rules/` checkout used by `get_hayabusa_rules`) and MITRE ATT&CK lookups as four `detection://` MCP **resources**. Resources are browsable/discoverable rather than invoked with arguments, and a not-found lookup raises an MCP `ResourceError` instead of returning a `{"error": ...}` dict (that convention is tool-specific — see the `scan_evtx`/`get_hayabusa_rules` sections above).

### `detection://rules`

Lists all rules in `./rules/` (currently 24: hand-authored plus a curated selection copied from upstream [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma), covering credential-access, lateral-movement, and persistence techniques).

```json
{
  "count": 24,
  "rules": [
    {
      "rule_name": "lsass_process_access",
      "title": "Suspicious Process Access to LSASS Memory",
      "id": "fe41d923-d63b-45bb-8c85-bbfb6886b6b3",
      "level": "high",
      "status": "test",
      "tags": ["attack.credential-access", "attack.t1003.001", "attack.s0002"],
      "techniques": ["T1003.001"],
      "description": "Detects non-standard processes requesting access to lsass.exe with access"
    }
  ]
}
```

### `detection://rules/{rule_name}`

Returns one rule's raw YAML content, looked up by filename stem (case-insensitive, extension optional — `lsass_process_access`, `lsass_process_access.yml`, and `LSASS_Process_Access` all resolve the same file). Raises if `rule_name` doesn't match any file in `./rules/`.

### `detection://rules/by-technique/{technique_id}`

Lists rules tagged with a given ATT&CK technique ID (case-insensitive, `T` prefix optional — `t1003.001` and `T1003.001` are equivalent). An unmatched technique returns `count: 0`, not an error.

```json
{
  "technique_id": "T1021.002",
  "count": 2,
  "rules": [ /* ... matching rule summaries, same shape as detection://rules ... */ ]
}
```

### `detection://attack/techniques/{technique_id}`

Looks up a technique in the downloaded MITRE ATT&CK data and cross-references it against `./rules/` in one call: what the technique is, whether we detect it, and how well.

```json
{
  "technique_id": "T1003.001",
  "name": "LSASS Memory",
  "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS)...",
  "is_subtechnique": true,
  "url": "https://attack.mitre.org/techniques/T1003/001",
  "rules": [ /* ... matching rule summaries ... */ ],
  "rule_count": 3,
  "coverage": "covered"
}
```

`coverage` is one of:

| Value | Meaning |
| --- | --- |
| `covered` | At least one rule is tagged with this exact technique ID. |
| `partial` | No exact-match rule, but the parent technique (for a sub-technique ID) or a sibling sub-technique (for a parent ID) is covered — related detection logic may catch some, but not all, variants. |
| `gap` | Nothing in `./rules/` references this technique at all, directly or via parent/child. |

Raises if the ATT&CK data hasn't been downloaded yet (run `scripts/download_attack_data.py` first) or if `technique_id` isn't a real ATT&CK technique.

## Testing

```
python tests/test_scan_evtx.py
```

A manual script (not a pytest suite) that exercises both tools: `scan_evtx` against the sample downloaded by `download_sample_evtx.py` (default/full `output_format`, `min_severity`, `rule_filter`, `max_results`, and error cases), and `get_hayabusa_rules` against the local rule set (default cap, `keyword` filtering, and error cases). It does not cover the `detection://` resources — those were verified manually via `mcp.read_resource()`.

## Notes

- Severity filtering is delegated to Hayabusa's own `-m/--min-level` flag rather than reimplemented in Python; `rule_filter`, `output_format`, and `max_results` have no Hayabusa CLI equivalent, so they're applied as post-processing in Python.
- Output parsing uses Hayabusa's `-L`/JSONL mode. Hayabusa's default `-o` (non-`-L`) output is pretty-printed JSON objects concatenated with no array wrapper — not valid JSON or JSONL — so `-L` is required for reliable parsing.
- `get_hayabusa_rules` parses rule YAML with regex line-scanning instead of a full YAML parser, to avoid adding a PyYAML dependency for what's just a fuzzy listing tool — Hayabusa itself does the real YAML parsing when a rule is actually used to scan.
- `./rules/` is a deliberately curated cross-section of upstream Sigma, not a full mirror (~4,700 files across all platforms) — that was considered and rejected: it would duplicate `./hayabusa/rules/`, blow up repo size, and (given `./rules/`'s flat, non-`hayabusa`/`sigma`-subdirectory layout) risk filename collisions in the by-stem rule lookup.
- The MITRE ATT&CK STIX bundle (~50MB) is parsed once and cached in memory for the server process's lifetime, not re-parsed per request — it's static data that doesn't change while the server runs.
