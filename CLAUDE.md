# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Implemented. `server.py` is a single-file MCP server (`FastMCP`) exposing two tools: `scan_evtx`, which shells out to the Hayabusa CLI, and `get_hayabusa_rules`, which lists/filters the local Sigma/Hayabusa rule set. See `HANDOFF.md` for full design rationale and open items.

## Commands

- **Install dependencies**: `pip install -r requirements.txt` (just `mcp`; everything else is standard library).
- **Install Hayabusa**: `python scripts/download_hayabusa.py` — downloads the latest release for the current OS/architecture from the GitHub API and extracts it to `./hayabusa/` (gitignored).
- **Download a test sample**: `python scripts/download_sample_evtx.py` — fetches one real attack sample from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) into `./samples/` (gitignored).
- **Run the server**: `python server.py` (stdio transport — blocks waiting for an MCP client; exits cleanly on stdin EOF if run with no client attached).
- **Test**: `python tests/test_scan_evtx.py` — a manual script (not pytest) that calls `scan_evtx` and `get_hayabusa_rules` directly against the downloaded sample/rule set. No automated test framework is configured.
- **Lint**: none configured.

## Project goal

An MCP server that wraps the Hayabusa CLI for EVTX (Windows Event Log) analysis.

- Expose a `scan_evtx` tool that runs Hayabusa against EVTX files.
- Return results as structured JSON.
- Support filtering by severity level, rule title, and result count; support a trimmed vs. full output shape.
- Expose a `get_hayabusa_rules` tool so a caller can discover what detection rules exist before scanning.
- Handle errors gracefully.

## Architecture

- **`server.py`** is the whole server. `FastMCP("hayabusa")` instance, two `@mcp.tool()`-decorated functions (`scan_evtx`, `get_hayabusa_rules`), `main()` calls `mcp.run()`.
- **`scan_evtx(file_path, min_severity=None, rule_filter=None, output_format="summary", max_results=None) -> dict`**:
  1. Checks `file_path` exists.
  2. Validates `min_severity` against `SEVERITY_LEVELS` (`informational`, `low`, `medium`, `high`, `critical`), `output_format` against `OUTPUT_FORMATS` (`summary`, `full`), and `max_results` (must be `>= 0` if given).
  3. Locates the Hayabusa binary via `_find_hayabusa_binary()`, which globs `./hayabusa/` for `hayabusa*.exe` (Windows) or `hayabusa*` (other platforms) — the extracted release binary is version-suffixed (e.g. `hayabusa-3.10.0-win-x64.exe`), not literally `hayabusa.exe`.
  4. Runs `hayabusa json-timeline -f <file> -o <tmpfile> -L -w -q -Q`, adding `-m <min_severity>` when given. **Important**: `-L`/JSONL output is required — Hayabusa's default `-o` output (without `-L`) is pretty-printed JSON objects concatenated with no array wrapper or separators, which is neither valid single JSON nor JSONL, and will fail to parse.
  5. Parses the JSONL output (`json.loads` per non-blank line), then applies `rule_filter` (case-insensitive substring match against `RuleTitle`), `output_format` (trims each finding to `SUMMARY_FIELDS` when `"summary"`), and `max_results` (truncates the list), all as post-processing in Python — Hayabusa itself has no equivalent flags for these.
  6. Returns `{"file", "min_severity", "rule_filter", "output_format", "count", "returned", "truncated", "findings"}`, where `count` is the total after `rule_filter` but before `max_results`, `returned` is `len(findings)` after truncation, and `truncated` says whether `max_results` cut anything off.
  7. Any failure point (missing file, bad severity/output_format/max_results, missing binary, non-zero exit, 5-minute timeout, unparseable output) returns `{"error": ...}` instead of raising — the tool never lets a Hayabusa/subprocess failure crash the server.
- **Severity filtering happens inside Hayabusa itself** (`-m/--min-level`); `rule_filter`, `output_format`, and `max_results` are applied client-side in Python since Hayabusa has no equivalent CLI flags for a substring rule-title match, a trimmed output shape, or a result cap.
- **`get_hayabusa_rules(keyword=None, max_results=50) -> dict`**:
  1. Validates `max_results` (must be `>= 0` if given).
  2. Walks `./hayabusa/rules/**/*.yml` (skipping `.git`), parsing each rule with `_parse_rule_summary()` — a line-scan regex parser (not a full YAML parser, to avoid a PyYAML dependency) that extracts `title`, `id`, `level`, `status`, `ruletype` (`hayabusa` or `sigma`, from the top-level rule directory), `tags`, and `description` from the flat block of fields above each rule's `detection:` section.
  3. If `keyword` is given, keeps only rules where the (lowercased) keyword appears in the joined `title` + `description` + `tags`.
  4. Returns `{"keyword", "count", "returned", "truncated", "rules"}`, capped by `max_results` (default 50, since the full rule set is ~5,000 files).
  5. Returns `{"error": ...}` if the rules directory is missing or `max_results` is invalid.
- **`scripts/download_hayabusa.py` and `scripts/download_sample_evtx.py`** use only `urllib`/`zipfile`/`json` (stdlib) and resolve URLs dynamically via the GitHub releases/tree API — no hardcoded version numbers or download URLs.
- **`./hayabusa/`** (extracted binary + `rules/`/`config/`) and **`./samples/*.evtx`** are both gitignored — they're fetched on demand by the scripts above, not checked in.
- **`.mcp.json`** (gitignored) registers this server with Claude Code locally (`python server.py`, `cwd` pinned to this project's absolute path). It's `.mcp.json`, not `.claude/settings.json`/`settings.local.json` — Claude Code only reads `mcpServers` from `.mcp.json` (project root) or `~/.claude.json` (via `claude mcp add`); the settings files are for permissions/hooks/env and silently ignore an `mcpServers` key. It's gitignored rather than committed because the `cwd` is machine-specific and would break for other collaborators/OSes.
- **Claude Desktop registration** uses a different config, with a different launch shape than `.mcp.json`. On this machine Claude Desktop is the MSIX-packaged build (`Claude_pzs8sxrjxfjjc`), so Windows redirects its `%APPDATA%` to `C:\Users\<user>\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` — the plain `%APPDATA%\Claude\claude_desktop_config.json` path is a different, inert file the packaged app never reads. That file also gets rewritten by the app on every launch and only preserves the `command`/`args` keys of each `mcpServers` entry — a `cwd` key is silently dropped. So the Claude Desktop entry passes an **absolute path to `server.py` in `args`** instead of relying on `cwd`:
  ```json
  {"mcpServers": {"hayabusa": {"command": "python", "args": ["C:/Users/<user>/mcp-hayabusa/server.py"]}}}
  ```
  This works because `HAYABUSA_DIR` in `server.py` is derived from `Path(__file__).resolve().parent`, not from the process's working directory. Per-server connection logs land in `<that same Claude dir>\logs\mcp-server-hayabusa.log` — check there first if the server shows as disconnected.
