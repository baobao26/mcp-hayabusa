# State snapshot

Last updated: 2026-07-12

## Repo

- Location: `C:\Users\PC\mcp-hayabusa`
- Remote: `origin` -> `https://github.com/baobao26/mcp-hayabusa.git` (fetch/push)
- Branch: `master`, tracking `origin/master`, 3 commits:
  - `4f2d5c8` — Update STATE.md with commit history and Claude Desktop registration
  - `c4e5d04` — Add MCP server implementation, scripts, tests, and project state
  - `b7f719f` — Document Claude Desktop MCP registration
- Git identity: configured locally (not global) — `user.name "Katrina Ung"`, `user.email "ung.katrina@gmail.com"`
- **Uncommitted changes** (not yet committed as of this snapshot):
  - Modified: `.gitignore` (+`attack/`), `CLAUDE.md` (documents the knowledge-base expansion below), `server.py` (+237/-12 lines: curated-rule resources + ATT&CK lookup)
  - Untracked, intended to be added: `rules/` (24 curated Sigma rule files), `scripts/download_attack_data.py`
  - Untracked, intentionally not gitignored: `credential_access_rules.json`, `t1003_001_top10.json` — ad-hoc dumps from earlier `get_hayabusa_rules` debugging (see HANDOFF.md's `level: null` bug note), not project source; still undecided whether to delete or gitignore

## What's been built since the last snapshot

A detection-engineering knowledge base layer, alongside the original Hayabusa-scanning server:

- **`rules/`** — 24 curated Sigma rules (YAML), checked into git (once committed): 6 hand-authored covering T1003.001 (LSASS access), T1558.003 (Kerberoasting), T1003.006 (DCSync), T1550.002 (Pass-the-Hash), plus 18 unmodified rules copied from upstream [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (attribution preserved) broadening coverage across credential-access, lateral-movement, and persistence techniques. Deliberately curated, not a full mirror of upstream (~4,700 files) — see CLAUDE.md for why.
- **`scripts/download_attack_data.py`** — fetches the MITRE ATT&CK Enterprise STIX bundle into `./attack/enterprise-attack.json` (gitignored, ~50MB), same fetch-on-demand pattern as `download_hayabusa.py`/`download_sample_evtx.py`.
- **Four `detection://` MCP resources in `server.py`**:
  - `detection://rules` — list all curated rules
  - `detection://rules/{rule_name}` — raw YAML of one rule
  - `detection://rules/by-technique/{technique_id}` — rules tagged with a given ATT&CK ID
  - `detection://attack/techniques/{technique_id}` — ATT&CK technique name/description plus coverage assessment (`covered`/`partial`/`gap`) against `rules/`

Full design rationale for both layers is in CLAUDE.md's Architecture section.

## Files

| File | Purpose |
| --- | --- |
| `server.py` | The MCP server (`FastMCP`): `scan_evtx`/`get_hayabusa_rules` tools, plus four `detection://` resources |
| `requirements.txt` | Python dependency: `mcp` |
| `scripts/download_hayabusa.py` | Downloads the latest Hayabusa release for this OS/arch into `./hayabusa/` |
| `scripts/download_sample_evtx.py` | Downloads a sample attack EVTX into `./samples/` |
| `scripts/download_attack_data.py` | Downloads the MITRE ATT&CK STIX bundle into `./attack/` |
| `rules/` | 24 curated Sigma detection rules (YAML), checked into git |
| `tests/test_scan_evtx.py` | Manual script calling `scan_evtx` and `get_hayabusa_rules` directly against the sample/rule set |
| `CLAUDE.md` | Project spec / guidance for Claude Code |
| `README.md` | Setup, usage, and tool/response reference (not yet updated for the `detection://` resources) |
| `HANDOFF.md` | What was built, how to use it, what's left, and why key decisions were made (covers the original Hayabusa-scanning layer only) |
| `.gitignore` | Excludes `hayabusa/`, `*.zip`, `samples/*.evtx`, `attack/`, `.mcp.json`, Python build artifacts |
| `.mcp.json` | Registers this server with Claude Code locally (`python server.py`, machine-specific `cwd`) — gitignored. Not `.claude/settings.local.json`, which Claude Code doesn't read `mcpServers` from. |
| `hayabusa/` | Extracted Hayabusa binary + `rules/`/`config/` — gitignored, fetched on demand |
| `samples/` | Downloaded test EVTX samples — gitignored, fetched on demand |
| `attack/` | Downloaded MITRE ATT&CK STIX bundle (`enterprise-attack.json`) — gitignored, fetched on demand |

Also registered outside this repo, in Claude Desktop's own config (see README.md → "Registering with Claude Desktop"): on this machine that's `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` (MSIX-redirected path), entry uses an absolute path to `server.py` in `args` since this build strips `cwd`.

## Environment (this machine)

- Python 3.12.10
- Hayabusa v3.10.0 ("Independence Day Release"), Windows x64 build, extracted to `./hayabusa/hayabusa-3.10.0-win-x64.exe`
- `mcp` 1.28.1 installed (plus transitive deps: `pydantic`, `httpx`, `uvicorn`, `starlette`, etc. — see `requirements.txt` for the direct dependency, `pip freeze` for the full resolved set)
- MITRE ATT&CK Enterprise STIX bundle downloaded to `./attack/enterprise-attack.json` (~53MB)

## Outstanding

See `HANDOFF.md` → "What's left to do" for the original Hayabusa-scanning layer's open items (no automated test framework, no multi-file/directory scan support, no rule/config customization exposed, no `update-rules` integration). For the detection-engineering knowledge base layer:

- **Nothing from this session has been committed yet** — `.gitignore`/`CLAUDE.md`/`server.py` changes and the new `rules/`/`scripts/download_attack_data.py` files are all sitting uncommitted in the working tree.
- `mappings/` (explicit, hand-curated ATT&CK technique-to-rule mapping files) — planned, not started; current technique lookups are all derived on the fly from rule tags.
- `README.md` and `HANDOFF.md` haven't been updated for the `detection://` resources or the new scripts — only `CLAUDE.md` reflects them so far.
- `tests/test_scan_evtx.py` only covers the original two tools — no automated check for the new resources (they were verified manually in-session via `mcp.read_resource()`/`list_resource_templates()`).
- `credential_access_rules.json` and `t1003_001_top10.json` are still sitting in the working tree, untracked — decide whether to delete them or add them to `.gitignore`.
- A remote (`origin`) is now configured, but nothing has been pushed to it yet from this snapshot.
