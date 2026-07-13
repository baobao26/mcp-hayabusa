# State snapshot

Last updated: 2026-07-12

## Repo

- Location: `C:\Users\PC\mcp-hayabusa`
- Remote: `origin` -> `https://github.com/baobao26/mcp-hayabusa.git` (fetch/push)
- Branch: `master`, tracking `origin/master`, up to date, 10 commits:
  - `20c0bd5` — Close Credential Access coverage gaps identified by analyze_coverage
  - `16f1fb3` — Fix remaining staleness in README/HANDOFF after analyze_coverage
  - `da966f1` — Bring STATE.md's commit list and file table current
  - `d42d201` — Update HANDOFF's stale no-commits note
  - `a1cd588` — Document analyze_coverage in README and HANDOFF
  - `7e21e0d` — Update STATE.md with ab12b59 commit and analyze_coverage tool
  - `ab12b59` — Add detection engineering knowledge base and analyze_coverage tool
  - `4f2d5c8` — Update STATE.md with commit history and Claude Desktop registration
  - `c4e5d04` — Add MCP server implementation, scripts, tests, and project state
  - `b7f719f` — Document Claude Desktop MCP registration
- Git identity: configured locally (not global) — `user.name "Katrina Ung"`, `user.email "ung.katrina@gmail.com"`
- Working tree: clean, nothing uncommitted or unpushed as of this snapshot. `credential_access_rules.json`/`t1003_001_top10.json` (ad-hoc dumps from earlier `get_hayabusa_rules` debugging, noted as undecided in the prior snapshot) were deleted rather than committed.

## What's been built since the last snapshot

A detection-engineering knowledge base layer, alongside the original Hayabusa-scanning server — the layer itself plus `analyze_coverage` landed in `ab12b59`, with follow-up commits (`7e21e0d`, `a1cd588`, `d42d201`) updating this file and the docs:

- **`rules/`** — 31 curated Sigma rules (YAML), checked into git: 6 hand-authored covering T1003.001 (LSASS access), T1558.003 (Kerberoasting), T1003.006 (DCSync), T1550.002 (Pass-the-Hash), plus 25 unmodified rules copied from upstream [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) (attribution preserved) broadening coverage across credential-access, lateral-movement, and persistence techniques. Deliberately curated, not a full mirror of upstream (~4,700 files) — see CLAUDE.md for why. 7 of the 25 were added in a later gap-closing pass targeting `analyze_coverage`-identified Credential Access gaps (see below).
- **`scripts/download_attack_data.py`** — fetches the MITRE ATT&CK Enterprise STIX bundle into `./attack/enterprise-attack.json` (gitignored, ~50MB), same fetch-on-demand pattern as `download_hayabusa.py`/`download_sample_evtx.py`.
- **Four `detection://` MCP resources in `server.py`**:
  - `detection://rules` — list all curated rules
  - `detection://rules/{rule_name}` — raw YAML of one rule
  - `detection://rules/by-technique/{technique_id}` — rules tagged with a given ATT&CK ID
  - `detection://attack/techniques/{technique_id}` — ATT&CK technique name/description plus coverage assessment (`covered`/`partial`/`gap`) against `rules/`
- **`analyze_coverage` tool in `server.py`** — same coverage assessment as the ATT&CK resource above, but invocable as a tool rather than browsed, and accepts either a single technique ID (`"T1003.001"`) or a tactic name (`"Credential Access"` / `"credential-access"`), in which case it reports covered/partial/gap counts across every technique in that tactic. Reuses `_load_attack_techniques`/`_assess_technique_coverage`; adds `_load_attack_tactics` (same STIX-bundle-cached pattern) and `_normalize_tactic_name`.
- **7 new `sigmahq_` rules closing Credential Access gaps** — AS-REP Roasting (T1558.004), Impacket SecretDump (T1003.002/.003/.004 in one rule), a second NTDS.DIT-exfil rule (T1003.003), findstr password recon (T1552.001), Chromium profile-data access (T1555.003, plus a bonus T1539 tag), and two PowerShell-keylogger rules (T1056.001). Fetched fresh from the real SigmaHQ GitHub repo (not the local Hayabusa checkout, which turned out to be a transformed copy — see HANDOFF.md's "Closing analyze_coverage gaps" section for why that mattered). Moved Credential Access from 8/67 to 16/67 covered. T1558.001/.002 (Golden/Silver Ticket) were dropped from scope — no dedicated upstream rule exists for either.

Full design rationale for both layers is in CLAUDE.md's Architecture section.

## Files

| File | Purpose |
| --- | --- |
| `server.py` | The MCP server (`FastMCP`): `scan_evtx`/`get_hayabusa_rules`/`analyze_coverage` tools, plus four `detection://` resources |
| `requirements.txt` | Python dependency: `mcp` |
| `scripts/download_hayabusa.py` | Downloads the latest Hayabusa release for this OS/arch into `./hayabusa/` |
| `scripts/download_sample_evtx.py` | Downloads a sample attack EVTX into `./samples/` |
| `scripts/download_attack_data.py` | Downloads the MITRE ATT&CK STIX bundle into `./attack/` |
| `rules/` | 31 curated Sigma detection rules (YAML), checked into git |
| `tests/test_scan_evtx.py` | Manual script calling `scan_evtx` and `get_hayabusa_rules` directly against the sample/rule set |
| `CLAUDE.md` | Project spec / guidance for Claude Code |
| `README.md` | Setup, usage, and tool/response reference — covers `scan_evtx`, `get_hayabusa_rules`, the four `detection://` resources, and `analyze_coverage` |
| `HANDOFF.md` | What was built, how to use it, what's left, and why key decisions were made — covers both the original Hayabusa-scanning layer and the detection-engineering knowledge base layer (including `analyze_coverage`) |
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

- `mappings/` (explicit, hand-curated ATT&CK technique-to-rule mapping files) — planned, not started; current technique lookups are all derived on the fly from rule tags.
- `tests/test_scan_evtx.py` only covers the original two tools — no automated check for the `detection://` resources or `analyze_coverage` (all verified manually in-session).
