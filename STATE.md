# State snapshot

Last updated: 2026-07-13

## Repo

- Location: `C:\Users\PC\mcp-hayabusa`
- Remote: `origin` -> `https://github.com/baobao26/mcp-hayabusa.git` (fetch/push)
- Branch: `master`, tracking `origin/master`, **7 commits ahead, not pushed**, 21 commits total:
  - `1a05329` — Fix yr check lint warning in Cobalt Strike config-XOR rule
  - `9c07ed5` — Add Cobalt Strike Beacon config-block YARA rule (XOR TLV detection)
  - `21a42a4` — Add YARA-X rule for Cobalt Strike Beacon default named pipes
  - `6dce359` — Add references/ directory to detection-engineering skill
  - `80bac2e` — Add detection-engineering skill and rule validation script
  - `ed88063` — Add Azure AD ROPC authentication rule for T1078.004 coverage gap
  - `e6bce1d` — Add Golden Ticket rule; add severity justification and test case to LSASS MiniDump rule
  - (older commits pushed and on `origin/master` already — see `git log` for full history, not enumerated here since it grows every session and has gone stale on prior doc passes when hand-copied)
- Git identity: configured locally (not global) — `user.name "Katrina Ung"`, `user.email "ung.katrina@gmail.com"`
- Working tree: clean as of this snapshot.

## What's been built since the last snapshot

The last snapshot (2026-07-12) ended at `abe12e9`. Since then, three unrelated threads landed:

- **Two more curated Sigma rules, closing more coverage gaps**: `kerberos_golden_ticket_rc4_ticket_options.yml` (T1558.001, Golden Ticket — dropped from the earlier gap-closing pass for lack of an upstream rule, written by hand instead) and `azure_app_ropc_authentication.yml` (T1078.004, Azure AD ROPC auth — the first `./rules/` file with a non-Windows logsource; coverage-knowledge-base-only, not exercisable via `scan_evtx`). `./rules/` is now 33 files (was 31). Also backfilled a severity-justification comment and a test case into the pre-existing `lsass_comsvcs_minidump.yml`, which had shipped without either.
- **A new repo-local skill, `.claude/skills/detection-engineering/`**, prompted directly by that `lsass_comsvcs_minidump.yml` gap: codifies five quality standards every `./rules/` file must meet (ATT&CK tag, severity justification, documented false positives, a worked test case, naming convention), a `scripts/validate-rule.py` structural checker for the first four, and a `references/` directory (worked example rule, severity-guide, false-positive-patterns) added in a follow-up commit.
- **A new, so-far-separate `./yara/` directory**: two YARA-X rules detecting Cobalt Strike Beacon (`yara/MAL_Win_CobaltStrike_Beacon_Jul26.yar`) — default named pipes, and the XOR-obfuscated config block (TLV header match for the two known fixed keys, plus a brute-forced-XOR fallback on known internal strings). Written using the third-party `yara-authoring` plugin skill, not `detection-engineering`. Not registered with `server.py` in any form (no tool/resource) — unlike the Sigma layer, this one isn't part of the MCP server's exposed surface yet. `uv` and `yr` (YARA-X CLI) were installed locally (`winget`) in the course of this work, so both rules now pass `yr check`/`yr fmt --check` clean.

Full design rationale for all three tracks is in CLAUDE.md's Project status/Architecture sections and HANDOFF.md's per-track sections ("Detection engineering knowledge base" → "Post-gap-closing additions", and the new "YARA rule authoring" section).

## Files

| File | Purpose |
| --- | --- |
| `server.py` | The MCP server (`FastMCP`): `scan_evtx`/`get_hayabusa_rules`/`analyze_coverage`/`suggest_rule` tools, plus four `detection://` resources |
| `requirements.txt` | Python dependency: `mcp` |
| `scripts/download_hayabusa.py` | Downloads the latest Hayabusa release for this OS/arch into `./hayabusa/` |
| `scripts/download_sample_evtx.py` | Downloads a sample attack EVTX into `./samples/` |
| `scripts/download_attack_data.py` | Downloads the MITRE ATT&CK STIX bundle into `./attack/` |
| `rules/` | 33 curated Sigma detection rules (YAML), checked into git |
| `yara/` | Hand-authored YARA-X rules (currently 1 file, 2 rules — Cobalt Strike Beacon), checked into git. Not wired into `server.py`. |
| `.claude/skills/detection-engineering/` | Repo-local skill: `./rules/` quality standards, `scripts/validate-rule.py`, `references/` |
| `tests/test_scan_evtx.py` | Manual script calling `scan_evtx` and `get_hayabusa_rules` directly against the sample/rule set |
| `CLAUDE.md` | Project spec / guidance for Claude Code |
| `README.md` | Setup, usage, and tool/response reference — covers `scan_evtx`, `get_hayabusa_rules`, the four `detection://` resources, `analyze_coverage`, and `suggest_rule` |
| `HANDOFF.md` | What was built, how to use it, what's left, and why key decisions were made — covers the Hayabusa-scanning layer, the detection-engineering knowledge base layer, and the YARA rule-authoring track |
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
- `uv` 0.11.28, installed via `winget install --id=astral-sh.uv`
- YARA-X CLI (`yr`) 1.19.0, installed via `winget install --id=VirusTotal.YARA-X` (already present on this machine when checked; just not on `PATH` in a fresh PowerShell session without a manual `$env:Path` refresh — winget-installed `PATH` changes require a new shell)

## Outstanding

See `HANDOFF.md` → "What's left to do" for the original Hayabusa-scanning layer's open items (no automated test framework, no multi-file/directory scan support, no rule/config customization exposed, no `update-rules` integration). For the detection-engineering knowledge base layer:

- `mappings/` (explicit, hand-curated ATT&CK technique-to-rule mapping files) — planned, not started; current technique lookups are all derived on the fly from rule tags.
- `tests/test_scan_evtx.py` only covers the original two tools — no automated check for the `detection://` resources, `analyze_coverage`, or `suggest_rule` (all verified manually in-session).
- `suggest_rule`'s coverage check has no concept of detection-logic quality — a freshly generated `create_template=True` scaffold (`selection: {}`) counts as full coverage immediately, same as a real rule. See HANDOFF.md's "suggest_rule: decisions made and why" for why this wasn't special-cased.
- No distinction between "coverage-knowledge-base rule" and "rule `scan_evtx` can actually run" — `azure_app_ropc_authentication.yml` counts toward coverage identically to every Windows/EVTX rule despite `scan_evtx` having no way to actually run it. See HANDOFF.md.

For the YARA rule-authoring track:

- No goodware-corpus or real-Beacon-sample validation for either rule in `./yara/` — only `yr check`/`yr fmt --check` (syntax/formatting) have been run.
- No coverage of Cobalt Strike 4.8+'s multi-byte XOR config key — both `yara/` rules' config-block detection is single-byte-XOR only.
- No MCP integration (`server.py` doesn't expose `./yara/` as any tool or resource).
- No project setup script installs `uv`/`yr` for a new collaborator — both were installed ad hoc on this machine via `winget`.
- 7 local commits (see Repo above) are not yet pushed to `origin/master`.
