# State snapshot

Last updated: 2026-07-11

## Repo

- Location: `C:\Users\PC\mcp-hayabusa`
- Remote: none configured
- Branch: `master`, 2 commits:
  - `b7f719f` — README.md, CLAUDE.md, HANDOFF.md (Claude Desktop registration docs)
  - `c4e5d04` — server.py, scripts/, tests/, requirements.txt, .gitignore, STATE.md
- Git identity: configured locally (not global) — `user.name "Katrina Ung"`, `user.email "ung.katrina@gmail.com"`
- Untracked (intentionally, not gitignored): `credential_access_rules.json`, `t1003_001_top10.json` — ad-hoc dumps from `get_hayabusa_rules` debugging (see HANDOFF.md's `level: null` bug note), not project source

## Files

| File | Purpose |
| --- | --- |
| `server.py` | The MCP server itself (`FastMCP`, `scan_evtx` and `get_hayabusa_rules` tools) |
| `requirements.txt` | Python dependency: `mcp` |
| `scripts/download_hayabusa.py` | Downloads the latest Hayabusa release for this OS/arch into `./hayabusa/` |
| `scripts/download_sample_evtx.py` | Downloads a sample attack EVTX into `./samples/` |
| `tests/test_scan_evtx.py` | Manual script calling `scan_evtx` and `get_hayabusa_rules` directly against the sample/rule set |
| `CLAUDE.md` | Project spec / guidance for Claude Code |
| `README.md` | Setup, usage, and tool/response reference |
| `HANDOFF.md` | What was built, how to use it, what's left, and why key decisions were made |
| `.gitignore` | Excludes `hayabusa/`, `*.zip`, `samples/*.evtx`, `.mcp.json`, Python build artifacts |
| `.mcp.json` | Registers this server with Claude Code locally (`python server.py`, machine-specific `cwd`) — gitignored. Not `.claude/settings.local.json`, which Claude Code doesn't read `mcpServers` from. |
| `hayabusa/` | Extracted Hayabusa binary + `rules/`/`config/` — gitignored, fetched on demand |
| `samples/` | Downloaded test EVTX samples — gitignored, fetched on demand |

Also registered outside this repo, in Claude Desktop's own config (see README.md → "Registering with Claude Desktop"): on this machine that's `%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json` (MSIX-redirected path), entry uses an absolute path to `server.py` in `args` since this build strips `cwd`.

## Environment (this machine)

- Python 3.12.10
- Hayabusa v3.10.0 ("Independence Day Release"), Windows x64 build, extracted to `./hayabusa/hayabusa-3.10.0-win-x64.exe`
- `mcp` 1.28.1 installed (plus transitive deps: `pydantic`, `httpx`, `uvicorn`, `starlette`, etc. — see `requirements.txt` for the direct dependency, `pip freeze` for the full resolved set)

## Outstanding

See `HANDOFF.md` → "What's left to do" for functional/scope items (no automated test framework, no multi-file/directory scan support, no rule/config customization exposed, no `update-rules` integration). In addition:

- No remote configured — nothing has been pushed anywhere.
- `credential_access_rules.json` and `t1003_001_top10.json` are still sitting in the working tree, untracked — decide whether to delete them or add them to `.gitignore`.
