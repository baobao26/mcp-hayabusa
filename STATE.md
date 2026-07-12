# State snapshot

Last updated: 2026-07-11

## Repo

- Location: `C:\Users\PC\mcp-hayabusa`
- Remote: none configured
- Branch: `master`, no commits yet — all files are currently untracked
- Git identity: not configured, locally or globally (`git config user.name`/`user.email` both unset) — will need to be set before the first commit

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
| `.gitignore` | Excludes `hayabusa/`, `*.zip`, `samples/*.evtx`, `.claude/settings.local.json`, Python build artifacts |
| `.claude/settings.local.json` | Registers this server with Claude Code locally — gitignored, machine-specific `cwd` |
| `hayabusa/` | Extracted Hayabusa binary + `rules/`/`config/` — gitignored, fetched on demand |
| `samples/` | Downloaded test EVTX samples — gitignored, fetched on demand |

## Environment (this machine)

- Python 3.12.10
- Hayabusa v3.10.0 ("Independence Day Release"), Windows x64 build, extracted to `./hayabusa/hayabusa-3.10.0-win-x64.exe`
- `mcp` 1.28.1 installed (plus transitive deps: `pydantic`, `httpx`, `uvicorn`, `starlette`, etc. — see `requirements.txt` for the direct dependency, `pip freeze` for the full resolved set)

## Outstanding

See `HANDOFF.md` → "What's left to do" for functional/scope items (no automated test framework, no multi-file/directory scan support, no rule/config customization exposed, no `update-rules` integration). In addition:

- No commits yet — repo is initialized but nothing has been staged or committed.
- No git identity configured on this machine (see above) — needs to be set before committing.
- No remote configured — nothing has been pushed anywhere.
