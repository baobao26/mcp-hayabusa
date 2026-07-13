# Severity guide

Reference for picking `level:` when authoring or reviewing a rule under this
project's standard 2 (see `../SKILL.md`). `level:` must be exactly one of
`low`, `medium`, `high`, `critical` — always paired with a YAML comment
directly above the field explaining *why this level and not one notch
up/down*.

The two axes that actually decide severity:

- **Signal strength** — how specific is the match to malicious behavior,
  versus something a normal admin/user/service could also produce?
- **Expected legitimate trigger rate** — even a strong signal is noisier if
  common legitimate tooling produces it regularly in this environment.

A rule's severity is a function of both, not either alone. A highly specific
signal that nonetheless fires on routine EDR/backup activity is not
`critical` just because the behavior itself is scary — the false-positive
rate caps it.

## `low`

Use when the match is suggestive but common, ambiguous, or requires
significant additional context to be actionable on its own — mostly useful
as supporting evidence alongside other alerts, not a standalone trigger for
response.

- Broad reconnaissance-shaped commands that are also routine admin/dev
  activity (e.g. `findstr` searching for a common word across files).
- Access patterns that need correlation (time, user, asset) to mean anything.

## `medium`

Use when the behavior is a real, non-trivial signal, but legitimate tooling
or business processes are known to trigger it under specific, nameable
conditions — the false-positive rate is real, not hypothetical.

- A protocol/flow that bypasses a security control (e.g. ROPC bypassing MFA)
  but that some legacy applications still legitimately depend on.
- Registry/credential-store access that a specific, common category of
  admin/migration tooling also performs.

## `high`

Use when the behavior is strongly associated with malicious tooling or
technique, and the known legitimate callers are either rare, narrow, or
already excluded by a filter in the rule itself (`filter_*` selections) —
what's left in `falsepositives:` is real but a minority case, like EDR/backup
agents rather than routine admin work.

- Process access to a sensitive target (e.g. LSASS) with access rights
  specific to memory-reading tools, after excluding known OS/EDR callers.
- A specific tool invocation pattern (command-line, DLL export, ticket
  encryption downgrade) documented as a known attack technique, where
  legitimate use requires an unusual, specific justification.

## `critical`

Use when the match is close to unambiguous — legitimate activity producing
this exact pattern would be a genuine surprise, not just "possible but rare."
Reserve this for signals you would want to page someone for immediately,
not merely investigate at leisure.

- A specific, well-documented living-off-the-land command line
  (e.g. `comsvcs.dll`'s `MiniDump` export invoked via `rundll32.exe`) with
  essentially no normal administrative reason to occur.
- Direct evidence of a known attack artifact rather than a precursor or
  access pattern (e.g. a DCSync request from a non-DC principal).

## Judging an existing justification comment

Don't just check that a comment exists above `level:` — read it and ask:

1. Does it name the specific signal driving the severity (not just restate
   the rule's `description:`)?
2. Does it address why the level isn't one notch higher (what stops it from
   being unambiguous) or one notch lower (what makes it more than routine
   noise)?
3. Does it match what's actually in `falsepositives:`? A `critical` rule
   with three named legitimate-trigger conditions in `falsepositives:` is
   an inconsistency worth flagging in review — see
   [false-positive-patterns.md](false-positive-patterns.md) for how those
   conditions get documented.
