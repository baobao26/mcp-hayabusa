# False-positive patterns

Reference for populating `falsepositives:` under this project's standard 3
(see `../SKILL.md`): never a bare `[Unknown]`, always concrete conditions
under which a legitimate process/user/tool would trigger the rule. This
catalogs recurring categories seen across `./rules/`, to prompt what to check
for rather than to be copied verbatim — a listed pattern only belongs in a
specific rule's `falsepositives:` if that rule's `logsource:`/`detection:`
would genuinely trigger on it.

## Security/EDR/AV agents

Endpoint protection products routinely perform the same sensitive actions a
rule is trying to catch — reading process memory, opening handles to
`lsass.exe`, scanning credential stores — as part of legitimate real-time
scanning.

- Example: `rules/lsass_process_access.yml` filters `MsMpEng.exe` (Windows
  Defender) directly in the rule's `filter_*` selection, and still documents
  "Endpoint protection or EDR agents performing legitimate memory scans" in
  `falsepositives:` for third-party agents not in the filter.
- Watch for: any rule matching on process-access rights, memory reads, or
  registry hive access to credential-adjacent stores.

## Backup and monitoring tooling

Backup agents and monitoring/inventory software often run with broad,
privileged access across the filesystem, registry, or process table for
entirely legitimate reasons — the access pattern alone can't distinguish
them from credential theft.

- Example: `rules/lsass_process_access.yml` — "Backup or monitoring agents
  with broad process-access privileges."
- Watch for: rules keyed on broad access-right bitmasks or wide filesystem
  scans rather than a specific tool signature.

## Legacy protocols and deprecated auth flows

A protocol or flow being a security downgrade (weaker encryption, no MFA
support, no interactive prompt) doesn't mean every use of it is malicious —
some environments still have real dependencies on it that haven't been
migrated off yet.

- Example: `rules/azure_app_ropc_authentication.yml` — "Legacy line-of-business
  applications deliberately configured to use ROPC because they cannot
  support interactive/modern authentication."
- Example: `rules/kerberos_golden_ticket_rc4_ticket_options.yml` — "Legacy
  domain controllers, member servers, or third-party Kerberos clients that
  do not support AES and still negotiate RC4-HMAC by default."
- Watch for: rules keyed on an encryption type, protocol version, or
  auth-flow field rather than a specific malicious command/tool.

## Legitimate admin tooling with dual-use commands

Some built-in or common third-party admin tools intentionally perform
actions that are indistinguishable, at the log-field level, from attacker
use of the same primitive (e.g. `rundll32.exe` calling arbitrary DLL
exports, PowerShell reading files, `reg.exe` querying hives).

- Example: `rules/lsass_comsvcs_minidump.yml` — "Legitimate use of MiniDump
  for non-LSASS process troubleshooting (verify target PID)."
- Watch for: rules matching on a LOLBin (`rundll32.exe`, `regsvr32.exe`,
  `mshta.exe`, etc.) plus a generic argument pattern rather than a
  fully-qualified, hard-to-reproduce-innocently command line.

## Automation, migration, and legacy client libraries

Scripts and older SDKs/libraries sometimes default to a flagged behavior
(an older auth library defaulting to a legacy flow, a migration script
bulk-reading credential stores) as an artifact of their age rather than
malicious intent.

- Example: `rules/azure_app_ropc_authentication.yml` — "Automation,
  migration, or monitoring scripts built on older auth libraries... that
  default to ROPC instead of device code or authorization code flows."
- Watch for: rules where the trigger is "an old/default code path" rather
  than an explicit attacker action.

## When nothing legitimate is known

If a genuine search turns up no plausible legitimate trigger, say so as a
substantive line rather than leaving the section thin — e.g. "None known —
flag any match for investigation." That is a valid, complete answer under
standard 3; a placeholder like `[Unknown]` alone is not, because it gives a
reviewer no way to tell "we checked and found nothing" from "we didn't
check."
