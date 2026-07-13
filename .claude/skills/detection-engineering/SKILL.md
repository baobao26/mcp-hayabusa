---
name: detection-engineering
description: Use when writing or creating Sigma rules, reviewing detection rules, discussing detection coverage, or working with YAML detection files in this repo. Enforces this project's rule-quality standards (ATT&CK mapping, severity justification, false-positive documentation, test cases, naming convention) before a rule is considered done.
---

# Detection Engineering Standards

This project's `./rules/` directory is a curated Sigma rule set backing an ATT&CK
coverage knowledge base (see `CLAUDE.md`). Every rule in it must meet the standards
below. Apply this skill whenever you author a new rule, edit an existing one, review
someone else's rule, or answer questions about coverage — a rule that fails any check
here should not be treated as "done" or "covered."

## The five standards

Check every rule against all five. When creating or reviewing a rule, walk through
this list explicitly and call out any failing item rather than silently fixing or
ignoring it.

### 1. ATT&CK technique mapping

`tags:` must include at least one entry matching `attack.t####` or
`attack.t####.###` (case-insensitive), e.g. `attack.t1003.001`. This is what makes
the rule discoverable by `detection://rules/by-technique/{technique_id}`,
`detection://attack/techniques/{technique_id}`, `analyze_coverage`, and
`suggest_rule`'s coverage checks — an untagged rule is invisible to all of them and
counts as a coverage gap even if the detection logic itself is solid.

- Prefer the most specific sub-technique that applies over the parent technique.
- Multiple techniques are fine (`attack.t1003.001`, `attack.t1003.006`, etc.) if the
  rule genuinely covers more than one.

### 2. Severity with justification

`level:` must be exactly one of: `low`, `medium`, `high`, `critical` (matches this
project's `SEVERITY_LEVELS` in `server.py`, minus `informational` which Sigma allows
but a detection rule normally shouldn't use). Do not invent other values
(`warning`, `critical!`, etc.) — `_parse_rule_summary()` and `-m/--min-level`
filtering both depend on exact matches.

Justification is required but Sigma's `level:` field has no room for prose — record
it as a YAML comment directly above the field, e.g.:

```yaml
# high: direct LSASS memory access is a strong, low-noise indicator of credential
# dumping tooling; legitimate access is rare and usually from a known allowlist.
level: high
```

Judge the justification, don't just check it exists: it should explain *why this
severity and not one notch up/down* — tie it to how strong a signal the behavior is
and how often legitimate activity would trigger it.

### 3. Documented false positive conditions

Sigma's own `falsepositives:` field must be present and non-empty — never
`falsepositives: [Unknown]` alone. List concrete conditions under which a legitimate
process/user/tool would trigger this rule (e.g. specific backup software, admin
tooling, EDR agents), not a vague hedge. If genuinely nothing legitimate is known to
trigger it, that itself needs to be a substantive line (e.g. "None known — flag any
match for investigation"), not a placeholder.

### 4. At least one test case

Every rule needs at least one worked example showing a log event (or event
fragment) that the rule's `detection:` block matches, plus enough surrounding
context (fields involved) that a reader can verify the match by inspection.
This project has no automated Sigma-rule test harness (see `CLAUDE.md` — `tests/`
is a manual script for `scan_evtx`/`get_hayabusa_rules`, not for rule logic), so
record the test case as a comment block near the bottom of the rule file, e.g.:

```yaml
# Test case: matches an event with
#   EventID: 4104, ScriptBlockText: "... Invoke-Mimikatz ..."
# Should NOT match: ScriptBlockText containing "Get-Mimikatz-Detections" (a scanner
# name, not the tool itself) — confirms the selection isn't overly broad.
```

A true positive example alone isn't enough if the rule uses substring/keyword
matching prone to false matches — include a near-miss non-match too when that risk
is real.

### 5. Naming convention

Rule filenames must be lowercase with underscores, no spaces, no hyphens, matching
the existing `./rules/` convention (e.g. `lsass_memory_access.yml`,
`sigmahq_kerberoasting.yml`, `suggested_t1558_004_asrep_roasting.yml`). Reject
`CamelCase.yml`, `kebab-case.yml`, or names with spaces. The Sigma `title:` field
inside the rule is free text and doesn't need to follow this rule — only the
filename does.

## Automated validation

`scripts/validate-rule.py <path-to-rule.yml>` runs a structural first pass over
standards #1–#4 (technique tags present, `level:` is a valid value, `falsepositives:`
is non-empty, a `# Test case:` comment exists) and prints a JSON report — exit code
0 if all four pass, 1 otherwise. It's a presence check, not a judgment check: it
can't tell whether a severity justification actually argues for that severity, a
false-positive line is substantive rather than a vague hedge, or a test case
genuinely demonstrates a match — those still require reading the rule per the
standards above. It also doesn't check standard #5 (naming convention). Run it
before the manual review below to catch missing sections quickly, not as a
replacement for it.

## Reviewing an existing rule

When asked to review a rule (or as part of a coverage discussion), read the file
and go through the five checks above in order, reporting pass/fail per item rather
than a single overall verdict — a rule can be well-written and still miss one
standard (most commonly #3 or #4, since Sigma tooling doesn't enforce either).

## Creating a new rule

1. Confirm the target technique isn't already covered — check
   `detection://rules/by-technique/{technique_id}` or run `analyze_coverage` first
   rather than duplicating an existing rule.
2. If starting from `suggest_rule(..., create_template=True)`, remember the
   generated template is a skeleton: `selection: {}` is empty and `falsepositives`/
   test case are `TODO` placeholders. Per `CLAUDE.md`, a freshly-created template
   counts as tag-derived "covered" immediately even before real logic is filled in —
   don't treat template creation alone as satisfying these standards; all five
   checks above still apply before the rule is actually done.
3. Follow the existing `./rules/*.yml` files as structural examples (front matter
   order, `logsource:`, `detection:` block shape) rather than inventing a new shape.
