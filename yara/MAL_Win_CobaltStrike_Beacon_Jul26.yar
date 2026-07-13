rule MAL_Win_CobaltStrike_Beacon_NamedPipes_Jul26 {
  meta:
    description = "Detects Cobalt Strike Beacon via its default named-pipe format strings, used for SMB Beacon peer-to-peer C2 and post-exploitation jobs (psexec_psh, jobs, SSH agent tunneling)"
    author      = "Detection Engineering KB"
    reference   = "https://attack.mitre.org/software/S0154/"
    date        = "2026-07-13"

  strings:
    // Literal sprintf/wsprintf format strings embedded in the beacon
    // binary before pipe-name construction (e.g. "\\.\pipe\MSSE-1234-server").
    // Individually distinctive - not generic Windows pipe naming.
    $pipe_msse    = "\\\\.\\pipe\\MSSE-%d-server" ascii
    $pipe_msagent = "\\\\.\\pipe\\msagent_%x" ascii
    $pipe_status  = "\\\\.\\pipe\\status_%x" ascii
    $pipe_postex  = "\\\\.\\pipe\\postex_%x" ascii
    $pipe_postssh = "\\\\.\\pipe\\postex_ssh_%x" ascii

  condition:
    filesize < 10MB and
    uint16(0) == 0x5A4D and
    any of ($pipe_*)
}

// LIMITATIONS (read before deploying):
//
// - These are Cobalt Strike's *default* pipe-name templates. Since CS 4.x,
//   Malleable C2 profiles let an operator override pipe names entirely
//   (`set pipename "..."` / stage.pipename block) - a deliberately evasive
//   actor will not match this rule. It catches unconfigured/default beacons,
//   which is still a meaningful share of real-world deployments, but treat
//   a non-match as "no default-config beacon found," not "no beacon here."
// - Not validated against a goodware corpus or real Cobalt Strike samples in
//   this environment (no `yr` CLI or sample set available here) - per this
//   skill's standard workflow, run `yr check`, `yr fmt -w`, and a goodware
//   scan (VirusTotal corpus or local clean-file set) before treating this as
//   production-ready, and confirm on current in-the-wild beacon samples,
//   since Cobalt Strike's internals change across releases.
// - Consider pairing this with a second rule targeting the beacon's
//   XOR-obfuscated configuration block (well documented by Didier Stevens'
//   1768.py and related public research) for coverage of stageless/staged
//   payloads that don't reference these pipes at all - deliberately left out
//   here rather than guessed, since the XOR key and TLV layout have changed
//   across Cobalt Strike versions and should be confirmed against current
//   samples rather than asserted from memory.
