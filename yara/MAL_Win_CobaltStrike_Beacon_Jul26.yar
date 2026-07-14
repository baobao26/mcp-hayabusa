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

rule MAL_Win_CobaltStrike_Beacon_ConfigXOR_Jul26 {
  meta:
    description = "Detects an embedded Cobalt Strike Beacon configuration block via its single-byte XOR-obfuscated TLV header (the BeaconType setting) and/or brute-forced single-byte XOR of distinctive internal Beacon format strings"
    author      = "Detection Engineering KB"
    reference   = "https://www.sentinelone.com/labs/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/, https://github.com/Sentinel-One/CobaltStrikeParser, https://github.com/Neo23x0/signature-base/blob/master/yara/apt_cobaltstrike.yar"
    date        = "2026-07-13"

  strings:
    // Every Beacon config's first TLV entry is the BeaconType setting: a
    // 6-byte header [reserved=00][id=01][reserved=00][type=01 SHORT]
    // [len=00 02], XOR'd with the build's fixed single-byte key. Header
    // layout confirmed against CobaltStrikeParser's binary_repr() struct;
    // keys (0x69 = Beacon v3, 0x2e = Beacon v4 pre-4.8) confirmed via
    // SentinelOne's published analysis - not guessed. Written as ASCII text
    // literals rather than hex bytes per `yr check`'s text_as_hex lint,
    // since the XOR'd header happens to land on printable characters.
    $hdr_69 = "ihihik" ascii
    $hdr_2e = "././.," ascii

    // Distinctive internal Beacon format strings, brute-forced across every
    // single-byte XOR key - catches a config encoded with a key other than
    // the two fixed ones above. Strings and technique taken directly from
    // Neo23x0's signature-base (HKTL_CobaltStrike_Beacon_XOR_Strings), a
    // production-validated public rule; required as 2-of to offset the FP
    // risk of full-range xor() on format strings.
    $str_time = "%02d/%02d/%02d %02d:%02d:%02d" xor(0x01-0xff)
    $str_svc  = "Started service %s on %s" xor(0x01-0xff)
    $str_tok  = "%s as %s\\%s: %d" xor(0x01-0xff)

  condition:
    filesize < 10MB and
    uint16(0) == 0x5A4D and
    (any of ($hdr_*) or 2 of ($str_*))
}

// LIMITATIONS (read before deploying):
//
// - Named-pipe rule: these are Cobalt Strike's *default* pipe-name
//   templates. Since CS 4.x, Malleable C2 profiles let an operator override
//   pipe names entirely (`set pipename "..."` / stage.pipename block) - a
//   deliberately evasive actor will not match this rule. It catches
//   unconfigured/default beacons, which is still a meaningful share of
//   real-world deployments, but treat a non-match as "no default-config
//   beacon found," not "no beacon here."
// - Config-XOR rule: as of Cobalt Strike 4.8, the config block is encoded
//   with a randomly generated *multi-byte* XOR key instead of the fixed
//   single-byte 0x69/0x2e keys - both $hdr_* (exact bytes) and $str_*
//   (single-byte xor() brute force) will miss a 4.8+ default config. This
//   rule only covers CS v3, and v4 builds prior to 4.8, plus any later
//   build an operator has manually reverted to a fixed key.
// - $hdr_69/$hdr_2e are each a 6-byte pattern with a 2-byte repeating
//   structure (e.g. `69 68 69 68 ...`), which is a weaker atom than a fully
//   random 6 bytes - it lowers the bar for a coincidental match in large
//   scans versus a higher-entropy string. The $str_* path with its 2-of
//   requirement is the higher-confidence signal if both fire independently.
// - Both rules pass `yr check` (no errors/warnings) and `yr fmt --check`
//   (correctly formatted). Neither has been validated against a goodware
//   corpus or real Cobalt Strike samples (no sample set available in this
//   environment) - per this skill's standard workflow, run a goodware scan
//   (VirusTotal corpus or local clean-file set) before treating either as
//   production-ready, and confirm against current in-the-wild beacon
//   samples, since Cobalt Strike's internals change across releases.
// - The two rules target independent artifacts (pipes vs. config block);
//   a non-match on one says nothing about the other. Neither is a
//   substitute for the still-missing coverage of CS 4.8+'s multi-byte XOR
//   scheme, which would need a dedicated brute-force/parsing approach
//   (e.g. Didier Stevens' 1768.py) rather than a static YARA pattern.
