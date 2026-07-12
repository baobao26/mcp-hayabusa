#!/usr/bin/env python3
"""Simple manual test: exercise scan_evtx and get_hayabusa_rules directly.

Run scripts/download_hayabusa.py and scripts/download_sample_evtx.py first.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server import get_hayabusa_rules, scan_evtx

SAMPLE_FILE = Path(__file__).resolve().parent.parent / "samples" / "4794_DSRM_password_change_t1098.evtx"


def test_scan_evtx() -> None:
    if not SAMPLE_FILE.exists():
        print(f"Sample file not found: {SAMPLE_FILE}")
        print("Run scripts/download_sample_evtx.py first.")
        sys.exit(1)

    print(f"Scanning {SAMPLE_FILE.name}...")
    result = scan_evtx(str(SAMPLE_FILE))
    if "error" in result:
        print("FAILED:", result["error"])
        sys.exit(1)
    print(f"Found {result['count']} events (output_format={result['output_format']})")
    print(json.dumps(result["findings"][:2], indent=2))

    full = scan_evtx(str(SAMPLE_FILE), output_format="full")
    assert "Details" in full["findings"][0], "output_format='full' should include Details"
    print(f"\noutput_format='full': {full['count']} events, first finding has 'Details'")

    filtered = scan_evtx(str(SAMPLE_FILE), min_severity="medium")
    print(f"With min_severity='medium': {filtered.get('count')} events")

    rule_filtered = scan_evtx(str(SAMPLE_FILE), rule_filter="DSRM")
    assert rule_filtered["count"] >= 1, "rule_filter='DSRM' should match the sample's DSRM finding"
    print(f"With rule_filter='DSRM': {rule_filtered['count']} events")

    no_rule_match = scan_evtx(str(SAMPLE_FILE), rule_filter="zzz_no_such_rule_zzz")
    assert no_rule_match["count"] == 0, "rule_filter with no matches should return count=0"
    print(f"With rule_filter='zzz_no_such_rule_zzz': {no_rule_match['count']} events")

    capped = scan_evtx(str(SAMPLE_FILE), max_results=0)
    assert capped["returned"] == 0 and capped["truncated"] is True
    print(f"With max_results=0: returned={capped['returned']}, truncated={capped['truncated']}")

    bad_format = scan_evtx(str(SAMPLE_FILE), output_format="bogus")
    assert "error" in bad_format, "invalid output_format should return an error"
    print(f"With output_format='bogus': error={bad_format['error']!r}")


def test_get_hayabusa_rules() -> None:
    print("\nListing Hayabusa rules...")
    result = get_hayabusa_rules()
    if "error" in result:
        print("FAILED:", result["error"])
        sys.exit(1)
    assert result["returned"] <= 50, "default max_results should cap at 50"
    print(f"Found {result['count']} rules total, returned {result['returned']} (default cap)")

    mimikatz = get_hayabusa_rules(keyword="mimikatz")
    assert mimikatz["count"] > 0, "expected at least one rule matching 'mimikatz'"
    print(f"keyword='mimikatz': {mimikatz['count']} rules, e.g. {mimikatz['rules'][0]['title']!r}")

    lateral = get_hayabusa_rules(keyword="lateral", max_results=3)
    assert lateral["returned"] == 3, "max_results=3 should cap the returned list at 3"
    assert lateral["truncated"] is True
    print(f"keyword='lateral', max_results=3: returned={lateral['returned']}, truncated={lateral['truncated']}")

    no_keyword_match = get_hayabusa_rules(keyword="zzz_no_such_keyword_zzz")
    assert no_keyword_match["count"] == 0, "unmatched keyword should return count=0"
    print(f"keyword='zzz_no_such_keyword_zzz': {no_keyword_match['count']} rules")

    bad_max_results = get_hayabusa_rules(max_results=-1)
    assert "error" in bad_max_results, "negative max_results should return an error"
    print(f"max_results=-1: error={bad_max_results['error']!r}")


def main() -> None:
    test_scan_evtx()
    test_get_hayabusa_rules()
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
