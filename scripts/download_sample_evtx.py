#!/usr/bin/env python3
"""Download a sample attack EVTX file for testing scan_evtx.

Source: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
"""

import urllib.parse
import urllib.request
from pathlib import Path

REPO = "sbousseaden/EVTX-ATTACK-SAMPLES"
BRANCH = "master"
SAMPLE_PATH = "Credential Access/4794_DSRM_password_change_t1098.evtx"
DEST = Path(__file__).resolve().parent.parent / "samples" / "4794_DSRM_password_change_t1098.evtx"


def main() -> None:
    encoded_path = "/".join(urllib.parse.quote(part) for part in SAMPLE_PATH.split("/"))
    url = f"https://raw.githubusercontent.com/{REPO}/{BRANCH}/{encoded_path}"

    DEST.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {SAMPLE_PATH}...")
    req = urllib.request.Request(url, headers={"User-Agent": "evtx-sample-downloader"})
    with urllib.request.urlopen(req) as resp, open(DEST, "wb") as out:
        out.write(resp.read())
    print(f"Saved to {DEST} ({DEST.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
