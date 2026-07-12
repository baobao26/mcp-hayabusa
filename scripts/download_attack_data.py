#!/usr/bin/env python3
"""Download the MITRE ATT&CK Enterprise STIX bundle into ./attack/.

Source: https://github.com/mitre-attack/attack-stix-data
"""

import sys
import urllib.request
from pathlib import Path

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DEST = Path(__file__).resolve().parent.parent / "attack" / "enterprise-attack.json"


def main() -> None:
    DEST.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {URL}...")
    req = urllib.request.Request(URL, headers={"User-Agent": "attack-data-downloader"})
    with urllib.request.urlopen(req) as resp, open(DEST, "wb") as out:
        out.write(resp.read())
    print(f"Saved to {DEST} ({DEST.stat().st_size} bytes)")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
