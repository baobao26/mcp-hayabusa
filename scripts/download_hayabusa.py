#!/usr/bin/env python3
"""Download the latest Hayabusa release for the current platform and extract it to ./hayabusa/."""

import json
import platform
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO = "Yamato-Security/hayabusa"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPO}/releases/latest"
DEST_DIR = Path(__file__).resolve().parent.parent / "hayabusa"


def platform_asset_keys():
    system = platform.system()
    machine = platform.machine().lower()
    is_arm = machine in ("arm64", "aarch64")

    if system == "Windows":
        if machine in ("amd64", "x86_64"):
            arch_key = "x64"
        elif is_arm:
            arch_key = "aarch64"
        elif machine in ("x86", "i386", "i686"):
            arch_key = "x86"
        else:
            raise RuntimeError(f"Unsupported Windows architecture: {machine}")
        return "win", arch_key
    if system == "Linux":
        return "lin", ("aarch64" if is_arm else "x64")
    if system == "Darwin":
        return "mac", ("aarch64" if is_arm else "x64")
    raise RuntimeError(f"Unsupported platform: {system}")


def fetch_latest_release():
    req = urllib.request.Request(
        LATEST_RELEASE_API,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "hayabusa-downloader"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def pick_asset(release):
    assets = release.get("assets", [])
    os_key, arch_key = platform_asset_keys()

    candidates = [
        asset
        for asset in assets
        if asset["name"].lower().endswith(".zip")
        and os_key in asset["name"].lower()
        and arch_key in asset["name"].lower()
        and "live-response" not in asset["name"].lower()
    ]
    if not candidates:
        raise RuntimeError(
            f"No matching .zip asset found for {os_key}/{arch_key} among: "
            f"{[a['name'] for a in assets]}"
        )
    # Prefer glibc builds over musl when both are present (Linux).
    for asset in candidates:
        if "musl" not in asset["name"].lower():
            return asset
    return candidates[0]


def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": "hayabusa-downloader"})
    with urllib.request.urlopen(req) as resp, open(dest, "wb") as out:
        out.write(resp.read())


def extract(zip_path, dest_dir):
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest_dir)


def make_executable(dest_dir):
    if platform.system() == "Windows":
        return
    for path in dest_dir.rglob("hayabusa*"):
        if path.is_file() and not path.suffix:
            path.chmod(path.stat().st_mode | 0o111)


def main():
    print(f"Fetching latest release info for {REPO}...")
    release = fetch_latest_release()
    tag = release.get("tag_name", "unknown")
    print(f"Latest release: {tag}")

    asset = pick_asset(release)
    print(f"Selected asset: {asset['name']}")

    zip_path = DEST_DIR.parent / asset["name"]
    print(f"Downloading to {zip_path}...")
    download(asset["browser_download_url"], zip_path)

    print(f"Extracting to {DEST_DIR}...")
    extract(zip_path, DEST_DIR)
    zip_path.unlink()

    make_executable(DEST_DIR)
    print("Done.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
