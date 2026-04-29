#!/usr/bin/env python3
# Copyright (C) 2026
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

"""Fetch the latest LOLDrivers community feed and write to data/loldrivers.json.

The feed (~30 MB) is too large to commit to git, so this script downloads it
on demand. Run after `community.py` install/update, or whenever a fresh
catalog is desired.

Usage:
    poetry run python utils/fetch_loldrivers.py
    poetry run python utils/fetch_loldrivers.py --dest /custom/path/loldrivers.json
"""

import argparse
import json
import os
import sys
import urllib.request

DEFAULT_URL = "https://www.loldrivers.io/api/drivers.json"
DEFAULT_DEST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "loldrivers.json")
CHUNK_SIZE = 1024 * 1024  # 1 MiB


def fetch(url: str, dest: str) -> int:
    print(f"Downloading {url} -> {dest}", file=sys.stderr)
    dest_dir = os.path.dirname(dest)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    tmp = dest + ".tmp"
    req = urllib.request.Request(url, headers={"User-Agent": "CAPE-community/fetch_loldrivers"})
    total = 0
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as out:
            while True:
                chunk = r.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                out.write(chunk)
    except Exception:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass
        raise

    # Validate as JSON array of entries (read the staged file once).
    try:
        with open(tmp, "rb") as f:
            parsed = json.load(f)
    except Exception as e:
        os.unlink(tmp)
        print(f"error: response is not valid JSON: {e}", file=sys.stderr)
        return 2
    if not isinstance(parsed, list):
        os.unlink(tmp)
        print(f"error: expected JSON array, got {type(parsed).__name__}", file=sys.stderr)
        return 3

    samples = sum(len(e.get("KnownVulnerableSamples") or []) for e in parsed)
    if not parsed or samples == 0:
        os.unlink(tmp)
        print("error: feed contained no entries with KnownVulnerableSamples", file=sys.stderr)
        return 5

    # Atomic publish.
    os.replace(tmp, dest)
    print(f"wrote {len(parsed)} entries ({samples} samples, {total} bytes) to {dest}", file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", default=DEFAULT_URL, help="LOLDrivers feed URL")
    ap.add_argument("--dest", default=DEFAULT_DEST, help="output path (default: data/loldrivers.json)")
    args = ap.parse_args()
    sys.exit(fetch(args.url, args.dest))


if __name__ == "__main__":
    main()
