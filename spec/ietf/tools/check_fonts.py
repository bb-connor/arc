#!/usr/bin/env python3
"""Verify the bundled PDF fonts and licenses against tools/fonts/sources.json.

Every manifest entry must exist with its recorded size and SHA-256 digest,
and the directory must hold no font file that the manifest does not list,
because fonts.conf hands every font in the directory to the PDF renderer.
"""
import hashlib
import json
import sys
from pathlib import Path

FONTS = Path(__file__).resolve().parent / "fonts"
FONT_SUFFIXES = {".ttf", ".otf", ".ttc", ".otc", ".woff", ".woff2", ".pfa", ".pfb"}


def check(directory=FONTS):
    manifest = json.loads((directory / "sources.json").read_text(encoding="utf-8"))
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("sources.json lists no files")
    listed = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("sources.json has a malformed entry")
        name, size, digest = entry.get("file"), entry.get("bytes"), entry.get("sha256")
        if (not isinstance(name, str) or not name or "/" in name or name in listed
                or type(size) is not int or not isinstance(digest, str)):
            raise ValueError(f"sources.json has a malformed entry for {name!r}")
        listed.add(name)
        path = directory / name
        if not path.is_file():
            raise ValueError(f"{name} is listed in sources.json but missing")
        data = path.read_bytes()
        if len(data) != size:
            raise ValueError(f"{name} has {len(data)} bytes, sources.json records {size}")
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise ValueError(f"{name} has SHA-256 {actual}, sources.json records {digest}")
    for path in sorted(directory.iterdir()):
        if path.suffix.lower() in FONT_SUFFIXES and path.name not in listed:
            raise ValueError(f"{path.name} is a font file that sources.json does not list")
    return len(listed)


if __name__ == "__main__":
    try:
        if len(sys.argv) not in (1, 2):
            raise ValueError("expected at most one font directory")
        count = check(Path(sys.argv[1]) if len(sys.argv) == 2 else FONTS)
    except (OSError, ValueError, TypeError) as error:
        print(f"check_fonts: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"check_fonts: {count} files match sources.json")
