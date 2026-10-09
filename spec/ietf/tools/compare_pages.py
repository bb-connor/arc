#!/usr/bin/env python3
"""Compare the rasterized pages of the committed and a freshly built PDF.

Extracted text does not cover figure artwork, so check.sh also renders both
PDFs with `pdftoppm -r 50 -gray` and compares the pages here. The page sets
and sizes must match, and no pixel may differ by more than TOLERANCE gray
levels. The tolerance absorbs antialiasing changes from sub-point glyph
placement differences between build hosts (a 0.36 pt shift of a whole page
moves no pixel by more than 64 levels); a changed stroke or shape moves the
pixels it covers by far more.
"""
import re
import sys
from pathlib import Path

TOLERANCE = 96
HEADER = re.compile(rb"P5\s+(\d+)\s+(\d+)\s+255\s")


def read_pgm(path):
    data = path.read_bytes()
    match = HEADER.match(data)
    if not match:
        raise ValueError(f"{path.name} is not an 8-bit binary PGM page")
    width, height = int(match.group(1)), int(match.group(2))
    pixels = data[match.end():]
    if width <= 0 or height <= 0 or len(pixels) != width * height:
        raise ValueError(f"{path.name} has a truncated or malformed raster")
    return (width, height), pixels


def compare(committed, fresh, tolerance=TOLERANCE):
    """Return (failures, notes) for two directories of pdftoppm pages."""
    names = sorted(p.name for p in committed.glob("*.pgm"))
    fresh_names = sorted(p.name for p in fresh.glob("*.pgm"))
    if not names:
        raise ValueError("the committed PDF rendered no pages")
    if names != fresh_names:
        return [f"page sets differ: {len(names)} committed, {len(fresh_names)} fresh"], []
    failures, notes = [], []
    for name in names:
        size, pixels = read_pgm(committed / name)
        fresh_size, fresh_pixels = read_pgm(fresh / name)
        if size != fresh_size:
            failures.append(f"{name}: page size {size} differs from {fresh_size}")
            continue
        if pixels == fresh_pixels:
            continue
        deltas = [abs(a - b) for a, b in zip(pixels, fresh_pixels)]
        over = sum(1 for delta in deltas if delta > tolerance)
        summary = f"{name}: max delta {max(deltas)}, {sum(1 for d in deltas if d)} pixels changed"
        if over:
            failures.append(f"{summary}, {over} beyond the tolerance of {tolerance}")
        else:
            notes.append(summary)
    return failures, notes


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("expected the committed and the fresh page directories")
        failures, notes = compare(Path(sys.argv[1]), Path(sys.argv[2]))
    except (OSError, ValueError) as error:
        print(f"compare_pages: {error}", file=sys.stderr)
        sys.exit(1)
    for note in notes:
        print(f"compare_pages: within tolerance: {note}", file=sys.stderr)
    for failure in failures:
        print(f"compare_pages: {failure}", file=sys.stderr)
    sys.exit(1 if failures else 0)
