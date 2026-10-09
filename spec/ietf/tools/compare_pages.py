#!/usr/bin/env python3
"""Compare the rasterized pages of the committed and a freshly built PDF.

Extracted text does not cover figure artwork, so check.sh also renders both
PDFs with `pdftoppm -r 50 -gray` and compares the pages here. The page sets
and sizes must match. The committed PDF and the Linux CI rebuild rasterize
byte-identically (the ietf-draft run on f3a921aa6 reported no differing
page), so a page that differs at all may carry only isolated antialiasing
noise, bounded three ways in exact rational arithmetic:

- no pixel may change by more than PIXEL_TOLERANCE gray levels, an eighth
  of the gray range (an eighth of the coverage of a 1.44 pt pixel);
- at most MAX_CHANGED_FRACTION of the page's pixels may change at all; and
- the mean absolute change over the page may not exceed MAX_MEAN_DELTA
  gray levels.

A per-pixel threshold alone accepts arbitrarily large low-contrast changes,
such as black artwork recolored to gray or light gray lines drawn on white.
On a 414 by 585 page the changed-pixel bound rejects a change to more than
121 pixels, whatever its contrast, and the mean bound rejects as few as 38
pixels changed by the full tolerance. Layout drift, which moves every glyph
edge on a page, fails the same way.
"""
import operator
import re
import sys
from collections import Counter
from fractions import Fraction
from pathlib import Path

PIXEL_TOLERANCE = 32
MAX_CHANGED_FRACTION = Fraction(1, 2000)
MAX_MEAN_DELTA = Fraction(1, 200)
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


def page_problems(pixels, fresh_pixels):
    """Return (summary, problems) for two same-size rasters that differ."""
    histogram = Counter(map(abs, map(operator.sub, pixels, fresh_pixels)))
    total = len(pixels)
    changed = total - histogram[0]
    over = sum(count for delta, count in histogram.items() if delta > PIXEL_TOLERANCE)
    delta_sum = sum(delta * count for delta, count in histogram.items())
    summary = (f"{changed} of {total} pixels changed, max delta {max(histogram)}, "
               f"mean delta {float(Fraction(delta_sum, total)):.4f}")
    problems = []
    if over:
        problems.append(f"{over} beyond the per-pixel tolerance of {PIXEL_TOLERANCE}")
    if Fraction(changed, total) > MAX_CHANGED_FRACTION:
        problems.append(f"more than {float(MAX_CHANGED_FRACTION):.2%} of the page changed")
    if Fraction(delta_sum, total) > MAX_MEAN_DELTA:
        problems.append(f"mean delta above {float(MAX_MEAN_DELTA)}")
    return summary, problems


def compare(committed, fresh):
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
        summary, problems = page_problems(pixels, fresh_pixels)
        if problems:
            failures.append(f"{name}: {summary}; " + "; ".join(problems))
        else:
            notes.append(f"{name}: {summary}")
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
