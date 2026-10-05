#!/usr/bin/env python3
"""Verify the complete CFLite build, then select exported fuzz executables.

The upstream GitHub action clones a clean checkout into its builder. Selection
therefore happens in the exported output directory, after that build finishes.
Corpus archives, dictionaries, options and shared runtime files are preserved.
"""

import argparse
from pathlib import Path
import stat
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def select_outputs(output: Path, selection: Path | None) -> list[str]:
    inventory = set(
        tomllib.loads((ROOT / "fuzz/target-map.toml").read_text())["targets"]
    )
    if not inventory:
        raise ValueError("fuzz inventory is empty")
    selected = inventory
    if selection is not None:
        names = selection.read_text().splitlines()
        selected = set(names)
        if not names or len(names) != len(selected) or not selected <= inventory:
            raise ValueError("fuzz selection is empty, duplicated or unknown")
    # Validate the entire build before deleting anything. An omitted fuzzer,
    # non-executable result or substituted symlink is a build failure even when
    # that target was not selected by this diff.
    for name in sorted(inventory):
        binary = output / name
        mode = binary.lstat().st_mode
        if not stat.S_ISREG(mode) or not mode & 0o111:
            raise ValueError(f"fuzz build did not export a regular executable: {name}")
    for name in sorted(inventory - selected):
        (output / name).unlink()
    return sorted(selected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--selection", type=Path)
    args = parser.parse_args()
    try:
        selected = select_outputs(args.output, args.selection)
    except (OSError, ValueError) as error:
        parser.exit(1, f"fuzz export selection failed: {error}\n")
    print(f"Verified full build; selected {len(selected)} fuzz executables:")
    print("\n".join(selected))


if __name__ == "__main__":
    main()
