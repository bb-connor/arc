#!/usr/bin/env python3
"""Render an enforcing profile for one measured research controller.

The controller creates a trusted auditor which creates checker namespaces.
The package Bubblewrap profile strips namespace capabilities at every exec,
so it cannot support that nesting. Inherit this controller-specific label;
the Rust launcher still enforces mounts, capability drops and leaf userns limits.
This is an ephemeral research-runner fixture, not a production confinement policy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


def render_profile(executable: str) -> str:
    path = PurePosixPath(executable)
    if (not re.fullmatch(r"/[A-Za-z0-9_./-]+", executable)
            or executable.startswith("//") or path.as_posix() != executable
            or ".." in path.parts):
        raise ValueError("controller attachment must be a normalized absolute literal path")
    name = "chio_outcome_" + hashlib.sha256(executable.encode()).hexdigest()
    return f'''# Candidate controller only; no global Bubblewrap or sysctl change.
profile {name} "{executable}" flags=(attach_disconnected,mediate_deleted) {{
  # AppArmor permits namespace setup; it does not grant Linux capabilities.
  allow capability,
  allow file rwlkm /{{**,}},
  # Preserve this label through the controller, auditor, Git and Python.
  # Untrusted leaves retain --cap-drop ALL and --disable-userns.
  allow ix /**,
  allow network,
  allow unix,
  allow signal,
  allow ptrace,
  allow userns,
  allow mount,
  allow umount,
  allow pivot_root,
}}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.controller.is_symlink():
        raise ValueError("controller must not be a symlink")
    executable = args.controller.resolve(strict=True)
    if (executable.name != "chio-outcome-ledger-comparison"
            or not stat.S_ISREG(executable.stat().st_mode)
            or not os.access(executable, os.X_OK)):
        raise ValueError("controller must be the built outcome-ledger executable")
    policy = render_profile(executable.as_posix())
    with executable.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    with args.output.open("x") as output:
        output.write(policy)
    print(json.dumps({"controller": str(executable), "sha256": digest,
                      "profile": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
