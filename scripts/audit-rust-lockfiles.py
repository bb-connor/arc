#!/usr/bin/env python3
"""Apply one advisory policy to production, generated and evidence lockfiles."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess

from research_workspaces import ROOT, WORKSPACES

LOCKFILES = ('Cargo.lock', 'deploy/docker/chio-workspace/Cargo.lock',
             'deploy/docker/proof-room-workspace/Cargo.lock',
             *(f'{workspace}/Cargo.lock' for workspace in WORKSPACES))


def audit(root: Path, options: list[str]) -> int:
    missing = [path for path in LOCKFILES if not (root / path).is_file()]
    if missing:
        raise ValueError(f'advisory scan requires every lockfile: {missing}')
    reports = root / 'cargo-audit-workspaces'
    reports.mkdir(exist_ok=True)
    failed = False
    for relative in LOCKFILES:
        output = root / 'cargo-audit.json' if relative == 'Cargo.lock' else reports / (relative.replace('/', '_') + '.json')
        with output.open('w') as stream:
            result = subprocess.run(['cargo', 'audit', '--file', str(root / relative), *options],
                                    stdout=stream, cwd=root)
        failed |= result.returncode != 0
        print(f'{relative}: cargo audit exit {result.returncode}', flush=True)
    return int(failed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo-root', type=Path, default=ROOT)
    args, options = parser.parse_known_args()
    return audit(args.repo_root.resolve(), options)


if __name__ == '__main__':
    raise SystemExit(main())
