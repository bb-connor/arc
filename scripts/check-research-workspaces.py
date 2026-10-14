#!/usr/bin/env python3
"""Qualify research graphs against production source policy and locked audits."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tomllib

from research_workspaces import ROOT, WORKSPACES


def verify_sources(metadata: dict, patches: dict, root: Path) -> None:
    for package in metadata['packages']:
        patch = patches.get(package['name'])
        if patch is None:
            continue
        expected = (root / patch['path'] / 'Cargo.toml').resolve()
        if package['source'] is not None or Path(package['manifest_path']).resolve() != expected:
            raise ValueError(f'{package["name"]} resolves outside the production source policy')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', choices=WORKSPACES)
    parser.add_argument('--vet', action='store_true')
    args = parser.parse_args()
    patches = tomllib.loads((ROOT / 'Cargo.toml').read_text())['patch']['crates-io']
    for workspace in [args.workspace] if args.workspace else WORKSPACES:
        manifest = ROOT / workspace / 'Cargo.toml'
        result = subprocess.run(['cargo', 'metadata', '--locked', '--all-features',
                                 '--format-version', '1', '--manifest-path', str(manifest)],
                                check=True, capture_output=True)
        metadata = json.loads(result.stdout)
        verify_sources(metadata, patches, ROOT)
        if args.vet:
            subprocess.run(['cargo', 'vet', '--locked', '--no-minimize-exemptions',
                            '--manifest-path', str(manifest), '--store-path', str(ROOT / 'supply-chain')],
                           check=True, cwd=ROOT)
        print(f'OK {workspace}: {len(metadata["packages"])} locked packages, production source policy', flush=True)


if __name__ == '__main__':
    main()
