#!/usr/bin/env python3
"""Registry and alternate-path substitutions cannot escape source qualification."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
SPEC = importlib.util.spec_from_file_location('research_gate', ROOT / 'scripts/check-research-workspaces.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class SourcePolicyTests(unittest.TestCase):
    def test_patched_packages_require_the_exact_source(self):
        patches = {'aws-lc-rs': {'path': 'third_party/aws-lc-rs-chio'}}
        package = dict(name='aws-lc-rs', source=None,
                       manifest_path=str(ROOT / 'third_party/aws-lc-rs-chio/Cargo.toml'))
        CHECK.verify_sources({'packages': [package]}, patches, ROOT)
        for change in [dict(source='registry+https://github.com/rust-lang/crates.io-index'),
                       dict(manifest_path=str(ROOT / 'unreviewed/Cargo.toml'))]:
            changed = copy.deepcopy(package)
            changed.update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                CHECK.verify_sources({'packages': [changed]}, patches, ROOT)


if __name__ == '__main__':
    unittest.main()
