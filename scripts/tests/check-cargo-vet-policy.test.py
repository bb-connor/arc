#!/usr/bin/env python3
"""Policy requirements must not bypass the exemption growth gate."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / 'scripts/check-cargo-vet-exemptions.py'


class PolicyGateTests(unittest.TestCase):
    def gate(self, base, head, audits=''):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'base.toml').write_text(base)
            (root / 'head.toml').write_text(head)
            (root / 'audits.toml').write_text(audits)
            return subprocess.run(['python3', str(CHECK), '--base', str(root / 'base.toml'),
                                   '--head', str(root / 'head.toml')], capture_output=True, text=True)

    def test_weakened_policy_requirements_are_rejected(self):
        for head in [
            '[policy.example]\ncriteria = "safe-to-run"\n',
            '[policy.example]\ncriteria = []\n',
            '[policy.example]\ncriteria = "review-only"\n',
            '[policy.example]\ndev-criteria = []\n',
            '[policy.example.dependency-criteria]\nserde = "safe-to-run"\n',
        ]:
            with self.subTest(head=head):
                result = self.gate('', head, '[criteria.review-only]\ndescription="No deployment audit"\n')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('weakened cargo-vet policy', result.stderr)

    def test_stronger_standard_and_custom_criteria_pass(self):
        for criteria in ['safe-to-deploy', 'reviewed-and-deployable']:
            result = self.gate('', f'[policy.example]\ncriteria="{criteria}"\n',
                               '[criteria.reviewed-and-deployable]\nimplies=["safe-to-deploy"]\n')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_reviewed_aws_lc_composite_is_the_only_non_implying_exception(self):
        policy = (ROOT / 'supply-chain/config.toml').read_text().split('[policy.aws-lc-rs]', 1)[1].split('[policy.chio-a2a-adapter]', 1)[0]
        policy = '[policy.aws-lc-rs]' + policy
        self.assertEqual(self.gate('', policy).returncode, 0)
        for changed in [policy.replace('aws-lc-upstream-reviewed', 'anything-reviewed'),
                        policy.replace('aws-lc-sys = "safe-to-deploy"', 'aws-lc-sys = []'),
                        policy.replace('[policy.aws-lc-rs]', '[policy.unrelated]')]:
            self.assertEqual(self.gate('', changed).returncode, 1)

    def test_removing_an_implication_is_a_policy_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'config.toml').write_text('[policy.example]\ncriteria="custom"\n')
            (root / 'before.toml').write_text('[criteria.custom]\nimplies=["safe-to-deploy"]\n')
            (root / 'after.toml').write_text('[criteria.custom]\nimplies=[]\n')
            result = subprocess.run(['python3', str(CHECK), '--base', str(root / 'config.toml'),
                                     '--head', str(root / 'config.toml'), '--base-audits', str(root / 'before.toml'),
                                     '--head-audits', str(root / 'after.toml'), '--policy-only'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn('weakened cargo-vet policy', result.stderr)


if __name__ == '__main__':
    unittest.main()
