"""Reject missing or substituted evidence instead of certifying stale results."""
import importlib.util
import tempfile
import unittest
import subprocess
from pathlib import Path

if importlib.util.find_spec('check'):
    from check import verify_files
    import check
else:
    verify_files = None


class EvidenceTests(unittest.TestCase):
    def test_historical_source_is_verified_at_its_retained_revision(self):
        self.assertTrue(hasattr(check, 'verify_revision_files'))
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root/'result').write_bytes(b'abc')
            subprocess.run(['git', '-C', d, 'add', 'result'], check=True)
            subprocess.run(['git', '-C', d, '-c', 'user.name=Evidence test',
                            '-c', 'user.email=evidence@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            revision = subprocess.check_output(['git', '-C', d, 'rev-parse', 'HEAD'], text=True).strip()
            hashes = {'result': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'}
            (root/'result').write_bytes(b'abd')
            self.assertEqual(check.verify_revision_files(root, revision, hashes), [])
            self.assertEqual(check.verify_files(root, hashes), ['hash mismatch: result'])
            self.assertTrue(check.verify_revision_files(root, revision, {'result':'0'*64}))
            self.assertTrue(check.verify_revision_files(root, revision, {'missing':'0'*64}))
            self.assertTrue(check.verify_revision_files(root, '--all', hashes))
            self.assertTrue(check.verify_revision_files(root, revision, {'../result':'0'*64}))

    def test_publication_cannot_drop_required_gates(self):
        self.assertTrue(hasattr(check, 'verify_publication'), 'publication validator missing')
        self.assertIn('missing publication gate: independent-operation',
                      check.verify_publication({'publish_ready': True,
                                                'breakthrough_established': True,
                                                'gates': []}))

    def test_publication_requires_results_and_explicit_readiness(self):
        self.assertTrue(hasattr(check, 'verify_publication'), 'publication validator missing')
        import json
        release = json.loads((Path(__file__).parents[1]/'PUBLICATION.json').read_text())
        errors = check.verify_publication(release)
        self.assertIn('publication gate open: independent-operation', errors)
        self.assertIn('publish_ready is not true', errors)
        for gate in release['gates']:
            gate['status'] = 'passed'
        release.update(publish_ready=True, breakthrough_established=True)
        self.assertEqual(check.verify_publication(release), [])
        release['gates'].append(dict(release['gates'][0]))
        self.assertIn('duplicate publication gate: manuscript', check.verify_publication(release))

    def test_changed_evidence_fails_closed(self):
        self.assertIsNotNone(verify_files, 'evidence verifier missing')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'result').write_bytes(b'abc')
            hashes = {'result': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'}
            self.assertEqual(verify_files(root, hashes), [])
            (root/'result').write_bytes(b'abd')
            self.assertEqual(verify_files(root, hashes), ['hash mismatch: result'])
            (root/'result').unlink()
            self.assertEqual(verify_files(root, hashes), ['missing: result'])

    def test_inventory_cannot_read_outside_artifact_root(self):
        self.assertIsNotNone(verify_files, 'evidence verifier missing')
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(verify_files(Path(d), {'../outside': 'a'*64}), ['outside root: ../outside'])

if __name__ == '__main__':
    unittest.main()
