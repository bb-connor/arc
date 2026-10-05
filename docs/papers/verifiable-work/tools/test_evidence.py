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
        self.assertTrue(check.verify_publication(release),
                        'status edits alone cannot establish publication evidence')
        release['gates'].append(dict(release['gates'][0]))
        self.assertIn('duplicate publication gate: manuscript', check.verify_publication(release))

    def test_publication_cannot_freeze_its_own_authority(self):
        for writer in ('--freeze', '--refresh'):
            script = ('import check,sys; from unittest.mock import patch; '
                      f'sys.argv=["check.py","{writer}","--publication"]; '
                      'p=patch("check.derived",side_effect=AssertionError("unsafe CLI accepted")); '
                      'p.start(); check.main()')
            result = subprocess.run(['python3', '-c', script],
                                    cwd=Path(check.__file__).parent, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn('not allowed with argument', result.stderr)

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

class PublicationEvidenceTests(unittest.TestCase):
    def test_frozen_named_evidence_and_claims_are_required(self):
        import copy
        import hashlib
        import json
        from publication import CLAIM_REQUIREMENTS, REQUIRED_GATES, verify
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'result.json').write_text('{"verified":true}')
            claim_statuses = {}
            for requirements in CLAIM_REQUIREMENTS.values():
                for name, status in requirements.items():
                    claim_statuses.setdefault(name, set()).add(status)
            claims = {'claims': [dict(claim_id=name, status=sorted(statuses),
                                     evidence_paths=['result.json'])
                                  for name, statuses in claim_statuses.items()]}
            release = dict(publish_ready=True, breakthrough_established=True,
                           gates=[dict(id=name, status='passed', acceptance='criterion',
                                       result='observed', evidence='result.json')
                                  for name in sorted(REQUIRED_GATES)])
            (root / 'PUBLICATION.json').write_text(json.dumps(release))
            (root / 'CLAIMS.json').write_text(json.dumps(claims))
            manifest = {'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in root.iterdir()}}
            def check(r=release, c=claims, m=manifest):
                return verify(r, c, m, root=root, paper=root)
            self.assertEqual(check(), [])
            for name in ('result.json', 'PUBLICATION.json', 'CLAIMS.json'):
                missing = copy.deepcopy(manifest)
                del missing['files'][name]
                self.assertTrue(check(m=missing), name)
            unsupported = copy.deepcopy(claims)
            unsupported['claims'][0]['status'] = ['hypothesis']
            self.assertTrue(check(c=unsupported))
            absent = copy.deepcopy(release)
            absent['gates'][0].pop('evidence')
            self.assertTrue(check(r=absent))
            absent['gates'][0]['evidence'] = '../outside'
            self.assertTrue(check(r=absent))
            (root / 'result.json').write_text('{"verified":false}')
            self.assertTrue(check())
            (root / 'result.json').unlink()
            self.assertTrue(check())


if __name__ == '__main__':
    unittest.main()
