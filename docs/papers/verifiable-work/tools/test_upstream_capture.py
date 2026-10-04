import copy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from upstream_capture import verify_capture


class CaptureTests(unittest.TestCase):
    def test_retained_capture_keeps_upstream_pin(self):
        paper = Path(__file__).resolve().parents[1]
        root = paper / 'evidence/erc8183'
        spec = json.loads((root / 'provenance/spec.json').read_text())
        sources = json.loads((paper / 'sources.json').read_text())['sources']
        source = next(item for item in sources if item['id'] == 'erc8183')
        self.assertEqual(verify_capture(root, spec, source), [])

    def test_capture_rejects_substitution_truncation_expansion_and_bad_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b'original upstream bytes'
            source = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), url='source', version='commit')
            spec = dict(sha256=source['sha256'], source_url='source', git_commit='commit',
                        capture=dict(path='capture.gz', compression='gzip', uncompressed_bytes=len(raw)))
            path = root / 'capture.gz'
            for encoded in (b'not gzip', gzip.compress(raw)[:-2], gzip.compress(b'x' * len(raw)),
                            gzip.compress(raw * 10000), gzip.compress(raw) + gzip.compress(b'extra')):
                path.write_bytes(encoded)
                self.assertTrue(verify_capture(root, spec, source))
            path.write_bytes(gzip.compress(raw))
            self.assertEqual(verify_capture(root, spec, source), [])
            outside = copy.deepcopy(spec)
            outside['capture']['path'] = '../capture.gz'
            self.assertTrue(verify_capture(root, outside, source))
            substituted = dict(spec, sha256='0' * 64)
            self.assertTrue(verify_capture(root, substituted, source))
            path.unlink()
            self.assertTrue(verify_capture(root, spec, source))


if __name__ == '__main__':
    unittest.main()
