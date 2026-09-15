"""Independent parser regressions; signatures below are shape fixtures only."""
import copy
import json
from pathlib import Path
import unittest

import rfc8785
import funded_wire as wire


class WireTests(unittest.TestCase):
    def setUp(self):
        self.value = {'body': {
            'schema': 'chio.experimental.native-funded-dependency.v1',
            **{key: 'a' * 64 for key in ['parentAgreement', 'childAgreement', 'parentRequest', 'childRequest', 'inputSha256']},
            'parentAuthority': 'parent', 'childAuthority': 'child'}, 'signature': 'b' * 128}
        self.raw = rfc8785.dumps(self.value)

    def test_valid_dependency_never_claims_authority(self):
        self.assertIs(wire.parse(self.raw)['authorityVerified'], False)

    def test_raw_malformed_variants(self):
        for raw in [self.raw + b'\n', b' ' + self.raw,
                    self.raw.replace(b'"body":', b'"body":{},"body":', 1),
                    self.raw.replace(b'"body":', b'"bo\\u0064y":{},"body":', 1),
                    self.raw.replace(b'"parent"', b'1.0'),
                    self.raw.replace(b'"parent"', b'1e0'),
                    self.raw.replace(b'"parent"', b'NaN'),
                    self.raw.replace(b'"parent"', b'9007199254740992'),
                    self.raw.replace(b'"parent"', b'-1'),
                    self.raw.replace(b'"parent"', b'null'),
                    b' ' * (wire.MAX_BYTES + 1)]:
            with self.subTest(raw=raw[:80]), self.assertRaises((ValueError, UnicodeError)):
                wire.parse(raw)

    def test_shape_and_semantic_rejections(self):
        for key, value in [('parentAuthority', 'child'), ('parentAuthority', 'x' * 513),
                           ('parentAuthority', '\u00e9' * 257), ('parentAuthority', 'has space'),
                           ('parentAuthority', 'x\x00'), ('schema', 'unknown'),
                           ('inputSha256', 'A' * 64), ('inputSha256', 'a' * 63),
                           ('inputSha256', True)]:
            changed = copy.deepcopy(self.value)
            changed['body'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                wire.parse(rfc8785.dumps(changed))
        changed = copy.deepcopy(self.value)
        changed['body']['extra'] = 'unknown'
        with self.assertRaises(ValueError):
            wire.parse(rfc8785.dumps(changed))

    def test_offline_interpreter_rejects_unknown_instructions_and_refs(self):
        shapes = wire.Shapes()
        for schema in [{'unknownKeyword': True}, {'$ref': 'https://attacker.invalid/schema'}]:
            with self.assertRaises(RuntimeError):
                shapes.check({}, schema, 'https://chio.world/')

    def test_ed25519_key_validation(self):
        wire.ed25519_key('5866666666666666666666666666666666666666666666666666666666666666', weak=True)
        for value in ['00' * 32, '01' + '00' * 31]:
            with self.assertRaises(ValueError):
                wire.ed25519_key(value, weak=True)

    def test_shared_vectors_when_published(self):
        manifest = Path(__file__).parent / 'fixtures/registered-work/manifest.json'
        if not manifest.exists():
            self.skipTest('root integration has not published shared vectors yet')
        result = wire.vectors(manifest)
        self.assertTrue(result['passed'])
        self.assertGreaterEqual(result['cases'], 4)


if __name__ == '__main__':
    unittest.main()
