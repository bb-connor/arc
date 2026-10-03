"""Current evidence must represent completed checks on the current inputs."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from provenance import COMMANDS, EVIDENCE, native_sources, verify_qualification


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root/'Cargo.toml').write_text('[workspace]\n')
        (self.root/EVIDENCE).mkdir(parents=True)
        self.record = dict(schema='chio.dynamic-delegation.qualification.v1',
                           source_files=native_sources(self.root), commands={}, outputs={})
        for name, command in COMMANDS.items():
            result = dict(command=command, exit_code=0)
            for stream in ('stdout', 'stderr'):
                path = str(EVIDENCE/f'qualified-{name}.{stream}')
                result[stream] = path
                self.write(path, '')
            self.record['commands'][name] = result
        self.recovery = dict(cut='ToolReturnRecorded', signal=9,
                             blind_replacement_rejected=True,
                             sibling_completed_before_recovery=True,
                             recovery_dispatches=0, original_request='original-uncertain',
                             recovered_receipt={'signature':'fixture'},
                             sibling_receipt={'signature':'fixture'})
        self.write(str(EVIDENCE/'qualified-native-recovery.json'), json.dumps(self.recovery))

    def write(self, name, contents):
        data = contents.encode()
        (self.root/name).write_bytes(data)
        self.record['outputs'][name] = hashlib.sha256(data).hexdigest()

    def test_complete_record_then_source_or_output_drift(self):
        self.assertEqual(verify_qualification(self.root, self.record), [])
        (self.root/'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
        self.assertIn('dynamic native source inventory drift', verify_qualification(self.root, self.record))
        (self.root/'Cargo.toml').write_text('[workspace]\n')
        path = self.record['commands']['example']['stdout']
        (self.root/path).write_text('substituted')
        self.assertTrue(any('evidence mismatch' in e for e in verify_qualification(self.root, self.record)))

    def test_native_inventory_binds_directory_links_and_their_targets(self):
        (self.root/'spec/fixtures').mkdir(parents=True)
        (self.root/'spec/fixtures/data').write_text('first')
        (self.root/'crates').mkdir()
        link = self.root/'crates/fixtures'
        link.symlink_to('../spec/fixtures')
        first = native_sources(self.root)
        self.assertIn('crates/fixtures', first)
        (self.root/'spec/fixtures/data').write_text('second')
        self.assertNotEqual(native_sources(self.root), first)
        link.unlink()
        link.symlink_to('/tmp')
        with self.assertRaises(ValueError):
            native_sources(self.root)

    def test_failed_incomplete_or_missing_commands_are_not_qualification(self):
        for mutation in ('failed', 'missing', 'unfinished', 'wrong-command'):
            record = copy.deepcopy(self.record)
            if mutation == 'missing':
                del record['commands']['native-tests']
            elif mutation == 'failed':
                record['commands']['native-tests']['exit_code'] = 101
            elif mutation == 'unfinished':
                del record['commands']['native-tests']['exit_code']
            else:
                record['commands']['native-tests']['command'] = ['true']
            with self.subTest(mutation=mutation):
                self.assertTrue(verify_qualification(self.root, record))

    def test_missing_or_wrong_recovery_cannot_be_promoted_by_exit_zero(self):
        path = str(EVIDENCE/'qualified-native-recovery.json')
        for field, value in [('signal', 0), ('cut', 'AdmissionCommitted'),
                             ('recovery_dispatches', 1), ('blind_replacement_rejected', False),
                             ('sibling_completed_before_recovery', False), ('recovered_receipt', {})]:
            body = dict(self.recovery, **{field:value})
            self.write(path, json.dumps(body))
            with self.subTest(field=field):
                self.assertTrue(verify_qualification(self.root, self.record))
        del self.record['outputs'][path]
        self.assertTrue(verify_qualification(self.root, self.record))


if __name__ == '__main__':
    unittest.main()
