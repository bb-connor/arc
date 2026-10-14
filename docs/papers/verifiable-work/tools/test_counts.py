import hashlib
from pathlib import Path
import tempfile
import unittest

from counts import native_counts


class CountTests(unittest.TestCase):
    def test_counts_come_from_terminal_authenticated_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'native.stdout'
            output.write_text('test result: ok. 3 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out;\n'
                              'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n')
            record = dict(source_files={'a': 'hash', 'b': 'hash'}, commands={
                'native-tests': dict(exit_code=0, stdout='native.stdout')},
                outputs={'native.stdout': hashlib.sha256(output.read_bytes()).hexdigest()})
            self.assertEqual(native_counts(root, record, {'NativeTests': 'native-tests'}),
                             {'NativeCommands': 1, 'NativeSources': 2, 'NativeOutputs': 1,
                              'NativeTests': 7, 'NativeTestsIgnored': 2})
            record['commands']['native-tests']['exit_code'] = 1
            with self.assertRaisesRegex(ValueError, 'nonterminal or failed'):
                native_counts(root, record, {'NativeTests': 'native-tests'})
            record['commands']['native-tests']['exit_code'] = 0
            output.write_text('test result: ok. 100 passed; 0 failed; 0 ignored;\n')
            with self.assertRaisesRegex(ValueError, 'hash'):
                native_counts(root, record, {'NativeTests': 'native-tests'})
            record['outputs']['native.stdout'] = hashlib.sha256(output.read_bytes()).hexdigest()
            self.assertEqual(native_counts(root, record, {'NativeTests': 'native-tests'})['NativeTests'], 100)
            output.write_text('running 100 tests\n')
            record['outputs']['native.stdout'] = hashlib.sha256(output.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, 'terminal test summary'):
                native_counts(root, record, {'NativeTests': 'native-tests'})
