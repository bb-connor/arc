"""Test-side calibration: load an isolated modified verifier, never edit repo code."""
from pathlib import Path
import sys
import types
import unittest

root = Path.cwd()
sys.path.insert(0, str(root / 'examples/funded-work'))
source = (root / 'examples/funded-work/verifier.py').read_text()
before = 'accepted = p.canonical(p.verify_output(output)) == p.canonical(expected)'
assert source.count(before) == 1
changed = source.replace(before, 'accepted = True')
module = types.ModuleType('verifier')
exec(compile(changed, '<checker-bypass-negative-control>', 'exec'), module.__dict__)
sys.modules['verifier'] = module
from test_verifier import VerifierTests
result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite([
    VerifierTests('test_false_authentication_observation_is_signed_rejection')]))
sys.exit(0 if result.wasSuccessful() else 1)
