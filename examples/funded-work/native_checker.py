"""Bounded independent W0 check for the native funded example. No signing keys."""
import importlib.util
from pathlib import Path
import sys

path = Path(__file__).resolve().with_name('reference_checker.py')
spec = importlib.util.spec_from_file_location('_native_w0_reference', path)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)
source = sys.stdin.buffer.read(65537)
if len(source) > 65536:
    raise ValueError('native W0 input exceeds profile')
result = reference.protocol.canonical(reference.review.observations(source.decode('utf-8')))
if len(result) > 65536:
    raise ValueError('native W0 output exceeds profile')
sys.stdout.buffer.write(result)
