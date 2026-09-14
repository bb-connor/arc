"""Load the selected reference sources without searching for local module names.

This is a trusted-host loader, not isolation from a malicious Python interpreter.
Only the reference checker's observations function is used by funded W0.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

BUYER = Path(__file__).resolve().parents[1] / 'federated-work/python_buyer'
PROFILE = json.loads((Path(__file__).parent / 'checker-profile.json').read_bytes())
SOURCE_HASHES = {}


def _load(name, pin=None):
    path = BUYER / (name + '.py')
    source = path.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if pin is not None and digest != pin:
        raise ImportError(name + ' differs from the pinned reference source')
    spec = importlib.util.spec_from_file_location('_funded_w0_' + name, path)
    module = importlib.util.module_from_spec(spec)
    # Execute the bytes just hashed, avoiding a separate loader/bytecode read.
    exec(compile(source, str(path), 'exec'), module.__dict__)
    SOURCE_HASHES[name] = digest
    return module


protocol = _load('protocol', PROFILE['pythonProtocolSha256'])
_missing = object()
_previous = {name: sys.modules.get(name, _missing) for name in ('protocol', 'subcontract')}
try:
    # The reference sources use absolute imports. Scope those names to the exact
    # selected dependencies during initialization, then restore the host state.
    sys.modules['protocol'] = protocol
    sys.modules['subcontract'] = _load('subcontract')
    review = _load('review', PROFILE['pythonSourceSha256'])
finally:
    for _name, _module in _previous.items():
        if _module is _missing:
            sys.modules.pop(_name, None)
        else:
            sys.modules[_name] = _module
