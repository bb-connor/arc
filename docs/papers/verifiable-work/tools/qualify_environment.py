"""Record the local toolchain and require the existing locked Python checker."""
import json
import os
from pathlib import Path
import platform
import re
import subprocess

ROOT = Path(__file__).resolve().parents[4]
python = os.environ['CHIO_FUNDED_PYTHON']
lock = ROOT/'examples/federated-work/python_buyer/requirements.txt'
expected = dict(re.findall(r'^([A-Za-z0-9_-]+)==([^\s]+)', lock.read_text(), re.M))
probe = 'import importlib.metadata as m,json; print(json.dumps({p:m.version(p) for p in '+repr(list(expected))+'}))'
installed = json.loads(subprocess.check_output([python, '-I', '-c', probe], text=True))
if installed != expected:
    raise SystemExit('Python checker packages differ from the pinned requirements')
subprocess.run([python, '-I', '-B', str(ROOT/'examples/funded-work/native_checker.py')],
               input=(ROOT/'examples/federated-work/fixtures/openapi.json').read_bytes(),
               stdout=subprocess.DEVNULL, check=True)
versions = {name: subprocess.check_output([name, '--version'], text=True).strip()
            for name in ('rustc', 'cargo', 'node')}
versions['checkerPython'] = subprocess.check_output([python, '--version'], text=True).strip()
print(json.dumps(dict(platform=platform.platform(), packages=installed, versions=versions), indent=2))
