#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "pact-py release checks require python3 on PATH" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/pact-py-release.XXXXXX")"
builder_venv="${work_dir}/builder"
wheel_venv="${work_dir}/wheel-smoke"
sdist_venv="${work_dir}/sdist-smoke"
dist_dir="${work_dir}/dist"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

python3 - <<'PY'
from pathlib import Path
import tomllib

pyproject = tomllib.loads(Path("packages/sdk/pact-py/pyproject.toml").read_text())
declared_version = pyproject["project"]["version"]
declared_name = pyproject["project"]["name"]

version_ns = {}
exec(Path("packages/sdk/pact-py/src/pact/version.py").read_text(), version_ns)
module_version = version_ns["__version__"]

if declared_name != "pact-py":
    raise SystemExit(f"expected distribution name pact-py, found {declared_name}")
if declared_version != module_version:
    raise SystemExit(
        f"pyproject version {declared_version} does not match pact.version {module_version}"
    )
print(f"pact-py metadata version {declared_version} verified")
PY

python3 -m venv "${builder_venv}"
. "${builder_venv}/bin/activate"
python -m pip install --quiet --upgrade pip build twine
python -m build packages/sdk/pact-py --sdist --wheel --outdir "${dist_dir}"
python -m twine check "${dist_dir}"/*
python - "${dist_dir}" <<'PY'
from pathlib import Path
import sys
import tarfile
import zipfile

dist_dir = Path(sys.argv[1])
wheel = next(dist_dir.glob("pact_py-*.whl"))
sdist = next(dist_dir.glob("pact_py-*.tar.gz"))

with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    if not any(name.endswith("pact/py.typed") for name in names):
        raise SystemExit("wheel is missing pact/py.typed")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("wheel contains forbidden Python cache artifacts")

with tarfile.open(sdist, "r:gz") as archive:
    names = archive.getnames()
    if not any(name.endswith("src/pact/py.typed") for name in names):
        raise SystemExit("sdist is missing src/pact/py.typed")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("sdist contains forbidden Python cache artifacts")
    if any("/src/pact.egg-info/" in name or name.endswith("/src/pact.egg-info") for name in names):
        raise SystemExit("sdist contains stale src/pact.egg-info metadata")

print(f"validated wheel {wheel.name} and sdist {sdist.name}")
PY
deactivate

python3 -m venv "${wheel_venv}"
. "${wheel_venv}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "${dist_dir}"/pact_py-*.whl
python - <<'PY'
import importlib.metadata
import pact

assert importlib.metadata.version("pact-py") == pact.__version__
assert pact.PactClient is not None
assert pact.PactSession is not None
print(f"wheel smoke verified pact-py {pact.__version__}")
PY
deactivate

python3 -m venv "${sdist_venv}"
. "${sdist_venv}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "${dist_dir}"/pact_py-*.tar.gz
python - <<'PY'
import importlib.metadata
import pact

assert importlib.metadata.version("pact-py") == pact.__version__
assert pact.PactClient is not None
assert pact.PactSession is not None
print(f"sdist smoke verified pact-py {pact.__version__}")
PY
