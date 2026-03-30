#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "arc-py release checks require python3 on PATH" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/arc-py-release.XXXXXX")"
builder_venv="${work_dir}/builder"
wheel_venv="${work_dir}/wheel-smoke"
sdist_venv="${work_dir}/sdist-smoke"
dist_dir="${work_dir}/dist"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

rm -rf packages/sdk/arc-py/build packages/sdk/arc-py/dist
find packages/sdk/arc-py/src -maxdepth 1 -type d -name '*.egg-info' -prune -exec rm -rf {} +
find packages/sdk/arc-py -type d -name '__pycache__' -prune -exec rm -rf {} +

python3 - <<'PY'
from pathlib import Path
import tomllib

pyproject = tomllib.loads(Path("packages/sdk/arc-py/pyproject.toml").read_text())
declared_version = pyproject["project"]["version"]
declared_name = pyproject["project"]["name"]

version_ns = {}
exec(Path("packages/sdk/arc-py/src/arc/version.py").read_text(), version_ns)
module_version = version_ns["__version__"]

if declared_name != "arc-py":
    raise SystemExit(f"expected distribution name arc-py, found {declared_name}")
if declared_version != module_version:
    raise SystemExit(
        f"pyproject version {declared_version} does not match arc.version {module_version}"
    )
print(f"arc-py metadata version {declared_version} verified")
PY

python3 -m venv "${builder_venv}"
. "${builder_venv}/bin/activate"
python -m pip install --quiet --upgrade pip build twine
python -m build packages/sdk/arc-py --sdist --wheel --outdir "${dist_dir}"
python -m twine check "${dist_dir}"/*
python - "${dist_dir}" <<'PY'
from pathlib import Path
import sys
import tarfile
import zipfile

dist_dir = Path(sys.argv[1])
wheel = next(dist_dir.glob("arc_py-*.whl"))
sdist = next(dist_dir.glob("arc_py-*.tar.gz"))

with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()
    if not any(name.endswith("arc/py.typed") for name in names):
        raise SystemExit("wheel is missing arc/py.typed")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("wheel contains forbidden Python cache artifacts")

with tarfile.open(sdist, "r:gz") as archive:
    names = archive.getnames()
    if not any(name.endswith("src/arc/py.typed") for name in names):
        raise SystemExit("sdist is missing src/arc/py.typed")
    if any("__pycache__/" in name or name.endswith((".pyc", ".pyo")) for name in names):
        raise SystemExit("sdist contains forbidden Python cache artifacts")
    if any("/src/arc.egg-info/" in name or name.endswith("/src/arc.egg-info") for name in names):
        raise SystemExit("sdist contains stale src/arc.egg-info metadata")

print(f"validated wheel {wheel.name} and sdist {sdist.name}")
PY
deactivate

python3 -m venv "${wheel_venv}"
. "${wheel_venv}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "${dist_dir}"/arc_py-*.whl
python - <<'PY'
import importlib.metadata
import arc

assert importlib.metadata.version("arc-py") == arc.__version__
assert arc.ArcClient is not None
assert arc.ArcSession is not None
print(f"wheel smoke verified arc-py {arc.__version__}")
PY
deactivate

python3 -m venv "${sdist_venv}"
. "${sdist_venv}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "${dist_dir}"/arc_py-*.tar.gz
python - <<'PY'
import importlib.metadata
import arc

assert importlib.metadata.version("arc-py") == arc.__version__
assert arc.ArcClient is not None
assert arc.ArcSession is not None
print(f"sdist smoke verified arc-py {arc.__version__}")
PY
