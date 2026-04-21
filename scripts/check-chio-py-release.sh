#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v python3 >/dev/null 2>&1; then
  echo "chio-sdk release checks require python3 on PATH" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-sdk-release.XXXXXX")"
builder_venv="${work_dir}/builder"
wheel_venv="${work_dir}/wheel-smoke"
sdist_venv="${work_dir}/sdist-smoke"
dist_dir="${work_dir}/dist"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

rm -rf packages/sdk/chio-py/build packages/sdk/chio-py/dist
find packages/sdk/chio-py/src -maxdepth 1 -type d -name '*.egg-info' -prune -exec rm -rf {} +
find packages/sdk/chio-py -type d -name '__pycache__' -prune -exec rm -rf {} +

python3 - <<'PY'
from pathlib import Path
import tomllib

pyproject = tomllib.loads(Path("packages/sdk/chio-py/pyproject.toml").read_text())
declared_version = pyproject["project"]["version"]
declared_name = pyproject["project"]["name"]

version_ns = {}
exec(Path("packages/sdk/chio-py/src/arc/version.py").read_text(), version_ns)
module_version = version_ns["__version__"]

if declared_name != "chio-sdk":
    raise SystemExit(f"expected distribution name chio-sdk, found {declared_name}")
if declared_version != module_version:
    raise SystemExit(
        f"pyproject version {declared_version} does not match arc.version {module_version}"
    )
print(f"chio-sdk metadata version {declared_version} verified")
PY

python3 -m venv "${builder_venv}"
. "${builder_venv}/bin/activate"
python -m pip install --quiet --upgrade pip build twine
python -m build packages/sdk/chio-py --sdist --wheel --outdir "${dist_dir}"
python -m twine check "${dist_dir}"/*
python - "${dist_dir}" <<'PY'
from pathlib import Path
import sys
import tarfile
import zipfile

dist_dir = Path(sys.argv[1])
wheel = next(dist_dir.glob("chio_sdk-*.whl"))
sdist = next(dist_dir.glob("chio_sdk-*.tar.gz"))

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
    if any("/src/chio_py.egg-info/" in name or name.endswith("/src/chio_py.egg-info") for name in names):
        raise SystemExit("sdist contains stale src/chio_py.egg-info metadata")

print(f"validated wheel {wheel.name} and sdist {sdist.name}")
PY
deactivate

python3 -m venv "${wheel_venv}"
. "${wheel_venv}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "${dist_dir}"/chio_sdk-*.whl
python - <<'PY'
import importlib.metadata
import arc

assert importlib.metadata.version("chio-sdk") == arc.__version__
assert arc.ChioClient is not None
assert arc.ChioSession is not None
assert arc.ReceiptQueryClient is not None
print(f"wheel smoke verified chio-sdk {arc.__version__}")
PY
deactivate

python3 -m venv "${sdist_venv}"
. "${sdist_venv}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "${dist_dir}"/chio_sdk-*.tar.gz
python - <<'PY'
import importlib.metadata
import arc

assert importlib.metadata.version("chio-sdk") == arc.__version__
assert arc.ChioClient is not None
assert arc.ChioSession is not None
assert arc.ReceiptQueryClient is not None
print(f"sdist smoke verified chio-sdk {arc.__version__}")
PY
