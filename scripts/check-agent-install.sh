#!/usr/bin/env bash
set -euo pipefail
umask 022

usage() {
  cat <<'HELP'
Usage: scripts/check-agent-install.sh --output NEW_DIRECTORY [--debug]

Install Chio and its Python wheels into a fresh directory outside the checkout,
then exercise MCP adoption, restart persistence, and LangChain tool execution.
Requires Rust, Git, uv, Python 3.11+, and the CLI's native build dependencies.
The output retains the installed CLI, wheels, examples, and local evidence.
This is an installation acceptance check, not release qualification.
HELP
}

die() { printf '%s\n' "$*" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output=''
profile=release
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      [[ $# -ge 2 && -n "$2" && "$2" != -* ]] || die '--output requires a new directory'
      output="$2"
      shift 2
      ;;
    --debug) profile=dev; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done
[[ -n "$output" ]] || die '--output is required; use --help for usage'
for tool in cargo git uv python3; do
  command -v "$tool" >/dev/null || die "Required tool missing: $tool"
done
output="$(python3 - "$output" "$repo_root" <<'PY'
import sys
from pathlib import Path
requested = Path(sys.argv[1])
if requested.exists() or requested.is_symlink():
    sys.exit('Output already exists. Choose a new directory.')
destination = requested.resolve()
if destination.is_relative_to(Path(sys.argv[2]).resolve()):
    sys.exit('Output must be outside the source checkout.')
print(destination)
PY
)"
# mkdir without -p refuses an existing output, including a symlink.
mkdir -m 700 "$output"
cd "$repo_root"
source_revision="$(git rev-parse HEAD)"
rustc_version="$(rustc --version --verbose)"
source_dirty=false
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then source_dirty=true; fi
unset PYTHONPATH PYTHONHOME PYTHONOPTIMIZE
export PYTHONNOUSERSITE=1

install_args=(--root "$output/install")
if [[ "$profile" = dev ]]; then install_args+=(--debug); fi
"$repo_root/scripts/install-chio.sh" "${install_args[@]}"
for package in chio-py chio-sdk-python chio-adapter-base chio-langchain; do
  uv build --wheel --out-dir "$output/wheels" "$repo_root/sdks/python/$package"
done
# Export only third-party dependencies. All four Chio distributions below are
# installed from the wheels just built, never substituted from a package index.
uv export --locked --project "$repo_root/sdks/python/chio-langchain" --extra mcp \
  --no-dev --no-emit-local --no-header --no-annotate \
  --output-file "$output/requirements.txt" >/dev/null
uv venv --python "${CHIO_INSTALL_PYTHON:-python3}" "$output/venv"
python="$output/venv/bin/python"
uv pip install --python "$python" --require-hashes -r "$output/requirements.txt"
uv pip install --python "$python" --no-deps "$output"/wheels/*.whl
uv pip check --python "$python"

mkdir "$output/examples"
for example in mcp-adoption langchain-kernel; do
  mkdir "$output/examples/$example"
  cp "$repo_root/examples/$example/"*.py "$repo_root/examples/$example/policy.yaml" \
    "$output/examples/$example/"
done
cp "$repo_root/LICENSE" "$repo_root/NOTICE" "$output/"
cd "$output"
record_artifact_hashes() {
  "$python" -I - <<'PY'
import hashlib
import json
from pathlib import Path

artifacts = [
    Path('install/bin/chio'), Path('requirements.txt'), Path('LICENSE'), Path('NOTICE'),
    *sorted(Path('wheels').glob('*.whl')),
    *sorted(Path('examples').glob('*/*.py')),
    *sorted(Path('examples').glob('*/policy.yaml')),
]
checksums = {}
for artifact in artifacts:
    with artifact.open('rb') as stream:
        checksums[str(artifact)] = hashlib.file_digest(stream, 'sha256').hexdigest()
print(json.dumps(checksums, sort_keys=True))
PY
}
record_artifact_hashes > artifact-hashes.before.json
"$python" -I examples/mcp-adoption/check.py \
  --chio "$output/install/bin/chio" --state-dir "$output/mcp-state"
"$python" -I examples/langchain-kernel/run.py \
  --chio "$output/install/bin/chio" --state-dir "$output/langchain-state"
record_artifact_hashes > artifact-hashes.after.json
cmp -s artifact-hashes.before.json artifact-hashes.after.json \
  || die 'Installed artifacts changed during acceptance; no acceptance report was produced.'
[[ "$(git -C "$repo_root" rev-parse HEAD)" = "$source_revision" ]] \
  || die 'The source revision changed during installation; rerun from a stable checkout.'
if [[ "$source_dirty" = false && -n "$(git -C "$repo_root" status --porcelain --untracked-files=normal)" ]]; then
  die 'The clean source checkout changed during installation; rerun from a stable checkout.'
fi
uv pip freeze --python "$python" > installed-packages.txt
"$python" -I - "$source_revision" "$source_dirty" "$profile" "$rustc_version" <<'PY'
import importlib.metadata
import json
import sys
from pathlib import Path

checksums = json.loads(Path('artifact-hashes.before.json').read_text())
packages = {}
for name in ('chio-sdk', 'chio-sdk-python', 'chio-adapter-base', 'chio-langchain'):
    distribution = importlib.metadata.distribution(name)
    direct = json.loads(distribution.read_text('direct_url.json') or '{}')
    if direct.get('dir_info', {}).get('editable') or not direct.get('url', '').endswith('.whl'):
        raise RuntimeError(f'{name} was not installed from a wheel')
    packages[name] = distribution.version
adoption = json.loads(Path('mcp-state/evidence.json').read_text())
langchain = json.loads(Path('langchain-state/evidence.json').read_text())
if adoption.get('activation', {}).get('operation') != 'activate' or adoption.get('restoration', {}).get('operation') != 'restore':
    raise RuntimeError('MCP acceptance must include activation and restoration')
report = {
    'kind': 'chio.local-installation-acceptance.v1',
    'source_revision': sys.argv[1],
    'source_dirty': sys.argv[2] == 'true',
    'build_profile': sys.argv[3],
    'release_qualified': False,
    'activation_restore_verified': True,
    'rustc': sys.argv[4],
    'python': sys.version,
    'packages': packages,
    'sha256': checksums,
    'mcp_adoption': {'effects': len(adoption['effects']), 'verified_receipts': len(adoption['receipts'])},
    'langchain': {'effects': len(langchain['effects']), 'verified_receipts': len(langchain['receipts'])},
}
Path('acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
PY
printf '\nInstallation acceptance passed. Evidence: %s/acceptance.json\n' "$output"
