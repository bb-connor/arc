#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

nightly=".github/workflows/nightly.yml"
for required in \
  'unset CHIO_RUST_VERIFICATION_METADATA_ONLY' \
  './scripts/check-proof-report.sh --require-strict' \
  'if [[ "${mode}" != "strict" ]]; then'
do
  if ! grep -Fq "${required}" "${nightly}"; then
    echo "nightly formal qualification lacks strict-mode control: ${required}" >&2
    exit 1
  fi
done
if grep -Fq '"${mode}" != "strict" &&' "${nightly}"; then
  echo "nightly formal qualification still accepts a non-strict proof mode" >&2
  exit 1
fi

python3 - <<'PY'
import fnmatch
import os
import re
import subprocess
import tempfile
import textwrap
from pathlib import Path

import tomllib

workflow = Path(".github/workflows/formal-pr-smoke.yml").read_text(encoding="utf-8")
lake_cache_lines = [
    line for line in workflow.splitlines() if "runner.os }}-lake-" in line
]
if len(lake_cache_lines) != 2:
    raise SystemExit(
        "formal PR workflow must define one Lean cache key and restore key"
    )
if any("formal/lean4/Chio/lakefile.lean" not in line for line in lake_cache_lines):
    raise SystemExit("formal PR Lean cache does not hash lakefile.lean")
if any("formal/lean4/Chio/lakefile.toml" in line for line in lake_cache_lines):
    raise SystemExit("formal PR Lean cache still hashes nonexistent lakefile.toml")
metadata_lines = [
    line for line in workflow.splitlines() if "set_output metadata" in line
]
if len(metadata_lines) != 1 or r"\.kani/harnesses\.toml$" not in metadata_lines[0]:
    raise SystemExit(
        "multi-crate Kani manifest changes do not trigger metadata validation"
    )
job_start = workflow.index("  kani-public-pr:")
job_end = workflow.index("\n  kani-manifest-pr:", job_start)
job = workflow[job_start:job_end]
if "timeout-minutes: 120" not in job:
    raise SystemExit("public Kani PR job does not retain its 120-minute budget")
if workflow.count("if ! bash scripts/check-kani-version.sh >/dev/null 2>&1; then") != 2:
    raise SystemExit("formal PR Kani jobs do not repair incomplete tool caches")
if workflow.count("cargo kani setup") != 2:
    raise SystemExit("formal PR Kani jobs do not ensure the verifier is installed")
if workflow.count("python3 scripts/kani-toolchain.py install") != 2:
    raise SystemExit("formal PR Kani jobs do not qualify the pinned compiler repair")

# Exercise the actual classifier with every enrolled PR crate, instead of
# maintaining another list that can drift when a proof is added.
paths = re.search(
    r"  pull_request:\n    paths:\n(.*?)  workflow_dispatch:", workflow, re.S
)
classifier = re.search(
    r"^          set_output\(\) \{.*?^          set_output fuzz_smoke[^\n]*",
    workflow,
    re.S | re.M,
)
if paths is None or classifier is None:
    raise SystemExit("formal PR trigger or executable classifier is absent")
triggers = re.findall(r'^      - "([^"]+)"$', paths[1], re.M)
manifest = tomllib.loads(Path(".kani/harnesses.toml").read_text())
packages = {}
for member in tomllib.loads(Path("Cargo.toml").read_text())["workspace"]["members"]:
    for directory in Path().glob(member):
        cargo = directory / "Cargo.toml"
        package = tomllib.loads(cargo.read_text()).get("package")
        if package:
            packages[package["name"]] = directory
with tempfile.TemporaryDirectory(prefix="formal-pr-paths-") as temporary:
    changed = Path(temporary) / "changed"
    output = Path(temporary) / "outputs"
    for crate in sorted({h["crate"] for h in manifest["harness"] if h["lane"] == "pr"}):
        lane = "kani_core" if crate == "chio-kernel-core" else "kani_manifest"
        for relative in ("Cargo.toml", "src/lib.rs"):
            source = (packages[crate] / relative).as_posix()
            if not any(fnmatch.fnmatchcase(source, pattern) for pattern in triggers):
                raise SystemExit(
                    f"registered PR proof crate cannot trigger workflow: {source}"
                )
            changed.write_text(source + "\n")
            output.write_text("")
            subprocess.run(
                ["bash", "-euo", "pipefail", "-c", textwrap.dedent(classifier[0])],
                env={
                    "PATH": os.environ["PATH"],
                    "changed": str(changed),
                    "GITHUB_OUTPUT": str(output),
                },
                check=True,
            )
            if f"{lane}=true" not in output.read_text().splitlines():
                raise SystemExit(
                    f"registered PR proof crate does not select {lane}: {source}"
                )

ci = Path(".github/workflows/ci.yml").read_text(encoding="utf-8")
for command in (
    "bash ./scripts/tests/check-rust-verification-gates.test.sh",
    "bash ./scripts/tests/formal-workflow-wiring.test.sh",
):
    if ci.count(command) != 1:
        raise SystemExit(f"required PR CI must execute exactly once: {command}")
PY

echo "Formal workflow wiring contract passed"
