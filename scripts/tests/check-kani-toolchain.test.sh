#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
work="$(mktemp -d "${TMPDIR:-/tmp}/chio-kani-toolchain.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat > "$work/bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == "kani --version --verbose" ]]; then
  printf '%s\n' "${KANI_FIXTURE}"
  exit "${KANI_FIXTURE_EXIT:-0}"
fi
printf '%s\n' "$*" >> "$KANI_PROOF_CALLS"
exit 0
SH
chmod +x "$work/bin/cargo"
export PATH="$work/bin:$PATH"
export KANI_PROOF_CALLS="$work/proof-calls"
export KANI_FIXTURE=$'Kani Rust Verifier 0.68.0 (kani-0.68.0) (cargo plugin)\nusing rustc 1.100.0-nightly (8925ea358 2026-08-20) (commit 8925ea35 2026-08-20) with LLVM 22.1.0\nCBMC 6.11.0'
valid="$KANI_FIXTURE"
bash scripts/check-kani-toolchain.sh > "$work/valid.log"
KANI_FIXTURE="${valid/ (kani-0.68.0)/}" bash scripts/check-kani-toolchain.sh > "$work/valid-without-revision.log"

refuse() {
  local name="$1"
  if bash scripts/check-kani-toolchain.sh > "$work/$name.log" 2>&1; then
    echo "Kani toolchain accepted $name" >&2
    exit 1
  fi
}
KANI_FIXTURE="${valid/0.68.0/0.67.0}" refuse old-release
KANI_FIXTURE="${valid/1.100.0-nightly/1.93.0-nightly}" refuse old-compiler
KANI_FIXTURE="${valid/8925ea358/000000000}" refuse different-compiler-commit
KANI_FIXTURE="${valid/CBMC 6.11.0/CBMC 6.10.0}" refuse different-cbmc
KANI_FIXTURE="${valid%$'\n'*}" refuse missing-cbmc
KANI_FIXTURE="$valid"$'\nunexpected trailer' refuse unexpected-trailer
KANI_FIXTURE_EXIT=1 refuse failed-probe
CHIO_KANI_VERSION=latest refuse unpinned-selector
if [[ -e "$KANI_PROOF_CALLS" ]]; then
  echo "version controls invoked a proof" >&2
  exit 1
fi

export KANI_FIXTURE="${valid/0.68.0/0.67.0}"
for runner in scripts/check-kani-core.sh scripts/check-kani-smoke.sh \
              scripts/check-kani-public-core.sh scripts/kani-mutant-killer.sh \
              scripts/run-kani-manifest.sh; do
  if bash "$runner" > "$work/runner-$(basename "$runner").log" 2>&1; then
    echo "$runner accepted an incompatible release" >&2
    exit 1
  fi
  if [[ -e "$KANI_PROOF_CALLS" ]]; then
    echo "$runner invoked a proof with an incompatible release" >&2
    exit 1
  fi
done
bash scripts/run-kani-manifest.sh --lane pr --dry-run > "$work/dry-run.log"
bash scripts/check-kani-public-core.sh --lane pr --list > "$work/public-list.log"
if [[ -e "$KANI_PROOF_CALLS" ]]; then
  echo "informational harness enumeration invoked a proof" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path
import hashlib
import re
import tomllib

for name in ["ci", "formal-pr-smoke", "nightly", "release-qualification", "proof-mutants"]:
    text = Path(f".github/workflows/{name}.yml").read_text()
    if re.findall(r"CHIO_KANI_VERSION: ([^\n]+)", text) != ["0.68.0"]:
        raise SystemExit(f"{name} does not pin the compatible Kani release")
    if "bash scripts/check-kani-toolchain.sh" not in text:
        raise SystemExit(f"{name} does not verify the installed compiler")
    if "uses: ./.github/actions/setup-kani" not in text:
        raise SystemExit(f"{name} does not install Kani through the shared setup owner")
    if "cargo install kani-verifier" in text or "cargo kani setup" in text:
        raise SystemExit(f"{name} still acquires a stock hosted Kani bundle")
smoke = Path(".github/workflows/formal-pr-smoke.yml").read_text()
if smoke.count("uses: ./.github/actions/setup-kani") != 2:
    raise SystemExit("formal PR Kani jobs must install through the shared setup owner")
if "if ! bash scripts/check-kani-toolchain.sh" in smoke:
    raise SystemExit("cached Kani probing must follow explicit pinned installation and setup")
if "~/.kani" in smoke:
    raise SystemExit("formal PR Kani jobs must not restore stock hosted-bundle caches")
patch = Path("formal/rust-verification/patches/kani-catch-unwind.patch").read_bytes()
if hashlib.sha256(patch).hexdigest() != (
    "84440a2046d1fc81bfdac1003c91a974103dc05b6fd5bb2435227b6024c5f2c4"
):
    raise SystemExit("committed catch_unwind patch bytes drifted from the reviewed pin")
action = Path(".github/actions/setup-kani/action.yml").read_text()
for pin in (
    "0d2328a93f0e0ff66132d6bfa1a7d884877cf862",
    "84440a2046d1fc81bfdac1003c91a974103dc05b6fd5bb2435227b6024c5f2c4",
    "b250680abd40ff1aaa07081d0497dc2755ed112e",
    "cargo run --locked --target-dir target/tools -p build-kani -- build-dev --release --locked",
    "submodule update --init charon",
    "[[ \"${RUNNER_PLATFORM}\" == 'Linux-X64' ]]",
    "b3721aa541038384d7801ea3aeabbcddc3e8845ac8f1cbff637cf8dec7481ac8",
    "RUSTUP_TOOLCHAIN=nightly-2026-08-21",
    "CARGO_BUILD_JOBS=2",
    "kani-src/target",
    "/etc/os-release",
    "bash \"${GITHUB_WORKSPACE}/scripts/check-kani-toolchain.sh\"",
):
    if pin not in action:
        raise SystemExit(f"setup-kani lost a required pin: {pin}")
cache_paths = re.findall(r"^\s+path: (.+)$", action, re.MULTILINE)
if cache_paths != ["${{ runner.temp }}/kani-src/target"]:
    raise SystemExit("setup-kani must cache only its build output directory")
if smoke.count('".github/actions/setup-kani/action.yml"') != 1:
    raise SystemExit("formal PR paths do not trigger on setup-kani changes")
rust_common = next(
    line for line in smoke.splitlines() if line.lstrip().startswith("rust_common=")
)
for route in ("setup-kani/action\\.yml", "patches/kani-catch-unwind\\.patch"):
    if route not in rust_common:
        raise SystemExit(f"formal PR Kani jobs are not selected by route: {route}")
mutants = Path(".github/workflows/proof-mutants.yml").read_text()
for route in (
    '".github/actions/setup-kani/action.yml"',
    '"formal/rust-verification/patches/kani-catch-unwind.patch"',
):
    if route not in mutants:
        raise SystemExit(f"proof-mutants is not triggered by route: {route}")
manifest = tomllib.loads(Path(".kani/harnesses.toml").read_text())
for crate in {entry["crate"] for entry in manifest["harness"] if entry["lane"] == "pr"}:
    files = list(Path("crates").glob(f"*/{crate}/Cargo.toml"))
    if len(files) != 1 or f'      - "{files[0].as_posix()}"' not in smoke:
        raise SystemExit(f"formal workflow does not trigger for the enrolled {crate} crate")
PY
python3 -B scripts/tests/check-kani-probe-lifecycle.test.py
python3 -B -O scripts/tests/check-kani-probe-lifecycle.test.py
echo "Kani toolchain controls passed; no compiler or proof was executed"
