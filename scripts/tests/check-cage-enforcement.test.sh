#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
real_python3="$(command -v python3)"
work="$(mktemp -d -t chio-cage-enforcement-gate-XXXXXX)"
trap 'rm -rf "$work"' EXIT
fake_bin="$work/bin"
mkdir -p "$fake_bin"
trusted_root="$work/trusted"
gate_fixture="$work/check-cage-enforcement.sh"
candidate_artifacts="$work/candidate-artifacts"
verifier_artifacts="$work/verifier-artifacts"
mkdir -p "$trusted_root" "$candidate_artifacts" "$verifier_artifacts"
ld_cache="$work/etc/ld.so.cache"
musl_loader="$work/musl/ld-musl-x86_64.so.1"
mkdir -p "$(dirname "$ld_cache")" "$(dirname "$musl_loader")"
: >"$musl_loader"
cp "$repo_root/scripts/check-linux-enforcement-stack.py" \
  "$trusted_root/check-linux-enforcement-stack.py"
cp "$repo_root/scripts/check-cage-all-target-inventory.py" \
  "$trusted_root/check-cage-all-target-inventory.py"
cp "$repo_root/crates/security/chio-cage/scripts/check-linux-enforcement.sh" \
  "$trusted_root/check-cage-linux-enforcement.sh"
python3 - \
  "$repo_root" \
  "$trusted_root" \
  "$gate_fixture" \
  "$candidate_artifacts" \
  "$verifier_artifacts" \
  "$ld_cache" <<'PY'
import sys
from pathlib import Path


repo_root = Path(sys.argv[1])
trusted_root = Path(sys.argv[2])
fixture = Path(sys.argv[3])
candidate_artifacts = Path(sys.argv[4])
verifier_artifacts = Path(sys.argv[5])
ld_cache = Path(sys.argv[6])
source = (repo_root / "scripts/check-cage-enforcement.sh").read_text(encoding="utf-8")
replacements = {
    "/private/candidate": str(repo_root),
    "/opt/chio-security/gates/check-linux-enforcement-stack.py": str(
        trusted_root / "check-linux-enforcement-stack.py"
    ),
    "/opt/chio-security/gates/check-cage-all-target-inventory.py": str(
        trusted_root / "check-cage-all-target-inventory.py"
    ),
    "/opt/chio-security/gates/check-cage-linux-enforcement.sh": str(
        trusted_root / "check-cage-linux-enforcement.sh"
    ),
    "/proc/self/status": "/dev/null",
}
for old, new in replacements.items():
    if old not in source:
        raise SystemExit(f"cage gate fixture source is missing {old!r}")
    source = source.replace(old, new)
fixture.write_text(source, encoding="utf-8")

linux_runner = trusted_root / "check-cage-linux-enforcement.sh"
runner_source = linux_runner.read_text(encoding="utf-8")
runner_replacements = {
    "/private/candidate": str(repo_root),
    "/opt/chio-security/gates/check-cage-all-target-inventory.py": str(
        trusted_root / "check-cage-all-target-inventory.py"
    ),
    "/target/artifacts": str(candidate_artifacts),
    '[[ ! "$verifier_artifacts" =~ ^/baseline/candidate-state/[a-f0-9]{64}/verifier/artifacts$ ]]': (
        f'[[ "$verifier_artifacts" != "{verifier_artifacts}" ]]'
    ),
    "/etc/ld.so.cache": str(ld_cache),
}
for old, new in runner_replacements.items():
    if old not in runner_source:
        raise SystemExit(f"Linux cage fixture source is missing {old!r}")
    runner_source = runner_source.replace(old, new)
linux_runner.write_text(runner_source, encoding="utf-8")
PY
chmod 700 "$gate_fixture" "$trusted_root/check-cage-linux-enforcement.sh"

cat >"$fake_bin/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) printf 'Linux\n' ;;
esac
EOF

cat >"$fake_bin/python3" <<'EOF'
#!/usr/bin/env bash
checker="${1:-}"
if [[ "$checker" == "-I" ]]; then
  checker="${2:-}"
fi
if [[ "$checker" == *"/check-cage-all-target-inventory.py" ]] ||
  [[ "$checker" == "scripts/check-cage-all-target-inventory.py" ]]; then
  exec "${CHIO_REAL_PYTHON3:?}" "$@"
fi
exit 0
EOF

export FAKE_CAGE_RENDERER="$work/render-cage-run.py"
cat >"$FAKE_CAGE_RENDERER" <<'EOF'
import importlib.util
import os
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("cage_inventory", os.environ["FAKE_CAGE_CHECKER"])
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
root = Path(os.environ["FAKE_CAGE_ROOT"])
kind, mode = sys.argv[1], sys.argv[2]
inventory = checker.source_inventory(root)
mutations = checker.mutation_inventory(root)
UNIT_HEADERS = {
    "lib": "Running unittests src/lib.rs (/tmp/chio_cage-lib)",
    "lib_chio_cage_plan": "Running unittests src/lib.rs (/tmp/chio_cage_plan-lib)",
    "lib_chio_cage_init": "Running unittests src/lib.rs (/tmp/chio_cage_init-lib)",
    "bin_chio_cage_init": "Running unittests src/main.rs (/tmp/chio_cage_init-bin)",
}


def block(results, filtered=0, header=None):
    passed = sum(status == "ok" for _, status in results)
    ignored = len(results) - passed
    lines = [f"     {header}"] if header else []
    lines.append(f"running {len(results)} tests")
    lines.extend(f"test {name} ... {status}" for name, status in results)
    lines.append(
        f"test result: ok. {passed} passed; 0 failed; {ignored} ignored; "
        f"0 measured; {filtered} filtered out; finished in 0.01s"
    )
    return lines


def adjust(names, prefix, extra):
    results = [(name, "ok") for name in names]
    if mode == f"zero_{prefix}s":
        return []
    if mode == f"removed_{prefix}":
        return results[:-1]
    if mode == f"skipped_{prefix}":
        return results[:-1] + [(results[-1][0], "ignored")]
    if mode == f"extra_{prefix}":
        return results + [(extra, "ok")]
    return results


output = []
if kind == "all-targets":
    for target in checker.EXPECTED_COUNTS:
        header = UNIT_HEADERS.get(target, f"Running tests/{target}.rs (/tmp/{target})")
        names = inventory[target]
        if target == "linux_enforcement":
            results = adjust(names, "probe", "unratcheted_real_linux_probe")
        else:
            results = [(name, "ok") for name in names]
        output.extend(block(results, header=header))
elif kind == "mutations":
    results = adjust(mutations, "mutation", "enforcement_mutation_unratcheted")
    output.extend(block(results, filtered=len(inventory["linux_enforcement"])))
else:
    raise SystemExit(f"unknown fake cargo lane {kind}")
print("\n".join(output))
EOF
export FAKE_CAGE_CHECKER="$trusted_root/check-cage-all-target-inventory.py"
export FAKE_CAGE_ROOT="$repo_root"
expected_all_targets="$("$real_python3" -I "$FAKE_CAGE_CHECKER" --root "$repo_root" --expected all-targets)"
expected_probes="$("$real_python3" -I "$FAKE_CAGE_CHECKER" --root "$repo_root" --expected probes | grep -c .)"
expected_mutations="$("$real_python3" -I "$FAKE_CAGE_CHECKER" --root "$repo_root" --expected mutations | grep -c .)"
evidence_marker="all_targets=${expected_all_targets} probes=${expected_probes} mutations=${expected_mutations}"

cat >"$fake_bin/cc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
while (($#)); do
  if [[ "$1" == "-o" ]]; then
    output="$2"
    shift 2
  else
    shift
  fi
done
[[ -n "$output" ]]
printf '#!/bin/true\n' >"$output"
chmod 700 "$output"
EOF

cat >"$fake_bin/ldd" <<'EOF'
#!/usr/bin/env bash
case "${FAKE_LDD_MODE:-glibc}" in
  glibc)
    printf 'libc.so.6 => /bin/sh (0x1)\n'
    printf 'libm.so.6 => /bin/ls (0x2)\n'
    printf '\t/bin/cat (0x3)\n'
    ;;
  musl)
    printf '\t/lib/ld-musl-x86_64.so.1 (0x72361b094000)\n'
    printf '\tlibc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x72361b094000)\n'
    ;;
  musl_without_libc)
    printf '\t/lib/ld-musl-x86_64.so.1 (0x72361b094000)\n'
    ;;
  musl_without_interpreter)
    printf '\tlibc.musl-x86_64.so.1 => /lib/ld-musl-x86_64.so.1 (0x72361b094000)\n'
    ;;
  *) exit 64 ;;
esac
EOF

cat >"$fake_bin/readlink" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == "-e" ]]
shift
if [[ "${1:-}" == "--" ]]; then
  shift
fi
if [[ "$1" == "/lib/ld-musl-x86_64.so.1" ]]; then
  /bin/realpath "${FAKE_MUSL_LOADER:?}"
  exit
fi
/bin/realpath "$1"
EOF

cat >"$fake_bin/readelf" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -hW) printf '  Type:                              DYN (Position-Independent Executable file)\n' ;;
  -lW) printf 'Elf file type is DYN (Position-Independent Executable file)\n' ;;
  -dW) printf 'Dynamic section contains 8 entries:\n 0x0000000000000000 (NULL) 0x0\n' ;;
  *) exit 64 ;;
esac
EOF

cat >"$fake_bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=" $* "
if [[ "$args" == *" build "* ]] && [[ "$args" == *" --bin chio-cage-init "* ]]; then
  [[ "$args" == *" --target x86_64-unknown-linux-musl "* ]] || {
    echo "static helper requires an explicit target to isolate host procedural macros" >&2
    exit 1
  }
  helper="${CARGO_TARGET_DIR:?}/x86_64-unknown-linux-musl/debug/chio-cage-init"
  mkdir -p "$(dirname "$helper")"
  printf '#!/bin/true\n' >"$helper"
  chmod 700 "$helper"
  exit 0
fi
if [[ "$args" == *" --test enforcement_evidence "* ]] ||
   [[ "$args" == *" --test linux_compile "* ]]; then
  printf 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n'
  exit 0
fi
if [[ "${FAKE_CARGO_MODE:-success}" == "unavailable" ]] &&
  { [[ "$args" == *" --all-targets "* ]] || [[ "$args" == *" --test linux_enforcement "* ]]; }; then
  exit 127
fi
if [[ "$args" == *" --all-targets "* ]]; then
  exec "${CHIO_REAL_PYTHON3:?}" -I "${FAKE_CAGE_RENDERER:?}" all-targets "${FAKE_CARGO_MODE:-success}"
fi
if [[ "$args" == *" --test linux_enforcement "* ]] && [[ "$args" == *"enforcement-mutants"* ]]; then
  exec "${CHIO_REAL_PYTHON3:?}" -I "${FAKE_CAGE_RENDERER:?}" mutations "${FAKE_CARGO_MODE:-success}"
fi
printf 'unexpected fake cargo invocation: %s\n' "$*" >&2
exit 65
EOF

chmod 700 "$fake_bin"/*

run_gate() {
  local runner="$1"
  local cargo_mode="$2"
  local ldd_mode="${3:-glibc}"
  local output="$work/$runner-$cargo_mode.out"
  if [[ "$ldd_mode" != "glibc" ]]; then
    output="$work/$runner-$cargo_mode-$ldd_mode.out"
  fi
  rm -f "$ld_cache"
  if [[ "$ldd_mode" == "glibc" ]]; then
    : >"$ld_cache"
  fi
  set +e
  (
    cd "$repo_root"
    if [[ "$runner" == "1" ]]; then
      PATH="$fake_bin:$PATH" \
        CHIO_REAL_PYTHON3="$real_python3" \
        CHIO_ENTERPRISE_SECURITY_RUNNER=1 \
        CHIO_SECURITY_WORKSPACE="$repo_root" \
        CHIO_SECURITY_LINUX_STACK_CHECKER="$trusted_root/check-linux-enforcement-stack.py" \
        CHIO_SECURITY_CAGE_INVENTORY_CHECKER="$trusted_root/check-cage-all-target-inventory.py" \
        CHIO_SECURITY_CAGE_LINUX_RUNNER="$trusted_root/check-cage-linux-enforcement.sh" \
        CHIO_SECURITY_CANDIDATE_ARTIFACTS="$candidate_artifacts" \
        CHIO_SECURITY_VERIFIER_ARTIFACTS="$verifier_artifacts" \
        FAKE_CARGO_MODE="$cargo_mode" \
        FAKE_LDD_MODE="$ldd_mode" \
        FAKE_MUSL_LOADER="$musl_loader" \
        "$gate_fixture" --release
    else
      PATH="$fake_bin:$PATH" \
        CHIO_REAL_PYTHON3="$real_python3" \
        CHIO_ENTERPRISE_SECURITY_RUNNER=0 \
        FAKE_CARGO_MODE="$cargo_mode" \
        "$gate_fixture" --release
    fi
  ) >"$output" 2>&1
  local status=$?
  set -e
  printf '%s\n' "$status"
}

status="$(run_gate 0 success)"
if [[ "$status" -eq 0 ]]; then
  echo "release mode accepted a non-designated runner" >&2
  exit 1
fi

for mode in \
  zero_probes removed_probe skipped_probe extra_probe \
  zero_mutations removed_mutation skipped_mutation extra_mutation \
  unavailable; do
  status="$(run_gate 1 "$mode")"
  if [[ "$status" -eq 0 ]]; then
    echo "release mode accepted invalid cage evidence mode $mode" >&2
    exit 1
  fi
done

status="$(run_gate 1 success)"
if [[ "$status" -ne 0 ]]; then
  cat "$work/1-success.out" >&2
  exit "$status"
fi
grep -Eq "^CHIO_CAGE_REAL_LINUX_EVIDENCE challenge=[a-f0-9]{64} ${evidence_marker}$" \
  "$work/1-success.out"

status="$(run_gate 1 success musl)"
if [[ "$status" -ne 0 ]]; then
  cat "$work/1-success-musl.out" >&2
  exit "$status"
fi
grep -Eq "^CHIO_CAGE_REAL_LINUX_EVIDENCE challenge=[a-f0-9]{64} ${evidence_marker}$" \
  "$work/1-success-musl.out"

for ldd_mode in musl_without_libc musl_without_interpreter; do
  status="$(run_gate 1 success "$ldd_mode")"
  if [[ "$status" -eq 0 ]]; then
    echo "release mode accepted dynamic runtime mode $ldd_mode" >&2
    exit 1
  fi
  grep -Fq 'dynamic probe did not resolve an interpreter and shared library' \
    "$work/1-success-$ldd_mode.out"
done

python3 scripts/tests/check-cage-all-target-inventory.test.py

printf 'check-cage-enforcement.test.sh: all assertions passed\n'
