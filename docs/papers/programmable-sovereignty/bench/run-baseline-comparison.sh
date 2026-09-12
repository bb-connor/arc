#!/usr/bin/env bash
set -euo pipefail

# The composed alternative, head to head with the Chio cross-organization
# receiver, over the same two corpora.
#
# The alternative is the strongest thing a competent engineer assembles today
# out of parts that already exist: a tool-call server, a caller identity
# authenticated by a key pinned out of band (a federated workload-identity
# trust bundle without the issuance mechanism, since the property at stake is
# peer authentication), a policy engine that evaluates a local rule set and
# signs its decision, and a receiver-side replay table keyed by a request
# identifier. It lives in examples/composed-baseline, outside this workspace,
# with its own lockfile, and it signs and canonicalizes with the same Chio
# crate the receiver under comparison uses, so a latency difference between the
# two is a difference in what they check.
#
# Two wirings of those parts run over the same code: `composed`, each part used
# the way it documents itself, and `hardened`, the same parts with every
# operator-authored check written in. Both are reported. Several of the four
# properties turn on which wiring an operator happens to have, and nothing in
# the composition records which one that is; reporting one wiring alone would
# either flatter or straw-man the alternative.
#
# The Chio side of every comparison is read from the committed
# bilateral-admission result rather than re-measured here, so the two halves
# cannot drift: if that file is missing, or its counters disagree with
# themselves, this script refuses to write a comparison.

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
SOURCE="${CHIO_SOURCE:-$ROOT}"
if [[ ! -d "$SOURCE/crates" || ! -f "$SOURCE/Cargo.toml" ]]; then
  echo "CHIO_SOURCE does not name a Chio workspace: $SOURCE" >&2
  exit 2
fi
SOURCE="$(cd "$SOURCE" && pwd -P)"
SOURCE_COMMIT="$(git -C "$SOURCE" rev-parse HEAD)"

BASELINE_DIR="$SOURCE/examples/composed-baseline"
NEGATIVE_CORPUS="$SOURCE/examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
CHIO_RESULT="$SCRIPT_DIR/results/bilateral-admission.json"

if [[ ! -f "$BASELINE_DIR/Cargo.toml" ]]; then
  echo "the composed baseline project is missing: $BASELINE_DIR" >&2
  exit 2
fi
if [[ ! -f "$NEGATIVE_CORPUS" ]]; then
  echo "the negative corpus fixture is missing: $NEGATIVE_CORPUS" >&2
  exit 2
fi
if [[ ! -f "$CHIO_RESULT" ]]; then
  echo "the Chio side of the comparison is missing: $CHIO_RESULT" >&2
  echo "run run-bilateral-admission.sh first; this script does not re-measure Chio." >&2
  exit 2
fi

# ---- Input tree ------------------------------------------------------------

# Everything the result depends on. A change to any of it changes the recorded
# digest, and an uncommitted change to any of it refuses the measurement.
INPUT_PATHS=(
  "examples/composed-baseline"
  "examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
  "crates/core/chio-core-types"
  "docs/papers/programmable-sovereignty/bench/run-baseline-comparison.sh"
)

if [[ -n "$(git -C "$SOURCE" status --short -- "${INPUT_PATHS[@]}")" ]]; then
  SOURCE_DIRTY=true
else
  SOURCE_DIRTY=false
fi
if [[ "$SOURCE_DIRTY" == true && "${CHIO_BENCH_ALLOW_DIRTY:-0}" != "1" ]]; then
  echo "refusing to measure: the benchmark input tree has uncommitted changes." >&2
  echo "commit them, or set CHIO_BENCH_ALLOW_DIRTY=1 for a result that must not be pinned." >&2
  git -C "$SOURCE" status --short -- "${INPUT_PATHS[@]}" >&2
  exit 2
fi

BENCHMARK_INPUT_TREE_SHA256="$(
  git -C "$SOURCE" ls-files -s -- "${INPUT_PATHS[@]}" \
    | sort \
    | { command -v sha256sum >/dev/null 2>&1 && sha256sum || shasum -a 256; } \
    | awk '{ print $1 }'
)"
if [[ ! "$BENCHMARK_INPUT_TREE_SHA256" =~ ^[0-9a-f]{64}$ ]]; then
  echo "cannot digest the benchmark input tree" >&2
  exit 2
fi

# ---- Parameters ------------------------------------------------------------

RESULT_DIR="${CHIO_PAPER_RESULT_DIR:-$SCRIPT_DIR/results}"
TARGET_DIR="${CHIO_BASELINE_TARGET_DIR:-${TMPDIR:-/tmp}/chio-composed-baseline-target}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chio-baseline-comparison.XXXXXX")"

CALLS="${CHIO_BASE_CALLS:-2000}"
WARMUP="${CHIO_BASE_WARMUP:-50}"
STAGE_TIMEOUT_SECS="${CHIO_BASE_STAGE_TIMEOUT_SECS:-1800}"
MAX_LOAD="${CHIO_BENCH_MAX_LOAD:-4.0}"

case "$CALLS:$WARMUP:$STAGE_TIMEOUT_SECS" in
  *[!0-9:]*)
    echo "call counts, warmups and timeouts must be nonnegative integers" >&2
    exit 2
    ;;
esac
if [[ "$CALLS" -lt 2 ]]; then
  echo "CHIO_BASE_CALLS must be at least 2: every reported distribution needs two observations" >&2
  exit 2
fi
if [[ "$STAGE_TIMEOUT_SECS" -lt 1 ]]; then
  echo "CHIO_BASE_STAGE_TIMEOUT_SECS must be at least one second" >&2
  exit 2
fi
if [[ ! "$MAX_LOAD" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "CHIO_BENCH_MAX_LOAD must be a nonnegative decimal number: $MAX_LOAD" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR" "$TARGET_DIR"
RESULT_DIR="$(cd "$RESULT_DIR" && pwd -P)"

RESULT_JSON="$RESULT_DIR/baseline-comparison.json"
BASELINE_JSON="$RESULT_DIR/baseline-composed.json"
NEGATIVE_CSV="$RESULT_DIR/baseline-negative-matrix.csv"
SUBSTITUTION_CSV="$RESULT_DIR/baseline-substitution-matrix.csv"
INLINE="$RESULT_DIR/baseline-inline.tex"
ENVIRONMENT="$RESULT_DIR/baseline-environment.txt"
ENVIRONMENT_JSON="$RESULT_DIR/baseline-environment.json"
BUILD_LOG="$RESULT_DIR/baseline-build.log"
DRIVER_LOG="$RESULT_DIR/baseline-driver.log"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}
trap 'emit_unreported' ERR

# ---- Environment -----------------------------------------------------------

KERNEL_NAME="$(uname -s)"
KERNEL_RELEASE="$(uname -r)"
MACHINE="$(uname -m)"
OS_DESCRIPTION="$KERNEL_NAME $KERNEL_RELEASE $MACHINE"
CPU_MODEL=""
CORES=""
MEMORY_BYTES=""
LOAD_1M=""
PLATFORM_DETAIL=""

case "$KERNEL_NAME" in
  Linux)
    if command -v lscpu >/dev/null 2>&1; then
      PLATFORM_DETAIL="$(lscpu)"
      CPU_MODEL="$(printf '%s\n' "$PLATFORM_DETAIL" | sed -n 's/^Model name:[[:space:]]*//p' | head -n 1)"
    fi
    if [[ -z "$CPU_MODEL" && -r /proc/cpuinfo ]]; then
      CPU_MODEL="$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -n 1)"
    fi
    CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || true)"
    if [[ -r /proc/meminfo ]]; then
      MEMORY_KIB="$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)"
      if [[ "$MEMORY_KIB" =~ ^[0-9]+$ ]]; then
        MEMORY_BYTES=$((MEMORY_KIB * 1024))
      fi
      PLATFORM_DETAIL="$PLATFORM_DETAIL"$'\n'"$(sed -n '1,3p' /proc/meminfo)"
    fi
    if [[ -r /proc/loadavg ]]; then
      LOAD_1M="$(cut -d ' ' -f 1 /proc/loadavg)"
    fi
    ;;
  Darwin)
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
    CORES="$(sysctl -n hw.ncpu 2>/dev/null || true)"
    MEMORY_BYTES="$(sysctl -n hw.memsize 2>/dev/null || true)"
    LOAD_1M="$(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{ print $1 }' || true)"
    PLATFORM_DETAIL="$(sw_vers 2>/dev/null || true)"
    ;;
  *)
    echo "unsupported benchmark host kernel: $KERNEL_NAME (Linux and Darwin are supported)" >&2
    exit 2
    ;;
esac

if [[ -z "$CPU_MODEL" ]]; then
  echo "cannot determine the CPU model on $KERNEL_NAME; refusing to record an unidentified host" >&2
  exit 2
fi
if [[ ! "$CORES" =~ ^[0-9]+$ || "$CORES" -lt 1 ]]; then
  echo "cannot determine the online CPU count on $KERNEL_NAME" >&2
  exit 2
fi
if [[ ! "$MEMORY_BYTES" =~ ^[0-9]+$ || "$MEMORY_BYTES" -lt 1 ]]; then
  echo "cannot determine the physical memory size on $KERNEL_NAME" >&2
  exit 2
fi
if [[ ! "$LOAD_1M" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "cannot determine the one-minute load average on $KERNEL_NAME" >&2
  exit 2
fi
LOAD_VERDICT="$(
  awk -v current="$LOAD_1M" -v limit="$MAX_LOAD" \
    'BEGIN { if (current + 0 > limit + 0) { print "exceeded" } else { print "within" } }'
)"
if [[ "$LOAD_VERDICT" != within ]]; then
  echo "one-minute load average $LOAD_1M exceeds CHIO_BENCH_MAX_LOAD=$MAX_LOAD; wait for the host to settle or raise CHIO_BENCH_MAX_LOAD" >&2
  exit 3
fi

TOOLCHAIN_PIN="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$SOURCE/rust-toolchain.toml" | head -n 1)"
if [[ -z "$TOOLCHAIN_PIN" ]]; then
  echo "cannot read the pinned toolchain channel from $SOURCE/rust-toolchain.toml" >&2
  exit 2
fi
RUSTC_VERBOSE="$(cd "$SOURCE" && rustc -Vv)"
RUSTC_RELEASE="$(printf '%s\n' "$RUSTC_VERBOSE" | sed -n 's/^release:[[:space:]]*//p' | head -n 1)"
CARGO_VERSION_LINE="$(cd "$SOURCE" && cargo -V)"
CARGO_VERSION="$(printf '%s\n' "$CARGO_VERSION_LINE" | awk '{ print $2 }')"
if [[ -z "$RUSTC_RELEASE" || -z "$CARGO_VERSION" ]]; then
  echo "cannot determine the rustc and cargo versions" >&2
  exit 2
fi
if [[ "$RUSTC_RELEASE" != "$TOOLCHAIN_PIN" ]]; then
  echo "rustc $RUSTC_RELEASE is not the toolchain pinned by rust-toolchain.toml ($TOOLCHAIN_PIN); remove the override and rerun" >&2
  exit 2
fi

if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
else
  echo "no timeout(1) or gtimeout(1) on PATH; the measurement stage needs a wall-clock guard" >&2
  exit 2
fi

{
  printf '%s\n' "$SOURCE_COMMIT"
  if [[ "$SOURCE_DIRTY" == true ]]; then
    printf 'worktree=dirty\n'
  else
    printf 'worktree=clean\n'
  fi
  printf 'cpu_model=%s\n' "$CPU_MODEL"
  printf 'cores=%s\n' "$CORES"
  printf 'memory_bytes=%s\n' "$MEMORY_BYTES"
  printf 'os=%s\n' "$OS_DESCRIPTION"
  printf 'load_average_1m=%s\n' "$LOAD_1M"
  printf 'max_load_average_1m=%s\n' "$MAX_LOAD"
  printf 'toolchain_pin=%s\n' "$TOOLCHAIN_PIN"
  printf '%s\n' "$RUSTC_VERBOSE"
  printf '%s\n' "$CARGO_VERSION_LINE"
  uname -a
  printf '%s\n' "$PLATFORM_DETAIL"
  printf 'profile=release\n'
  printf 'baseline_calls=%s\n' "$CALLS"
  printf 'baseline_warmup=%s\n' "$WARMUP"
  printf 'baseline_store=SQLite WAL synchronous=FULL\n'
  printf 'benchmark_input_tree_sha256=%s\n' "$BENCHMARK_INPUT_TREE_SHA256"
} > "$ENVIRONMENT"

python3 - "$ENVIRONMENT_JSON" "$CPU_MODEL" "$CORES" "$MEMORY_BYTES" \
  "$OS_DESCRIPTION" "$RUSTC_RELEASE" "$CARGO_VERSION" "$LOAD_1M" \
  "$TOOLCHAIN_PIN" "$SOURCE_COMMIT" "$SOURCE_DIRTY" <<'PY'
import json
import pathlib
import sys

(
    output,
    cpu_model,
    cores,
    memory_bytes,
    os_description,
    rustc,
    cargo,
    load_1m,
    toolchain_pin,
    commit,
    dirty,
) = sys.argv[1:]
document = {
    "cpuModel": cpu_model,
    "cores": int(cores),
    "memoryGiB": int(memory_bytes) / 1073741824.0,
    "os": os_description,
    "rustc": rustc,
    "cargo": cargo,
    "loadAverage1m": float(load_1m),
    "toolchainPin": toolchain_pin,
    "commit": commit,
    "worktreeDirty": dirty == "true",
}
pathlib.Path(output).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

# ---- Build and run the alternative -----------------------------------------

(
  cd "$BASELINE_DIR"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release --locked --bin run-composed-baseline
) > "$BUILD_LOG" 2>&1

DRIVER_BIN="$TARGET_DIR/release/run-composed-baseline"
if [[ ! -x "$DRIVER_BIN" ]]; then
  echo "the composed baseline driver was not built: $DRIVER_BIN" >&2
  exit 2
fi

"$TIMEOUT_BIN" "${STAGE_TIMEOUT_SECS}s" "$DRIVER_BIN" \
  --work-dir "$WORK_DIR/baseline" \
  --out "$BASELINE_JSON" \
  --calls "$CALLS" \
  --warmup "$WARMUP" \
  > "$DRIVER_LOG" 2>&1

# ---- Comparison ------------------------------------------------------------

python3 - "$RESULT_JSON" "$BASELINE_JSON" "$CHIO_RESULT" "$NEGATIVE_CORPUS" \
  "$ENVIRONMENT_JSON" "$NEGATIVE_CSV" "$SUBSTITUTION_CSV" "$INLINE" \
  "$SOURCE_COMMIT" "$SOURCE_DIRTY" "$BENCHMARK_INPUT_TREE_SHA256" <<'PY'
import csv
import json
import pathlib
import sys

(
    result_json,
    baseline_json,
    chio_json,
    corpus_json,
    environment_json,
    negative_csv,
    substitution_csv,
    inline_out,
    source_commit,
    source_dirty,
    benchmark_input_tree_sha256,
) = sys.argv[1:12]


def load(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


baseline = load(baseline_json)
chio = load(chio_json)
corpus = load(corpus_json)
environment = load(environment_json)

# --- fail closed on the corpora ---------------------------------------------

corpus_threats = sorted({case["threatId"] for case in corpus["cases"]})
covered_threats = sorted(
    {
        entry["threat_id"]
        for entry in baseline["negativeCorpus"]
        if entry["threat_id"].startswith("PS-TH-")
    }
)
missing = [threat for threat in corpus_threats if threat not in covered_threats]
if missing:
    raise SystemExit(
        "the baseline run did not answer every case of the negative corpus: "
        + ", ".join(missing)
    )

# The fifteen binding fields, with the signer list appearing twice.
SUBSTITUTION_FIELDS = 15
SUBSTITUTION_ROWS = 16
rows = baseline["substitutionCorpus"]
if len(rows) != SUBSTITUTION_ROWS:
    raise SystemExit(
        f"the substitution corpus reported {len(rows)} rows, not {SUBSTITUTION_ROWS}"
    )
distinct_fields = {row["chio_field"].split(",")[0] for row in rows}
if len(distinct_fields) != SUBSTITUTION_FIELDS:
    raise SystemExit(
        f"the substitution corpus covered {len(distinct_fields)} binding fields, "
        f"not {SUBSTITUTION_FIELDS}"
    )

null_case = next(
    entry
    for entry in baseline["negativeCorpus"]
    if entry["baseline_case_id"] == "unmodified-admissible-call"
)
for profile in ("composed", "hardened"):
    if not null_case[profile]["dispatched"]:
        raise SystemExit(
            f"the null case was denied under {profile}; no denial in this corpus is attributable"
        )

# --- fail closed on the Chio side -------------------------------------------

components = {entry["component"]: entry for entry in chio["components"]}
for required in (
    "treaty_predispatch_allow",
    "treaty_predispatch_deny",
    "receipt_append_sqlite",
    "strict_bilateral_dsse_verify",
    "cross_boundary_admission_allow",
):
    if required not in components:
        raise SystemExit(f"the Chio result carries no {required} component")

sustained = chio["sustainedLoad"]
if sustained["dispatchCount"] != sustained["calls"]:
    raise SystemExit(
        "the Chio sustained-load record disagrees with itself: "
        f"{sustained['dispatchCount']} dispatches for {sustained['calls']} calls"
    )
if sustained["denials"] != 0:
    raise SystemExit(
        f"the Chio sustained-load record carries {sustained['denials']} denials; "
        "its per-call storage figure would not be a per-admitted-call figure"
    )
if sustained["calls"] < 2:
    raise SystemExit("the Chio sustained-load record carries fewer than two calls")

negative_matrix = chio["negativeMatrix"]
if negative_matrix["cases"] != len(corpus["cases"]):
    raise SystemExit(
        f"the Chio negative matrix reports {negative_matrix['cases']} cases and the "
        f"fixture carries {len(corpus['cases'])}"
    )

chio_storage_bytes_per_call = (
    sustained["receiptStoreBytesAfter"] - sustained["receiptStoreBytesBefore"]
) / sustained["calls"]
if chio_storage_bytes_per_call <= 0:
    raise SystemExit("the Chio receipt store did not grow; refusing a per-call figure")

# --- the baseline's measurements --------------------------------------------

measurements = {
    (entry["profile"], entry["durability"]): entry for entry in baseline["measurements"]
}
composed_before = measurements[("composed", "before_dispatch")]
composed_after = measurements[("composed", "after_dispatch")]
hardened_before = measurements[("hardened", "before_dispatch")]

for entry in baseline["measurements"]:
    if entry["dispatched"] != entry["calls"]:
        raise SystemExit(
            f"{entry['profile']}/{entry['durability']} dispatched "
            f"{entry['dispatched']} of {entry['calls']} calls"
        )

chio_allow_ms = components["treaty_predispatch_allow"]["p50_us"] / 1000.0
chio_append_ms = components["receipt_append_sqlite"]["p50_us"] / 1000.0
chio_verify_us = components["strict_bilateral_dsse_verify"]["p50_us"]
chio_decision_us = components["cross_boundary_admission_allow"]["p50_us"]

base_allow_ms = composed_before["latency"]["p50_us"] / 1000.0
base_response_ms = composed_after["response_latency"]["p50_us"] / 1000.0
ordering_cost_ms = base_allow_ms - base_response_ms
hardened_allow_ms = hardened_before["latency"]["p50_us"] / 1000.0
hardening_cost_ms = hardened_allow_ms - base_allow_ms
base_bytes_per_call = composed_before["durable_bytes_per_call"]

if ordering_cost_ms <= 0:
    raise SystemExit(
        "the response-before-record ordering measured no cheaper than the "
        "record-before-response ordering; refusing to report an ordering cost"
    )

# Whether the hardened wiring's extra checks are separable from the composed
# wiring's cost at this sample size, from the two mean intervals. They sit far
# below the durable write, so the expected answer is that they are not, and
# saying so is more useful than printing a delta the run cannot resolve.
composed_ci = (
    composed_before["checks_latency"]["ci_low_us"],
    composed_before["checks_latency"]["ci_high_us"],
)
hardened_ci = (
    hardened_before["checks_latency"]["ci_low_us"],
    hardened_before["checks_latency"]["ci_high_us"],
)
hardening_separated = composed_ci[1] < hardened_ci[0] or hardened_ci[1] < composed_ci[0]
hardening_verdict = "separated" if hardening_separated else "indistinguishable"
composed_checks_us = composed_before["checks_latency"]["p50_us"]
hardened_checks_us = hardened_before["checks_latency"]["p50_us"]
hardening_checks_cost_us = hardened_checks_us - composed_checks_us
checks_share = composed_checks_us / composed_before["latency"]["p50_us"]

# --- counts over the corpora -------------------------------------------------

negative = baseline["negativeCorpus"]
driven = [entry for entry in negative if entry.get("composed") is not None]
no_analogue = [entry for entry in negative if entry.get("composed") is None]
attacks = [
    entry for entry in driven if entry["baseline_case_id"] != "unmodified-admissible-call"
]


def dispatched(entry, profile):
    return entry[profile]["dispatched"]


composed_admits = [entry for entry in attacks if dispatched(entry, "composed")]
hardened_admits = [entry for entry in attacks if dispatched(entry, "hardened")]
hardening_closes = [
    entry
    for entry in attacks
    if dispatched(entry, "composed") and not dispatched(entry, "hardened")
]

noticed_composed = [row for row in rows if row["noticed_composed"]]
noticed_hardened = [row for row in rows if row["noticed_hardened"]]
not_carried = [row for row in rows if row["basis"] == "not_carried"]

properties = baseline["properties"]


def property_count(profile, verdict):
    return sum(1 for entry in properties if entry[profile] == verdict)


# --- files ------------------------------------------------------------------

with pathlib.Path(negative_csv).open("w", encoding="utf-8", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(
        [
            "threat_id",
            "chio_case_id",
            "chio_expected_code",
            "baseline_case_id",
            "analogue",
            "composed_dispatched",
            "composed_code",
            "composed_step",
            "hardened_dispatched",
            "hardened_code",
            "hardened_step",
        ]
    )
    for entry in negative:
        composed = entry.get("composed") or {}
        hardened = entry.get("hardened") or {}
        writer.writerow(
            [
                entry["threat_id"],
                entry["chio_case_id"],
                entry["chio_expected_code"],
                entry["baseline_case_id"],
                entry["analogue"],
                composed.get("dispatched", ""),
                composed.get("denial_code", ""),
                composed.get("denial_step", ""),
                hardened.get("dispatched", ""),
                hardened.get("denial_code", ""),
                hardened.get("denial_step", ""),
            ]
        )

with pathlib.Path(substitution_csv).open("w", encoding="utf-8", newline="") as handle:
    writer = csv.writer(handle)
    writer.writerow(
        [
            "chio_field",
            "baseline_carrier",
            "basis",
            "noticed_composed",
            "noticed_hardened",
            "composed_code",
            "consistent_composed_code",
        ]
    )
    for row in rows:
        composed = row.get("composed") or {}
        consistent = row.get("consistent_composed") or {}
        writer.writerow(
            [
                row["chio_field"],
                row.get("baseline_carrier", ""),
                row["basis"],
                row["noticed_composed"],
                row["noticed_hardened"],
                composed.get("denial_code", ""),
                consistent.get("denial_code", ""),
            ]
        )

document = {
    "schema": "chio.programmable-sovereignty.baseline-comparison.v1",
    "commit": source_commit,
    "worktreeDirty": source_dirty == "true",
    "benchmarkInputTreeSha256": benchmark_input_tree_sha256,
    "profile": "release",
    "environment": environment,
    "alternative": baseline["baseline"],
    "negativeCorpus": {
        "cases": len(negative),
        "chioThreatIds": len(corpus_threats),
        "driven": len(driven),
        "noAnalogue": len(no_analogue),
        "attacks": len(attacks),
        "composedAdmits": len(composed_admits),
        "hardenedAdmits": len(hardened_admits),
        "closedByHardening": len(hardening_closes),
        "composedAdmittedCaseIds": [entry["baseline_case_id"] for entry in composed_admits],
        "hardenedAdmittedCaseIds": [entry["baseline_case_id"] for entry in hardened_admits],
        "noAnalogueCaseIds": [entry["baseline_case_id"] for entry in no_analogue],
        "entries": negative,
    },
    "substitutionCorpus": {
        "bindingFields": SUBSTITUTION_FIELDS,
        "rows": SUBSTITUTION_ROWS,
        "noticedComposed": len(noticed_composed),
        "noticedHardened": len(noticed_hardened),
        "notCarried": len(not_carried),
        "entries": rows,
    },
    "properties": properties,
    "propertySummary": {
        profile: {
            "holds": property_count(profile, "holds"),
            "holdsWeakened": property_count(profile, "holds_weakened"),
            "fails": property_count(profile, "fails"),
        }
        for profile in ("composed", "hardened")
    },
    "cost": {
        "alternative": {
            "admittedCallP50Ms": base_allow_ms,
            "admittedCallP99Ms": composed_before["latency"]["p99_us"] / 1000.0,
            "admittedCallMeanMs": composed_before["latency"]["mean_us"] / 1000.0,
            "admittedCallMeanCiLowMs": composed_before["latency"]["ci_low_us"] / 1000.0,
            "admittedCallMeanCiHighMs": composed_before["latency"]["ci_high_us"] / 1000.0,
            "samples": composed_before["latency"]["samples"],
            "responseBeforeRecordP50Ms": base_response_ms,
            "orderingCostP50Ms": ordering_cost_ms,
            "hardenedAdmittedCallP50Ms": hardened_allow_ms,
            "hardeningCostWholePathP50Ms": hardening_cost_ms,
            "checksOnlyP50Us": composed_checks_us,
            "hardenedChecksOnlyP50Us": hardened_checks_us,
            "hardenedChecksOnlyMeanCiLowUs": hardened_ci[0],
            "hardenedChecksOnlyMeanCiHighUs": hardened_ci[1],
            "hardeningChecksCostP50Us": hardening_checks_cost_us,
            "hardeningCostVerdict": hardening_verdict,
            "checksShareOfAdmittedCall": checks_share,
            "durableBytesPerCall": base_bytes_per_call,
            "decisionRecordBytes": composed_before["decision_record_bytes_p50"],
            "requestWireBytes": composed_before["request_wire_bytes"],
        },
        "chio": {
            "admittedCallP50Ms": chio_allow_ms,
            "receiptAppendP50Ms": chio_append_ms,
            "envelopeVerifyP50Us": chio_verify_us,
            "crossBoundaryDecisionP50Us": chio_decision_us,
            "durableBytesPerCall": chio_storage_bytes_per_call,
            "sustainedCalls": sustained["calls"],
            "source": "results/bilateral-admission.json",
        },
        "ratios": {
            "latencyChioOverAlternative": chio_allow_ms / base_allow_ms,
            "storageChioOverAlternative": chio_storage_bytes_per_call / base_bytes_per_call,
        },
    },
    "method": {
        "percentile": "linear interpolation between order statistics",
        "confidence": baseline["method"]["confidence"],
        "bootstrap": baseline["method"]["bootstrap"],
        "interval": (
            "the bootstrap interval is over the mean, so it brackets the mean "
            "and not the median; the two are reported separately and the "
            "distribution is right-skewed by the durable write's tail"
        ),
        "latency": baseline["method"]["latency"],
        "storage": baseline["method"]["storage"],
        "chioSide": (
            "read from the committed bilateral-admission result rather than "
            "re-measured, so the two halves of the comparison cannot drift; the "
            "run refuses if that file is absent or its own counters disagree"
        ),
        "profiles": (
            "both wirings are reported. Reporting the hardened wiring alone "
            "would credit the composition with checks no part of it requires; "
            "reporting the composed wiring alone would understate what a "
            "careful operator can reach"
        ),
        "hardeningCost": (
            "the hardened wiring runs six checks the composed wiring does not. "
            "Their cost is taken over the checks span alone, with the two "
            "durable writes excluded, because against a store that fsyncs a "
            "whole-path delta of that size is not resolvable; the verdict is "
            "over the two mean intervals of that span"
        ),
        "checksSpan": (
            "every signature verification, canonical encoding, consistency "
            "comparison, table lookup and rule evaluation the receiver "
            "performs, timed around the admission path and less the durable "
            "claim that sits in the middle of it"
        ),
        "propertyVerdicts": (
            "derived from cases the run drove, not asserted: a property fails "
            "only when a driven case dispatched a call the property forbids"
        ),
    },
}

pathlib.Path(result_json).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

macros = [
    ("PSBaseParts", str(len(baseline["baseline"]["parts"]))),
    ("PSBaseChioThreatIds", str(len(corpus_threats))),
    ("PSBaseNegativeCases", str(len(negative))),
    ("PSBaseNegativeDriven", str(len(driven))),
    ("PSBaseNegativeNoAnalogue", str(len(no_analogue))),
    ("PSBaseNegativeAttacks", str(len(attacks))),
    ("PSBaseComposedAdmits", str(len(composed_admits))),
    ("PSBaseHardenedAdmits", str(len(hardened_admits))),
    ("PSBaseClosedByHardening", str(len(hardening_closes))),
    ("PSBaseSubstFields", str(SUBSTITUTION_FIELDS)),
    ("PSBaseSubstRows", str(SUBSTITUTION_ROWS)),
    ("PSBaseSubstNoticedComposed", str(len(noticed_composed))),
    ("PSBaseSubstNoticedHardened", str(len(noticed_hardened))),
    ("PSBaseSubstNotCarried", str(len(not_carried))),
    ("PSBasePropsHoldComposed", str(property_count("composed", "holds"))),
    ("PSBasePropsWeakComposed", str(property_count("composed", "holds_weakened"))),
    ("PSBasePropsFailComposed", str(property_count("composed", "fails"))),
    ("PSBasePropsHoldHardened", str(property_count("hardened", "holds"))),
    ("PSBasePropsWeakHardened", str(property_count("hardened", "holds_weakened"))),
    ("PSBasePropsFailHardened", str(property_count("hardened", "fails"))),
    ("PSBaseAllowPFiftyMs", f"{base_allow_ms:.3f}"),
    ("PSBaseAllowPNinetyNineMs", f"{composed_before['latency']['p99_us'] / 1000.0:.3f}"),
    ("PSBaseAllowMeanMs", f"{composed_before['latency']['mean_us'] / 1000.0:.3f}"),
    ("PSBaseAllowMeanCiLowMs", f"{composed_before['latency']['ci_low_us'] / 1000.0:.3f}"),
    ("PSBaseAllowMeanCiHighMs", f"{composed_before['latency']['ci_high_us'] / 1000.0:.3f}"),
    ("PSBaseAllowSampleCount", str(composed_before["latency"]["samples"])),
    ("PSBaseResponsePFiftyMs", f"{base_response_ms:.3f}"),
    ("PSBaseOrderingCostMs", f"{ordering_cost_ms:.3f}"),
    ("PSBaseHardenedAllowPFiftyMs", f"{hardened_allow_ms:.3f}"),
    ("PSBaseChecksPFiftyUs", f"{composed_checks_us:.1f}"),
    ("PSBaseHardenedChecksPFiftyUs", f"{hardened_checks_us:.1f}"),
    ("PSBaseHardeningChecksCostUs", f"{hardening_checks_cost_us:.1f}"),
    ("PSBaseHardeningCostVerdict", hardening_verdict),
    ("PSBaseChecksSharePercent", f"{checks_share * 100.0:.2f}"),
    ("PSBaseBytesPerCall", f"{base_bytes_per_call:.1f}"),
    ("PSBaseRequestWireBytes", str(composed_before["request_wire_bytes"])),
    ("PSBaseChioAllowPFiftyMs", f"{chio_allow_ms:.3f}"),
    ("PSBaseChioAppendPFiftyMs", f"{chio_append_ms:.3f}"),
    ("PSBaseChioKiBPerCall", f"{chio_storage_bytes_per_call / 1024.0:.2f}"),
    ("PSBaseLatencyRatio", f"{chio_allow_ms / base_allow_ms:.2f}"),
    (
        "PSBaseStorageRatio",
        f"{chio_storage_bytes_per_call / base_bytes_per_call:.1f}",
    ),
]
pathlib.Path(inline_out).write_text(
    "".join(f"\\newcommand{{\\{name}}}{{{value}}}\n" for name, value in macros),
    encoding="utf-8",
)
PY

trap - ERR
printf 'baseline comparison complete: %s\n' "$RESULT_JSON"
