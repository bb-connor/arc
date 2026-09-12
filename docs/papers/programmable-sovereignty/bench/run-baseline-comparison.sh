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
# operator-authored check written in. Both are reported, because several of the
# four properties turn on which wiring an operator happens to have and nothing
# in the composition records which one that is. One wiring alone would either
# credit the composition with checks no part of it requires or understate what
# a careful operator reaches.
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


def field_of(row):
    return row["chio_field"].split(",")[0]


def rows_of(field):
    return [row for row in rows if field_of(row) == field]


# A field has no carrier only when every row for it has none: the ordered signer
# list is a second row of a field that is carried, and counting rows as fields
# would report one carrier too few.
not_carried_fields = sorted(
    field
    for field in distinct_fields
    if all(row["basis"] == "not_carried" for row in rows_of(field))
)
carried_never_compared_fields = sorted(
    field
    for field in distinct_fields
    if field not in not_carried_fields
    and any(row["basis"] == "carried_never_compared" for row in rows_of(field))
)
noticed_fields = sorted(
    field
    for field in distinct_fields
    if any(row["noticed_composed"] or row["noticed_hardened"] for row in rows_of(field))
)
partition = len(not_carried_fields) + len(carried_never_compared_fields) + len(noticed_fields)
if partition != SUBSTITUTION_FIELDS:
    raise SystemExit(
        f"the {SUBSTITUTION_FIELDS} binding fields do not partition into noticed, "
        f"carried-and-never-compared and not-carried: {partition} accounted for"
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


def separated(left, right):
    """Whether two mean intervals are disjoint at this sample size."""
    return left[1] < right[0] or right[1] < left[0]


hardening_verdict = (
    "separated" if separated(composed_ci, hardened_ci) else "indistinguishable"
)
composed_checks_us = composed_before["checks_latency"]["p50_us"]
hardened_checks_us = hardened_before["checks_latency"]["p50_us"]
hardening_checks_cost_us = hardened_checks_us - composed_checks_us
checks_share = composed_checks_us / composed_before["latency"]["p50_us"]

# The hardened wiring also makes a second durable replay claim, on the
# identifier the decision carries for itself. That is a write and not a check,
# so it is measured over its own span rather than inferred from two whole-path
# medians.
composed_claim_us = composed_before["claim_latency"]["p50_us"]
hardened_claim_us = hardened_before["claim_latency"]["p50_us"]
claim_cost_us = hardened_claim_us - composed_claim_us
claim_verdict = (
    "separated"
    if separated(
        (
            composed_before["claim_latency"]["ci_low_us"],
            composed_before["claim_latency"]["ci_high_us"],
        ),
        (
            hardened_before["claim_latency"]["ci_low_us"],
            hardened_before["claim_latency"]["ci_high_us"],
        ),
    )
    else "indistinguishable"
)

# The whole path is the noisiest span the run reports, and the two wirings are
# measured in two separate conditions, so the pair is quotable only when the two
# mean intervals are disjoint. Otherwise the difference between them is host
# noise and the macro says so rather than printing a number.
whole_path_verdict = (
    "separated"
    if separated(
        (
            composed_before["latency"]["ci_low_us"],
            composed_before["latency"]["ci_high_us"],
        ),
        (
            hardened_before["latency"]["ci_low_us"],
            hardened_before["latency"]["ci_high_us"],
        ),
    )
    else "indistinguishable"
)

# A timing is quotable only from a run the paper could reproduce: a clean input
# tree, a sample large enough that the median is stable, and a host that was
# quiet by an absolute standard rather than by whatever ceiling the run was
# allowed to raise. A run that misses any of these still writes its corpora and
# its property verdicts, which are exact functions of the source, and refuses
# to hand the paper a number.
LATENCY_PINNABLE_MIN_CALLS = 1000
LATENCY_PINNABLE_MAX_LOAD_1M = 4.0
latency_pinnable_reasons = []
if source_dirty == "true":
    latency_pinnable_reasons.append("the benchmark input tree had uncommitted changes")
if composed_before["calls"] < LATENCY_PINNABLE_MIN_CALLS:
    latency_pinnable_reasons.append(
        f"the run took {composed_before['calls']} calls, fewer than "
        f"{LATENCY_PINNABLE_MIN_CALLS}"
    )
if environment["loadAverage1m"] > LATENCY_PINNABLE_MAX_LOAD_1M:
    latency_pinnable_reasons.append(
        f"the one-minute load average was {environment['loadAverage1m']}, above "
        f"{LATENCY_PINNABLE_MAX_LOAD_1M}"
    )
latency_pinnable = not latency_pinnable_reasons

UNPINNED = "\\textnormal{[unpinned]}"
NOT_SEPARABLE = "\\textnormal{[not separable]}"


def timing(value):
    """A measured duration or a verdict over two of them, or a marker when this
    run cannot pin one. A separability verdict is as unquotable as the
    intervals it was taken over."""
    return value if latency_pinnable else UNPINNED

# --- counts over the corpora -------------------------------------------------

negative = baseline["negativeCorpus"]
driven = [entry for entry in negative if entry.get("composed") is not None]
no_analogue = [entry for entry in negative if entry.get("composed") is None]
# Only a case the corpus marks as an attack is counted as one. The null case is
# a call that must be admitted, and an informational case is driven to record a
# difference between the wirings that is not a security difference; counting
# either as an attack would inflate every count taken over the attack set.
attacks = [entry for entry in driven if entry["role"] == "attack"]
informational = [entry for entry in driven if entry["role"] == "informational"]
if len(driven) != len(attacks) + len(informational) + 1:
    raise SystemExit(
        "the driven cases do not partition into attacks, informational cases "
        "and one null case"
    )
# A case excluded from the attack counts has to be a call the composition
# admits, or the exclusion is hiding a denial that belongs in the counts.
for entry in informational:
    if not entry["composed"]["dispatched"]:
        raise SystemExit(
            f"{entry['baseline_case_id']} is recorded as informational and the "
            "composed wiring denied it; a denied case is an attack"
        )

# Two Chio cases can collapse onto one baseline experiment, because the
# composition has one mechanism where Chio has two. An experiment is a drive
# against a receiver state, so the same drive against different state counts
# twice and the same drive against the same state counts once.
drive_ids = [entry["drive_id"] for entry in attacks]
distinct_drives = sorted(set(drive_ids))
collapsed_drives = [
    {
        "driveId": drive_id,
        "threatIds": [entry["threat_id"] for entry in attacks if entry["drive_id"] == drive_id],
        "caseIds": [
            entry["baseline_case_id"] for entry in attacks if entry["drive_id"] == drive_id
        ],
    }
    for drive_id in distinct_drives
    if drive_ids.count(drive_id) > 1
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
        "informational": len(informational),
        "distinctDrives": len(distinct_drives),
        "composedAdmits": len(composed_admits),
        "hardenedAdmits": len(hardened_admits),
        "closedByHardening": len(hardening_closes),
        "composedAdmittedCaseIds": [entry["baseline_case_id"] for entry in composed_admits],
        "hardenedAdmittedCaseIds": [entry["baseline_case_id"] for entry in hardened_admits],
        "noAnalogueCaseIds": [entry["baseline_case_id"] for entry in no_analogue],
        "informationalCaseIds": [entry["baseline_case_id"] for entry in informational],
        "collapsedDrives": collapsed_drives,
        "entries": negative,
    },
    "substitutionCorpus": {
        "bindingFields": SUBSTITUTION_FIELDS,
        "rows": SUBSTITUTION_ROWS,
        "noticedComposedRows": len(noticed_composed),
        "noticedHardenedRows": len(noticed_hardened),
        "notCarriedRows": len(not_carried),
        "notCarriedFields": len(not_carried_fields),
        "noticedFields": len(noticed_fields),
        "carriedNeverComparedFields": len(carried_never_compared_fields),
        "notCarriedFieldNames": not_carried_fields,
        "carriedNeverComparedFieldNames": carried_never_compared_fields,
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
            "hardenedAdmittedCallVerdict": whole_path_verdict,
            "hardeningCostWholePathP50Ms": (
                hardening_cost_ms if whole_path_verdict == "separated" else None
            ),
            "checksOnlyP50Us": composed_checks_us,
            "hardenedChecksOnlyP50Us": hardened_checks_us,
            "hardenedChecksOnlyMeanCiLowUs": hardened_ci[0],
            "hardenedChecksOnlyMeanCiHighUs": hardened_ci[1],
            "hardeningChecksCostP50Us": hardening_checks_cost_us,
            "hardeningCostVerdict": hardening_verdict,
            "durableClaimsP50Us": composed_claim_us,
            "hardenedDurableClaimsP50Us": hardened_claim_us,
            "hardeningDurableClaimCostP50Us": claim_cost_us,
            "hardeningDurableClaimVerdict": claim_verdict,
            "checksShareOfAdmittedCall": checks_share,
            "durableBytesPerCall": base_bytes_per_call,
            "hardenedDurableBytesPerCall": hardened_before["durable_bytes_per_call"],
            "hardeningStorageCostBytesPerCall": (
                hardened_before["durable_bytes_per_call"] - base_bytes_per_call
            ),
            "latencyPinnable": latency_pinnable,
            "latencyUnpinnableBecause": latency_pinnable_reasons,
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
            "storageChioOverAlternativeUpperBound": (
                chio_storage_bytes_per_call / base_bytes_per_call
            ),
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
        "storage": (
            "the two sides are read by two procedures and the ratio is a bound, "
            "not a measurement: the alternative's store is read after PRAGMA "
            "wal_checkpoint(TRUNCATE) on both the before and the after reading, "
            "so its delta is main-database growth with the write-ahead log "
            "excluded, while the Chio figure is read from the committed "
            "sustained-load record, which sums the database, its -wal and its "
            "-shm without checkpointing and so carries the log's high-water mark "
            "in its delta. The Chio side is inflated by that amount and the "
            "alternative's is not, so the ratio is an upper bound on how much "
            "more durable state a Chio admission leaves behind"
        ),
        "ratios": (
            "the latency ratio compares two whole admission paths and attributes "
            "nothing: no measurement here isolates the cost of any individual "
            "property, and the two paths differ in more than the properties they "
            "reach. It is against the local Chio path (treaty_predispatch_allow) "
            "because the alternative is in-process, and never against the "
            "federated figure"
        ),
        "pinnableTimings": (
            "a timing is written into the macros only from a run the paper could "
            "reproduce: a clean input tree, at least "
            f"{LATENCY_PINNABLE_MIN_CALLS} calls, and a one-minute load average "
            f"no higher than {LATENCY_PINNABLE_MAX_LOAD_1M}. A run that misses "
            "any of these still writes its corpora and its property verdicts, "
            "which are exact functions of the source, and writes [unpinned] "
            "wherever a duration would go"
        ),
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
            "the hardened wiring runs seven checks the composed wiring does not, "
            "and makes one more durable write: the replay claim on the "
            "identifier the decision carries for itself. The checks are costed "
            "over the checks span alone, because against a store that fsyncs a "
            "whole-path delta of that size is not resolvable; the extra write is "
            "costed over the durable-claim span, which is measured separately "
            "for that reason. Each verdict is over the two mean intervals of its "
            "own span, and the whole-path pair carries a verdict of its own "
            "because the two wirings are measured in two separate conditions"
        ),
        "checksSpan": (
            "the span from the start of peer resolution to the end of rule "
            "evaluation, less the durable replay claims that sit inside it. The "
            "argument digest, the decision parse, the record encoding and the "
            "record signature are outside it, so what is left over from an "
            "admitted call is everything that is not the checks span, dominated "
            "by the durable writes: two under the composed wiring, three under "
            "the hardened one"
        ),
        "propertyVerdicts": (
            "derived from cases the run drove, not asserted: a property fails "
            "only when a driven case dispatched a call the property forbids"
        ),
        "attackCounts": (
            "taken over the cases the corpus marks as attacks. The null case is "
            "a call that must be admitted, and an informational case is driven "
            "to record a difference between the wirings that is not a security "
            "difference; both are reported separately and neither is counted as "
            "an attack. Distinct drives counts the experiments behind those "
            "cases, since two Chio cases can collapse onto one baseline drive"
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
    ("PSBaseNegativeInformational", str(len(informational))),
    ("PSBaseNegativeDistinctDrives", str(len(distinct_drives))),
    ("PSBaseComposedAdmits", str(len(composed_admits))),
    ("PSBaseHardenedAdmits", str(len(hardened_admits))),
    ("PSBaseClosedByHardening", str(len(hardening_closes))),
    ("PSBaseSubstFields", str(SUBSTITUTION_FIELDS)),
    ("PSBaseSubstRows", str(SUBSTITUTION_ROWS)),
    ("PSBaseSubstNoticedComposedRows", str(len(noticed_composed))),
    ("PSBaseSubstNoticedHardenedRows", str(len(noticed_hardened))),
    ("PSBaseSubstNotCarriedRows", str(len(not_carried))),
    ("PSBaseSubstNotCarriedFields", str(len(not_carried_fields))),
    ("PSBaseSubstNoticedFields", str(len(noticed_fields))),
    ("PSBaseSubstCarriedNeverComparedFields", str(len(carried_never_compared_fields))),
    ("PSBasePropsHoldComposed", str(property_count("composed", "holds"))),
    ("PSBasePropsWeakComposed", str(property_count("composed", "holds_weakened"))),
    ("PSBasePropsFailComposed", str(property_count("composed", "fails"))),
    ("PSBasePropsHoldHardened", str(property_count("hardened", "holds"))),
    ("PSBasePropsWeakHardened", str(property_count("hardened", "holds_weakened"))),
    ("PSBasePropsFailHardened", str(property_count("hardened", "fails"))),
    ("PSBaseAllowPFiftyMs", timing(f"{base_allow_ms:.3f}")),
    ("PSBaseAllowPNinetyNineMs", timing(f"{composed_before['latency']['p99_us'] / 1000.0:.3f}")),
    ("PSBaseAllowMeanMs", timing(f"{composed_before['latency']['mean_us'] / 1000.0:.3f}")),
    ("PSBaseAllowMeanCiLowMs", timing(f"{composed_before['latency']['ci_low_us'] / 1000.0:.3f}")),
    (
        "PSBaseAllowMeanCiHighMs",
        timing(f"{composed_before['latency']['ci_high_us'] / 1000.0:.3f}"),
    ),
    ("PSBaseAllowSampleCount", str(composed_before["latency"]["samples"])),
    ("PSBaseResponsePFiftyMs", timing(f"{base_response_ms:.3f}")),
    ("PSBaseOrderingCostMs", timing(f"{ordering_cost_ms:.3f}")),
    # The two wirings' whole paths are measured in two separate conditions, so
    # this one is quotable only when their mean intervals are disjoint.
    (
        "PSBaseHardenedAllowPFiftyMs",
        timing(f"{hardened_allow_ms:.3f}" if whole_path_verdict == "separated" else NOT_SEPARABLE),
    ),
    ("PSBaseHardenedAllowVerdict", timing(whole_path_verdict)),
    ("PSBaseChecksPFiftyUs", timing(f"{composed_checks_us:.1f}")),
    ("PSBaseHardenedChecksPFiftyUs", timing(f"{hardened_checks_us:.1f}")),
    ("PSBaseHardeningChecksCostUs", timing(f"{hardening_checks_cost_us:.1f}")),
    ("PSBaseHardeningCostVerdict", timing(hardening_verdict)),
    ("PSBaseClaimPFiftyUs", timing(f"{composed_claim_us:.1f}")),
    ("PSBaseHardenedClaimPFiftyUs", timing(f"{hardened_claim_us:.1f}")),
    ("PSBaseHardeningClaimCostUs", timing(f"{claim_cost_us:.1f}")),
    ("PSBaseHardeningClaimVerdict", timing(claim_verdict)),
    ("PSBaseChecksSharePercent", timing(f"{checks_share * 100.0:.2f}")),
    ("PSBaseBytesPerCall", f"{base_bytes_per_call:.1f}"),
    ("PSBaseHardenedBytesPerCall", f"{hardened_before['durable_bytes_per_call']:.1f}"),
    ("PSBaseRequestWireBytes", str(composed_before["request_wire_bytes"])),
    ("PSBaseChioAllowPFiftyMs", f"{chio_allow_ms:.3f}"),
    ("PSBaseChioAppendPFiftyMs", f"{chio_append_ms:.3f}"),
    ("PSBaseChioKiBPerCall", f"{chio_storage_bytes_per_call / 1024.0:.2f}"),
    ("PSBaseLatencyRatio", timing(f"{chio_allow_ms / base_allow_ms:.2f}")),
    (
        "PSBaseStorageRatioUpperBound",
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
