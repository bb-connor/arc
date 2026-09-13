#!/usr/bin/env bash
set -euo pipefail

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
SOURCE="${CHIO_SOURCE:-$ROOT}"
if [[ ! -d "$SOURCE/crates" || ! -f "$SOURCE/Cargo.toml" ]]; then
  echo "CHIO_SOURCE does not name a Chio workspace: $SOURCE" >&2
  exit 2
fi
SOURCE="$(cd "$SOURCE" && pwd -P)"
GENERATOR="$SOURCE/scripts/generate-programmable-sovereignty-artifact.py"
SOURCE_COMMIT="$(git -C "$SOURCE" rev-parse HEAD)"
INPUT_PATHS=()
while IFS= read -r input_path; do
  INPUT_PATHS+=("$input_path")
done < <(python3 "$GENERATOR" --benchmark-input-paths PS-B01)
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
  python3 "$GENERATOR" --source-commit "$SOURCE_COMMIT" --benchmark-input-digest PS-B01
)"
SUSTAINED_INPUT_TREE_SHA256="$(
  python3 "$GENERATOR" --source-commit "$SOURCE_COMMIT" --benchmark-input-digest PS-B03
)"

RESULT_DIR="${CHIO_PAPER_RESULT_DIR:-$SCRIPT_DIR/results}"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-bilateral-target}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chio-bilateral-admission-bench.XXXXXX")"
SAMPLES="${CHIO_BENCH_SAMPLES:-100}"
WARMUPS="${CHIO_BENCH_WARMUPS:-2}"
CRITERION_SAMPLES="${CHIO_CRITERION_SAMPLES:-100}"
SUSTAINED_SECONDS="${CHIO_SUSTAINED_SECONDS:-60}"
SUSTAINED_SWEEP_SECONDS="${CHIO_SUSTAINED_SWEEP_SECONDS:-5}"
# Empty lets the load generator derive its ladder from the core count.
SUSTAINED_CONCURRENCY="${CHIO_SUSTAINED_CONCURRENCY:-}"
MAX_LOAD="${CHIO_BENCH_MAX_LOAD:-4.0}"

case "$SAMPLES:$WARMUPS:$CRITERION_SAMPLES:$SUSTAINED_SECONDS:$SUSTAINED_SWEEP_SECONDS" in
  *[!0-9:]*)
    echo "benchmark sample, warmup, and duration settings must be nonnegative integers" >&2
    exit 2
    ;;
esac
if [[ "$SAMPLES" -lt 2 || "$CRITERION_SAMPLES" -lt 10 || "$SUSTAINED_SECONDS" -lt 1 ]]; then
  echo "CHIO_BENCH_SAMPLES must be at least 2, CHIO_CRITERION_SAMPLES at least 10, and CHIO_SUSTAINED_SECONDS at least 1" >&2
  exit 2
fi
if [[ "$SUSTAINED_SWEEP_SECONDS" -lt 1 ]]; then
  echo "CHIO_SUSTAINED_SWEEP_SECONDS must be at least 1" >&2
  exit 2
fi
if [[ -n "$SUSTAINED_CONCURRENCY" \
  && ! "$SUSTAINED_CONCURRENCY" =~ ^[1-9][0-9]*(,[1-9][0-9]*)*$ ]]; then
  echo "CHIO_SUSTAINED_CONCURRENCY must be a comma separated list of positive integers: $SUSTAINED_CONCURRENCY" >&2
  exit 2
fi
if [[ ! "$MAX_LOAD" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "CHIO_BENCH_MAX_LOAD must be a nonnegative decimal number: $MAX_LOAD" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR" "$TARGET_DIR"
RESULT_DIR="$(cd "$RESULT_DIR" && pwd -P)"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

RAW_CSV="$RESULT_DIR/bilateral-admission-raw.csv"
COMPONENT_CSV="$RESULT_DIR/bilateral-admission-components.csv"
RESULT_JSON="$RESULT_DIR/bilateral-admission.json"
INLINE="$RESULT_DIR/bilateral-admission-inline.tex"
ENVIRONMENT="$RESULT_DIR/bilateral-admission-environment.txt"
ENVIRONMENT_JSON="$RESULT_DIR/bilateral-admission-environment.json"
SUSTAINED_JSON="$RESULT_DIR/bilateral-admission-sustained-load.json"
CRITERION_RESULT_DIR="$RESULT_DIR/criterion"
BUILD_LOG="$RESULT_DIR/bilateral-admission-build.log"
CRITERION_LOG="$RESULT_DIR/bilateral-admission-criterion.log"
NEGATIVE_LOG="$RESULT_DIR/bilateral-admission-negative-matrix.log"
SUSTAINED_LOG="$RESULT_DIR/bilateral-admission-sustained-load.log"
SAMPLES_DIR="$WORK_DIR/samples"
SUSTAINED_RAW="$WORK_DIR/sustained-load.json"

CRITERION_CASES=(
  receipt_sign
  receipt_verify
  receipt_append_sqlite
  treaty_predispatch_deny
  treaty_predispatch_allow
  strict_bilateral_dsse_verify
  cross_boundary_admission_allow
  buyer_proof_package_verify
)
PER_INVOCATION_CASES=(
  treaty_predispatch_deny
  treaty_predispatch_allow
  receipt_append_sqlite
)

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
    PLATFORM_DETAIL="$(sw_vers 2>/dev/null || true)"$'\n'"$(sysctl hw.ncpu hw.memsize hw.perflevel0.physicalcpu 2>/dev/null || true)"
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
  printf 'end_to_end_samples=%s\n' "$SAMPLES"
  printf 'end_to_end_warmups=%s\n' "$WARMUPS"
  printf 'criterion_samples=%s\n' "$CRITERION_SAMPLES"
  printf 'sustained_seconds=%s\n' "$SUSTAINED_SECONDS"
  printf 'sustained_sweep_seconds=%s\n' "$SUSTAINED_SWEEP_SECONDS"
  if [[ -n "$SUSTAINED_CONCURRENCY" ]]; then
    printf 'sustained_concurrency=%s\n' "$SUSTAINED_CONCURRENCY"
  else
    printf 'sustained_concurrency=derived from the core count\n'
  fi
  printf 'runtime_stores=SQLite\n'
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

# ---- Build -----------------------------------------------------------------

(
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release -p chio-cli --bin chio
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release \
    -p chio-spec-validate --bin chio-spec-validate
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release \
    -p chio-runtime-core --example treaty_sustained_load
) > "$BUILD_LOG" 2>&1

CHIO_BIN="$TARGET_DIR/release/chio"
SPEC_VALIDATE_BIN="$TARGET_DIR/release/chio-spec-validate"
if [[ ! -x "$CHIO_BIN" || ! -x "$SPEC_VALIDATE_BIN" ]]; then
  echo "release benchmark binaries were not produced" >&2
  exit 1
fi

# ---- Component benchmarks --------------------------------------------------

mkdir -p "$SAMPLES_DIR"
run_criterion_bench() {
  local package="$1"
  local bench="$2"
  (
    cd "$SOURCE"
    CARGO_TARGET_DIR="$TARGET_DIR" CHIO_PAPER_SAMPLES_DIR="$SAMPLES_DIR" \
      cargo bench -p "$package" --bench "$bench" -- \
      --sample-size "$CRITERION_SAMPLES" \
      --warm-up-time 1 \
      --measurement-time 3 \
      --noplot
  ) >> "$CRITERION_LOG" 2>&1
}

: > "$CRITERION_LOG"
run_criterion_bench chio-kernel paper_security_components
run_criterion_bench chio-federation bilateral_verify
run_criterion_bench chio-runtime-core cross_boundary_admission
run_criterion_bench chio-attest-buyer-core buyer_verify

rm -rf "$CRITERION_RESULT_DIR"
for case_name in "${CRITERION_CASES[@]}"; do
  for name in estimates.json sample.json; do
    source_path="$TARGET_DIR/criterion/$case_name/new/$name"
    if [[ ! -f "$source_path" ]]; then
      echo "missing Criterion output: $source_path" >&2
      exit 1
    fi
    mkdir -p "$CRITERION_RESULT_DIR/$case_name"
    cp "$source_path" "$CRITERION_RESULT_DIR/$case_name/$name"
  done
done
for case_name in "${PER_INVOCATION_CASES[@]}"; do
  if [[ ! -f "$SAMPLES_DIR/$case_name.csv" ]]; then
    echo "missing per-invocation samples: $SAMPLES_DIR/$case_name.csv (the bench must honor CHIO_PAPER_SAMPLES_DIR)" >&2
    exit 1
  fi
  cp "$SAMPLES_DIR/$case_name.csv" "$RESULT_DIR/bilateral-admission-$case_name-samples.csv"
done

# ---- Workflow paths --------------------------------------------------------

now_ns() {
  local stamp
  stamp="$(date +%s%N)"
  if [[ ! "$stamp" =~ ^[0-9]{16,}$ ]]; then
    echo "date does not report nanoseconds (got '$stamp'); GNU date is required for workflow timing" >&2
    return 1
  fi
  printf '%s\n' "$stamp"
}

printf 'path,sample,elapsed_ns,proof_package_bytes\n' > "$RAW_CSV"

file_size_bytes() {
  local path="$1"
  local size
  if size="$(stat -c %s -- "$path" 2>/dev/null)"; then
    :
  elif size="$(stat -f %z "$path" 2>/dev/null)"; then
    :
  else
    echo "cannot determine file size: $path" >&2
    return 1
  fi
  case "$size" in
    ''|*[!0-9]*)
      echo "stat returned a nonnumeric file size for $path: $size" >&2
      return 1
      ;;
  esac
  printf '%s\n' "$size"
}

run_hero_sample() {
  local mode="$1"
  local label="$2"
  local sample="$3"
  local out_dir="$WORK_DIR/$label-$sample"
  local log="$WORK_DIR/$label-$sample.log"
  local start_ns
  local end_ns
  start_ns="$(now_ns)"
  if ! (
    cd "$SOURCE"
    CHIO_BIN="$CHIO_BIN" \
      CHIO_SPEC_VALIDATE_BIN="$SPEC_VALIDATE_BIN" \
      CHIO_HERO_OUTPUT_DIR="$out_dir" \
      bash scripts/check-chio-treaty-buyer-hero-loop.sh "$mode"
  ) > "$log" 2>&1; then
    cp "$log" "$RESULT_DIR/bilateral-admission-$label-failure.log"
    return 1
  fi
  end_ns="$(now_ns)"
  local proof_bytes
  proof_bytes="$(file_size_bytes "$out_dir/proof-package.json")"
  printf '%s,%s,%s,%s\n' \
    "$label" "$sample" "$((end_ns - start_ns))" "$proof_bytes" >> "$RAW_CSV"
  rm -rf "$out_dir" "$log"
}

for warmup in $(seq 1 "$WARMUPS"); do
  run_hero_sample --producer-only producer_warmup "$warmup"
  run_hero_sample --packet-only full_warmup "$warmup"
done

for sample in $(seq 1 "$SAMPLES"); do
  run_hero_sample --producer-only producer_without_buyer_review "$sample"
done
for sample in $(seq 1 "$SAMPLES"); do
  run_hero_sample --packet-only complete_buyer_workflow "$sample"
done

# ---- Negative matrix -------------------------------------------------------

negative_start_ns="$(now_ns)"
if ! (
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" \
    CHIO_TEST_PROFILE=release \
    bash scripts/check-chio-live-treaty-buyer-closure.sh --matrix-only
) > "$NEGATIVE_LOG" 2>&1; then
  exit 1
fi
negative_end_ns="$(now_ns)"
negative_elapsed_ns=$((negative_end_ns - negative_start_ns))

# ---- Sustained load --------------------------------------------------------

# The generator keeps one throwaway receipt store per call in flight and
# clears each phase before the next, so WORK_DIR needs room for the widest
# phase rather than the whole run.
SUSTAINED_ARGS=(
  --seconds "$SUSTAINED_SECONDS"
  --sweep-seconds "$SUSTAINED_SWEEP_SECONDS"
  --store-dir "$WORK_DIR/sustained-stores"
  --out "$SUSTAINED_RAW"
)
if [[ -n "$SUSTAINED_CONCURRENCY" ]]; then
  SUSTAINED_ARGS+=(--concurrency "$SUSTAINED_CONCURRENCY")
fi
if ! (
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo run --release -p chio-runtime-core \
    --example treaty_sustained_load -- "${SUSTAINED_ARGS[@]}"
) > "$SUSTAINED_LOG" 2>&1; then
  echo "sustained-load run failed; see $SUSTAINED_LOG" >&2
  exit 1
fi
if [[ ! -f "$SUSTAINED_RAW" ]]; then
  echo "sustained-load run wrote no result: $SUSTAINED_RAW" >&2
  exit 1
fi

# ---- Aggregation -----------------------------------------------------------

python3 - "$CRITERION_RESULT_DIR" "$RESULT_DIR" "$RAW_CSV" "$COMPONENT_CSV" \
  "$RESULT_JSON" "$ENVIRONMENT_JSON" "$SUSTAINED_RAW" "$SUSTAINED_JSON" \
  "$SOURCE" "$SAMPLES" "$WARMUPS" "$CRITERION_SAMPLES" "$SUSTAINED_SECONDS" \
  "$negative_elapsed_ns" "$SOURCE_COMMIT" "$SOURCE_DIRTY" \
  "$BENCHMARK_INPUT_TREE_SHA256" "$SUSTAINED_INPUT_TREE_SHA256" <<'PY'
import csv
import json
import math
import pathlib
import random
import sys

(
    criterion_dir,
    result_dir,
    raw_csv,
    component_csv,
    result_json,
    environment_json,
    sustained_raw,
    sustained_json,
    source,
    samples,
    warmups,
    criterion_samples,
    sustained_seconds,
    negative_elapsed_ns,
    source_commit,
    source_dirty,
    benchmark_input_tree_sha256,
    sustained_input_tree_sha256,
) = sys.argv[1:]
criterion = pathlib.Path(criterion_dir)
results = pathlib.Path(result_dir)
criterion_samples = int(criterion_samples)

BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 1
CONFIDENCE = 0.95

PER_INVOCATION = {
    "treaty_predispatch_deny": (
        "full kernel path; real hook, SQLite denial receipt, tool uninvoked"
    ),
    "treaty_predispatch_allow": (
        "full kernel path; real hook, SQLite receipt, one real tool dispatch"
    ),
    "receipt_append_sqlite": "SQLite receipt store",
}
BATCH_MEAN = {
    "receipt_sign": "Ed25519 over the evaluated receipt shape",
    "receipt_verify": "Ed25519 over the evaluated receipt shape",
    "strict_bilateral_dsse_verify": (
        "two signatures over the canonical statement; schema and self-consistency checks"
    ),
    "cross_boundary_admission_allow": (
        "receiver treaty scope and verified evidence"
    ),
    "buyer_proof_package_verify": "offline three-vendor receiver verification",
}
WORKFLOW_NOTE = "release binaries; process and schema-validation costs included"


def percentile(ordered, quantile):
    if not ordered:
        raise SystemExit("cannot take a percentile of an empty sample")
    position = quantile * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def mean(values):
    return math.fsum(values) / len(values)


def sample_std(values):
    if len(values) < 2:
        return 0.0
    center = mean(values)
    return math.sqrt(
        math.fsum((value - center) ** 2 for value in values) / (len(values) - 1)
    )


def bootstrap_ci(values):
    rng = random.Random(BOOTSTRAP_SEED)
    count = len(values)
    means = sorted(
        math.fsum(rng.choices(values, k=count)) / count
        for _ in range(BOOTSTRAP_RESAMPLES)
    )
    alpha = (1.0 - CONFIDENCE) / 2.0
    return percentile(means, alpha), percentile(means, 1.0 - alpha)


def bootstrap_median_ci(ordered):
    """Percentile bootstrap interval for the median of `ordered`."""
    rng = random.Random(BOOTSTRAP_SEED)
    count = len(ordered)
    medians = sorted(
        percentile(sorted(rng.choices(ordered, k=count)), 0.50)
        for _ in range(BOOTSTRAP_RESAMPLES)
    )
    alpha = (1.0 - CONFIDENCE) / 2.0
    return percentile(medians, alpha), percentile(medians, 1.0 - alpha)


def median_interval_gaps(node, location="$"):
    """Names every reported median that is missing the interval beside it."""
    gaps = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key.startswith("p50_") and not key.startswith("p50_ci_"):
                unit = key[len("p50_") :]
                for bound in ("low", "high"):
                    needed = f"p50_ci_{bound}_{unit}"
                    beside = node.get(needed)
                    if not isinstance(beside, (int, float)) or isinstance(beside, bool):
                        gaps.append(f"{location}.{key} has no {needed}")
            gaps.extend(median_interval_gaps(value, f"{location}.{key}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            gaps.extend(median_interval_gaps(value, f"{location}[{index}]"))
    return gaps


def summarize(values, unit):
    if len(values) < 2:
        raise SystemExit("a summary needs at least two observations")
    ordered = sorted(values)
    low, high = bootstrap_ci(ordered)
    median_low, median_high = bootstrap_median_ci(ordered)
    return {
        "samples": len(ordered),
        f"p50_{unit}": percentile(ordered, 0.50),
        f"p50_ci_low_{unit}": median_low,
        f"p50_ci_high_{unit}": median_high,
        f"p99_{unit}": percentile(ordered, 0.99),
        f"mean_{unit}": mean(ordered),
        f"std_{unit}": sample_std(ordered),
        f"ci_low_{unit}": low,
        f"ci_high_{unit}": high,
        f"min_{unit}": ordered[0],
        f"max_{unit}": ordered[-1],
    }


def load_json(path):
    if not path.is_file():
        raise SystemExit(f"missing result input: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"{path} is not valid JSON: {error}") from error


def estimate(document, path, *keys):
    node = document
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            raise SystemExit(f"{path} lacks {'.'.join(keys)}")
        node = node[key]
    if not isinstance(node, (int, float)):
        raise SystemExit(f"{path} has a nonnumeric {'.'.join(keys)}")
    return float(node)


def per_invocation_component(name, note):
    path = results / f"bilateral-admission-{name}-samples.csv"
    if not path.is_file():
        raise SystemExit(f"missing per-invocation samples: {path}")
    with open(path, newline="", encoding="utf-8") as sample_file:
        reader = csv.DictReader(sample_file)
        if reader.fieldnames != ["invocation", "elapsed_ns"]:
            raise SystemExit(f"{path} does not have the header invocation,elapsed_ns")
        observations_us = []
        for row in reader:
            elapsed_ns = int(row["elapsed_ns"])
            if elapsed_ns <= 0:
                raise SystemExit(f"{path} records a nonpositive elapsed time")
            observations_us.append(elapsed_ns / 1000.0)
    if len(observations_us) < 2:
        raise SystemExit(f"{path} holds fewer than two invocations")
    summary = summarize(observations_us, "us")
    return {
        "component": name,
        "kind": "per_invocation",
        "note": note,
        **summary,
    }


def batch_mean_component(name, note):
    sample_path = criterion / name / "sample.json"
    estimates_path = criterion / name / "estimates.json"
    sample = load_json(sample_path)
    estimates = load_json(estimates_path)
    times = sample.get("times")
    iters = sample.get("iters")
    if not isinstance(times, list) or not isinstance(iters, list) or len(times) != len(iters):
        raise SystemExit(f"{sample_path} lacks matching times and iters lists")
    if len(times) != criterion_samples:
        raise SystemExit(
            f"{sample_path} holds {len(times)} samples, expected {criterion_samples}"
        )
    batch_means_us = sorted(
        float(elapsed_ns) / float(iterations) / 1000.0
        for elapsed_ns, iterations in zip(times, iters)
    )
    iterations = [int(value) for value in iters]
    median_low, median_high = bootstrap_median_ci(batch_means_us)
    return {
        "component": name,
        "kind": "batch_mean",
        "note": note,
        "samples": len(batch_means_us),
        "p50_us": percentile(batch_means_us, 0.50),
        "p50_ci_low_us": median_low,
        "p50_ci_high_us": median_high,
        "max_us": batch_means_us[-1],
        "min_us": batch_means_us[0],
        "mean_us": estimate(estimates, estimates_path, "mean", "point_estimate") / 1000.0,
        "std_us": estimate(estimates, estimates_path, "std_dev", "point_estimate") / 1000.0,
        "ci_low_us": estimate(
            estimates, estimates_path, "mean", "confidence_interval", "lower_bound"
        ) / 1000.0,
        "ci_high_us": estimate(
            estimates, estimates_path, "mean", "confidence_interval", "upper_bound"
        ) / 1000.0,
        "batchIterations": {"min": min(iterations), "max": max(iterations)},
    }


components = [
    *[per_invocation_component(name, note) for name, note in PER_INVOCATION.items()],
    *[batch_mean_component(name, note) for name, note in BATCH_MEAN.items()],
]

with open(raw_csv, newline="", encoding="utf-8") as raw_file:
    raw_rows = list(csv.DictReader(raw_file))

paths = {}
for row in raw_rows:
    if row["path"].endswith("_warmup"):
        continue
    paths.setdefault(row["path"], []).append(int(row["elapsed_ns"]) / 1_000_000.0)

path_summaries = {
    label: summarize(observations_ms, "ms")
    for label, observations_ms in paths.items()
}
for required in ("complete_buyer_workflow", "producer_without_buyer_review"):
    if required not in path_summaries:
        raise SystemExit(f"{raw_csv} holds no {required} samples")
    if path_summaries[required]["samples"] != int(samples):
        raise SystemExit(
            f"{raw_csv} holds {path_summaries[required]['samples']} {required} "
            f"samples, expected {samples}"
        )

proof_sizes = {
    int(row["proof_package_bytes"])
    for row in raw_rows
    if row["path"] == "complete_buyer_workflow"
}
if len(proof_sizes) != 1:
    raise SystemExit(f"proof package size was not stable: {sorted(proof_sizes)}")
proof_package_bytes = proof_sizes.pop()

fixture_path = (
    pathlib.Path(source)
    / "examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
)
threat_fixture = load_json(fixture_path)
threat_cases = len(threat_fixture["cases"])
assumptions = len(threat_fixture["assumptions"])
negative_ms = int(negative_elapsed_ns) / 1_000_000.0


def nonnegative_int(document, key, source):
    value = document.get(key) if isinstance(document, dict) else None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SystemExit(f"{source} lacks a nonnegative integer {key}")
    return value


def positive_int(document, key, source):
    value = nonnegative_int(document, key, source)
    if value < 1:
        raise SystemExit(f"{source} lacks a positive {key}")
    return value


def positive_number(document, key, source):
    value = document.get(key) if isinstance(document, dict) else None
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
        raise SystemExit(f"{source} lacks a positive {key}")
    return float(value)


def load_phase(document, label):
    """Accepts one held phase only when it admitted and dispatched every call
    it offered at the number of calls it claims to have held in flight."""
    if not isinstance(document, dict):
        raise SystemExit(f"{label} is not a phase record")
    concurrency = positive_int(document, "concurrency", label)
    calls = positive_int(document, "calls", label)
    positive_number(document, "calls_per_second", label)
    positive_number(document, "elapsed_seconds", label)
    if nonnegative_int(document, "dispatch_count", label) != calls:
        raise SystemExit(f"{label} did not dispatch exactly once per call")
    if nonnegative_int(document, "denials", label) != 0:
        raise SystemExit(f"{label} recorded a denial")
    if nonnegative_int(document, "in_flight_peak", label) != concurrency:
        raise SystemExit(
            f"{label} offered {concurrency} calls in flight and never held that many"
        )
    return document


sustained_source = pathlib.Path(sustained_raw)
sustained_raw_document = load_json(sustained_source)
for key in (
    "seconds",
    "calls",
    "dispatch_count",
    "denials",
    "receipt_store_bytes_before",
    "receipt_store_bytes_after",
):
    nonnegative_int(sustained_raw_document, key, sustained_source)
calls_per_second = positive_number(
    sustained_raw_document, "calls_per_second", sustained_source
)
if sustained_raw_document["seconds"] != int(sustained_seconds):
    raise SystemExit(
        f"{sustained_source} ran for {sustained_raw_document['seconds']} s, "
        f"expected {sustained_seconds}"
    )
if sustained_raw_document["denials"] != 0:
    raise SystemExit(f"sustained load recorded {sustained_raw_document['denials']} denials")
if sustained_raw_document["dispatch_count"] != sustained_raw_document["calls"]:
    raise SystemExit("sustained load dispatch count does not equal its call count")
if sustained_raw_document["calls"] < 1:
    raise SystemExit("sustained load recorded no calls")
bytes_before = sustained_raw_document["receipt_store_bytes_before"]
bytes_after = sustained_raw_document["receipt_store_bytes_after"]
if bytes_after < bytes_before:
    raise SystemExit("sustained load receipt store shrank")

concurrency = positive_int(sustained_raw_document, "concurrency", sustained_source)
cores = positive_int(sustained_raw_document, "cores", sustained_source)
held_in_flight = nonnegative_int(
    sustained_raw_document, "in_flight_peak", sustained_source
)
if held_in_flight != concurrency:
    raise SystemExit(
        f"{sustained_source} offered {concurrency} calls in flight and never held that many"
    )
hold = load_phase(sustained_raw_document.get("hold"), f"{sustained_source} hold")
if hold["concurrency"] != concurrency or hold["calls"] != sustained_raw_document["calls"]:
    raise SystemExit(f"{sustained_source} headline figures disagree with its hold phase")
sweep_document = sustained_raw_document.get("sweep")
if not isinstance(sweep_document, list) or not sweep_document:
    raise SystemExit(f"{sustained_source} holds no concurrency sweep")
sweep = [
    load_phase(point, f"{sustained_source} sweep point {index}")
    for index, point in enumerate(sweep_document)
]
swept = {point["concurrency"] for point in sweep}
if 1 not in swept:
    raise SystemExit(f"{sustained_source} swept no one-call-in-flight baseline")
if len(swept) < 2:
    raise SystemExit(
        f"{sustained_source} swept a single concurrency, so no knee can be visible"
    )
bottleneck = sustained_raw_document.get("bottleneck")
if not isinstance(bottleneck, dict) or not isinstance(
    bottleneck.get("classification"), str
):
    raise SystemExit(f"{sustained_source} names no bottleneck")
if bottleneck.get("peak_concurrency") != concurrency:
    raise SystemExit(
        f"{sustained_source} held a concurrency its sweep did not select as the peak"
    )
sustained_statistics = sustained_raw_document.get("statistics")
if not isinstance(sustained_statistics, dict):
    raise SystemExit(f"{sustained_source} records no statistical method")

sustained = {
    "seconds": sustained_raw_document["seconds"],
    "calls": sustained_raw_document["calls"],
    "callsPerSecond": float(calls_per_second),
    "concurrency": concurrency,
    "inFlightPeak": held_in_flight,
    "cores": cores,
    "dispatchCount": sustained_raw_document["dispatch_count"],
    "denials": sustained_raw_document["denials"],
    "receiptStoreBytesBefore": bytes_before,
    "receiptStoreBytesAfter": bytes_after,
    "receiptStoreGrowthKiB": (bytes_after - bytes_before) / 1024.0,
    "bottleneck": bottleneck,
    "hold": hold,
    "sweep": sweep,
    "statistics": sustained_statistics,
}

environment = load_json(pathlib.Path(environment_json))

with open(component_csv, "w", newline="", encoding="utf-8") as component_file:
    writer = csv.writer(component_file, lineterminator="\n")
    writer.writerow(
        [
            "component",
            "kind",
            "samples",
            "p50_us",
            "p50_ci_low_us",
            "p50_ci_high_us",
            "p99_us",
            "max_us",
            "mean_us",
            "std_us",
            "ci_low_us",
            "ci_high_us",
            "note",
        ]
    )
    for component in components:
        writer.writerow(
            [
                component["component"],
                component["kind"],
                component["samples"],
                f'{component["p50_us"]:.3f}',
                f'{component["p50_ci_low_us"]:.3f}',
                f'{component["p50_ci_high_us"]:.3f}',
                f'{component["p99_us"]:.3f}' if "p99_us" in component else "",
                f'{component["max_us"]:.3f}',
                f'{component["mean_us"]:.3f}',
                f'{component["std_us"]:.3f}',
                f'{component["ci_low_us"]:.3f}',
                f'{component["ci_high_us"]:.3f}',
                component["note"],
            ]
        )
    for label, summary in path_summaries.items():
        writer.writerow(
            [
                label,
                "workflow",
                summary["samples"],
                f'{summary["p50_ms"] * 1000.0:.3f}',
                f'{summary["p50_ci_low_ms"] * 1000.0:.3f}',
                f'{summary["p50_ci_high_ms"] * 1000.0:.3f}',
                f'{summary["p99_ms"] * 1000.0:.3f}',
                f'{summary["max_ms"] * 1000.0:.3f}',
                f'{summary["mean_ms"] * 1000.0:.3f}',
                f'{summary["std_ms"] * 1000.0:.3f}',
                f'{summary["ci_low_ms"] * 1000.0:.3f}',
                f'{summary["ci_high_ms"] * 1000.0:.3f}',
                WORKFLOW_NOTE,
            ]
        )

document = {
    "schema": "chio.programmable-sovereignty.bilateral-admission-results.v3",
    "commit": source_commit,
    "worktreeDirty": source_dirty == "true",
    "benchmarkInputTreeSha256": benchmark_input_tree_sha256,
    "profile": "release",
    "warmups": int(warmups),
    "samples": int(samples),
    "criterionSamples": criterion_samples,
    "stores": {
        "endToEnd": "SQLite",
        "receiptAppend": "SQLite",
    },
    "environment": environment,
    "statistics": {
        "percentile": "linear interpolation between order statistics",
        "confidence": CONFIDENCE,
        "bootstrap": {
            "statistics": ["mean", "median"],
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
            "appliesTo": [
                "paths",
                "per_invocation components",
                "batch_mean component medians",
            ],
        },
        "batchMean": (
            "Criterion estimates.json mean point estimate, standard deviation, "
            "and confidence interval; p50 and max are over Criterion batch "
            "means, and the p50 interval is a percentile bootstrap over them"
        ),
    },
    "paths": path_summaries,
    "components": components,
    "sustainedLoad": sustained,
    "negativeMatrix": {
        "cases": threat_cases,
        "elapsedMs": negative_ms,
        "explicitNonTestableAssumptions": assumptions,
    },
    "proofPackageBytes": proof_package_bytes,
}
sustained_document = {
    "schema": "chio.programmable-sovereignty.sustained-load-results.v2",
    "commit": source_commit,
    "worktreeDirty": source_dirty == "true",
    "benchmarkInputTreeSha256": sustained_input_tree_sha256,
    "profile": "release",
    **sustained,
}

for name, published in ((result_json, document), (sustained_json, sustained_document)):
    gaps = median_interval_gaps(published)
    if gaps:
        raise SystemExit(
            f"{name} reports a median with no interval beside it: " + "; ".join(gaps)
        )

pathlib.Path(result_json).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
pathlib.Path(sustained_json).write_text(
    json.dumps(sustained_document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

python3 "$GENERATOR" --render-inline "$RESULT_JSON" > "$INLINE"

if [[ "$RESULT_DIR" == "$SCRIPT_DIR/results" && "$SOURCE" == "$ROOT" ]]; then
  python3 "$GENERATOR" --write-measurements "$RESULT_JSON"
else
  printf 'results were written outside the tree; CLAIM_LEDGER.md was not updated\n'
fi

trap - ERR
printf 'bilateral admission benchmark complete: %s\n' "$RESULT_JSON"
