#!/usr/bin/env bash
set -euo pipefail

# Admission latency as a function of receipt-lineage depth.
#
# Section 6 names the lineage walk as the only part of admission linear in what
# the request presents. This measures it: one kernel per depth, the real runtime
# admission hook, a lineage bundle of that many verified statements, and two
# timed windows per call. The first is the receiver-side lineage work alone
# (resolve the bundle the request names from the receiver's own store, compare
# the digest the store recorded for it against the one the request cites, walk
# every edge). The second is the whole admitted call that contains it. Reporting
# both is the point: the linear term is real and it is small against the
# constant it sits inside.
#
# The depth is a property of the bundle the RECEIVER holds. A request names the
# bundle by id and digest and cannot carry one, so this is the cost of a deep
# lineage the receiver has already accepted, not a bundle a peer pushed at it.
#
#   ./run-admission-scaling.sh
#   CHIO_SCALING_DEPTHS=1,2,4,8,16,32,64 CHIO_SCALING_ITERATIONS=400 \
#     ./run-admission-scaling.sh

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

# The tree this measurement is a measurement OF. A change to any of these files
# changes the number, so a dirty one must not be pinned to a commit.
INPUT_PATHS=(
  "crates/kernel/chio-runtime-core/benches/admission_scaling.rs"
  "crates/kernel/chio-runtime-core/benches/fixtures/admission_scaling_fixture.rs"
  "crates/kernel/chio-runtime-core/src"
  "crates/kernel/chio-runtime-core/Cargo.toml"
  "crates/kernel/chio-kernel/src"
  "crates/platform/chio-store-sqlite/src"
  "docs/papers/programmable-sovereignty/bench/run-admission-scaling.sh"
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
# Hashed from the worktree rather than the index, so a run taken with
# CHIO_BENCH_ALLOW_DIRTY=1 names the code that was measured and not the last
# staged version of it.
BENCHMARK_INPUT_TREE_SHA256="$(
  cd "$SOURCE" && git ls-files -z -- "${INPUT_PATHS[@]}" \
    | xargs -0 sha256sum | sha256sum | cut -d ' ' -f 1
)"

RESULT_DIR="${CHIO_PAPER_RESULT_DIR:-$SCRIPT_DIR/results}"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-scaling-target}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chio-admission-scaling-bench.XXXXXX")"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

DEPTHS="${CHIO_SCALING_DEPTHS:-1,2,4,8,16,32}"
ITERATIONS="${CHIO_SCALING_ITERATIONS:-200}"
WARMUP="${CHIO_SCALING_WARMUP:-20}"
MAX_LOAD="${CHIO_BENCH_MAX_LOAD:-4.0}"
STAGE_TIMEOUT_SECS="${CHIO_SCALING_TIMEOUT_SECS:-3600}"

if [[ ! "$DEPTHS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  echo "CHIO_SCALING_DEPTHS must be a comma-separated list of whole numbers: $DEPTHS" >&2
  exit 2
fi
case "$ITERATIONS:$WARMUP:$STAGE_TIMEOUT_SECS" in
  *[!0-9:]*)
    echo "iteration, warm-up and timeout counts must be nonnegative integers" >&2
    exit 2
    ;;
esac
if [[ "$ITERATIONS" -lt 2 ]]; then
  echo "CHIO_SCALING_ITERATIONS must be at least 2: every reported distribution needs two observations" >&2
  exit 2
fi
DEPTH_COUNT="$(printf '%s' "$DEPTHS" | tr ',' '\n' | grep -c .)"
if [[ "$DEPTH_COUNT" -lt 3 ]]; then
  echo "CHIO_SCALING_DEPTHS must name at least three depths: two points are a line, not a shape" >&2
  exit 2
fi
if [[ ! "$MAX_LOAD" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "CHIO_BENCH_MAX_LOAD must be a nonnegative decimal number: $MAX_LOAD" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR" "$TARGET_DIR"
RESULT_DIR="$(cd "$RESULT_DIR" && pwd -P)"

RESULT_JSON="$RESULT_DIR/admission-scaling.json"
SAMPLES_CSV="$RESULT_DIR/admission-scaling-samples.csv"
INLINE="$RESULT_DIR/admission-scaling-inline.tex"
ENVIRONMENT="$RESULT_DIR/admission-scaling-environment.txt"
ENVIRONMENT_JSON="$RESULT_DIR/admission-scaling-environment.json"
BUILD_LOG="$RESULT_DIR/admission-scaling-build.log"
SWEEP_LOG="$RESULT_DIR/admission-scaling-sweep.log"

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}
trap 'emit_unreported; cleanup' ERR

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
  echo "no timeout(1) or gtimeout(1) on PATH; the measurement needs a wall-clock guard" >&2
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
  printf 'depths=%s\n' "$DEPTHS"
  printf 'iterations_per_depth=%s\n' "$ITERATIONS"
  printf 'warmup_per_depth=%s\n' "$WARMUP"
  printf 'receiver_stores=in-memory treaty artifacts, SQLite receipts\n'
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
pathlib.Path(output).write_text(
    json.dumps(
        {
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
        },
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
PY

# ---- Build and sweep --------------------------------------------------------

(
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release \
    -p chio-runtime-core --benches
) > "$BUILD_LOG" 2>&1

SAMPLES_DIR="$WORK_DIR/samples"
mkdir -p "$SAMPLES_DIR"
(
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" \
  CHIO_PAPER_SAMPLES_DIR="$SAMPLES_DIR" \
  CHIO_ADMISSION_SCALING_DEPTHS="$DEPTHS" \
  CHIO_ADMISSION_SCALING_ITERATIONS="$ITERATIONS" \
  CHIO_ADMISSION_SCALING_WARMUP="$WARMUP" \
    "$TIMEOUT_BIN" "$STAGE_TIMEOUT_SECS" cargo test --release \
      -p chio-runtime-core --bench admission_scaling -- --nocapture
) > "$SWEEP_LOG" 2>&1

# ---- Aggregate --------------------------------------------------------------

python3 - "$RESULT_JSON" "$SAMPLES_CSV" "$INLINE" "$ENVIRONMENT_JSON" \
  "$SAMPLES_DIR" "$SOURCE_COMMIT" "$SOURCE_DIRTY" "$ITERATIONS" "$WARMUP" \
  "$BENCHMARK_INPUT_TREE_SHA256" <<'PY'
import csv
import json
import math
import pathlib
import random
import sys

BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 1
CONFIDENCE = 0.95

(
    result_json,
    samples_csv,
    inline_out,
    environment_json,
    samples_dir,
    source_commit,
    source_dirty,
    iterations,
    warmup,
    benchmark_input_tree_sha256,
) = sys.argv[1:]

samples_dir = pathlib.Path(samples_dir)


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


def bootstrap_medians(values, seed):
    """Bootstrap replicates of the median, which is the statistic reported.

    Each series gets its own stream, so replicate `i` of one depth is drawn
    independently of replicate `i` of another and the replicates can be refitted
    against each other to put an interval on a slope.
    """
    rng = random.Random(seed)
    count = len(values)
    return [
        percentile(sorted(rng.choices(values, k=count)), 0.50)
        for _ in range(BOOTSTRAP_RESAMPLES)
    ]


def interval(replicates):
    ordered = sorted(replicates)
    alpha = (1.0 - CONFIDENCE) / 2.0
    return percentile(ordered, alpha), percentile(ordered, 1.0 - alpha)


def summarize(values, replicates):
    """One distribution, with an interval for the median and nothing else.

    `mean_us` and `std_us` describe the sample; the only interval reported is
    the one for the point estimate the macros print, so no interval can sit
    beside a number it does not bracket.
    """
    if len(values) < 2:
        raise SystemExit("a summary needs at least two observations")
    ordered = sorted(values)
    low, high = interval(replicates)
    return {
        "samples": len(ordered),
        "p50_us": percentile(ordered, 0.50),
        "p99_us": percentile(ordered, 0.99),
        "mean_us": mean(ordered),
        "std_us": sample_std(ordered),
        "median_ci_low_us": low,
        "median_ci_high_us": high,
        "min_us": ordered[0],
        "max_us": ordered[-1],
    }


def least_squares(xs, ys):
    """Slope, intercept and coefficient of determination of y against x."""
    n = len(xs)
    if n < 3:
        raise SystemExit("a fit needs at least three points")
    mean_x = mean(xs)
    mean_y = mean(ys)
    sxx = math.fsum((x - mean_x) ** 2 for x in xs)
    if sxx == 0.0:
        raise SystemExit("every point shares one depth; there is nothing to fit")
    sxy = math.fsum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = mean_y - slope * mean_x
    residual = math.fsum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    total = math.fsum((y - mean_y) ** 2 for y in ys)
    r_squared = 1.0 if total == 0.0 else 1.0 - residual / total
    return slope, intercept, r_squared


def fit_with_interval(xs, ys, replicates_by_point):
    """A slope and its interval, from the same replicates the points carry.

    Replicate `i` of the fit takes replicate `i` of every point, so the interval
    is the spread of the slope under the sampling noise in the points rather
    than a residual of a six-point line.
    """
    slope, intercept, r_squared = least_squares(xs, ys)
    slopes = []
    for index in range(BOOTSTRAP_RESAMPLES):
        replicate_slope, _, _ = least_squares(
            xs, [reps[index] for reps in replicates_by_point]
        )
        slopes.append(replicate_slope)
    low, high = interval(slopes)
    return {
        "slope": slope,
        "intercept": intercept,
        "rSquared": r_squared,
        "slopeCiLow": low,
        "slopeCiHigh": high,
        "slopeIntervalStraddlesZero": low <= 0.0 <= high,
    }


manifest_path = samples_dir / "admission_scaling_depths.csv"
if not manifest_path.exists():
    raise SystemExit(f"the sweep wrote no manifest at {manifest_path}")
with manifest_path.open(encoding="utf-8", newline="") as handle:
    manifest = list(csv.DictReader(handle))
if len(manifest) < 3:
    raise SystemExit("the sweep covered fewer than three depths")

rows = []
depths = []
lineage_replicates = []
call_replicates = []
for series, entry in enumerate(manifest):
    depth = int(entry["depth"])
    path = samples_dir / entry["samples_file"]
    with path.open(encoding="utf-8", newline="") as handle:
        samples = list(csv.DictReader(handle))
    if len(samples) != int(entry["samples"]):
        raise SystemExit(
            f"{path} holds {len(samples)} samples, the manifest declares {entry['samples']}"
        )
    call_us = [float(row["call_elapsed_ns"]) / 1_000.0 for row in samples]
    lineage_us = [float(row["lineage_elapsed_ns"]) / 1_000.0 for row in samples]
    for row in samples:
        rows.append(
            {
                "depth": depth,
                "lineage_bundle_bytes": entry["lineage_bundle_bytes"],
                "invocation": row["invocation"],
                "call_elapsed_ns": row["call_elapsed_ns"],
                "lineage_elapsed_ns": row["lineage_elapsed_ns"],
            }
        )
    # Two independent streams per depth, so no two series share resample indices.
    lineage_reps = bootstrap_medians(lineage_us, BOOTSTRAP_SEED * 1000 + series * 2)
    call_reps = bootstrap_medians(call_us, BOOTSTRAP_SEED * 1000 + series * 2 + 1)
    lineage_replicates.append(lineage_reps)
    call_replicates.append(call_reps)
    call = summarize(call_us, call_reps)
    lineage = summarize(lineage_us, lineage_reps)
    depths.append(
        {
            "depth": depth,
            "lineageBundleBytes": int(entry["lineage_bundle_bytes"]),
            "lineageWalk": lineage,
            "admittedCall": call,
            # What the linear term is worth inside the in-process call this
            # fixture makes. That call carries no durable admission-operation
            # store, so the share is against a far smaller denominator than a
            # federated receiver's window.
            "lineageShareOfInProcessCall": lineage["p50_us"] / call["p50_us"],
        }
    )

xs = [entry["depth"] for entry in depths]
lineage_p50s = [entry["lineageWalk"]["p50_us"] for entry in depths]
call_p50s = [entry["admittedCall"]["p50_us"] for entry in depths]
lineage_fit = fit_with_interval(xs, lineage_p50s, lineage_replicates)
byte_fit = fit_with_interval(
    [entry["lineageBundleBytes"] for entry in depths], lineage_p50s, lineage_replicates
)
call_fit = fit_with_interval(xs, call_p50s, call_replicates)

with pathlib.Path(samples_csv).open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(
        handle,
        fieldnames=[
            "depth",
            "lineage_bundle_bytes",
            "invocation",
            "call_elapsed_ns",
            "lineage_elapsed_ns",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

shallowest = depths[0]
deepest = depths[-1]
document = {
    "schema": "chio.programmable-sovereignty.admission-scaling-results.v1",
    "commit": source_commit,
    "worktreeDirty": source_dirty == "true",
    "benchmarkInputTreeSha256": benchmark_input_tree_sha256,
    "profile": "release",
    "environment": json.loads(pathlib.Path(environment_json).read_text(encoding="utf-8")),
    "iterationsPerDepth": int(iterations),
    "warmupPerDepth": int(warmup),
    "depths": depths,
    "fit": {
        "lineageWalkPerStatementUs": lineage_fit["slope"],
        "lineageWalkPerStatementCiLowUs": lineage_fit["slopeCiLow"],
        "lineageWalkPerStatementCiHighUs": lineage_fit["slopeCiHigh"],
        "lineageWalkInterceptUs": lineage_fit["intercept"],
        "lineageWalkRSquared": lineage_fit["rSquared"],
        "lineageWalkPerByteUs": byte_fit["slope"],
        "lineageWalkPerByteCiLowUs": byte_fit["slopeCiLow"],
        "lineageWalkPerByteCiHighUs": byte_fit["slopeCiHigh"],
        "lineageWalkPerByteInterceptUs": byte_fit["intercept"],
        "lineageWalkPerByteRSquared": byte_fit["rSquared"],
        "admittedCallPerStatementUs": call_fit["slope"],
        "admittedCallPerStatementCiLowUs": call_fit["slopeCiLow"],
        "admittedCallPerStatementCiHighUs": call_fit["slopeCiHigh"],
        "admittedCallInterceptUs": call_fit["intercept"],
        "admittedCallRSquared": call_fit["rSquared"],
        "admittedCallSlopeIntervalStraddlesZero": call_fit[
            "slopeIntervalStraddlesZero"
        ],
    },
    "range": {
        "shallowestDepth": shallowest["depth"],
        "deepestDepth": deepest["depth"],
        "lineageWalkGrowth": deepest["lineageWalk"]["p50_us"]
        / shallowest["lineageWalk"]["p50_us"],
        "admittedCallGrowth": deepest["admittedCall"]["p50_us"]
        / shallowest["admittedCall"]["p50_us"],
        "lineageShareOfInProcessCallAtShallowest": shallowest[
            "lineageShareOfInProcessCall"
        ],
        "lineageShareOfInProcessCallAtDeepest": deepest["lineageShareOfInProcessCall"],
    },
    "method": {
        "percentile": "linear interpolation between order statistics",
        "confidence": CONFIDENCE,
        "bootstrap": {"resamples": BOOTSTRAP_RESAMPLES, "seed": BOOTSTRAP_SEED},
        "interval": (
            "every interval here is a percentile bootstrap interval for the MEDIAN, "
            "which is the point estimate reported beside it. A slope's interval "
            "refits the line once per bootstrap replicate, taking replicate i of "
            "every depth, so it is the spread of the slope under the sampling noise "
            "in the points rather than a residual of a six-point line"
        ),
        "lineageWalk": (
            "resolve the lineage bundle the request names from the receiver's own "
            "store, compare the digest the store recorded when it accepted the "
            "bundle against the one the request cites, walk and validate every "
            "edge, and find the statement that binds the continuation and the "
            "bilateral invocation. The comparison is the string compare the hook "
            "makes, not a fresh canonicalize-and-hash: the hook never recomputes "
            "the bundle digest, so neither does this window. Timed on its own, "
            "immediately before the call that repeats it inside the hook"
        ),
        "admittedCall": (
            "one ChioKernel::evaluate_tool_call through the real runtime admission "
            "hook: resolution, bindings, both DSSE signature verifications, "
            "continuation and lease consumption, pre-dispatch revalidation, "
            "dispatch, the signed receipt in SQLite and the in-process co-signature"
        ),
        "fit": (
            "ordinary least squares of each depth's median against the depth, with "
            "a bootstrap interval on the slope. The lineage walk is the term "
            "Section 6 identifies as linear"
        ),
        "admittedCallFit": (
            "the admitted call's fit against depth is recorded with its own "
            "interval and coefficient of determination, and no per-statement macro "
            "is emitted for it. Over this depth range the fit does not resolve a "
            "slope: the interval covers zero, so a per-statement admission cost is "
            "not a quantity this sweep measured. The reportable quantity for the "
            "admitted call is range.admittedCallGrowth, the total growth of its "
            "median from the shallowest depth to the deepest"
        ),
        "shareOfInProcessCall": (
            "the lineage share is taken against THIS fixture's in-process admitted "
            "call, which installs no durable admission-operation store. A federated "
            "receiver's admitted window is roughly an order of magnitude larger, so "
            "the same walk is a correspondingly smaller share of it. The two shares "
            "are not interchangeable"
        ),
        "whatDepthIs": (
            "verified statements in the lineage bundle the RECEIVER holds. A request "
            "names the bundle by id and digest and cannot supply one, so a peer "
            "cannot impose a depth the receiver has not already accepted"
        ),
        "independence": (
            "each depth runs on its own kernel, its own admission store and its own "
            "SQLite receipt file, so no depth is measured against a store another "
            "depth warmed"
        ),
    },
}
pathlib.Path(result_json).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)

macros = [
    ("PSScalingDepths", str(len(depths))),
    ("PSScalingMinDepth", str(shallowest["depth"])),
    ("PSScalingMaxDepth", str(deepest["depth"])),
    ("PSScalingIterations", str(int(iterations))),
    ("PSScalingLineageMinUs", f"{shallowest['lineageWalk']['p50_us']:.3f}"),
    ("PSScalingLineageMaxUs", f"{deepest['lineageWalk']['p50_us']:.3f}"),
    (
        "PSScalingLineageMinCiLowUs",
        f"{shallowest['lineageWalk']['median_ci_low_us']:.3f}",
    ),
    (
        "PSScalingLineageMinCiHighUs",
        f"{shallowest['lineageWalk']['median_ci_high_us']:.3f}",
    ),
    ("PSScalingLineageMaxCiLowUs", f"{deepest['lineageWalk']['median_ci_low_us']:.3f}"),
    (
        "PSScalingLineageMaxCiHighUs",
        f"{deepest['lineageWalk']['median_ci_high_us']:.3f}",
    ),
    ("PSScalingPerStatementUs", f"{lineage_fit['slope']:.3f}"),
    ("PSScalingPerStatementCiLowUs", f"{lineage_fit['slopeCiLow']:.3f}"),
    ("PSScalingPerStatementCiHighUs", f"{lineage_fit['slopeCiHigh']:.3f}"),
    ("PSScalingInterceptUs", f"{lineage_fit['intercept']:.3f}"),
    ("PSScalingRSquared", f"{lineage_fit['rSquared']:.4f}"),
    ("PSScalingPerByteNs", f"{byte_fit['slope'] * 1000.0:.3f}"),
    ("PSScalingPerByteCiLowNs", f"{byte_fit['slopeCiLow'] * 1000.0:.3f}"),
    ("PSScalingPerByteCiHighNs", f"{byte_fit['slopeCiHigh'] * 1000.0:.3f}"),
    ("PSScalingCallMinUs", f"{shallowest['admittedCall']['p50_us']:.3f}"),
    ("PSScalingCallMaxUs", f"{deepest['admittedCall']['p50_us']:.3f}"),
    # No per-statement macro for the admitted call: over this range its slope
    # interval covers zero, so the growth across the whole range is what there
    # is to report.
    ("PSScalingCallGrowth", f"{document['range']['admittedCallGrowth']:.2f}"),
    (
        "PSScalingShareAtMinDepthInProcess",
        f"{shallowest['lineageShareOfInProcessCall'] * 100.0:.2f}",
    ),
    (
        "PSScalingShareAtMaxDepthInProcess",
        f"{deepest['lineageShareOfInProcessCall'] * 100.0:.2f}",
    ),
    ("PSScalingMaxBundleBytes", str(deepest["lineageBundleBytes"])),
]
pathlib.Path(inline_out).write_text(
    "".join(f"\\newcommand{{\\{name}}}{{{value}}}\n" for name, value in macros),
    encoding="utf-8",
)
PY

trap - ERR
printf 'admission scaling benchmark complete: %s\n' "$RESULT_JSON"
