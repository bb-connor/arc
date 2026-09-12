#!/usr/bin/env bash
set -euo pipefail

# Two separately administered kernels, two OS processes, one cross-organization
# tool call per measurement. Org A and Org B generate their own keys, a third
# party signs the transport directory that binds them, and the receiver decides
# every call on its own store.
#
# One machine is the default: this script starts the origin, the receiver and the
# driver here and records one host. A genuine two-host run is two invocations,
# one per machine, with disjoint CHIO_FED_ROLES and a CHIO_FED_STATE_DIR both
# machines can read; the recorded host count comes from the roles a run actually
# started, never from the host names it was handed.
#
#   host A:  CHIO_FED_ROLES=origin \
#            CHIO_FED_ORIGIN_HOST=10.0.0.1 CHIO_FED_RECEIVER_HOST=10.0.0.2 \
#            CHIO_FED_STATE_DIR=/srv/chio-federated-pair ./run-federated-pair.sh
#   host B:  CHIO_FED_ROLES=receiver,driver \
#            CHIO_FED_ORIGIN_HOST=10.0.0.1 CHIO_FED_RECEIVER_HOST=10.0.0.2 \
#            CHIO_FED_STATE_DIR=/srv/chio-federated-pair ./run-federated-pair.sh
#
# The state directory carries the generated keys, the signed directory, the
# treaty, the origin handshake, the readiness marker and the revoke/cut control
# document. Both hosts must see it (a shared mount, or a copy kept in sync) as
# the same user, since the key material is written owner-only, and the first
# invocation that finds it empty generates the material.

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
if [[ -n "$(git -C "$SOURCE" status --short)" ]]; then
  SOURCE_DIRTY=true
else
  SOURCE_DIRTY=false
fi

RESULT_DIR="${CHIO_PAPER_RESULT_DIR:-$SCRIPT_DIR/results}"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-federated-target}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chio-federated-pair-bench.XXXXXX")"

ALLOW_CALLS="${CHIO_FED_ALLOW_CALLS:-100}"
DENY_CALLS="${CHIO_FED_DENY_CALLS:-20}"
TICK_MS="${CHIO_FED_TICK_MS:-250}"
READY_TIMEOUT_SECS="${CHIO_FED_READY_TIMEOUT_SECS:-60}"
FLIP_TIMEOUT_MS="${CHIO_FED_FLIP_TIMEOUT_MS:-30000}"
REVOKE_REPEATS="${CHIO_FED_REVOKE_REPEATS:-10}"
CUT_REPEATS="${CHIO_FED_CUT_REPEATS:-10}"
STAGE_TIMEOUT_SECS="${CHIO_FED_STAGE_TIMEOUT_SECS:-1800}"
MAX_LOAD="${CHIO_BENCH_MAX_LOAD:-4.0}"

# Org A and Org B addresses. A two-host run changes these AND splits
# CHIO_FED_ROLES; changing them alone never changes the recorded host count.
ORIGIN_HOST="${CHIO_FED_ORIGIN_HOST:-127.0.0.1}"
RECEIVER_HOST="${CHIO_FED_RECEIVER_HOST:-127.0.0.1}"
SENDER_HOST="${CHIO_FED_SENDER_HOST:-0.0.0.0}"
ORIGIN_PORT="${CHIO_FED_ORIGIN_PORT:-41821}"
RECEIVER_PORT="${CHIO_FED_RECEIVER_PORT:-41822}"
SENDER_PORT="${CHIO_FED_SENDER_PORT:-0}"

ORIGIN_KERNEL="${CHIO_FED_ORIGIN_KERNEL:-did:chio:org-a}"
RECEIVER_KERNEL="${CHIO_FED_RECEIVER_KERNEL:-did:chio:org-b}"
SENDER_KERNEL="${CHIO_FED_SENDER_KERNEL:-did:chio:org-a-agent}"
ISSUER_KERNEL="${CHIO_FED_ISSUER_KERNEL:-did:chio:directory-issuer}"

DENY_SCENARIOS=(
  scope_hash_mismatch
  missing_required_evidence
  smuggled_trust_root
  smuggled_dynamic_trust
  intersection_hash_mismatch
  unknown_treaty_scope
  unknown_ladder_intersection
)

case "$ALLOW_CALLS:$DENY_CALLS:$TICK_MS:$READY_TIMEOUT_SECS:$FLIP_TIMEOUT_MS:$REVOKE_REPEATS:$CUT_REPEATS:$STAGE_TIMEOUT_SECS" in
  *[!0-9:]*)
    echo "call counts, repeats and timeouts must be nonnegative integers" >&2
    exit 2
    ;;
esac
if [[ "$ALLOW_CALLS" -lt 2 || "$DENY_CALLS" -lt 2 ]]; then
  echo "CHIO_FED_ALLOW_CALLS and CHIO_FED_DENY_CALLS must be at least 2: every reported distribution needs two observations" >&2
  exit 2
fi
if [[ "$REVOKE_REPEATS" -lt 2 || "$CUT_REPEATS" -lt 2 ]]; then
  echo "CHIO_FED_REVOKE_REPEATS and CHIO_FED_CUT_REPEATS must be at least 2: a single flip is not a distribution" >&2
  exit 2
fi
if [[ "$STAGE_TIMEOUT_SECS" -lt 1 ]]; then
  echo "CHIO_FED_STAGE_TIMEOUT_SECS must be at least one second" >&2
  exit 2
fi
if [[ ! "$MAX_LOAD" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
  echo "CHIO_BENCH_MAX_LOAD must be a nonnegative decimal number: $MAX_LOAD" >&2
  exit 2
fi

# ---- Roles and host topology -----------------------------------------------

# The roles THIS invocation runs. The host count is derived from these, so a run
# can only claim two hosts by actually leaving a role to another machine.
ROLES_REQUESTED="${CHIO_FED_ROLES:-origin,receiver,driver}"
if [[ -z "${ROLES_REQUESTED//,/}" ]]; then
  echo "CHIO_FED_ROLES named no role; there is nothing to run here" >&2
  exit 2
fi
IFS=',' read -r -a ROLE_LIST <<< "$ROLES_REQUESTED"
ROLES=()
for role in "${ROLE_LIST[@]}"; do
  role="${role// /}"
  [[ -z "$role" ]] && continue
  case "$role" in
    origin | receiver | driver) ;;
    *)
      echo "unknown role $role in CHIO_FED_ROLES; expected origin, receiver or driver" >&2
      exit 2
      ;;
  esac
  ROLES+=("$role")
done
if [[ "${#ROLES[@]}" -eq 0 ]]; then
  echo "CHIO_FED_ROLES named no role; there is nothing to run here" >&2
  exit 2
fi

has_role() {
  local wanted="$1"
  local role
  for role in "${ROLES[@]}"; do
    if [[ "$role" == "$wanted" ]]; then
      return 0
    fi
  done
  return 1
}

LOCAL_ADDRESSES="$(
  {
    printf '127.0.0.1\n::1\n0.0.0.0\nlocalhost\n'
    hostname 2>/dev/null || true
    hostname -f 2>/dev/null || true
    hostname -I 2>/dev/null | tr ' ' '\n' || true
    ip -o addr show 2>/dev/null | awk '{ print $4 }' | cut -d / -f 1 || true
    ifconfig 2>/dev/null | awk '/[[:space:]]inet6?[[:space:]]/ { print $2 }' | sed 's/^addr://' || true
  } | sed '/^$/d' | sort -u
)"

is_local_address() {
  printf '%s\n' "$LOCAL_ADDRESSES" | grep -Fxq -- "$1"
}

# A role this invocation starts must be reachable at an address this machine
# owns, and a role it does not start must NOT be: either way round the recorded
# topology would otherwise describe a deployment that did not happen.
check_role_locality() {
  local role="$1"
  local host="$2"
  local variable="$3"
  if has_role "$role"; then
    if ! is_local_address "$host"; then
      echo "CHIO_FED_ROLES names $role but $variable=$host is not an address of this machine." >&2
      echo "Run this script once per host with disjoint CHIO_FED_ROLES (for example CHIO_FED_ROLES=origin here and CHIO_FED_ROLES=receiver,driver there)." >&2
      exit 2
    fi
  elif is_local_address "$host"; then
    echo "CHIO_FED_ROLES omits $role but $variable=$host is an address of this machine, so the run cannot claim $role lives elsewhere." >&2
    echo "Either add $role to CHIO_FED_ROLES or point $variable at the machine that runs it." >&2
    exit 2
  fi
}

check_role_locality origin "$ORIGIN_HOST" CHIO_FED_ORIGIN_HOST
check_role_locality receiver "$RECEIVER_HOST" CHIO_FED_RECEIVER_HOST
if has_role driver && ! is_local_address "$SENDER_HOST"; then
  echo "CHIO_FED_ROLES names driver but CHIO_FED_SENDER_HOST=$SENDER_HOST is not an address of this machine" >&2
  exit 2
fi

REMOTE_HOSTS=()
has_role origin || REMOTE_HOSTS+=("$ORIGIN_HOST")
has_role receiver || REMOTE_HOSTS+=("$RECEIVER_HOST")
DISTINCT_REMOTE=0
if [[ "${#REMOTE_HOSTS[@]}" -gt 0 ]]; then
  DISTINCT_REMOTE="$(printf '%s\n' "${REMOTE_HOSTS[@]}" | sort -u | wc -l | tr -d ' ')"
fi
# This invocation is one host (it runs at least one role); every role it left to
# another machine adds that machine.
HOST_COUNT=$((DISTINCT_REMOTE + 1))
LOCAL_PROCESSES="${#ROLES[@]}"
ROLE_SLUG="$(printf '%s\n' "${ROLES[@]}" | sort | paste -sd '-' -)"
ROLE_LABEL="$(printf '%s\n' "${ROLES[@]}" | sort | paste -sd ',' -)"
case "$HOST_COUNT" in
  1) HOST_TOPOLOGY="one host, $LOCAL_PROCESSES processes" ;;
  2) HOST_TOPOLOGY="two hosts" ;;
  *) HOST_TOPOLOGY="$HOST_COUNT hosts" ;;
esac

# ---- Shared state ----------------------------------------------------------

STATE_EPHEMERAL=false
if [[ -n "${CHIO_FED_STATE_DIR:-}" ]]; then
  mkdir -p "$CHIO_FED_STATE_DIR"
  STATE_DIR="$(cd "$CHIO_FED_STATE_DIR" && pwd -P)"
else
  if (( HOST_COUNT > 1 )); then
    echo "a run split across hosts needs CHIO_FED_STATE_DIR: a directory every participating host can read, holding the keys, the signed directory, the treaty and the revoke/cut control document" >&2
    exit 2
  fi
  STATE_DIR="$WORK_DIR/state"
  mkdir -p "$STATE_DIR"
  STATE_EPHEMERAL=true
fi

mkdir -p "$RESULT_DIR" "$TARGET_DIR"
RESULT_DIR="$(cd "$RESULT_DIR" && pwd -P)"

RESULT_JSON="$RESULT_DIR/federated-pair.json"
ALLOW_CSV="$RESULT_DIR/federated-pair-allow-samples.csv"
DENY_CSV="$RESULT_DIR/federated-pair-deny-samples.csv"
INLINE="$RESULT_DIR/federated-pair-inline.tex"
ENVIRONMENT="$RESULT_DIR/federated-pair-environment-$ROLE_SLUG.txt"
ENVIRONMENT_JSON="$RESULT_DIR/federated-pair-environment-$ROLE_SLUG.json"
BUILD_LOG="$RESULT_DIR/federated-pair-build.log"
ORIGIN_LOG="$RESULT_DIR/federated-pair-origin.log"
RECEIVER_LOG="$RESULT_DIR/federated-pair-receiver.log"
DRIVER_LOG="$RESULT_DIR/federated-pair-driver.log"

ORIGIN_PID=""
RECEIVER_PID=""
cleanup() {
  for pid in "$RECEIVER_PID" "$ORIGIN_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}
# Only the host that writes the paper's macros may retract them.
if has_role driver; then
  trap 'emit_unreported' ERR
fi

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

# A stage that hangs must trip the error trap rather than block an unattended run.
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
else
  echo "no timeout(1) or gtimeout(1) on PATH; the measurement stages need a wall-clock guard" >&2
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
  printf 'roles_started_here=%s\n' "$ROLE_LABEL"
  printf 'topology=%s\n' "$HOST_TOPOLOGY"
  printf 'hosts=%s\n' "$HOST_COUNT"
  printf 'origin_endpoint=%s:%s\n' "$ORIGIN_HOST" "$ORIGIN_PORT"
  printf 'receiver_endpoint=%s:%s\n' "$RECEIVER_HOST" "$RECEIVER_PORT"
  printf 'transport=iroh QUIC, relays disabled\n'
  printf 'epoch_tick_ms=%s\n' "$TICK_MS"
  printf 'allow_calls=%s\n' "$ALLOW_CALLS"
  printf 'deny_calls_per_case=%s\n' "$DENY_CALLS"
  printf 'deny_cases=%s\n' "${#DENY_SCENARIOS[@]}"
  printf 'revoke_repeats=%s\n' "$REVOKE_REPEATS"
  printf 'cut_repeats=%s\n' "$CUT_REPEATS"
  printf 'receiver_stores=SQLite receipts and revocations\n'
} > "$ENVIRONMENT"

python3 - "$ENVIRONMENT_JSON" "$CPU_MODEL" "$CORES" "$MEMORY_BYTES" \
  "$OS_DESCRIPTION" "$RUSTC_RELEASE" "$CARGO_VERSION" "$LOAD_1M" \
  "$TOOLCHAIN_PIN" "$SOURCE_COMMIT" "$SOURCE_DIRTY" "$HOST_TOPOLOGY" \
  "$ROLE_LABEL" <<'PY'
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
    topology,
    roles,
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
    "topology": topology,
    "rolesStartedHere": roles.split(","),
}
pathlib.Path(output).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

if has_role driver; then
  cp "$ENVIRONMENT" "$RESULT_DIR/federated-pair-environment.txt"
  cp "$ENVIRONMENT_JSON" "$RESULT_DIR/federated-pair-environment.json"
fi

# ---- Build -----------------------------------------------------------------

(
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo build --release \
    -p chio-federation-transport-iroh --example federated_call_pair
) > "$BUILD_LOG" 2>&1

PAIR_BIN="$TARGET_DIR/release/examples/federated_call_pair"
if [[ ! -x "$PAIR_BIN" ]]; then
  echo "the release example binary was not produced" >&2
  exit 1
fi

# ---- Keys, directory, treaty ------------------------------------------------

ORIGIN_DIR="$STATE_DIR/org-a"
RECEIVER_DIR="$STATE_DIR/org-b"
SENDER_DIR="$STATE_DIR/org-a-agent"
ISSUER_DIR="$STATE_DIR/issuer"
SHARED_DIR="$STATE_DIR/shared"
RECEIVER_STORE="$STATE_DIR/receiver-stores"
mkdir -p "$ORIGIN_DIR" "$RECEIVER_DIR" "$SENDER_DIR" "$ISSUER_DIR" "$SHARED_DIR" "$RECEIVER_STORE"

: > "$DRIVER_LOG"
run_pair() {
  "$TIMEOUT_BIN" "$STAGE_TIMEOUT_SECS" "$PAIR_BIN" "$@" >> "$DRIVER_LOG" 2>&1
}

DIRECTORY="$SHARED_DIR/transport-directory.json"
TRUST="$SHARED_DIR/transport-directory-trust.json"
TREATY="$SHARED_DIR/treaty.json"
HANDSHAKE="$SHARED_DIR/origin-handshake.json"
CONTROL="${CHIO_FED_CONTROL:-$SHARED_DIR/origin-control.json}"
READY="$SHARED_DIR/receiver-ready.json"
EPOCH_RATE="$SHARED_DIR/origin-epoch-rate.json"

if [[ ! -f "$TREATY" ]]; then
  run_pair keygen --kernel-id "$ORIGIN_KERNEL" --dir "$ORIGIN_DIR"
  run_pair keygen --kernel-id "$RECEIVER_KERNEL" --dir "$RECEIVER_DIR"
  run_pair keygen --kernel-id "$SENDER_KERNEL" --dir "$SENDER_DIR"
  run_pair keygen --kernel-id "$ISSUER_KERNEL" --dir "$ISSUER_DIR"

  run_pair directory \
    --issuer-dir "$ISSUER_DIR" \
    --public "$ORIGIN_DIR/public.json" \
    --public "$RECEIVER_DIR/public.json" \
    --public "$SENDER_DIR/public.json" \
    --origin-kernel-id "$ORIGIN_KERNEL" \
    --receiver-kernel-id "$RECEIVER_KERNEL" \
    --sender-kernel-id "$SENDER_KERNEL" \
    --out-dir "$SHARED_DIR"
fi

# Each host clears only the files its own roles own, so a split run cannot delete
# a marker the other host has just written. The key material above is generated
# once and reused.
if has_role origin; then
  rm -f "$HANDSHAKE" "$CONTROL" "$EPOCH_RATE"
fi
if has_role receiver; then
  rm -f "$READY"
fi

wait_for_file() {
  local path="$1"
  local limit="$2"
  local waited=0
  while [[ ! -f "$path" ]]; do
    if (( waited >= limit * 10 )); then
      echo "timed out waiting for $path" >&2
      return 1
    fi
    if [[ -n "$ORIGIN_PID" ]] && ! kill -0 "$ORIGIN_PID" 2>/dev/null; then
      echo "the origin process exited early; see $ORIGIN_LOG" >&2
      return 1
    fi
    if [[ -n "$RECEIVER_PID" ]] && ! kill -0 "$RECEIVER_PID" 2>/dev/null; then
      echo "the receiver process exited early; see $RECEIVER_LOG" >&2
      return 1
    fi
    sleep 0.1
    waited=$((waited + 1))
  done
  return 0
}

# ---- The roles this host runs ----------------------------------------------

if has_role origin; then
  "$PAIR_BIN" origin \
    --dir "$ORIGIN_DIR" \
    --directory "$DIRECTORY" --trust "$TRUST" --treaty "$TREATY" \
    --bind "$ORIGIN_HOST:$ORIGIN_PORT" \
    --peer "$RECEIVER_KERNEL=$RECEIVER_HOST:$RECEIVER_PORT" \
    --handshake-out "$HANDSHAKE" \
    --control "$CONTROL" \
    --epoch-rate-out "$EPOCH_RATE" \
    --tick-ms "$TICK_MS" > "$ORIGIN_LOG" 2>&1 &
  ORIGIN_PID=$!
fi

if has_role receiver; then
  # The origin publishes the handshake envelope the receiver pins it with; on a
  # split run it arrives through the shared state directory.
  wait_for_file "$HANDSHAKE" "$READY_TIMEOUT_SECS"

  "$PAIR_BIN" receiver \
    --dir "$RECEIVER_DIR" \
    --directory "$DIRECTORY" --trust "$TRUST" --treaty "$TREATY" \
    --bind "$RECEIVER_HOST:$RECEIVER_PORT" \
    --peer "$ORIGIN_KERNEL=$ORIGIN_HOST:$ORIGIN_PORT" \
    --handshake "$HANDSHAKE" \
    --store-dir "$RECEIVER_STORE" \
    --ready-out "$READY" \
    --ready-timeout-secs "$READY_TIMEOUT_SECS" > "$RECEIVER_LOG" 2>&1 &
  RECEIVER_PID=$!
fi

if ! has_role driver; then
  printf 'started %s on this host; the driver runs elsewhere. Stop with SIGINT.\n' "$ROLE_LABEL"
  wait
  exit 0
fi

wait_for_file "$READY" "$READY_TIMEOUT_SECS"

SEND_FLAGS=(
  --dir "$SENDER_DIR"
  --directory "$DIRECTORY" --trust "$TRUST" --treaty "$TREATY"
  --bind "$SENDER_HOST:$SENDER_PORT"
  --peer "$RECEIVER_KERNEL=$RECEIVER_HOST:$RECEIVER_PORT"
)

# ---- Measurements ----------------------------------------------------------

ALLOW_SAMPLES="$WORK_DIR/allow-samples.csv"
ALLOW_SUMMARY="$WORK_DIR/allow-summary.json"
run_pair send "${SEND_FLAGS[@]}" \
  --scenario allow --calls "$ALLOW_CALLS" \
  --csv "$ALLOW_SAMPLES" --out "$ALLOW_SUMMARY"

DENY_SAMPLE_FILES=()
DENY_SUMMARY_FILES=()
for scenario in "${DENY_SCENARIOS[@]}"; do
  samples="$WORK_DIR/deny-$scenario.csv"
  summary="$WORK_DIR/deny-$scenario.json"
  run_pair send "${SEND_FLAGS[@]}" \
    --scenario "$scenario" --calls "$DENY_CALLS" \
    --csv "$samples" --out "$summary"
  DENY_SAMPLE_FILES+=("$samples")
  DENY_SUMMARY_FILES+=("$summary")
done

REVOKE_JSON="$WORK_DIR/revoke.json"
run_pair revoke "${SEND_FLAGS[@]}" \
  --control "$CONTROL" --timeout-ms "$FLIP_TIMEOUT_MS" \
  --repeats "$REVOKE_REPEATS" --out "$REVOKE_JSON"

CUT_JSON="$WORK_DIR/cut.json"
run_pair cut "${SEND_FLAGS[@]}" \
  --control "$CONTROL" --timeout-ms "$FLIP_TIMEOUT_MS" \
  --repeats "$CUT_REPEATS" --out "$CUT_JSON"

# ---- Aggregate -------------------------------------------------------------

python3 - \
  "$RESULT_JSON" "$ALLOW_CSV" "$DENY_CSV" "$INLINE" "$ENVIRONMENT_JSON" \
  "$ALLOW_SAMPLES" "$ALLOW_SUMMARY" "$REVOKE_JSON" "$CUT_JSON" \
  "$SOURCE_COMMIT" "$SOURCE_DIRTY" "$HOST_COUNT" "$HOST_TOPOLOGY" "$TICK_MS" \
  "$ROLE_LABEL" "$LOCAL_PROCESSES" "$EPOCH_RATE" "$RESULT_DIR" \
  "${DENY_SAMPLE_FILES[@]}" -- "${DENY_SUMMARY_FILES[@]}" <<'PY'
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
    allow_csv_out,
    deny_csv_out,
    inline_out,
    environment_json,
    allow_samples,
    allow_summary,
    revoke_json,
    cut_json,
    source_commit,
    source_dirty,
    host_count,
    host_topology,
    tick_ms,
    roles_started_here,
    local_processes,
    epoch_rate_path,
    result_dir,
) = sys.argv[1:19]
rest = sys.argv[19:]
split = rest.index("--")
deny_sample_files = rest[:split]
deny_summary_files = rest[split + 1 :]

CSV_FIELDS = [
    "scenario",
    "sequence",
    "request_id",
    "round_trip_ms",
    "evaluate_ms",
    "prepare_ms",
    "verdict",
    "failure_code",
    "cosign_connections",
]


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


def summarize(values):
    if len(values) < 2:
        raise SystemExit("a summary needs at least two observations")
    ordered = sorted(values)
    low, high = bootstrap_ci(ordered)
    return {
        "samples": len(ordered),
        "p50_ms": percentile(ordered, 0.50),
        "p99_ms": percentile(ordered, 0.99),
        "mean_ms": mean(ordered),
        "std_ms": sample_std(ordered),
        "ci_low_ms": low,
        "ci_high_ms": high,
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
    }


def load_json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def load_rows(path):
    with pathlib.Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def constant(values, what):
    """The one value every sample carried, or a hard failure.

    A per-call count that is not the same on every call is not a property of the
    call, and reporting its average would present a mixture as a measurement.
    """
    distinct = sorted(set(values))
    if len(distinct) != 1:
        raise SystemExit(f"{what} was not constant across the run: {distinct}")
    return distinct[0]


allow_rows = load_rows(allow_samples)
if not allow_rows:
    raise SystemExit("the allow scenario produced no samples")
for row in allow_rows:
    if row["verdict"] != "allow":
        raise SystemExit(f"an allow sample carried verdict {row['verdict']}")
allow_latencies = [float(row["round_trip_ms"]) for row in allow_rows]
allow_evaluate = [float(row["evaluate_ms"]) for row in allow_rows]
allow_prepare = [float(row["prepare_ms"]) for row in allow_rows]

deny_rows = []
deny_cases = {}
deny_absorbed_total = 0
for samples_path, summary_path in zip(deny_sample_files, deny_summary_files):
    summary = load_json(summary_path)
    rows = load_rows(samples_path)
    if not rows:
        raise SystemExit(f"{samples_path} produced no samples")
    for row in rows:
        if row["verdict"] != "deny":
            raise SystemExit(
                f"scenario {summary['scenario']} produced verdict {row['verdict']}"
            )
        if row["failure_code"] != summary["expectedFailureCode"]:
            raise SystemExit(
                f"scenario {summary['scenario']} produced failure code "
                f"{row['failure_code']}, expected {summary['expectedFailureCode']}"
            )
    if summary["dispatched"] != summary["expectedDispatched"]:
        raise SystemExit(
            f"scenario {summary['scenario']} dispatched {summary['dispatched']} times"
        )
    deny_rows.extend(rows)
    deny_absorbed_total += int(summary["freshnessDenialsAbsorbed"])
    deny_cases[summary["scenario"]] = {
        "failureCode": summary["expectedFailureCode"],
        "calls": summary["calls"],
        "dispatched": summary["dispatched"],
        "expectedDispatched": summary["expectedDispatched"],
        "freshnessDenialsAbsorbed": summary["freshnessDenialsAbsorbed"],
        "cosignConnectionsPerCall": summary["cosignConnectionsPerCall"],
        "roundTrip": summarize([float(row["round_trip_ms"]) for row in rows]),
    }

allow_summary_doc = load_json(allow_summary)
if allow_summary_doc["dispatched"] != allow_summary_doc["expectedDispatched"]:
    raise SystemExit(
        "the admitted run did not dispatch once per call: "
        f"{allow_summary_doc['dispatched']} of {allow_summary_doc['calls']}"
    )

# Measured, not assumed: the receiver counts the QUIC connections its kernel
# opened to the origin, and every admitted call must have cost the same number.
cosign_connections = constant(
    [int(row["cosign_connections"]) for row in allow_rows],
    "the co-sign connection count of an admitted call",
)
if cosign_connections != allow_summary_doc["cosignConnectionsPerCall"]:
    raise SystemExit(
        "the admitted run's per-call co-sign connection count disagrees with its samples"
    )

deny_latencies = [float(row["round_trip_ms"]) for row in deny_rows]
allow_stats = summarize(allow_latencies)
deny_stats = summarize(deny_latencies)
evaluate_stats = summarize(allow_evaluate)
prepare_stats = summarize(allow_prepare)

revoke = load_json(revoke_json)
cut = load_json(cut_json)
revoke_stats = summarize(revoke["samplesMs"])
cut_stats = summarize(cut["samplesMs"])
environment = load_json(environment_json)

# Every host that ran a role leaves its own environment file in the result
# directory; a split run retains one per host.
environments = {}
for path in sorted(pathlib.Path(result_dir).glob("federated-pair-environment-*.json")):
    environments[path.stem.removeprefix("federated-pair-environment-")] = load_json(path)

epoch_rate = None
if pathlib.Path(epoch_rate_path).exists():
    epoch_rate = load_json(epoch_rate_path)

allow_absorbed = int(allow_summary_doc["freshnessDenialsAbsorbed"])
revoke_absorbed = int(revoke["freshnessDenialsAbsorbed"])
cut_absorbed = int(cut["freshnessDenialsAbsorbed"])


def write_csv(path, rows):
    with pathlib.Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row[field] for field in CSV_FIELDS})


write_csv(allow_csv_out, allow_rows)
write_csv(deny_csv_out, deny_rows)

document = {
    "schema": "chio.programmable-sovereignty.federated-pair-results.v1",
    "commit": source_commit,
    "worktreeDirty": source_dirty == "true",
    "profile": "release",
    "environment": environment,
    "environments": environments,
    "topology": {
        "hosts": int(host_count),
        "description": host_topology,
        "rolesStartedHere": roles_started_here.split(","),
        "processesStartedHere": int(local_processes),
        "transport": "iroh QUIC, relays disabled",
        "epochTickMs": int(tick_ms),
        "achievedEpochRate": epoch_rate,
        "cosignConnectionsPerAdmittedCall": cosign_connections,
    },
    "admitted": {
        "roundTrip": allow_stats,
        "receiverEvaluate": evaluate_stats,
        "evidencePreparation": prepare_stats,
        "dispatched": allow_summary_doc["dispatched"],
        "calls": allow_summary_doc["calls"],
        "freshnessDenialsAbsorbed": allow_absorbed,
    },
    "denied": {
        "roundTrip": deny_stats,
        "cases": deny_cases,
        "freshnessDenialsAbsorbed": deny_absorbed_total,
    },
    "revocation": {
        "revokeToDeny": revoke_stats,
        "revokeRepeats": revoke["repeats"],
        "callsUntilDeny": revoke["callsUntilDeny"],
        "failureCodes": revoke["failureCodes"],
        "cutToDeny": cut_stats,
        "cutRepeats": cut["repeats"],
        "cutCallsUntilDeny": cut["callsUntilDeny"],
        "cutFailureCodes": cut["failureCodes"],
        "cutConfirmations": cut["confirmations"],
        "freshnessDenialsAbsorbed": revoke_absorbed + cut_absorbed,
    },
    "freshnessDenialsAbsorbed": {
        "admitted": allow_absorbed,
        "denied": deny_absorbed_total,
        "revocation": revoke_absorbed + cut_absorbed,
        "total": allow_absorbed + deny_absorbed_total + revoke_absorbed + cut_absorbed,
    },
    "method": {
        "percentile": "linear interpolation between order statistics",
        "confidence": CONFIDENCE,
        "bootstrap": {
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
        },
        "hosts": (
            "derived from the roles this run started: every role left to another "
            "machine adds a host, and a run that starts all of them records one"
        ),
        "roundTrip": (
            "sender send to sender receive on the experiment lane; includes the "
            "receiver's whole admission decision and, on the admitted path, both "
            "co-sign hops back to the origin"
        ),
        "evidencePreparation": (
            "untimed relative to admission: the receiver mints the per-call treaty "
            "evidence and obtains the origin's DSSE signature over lane d"
        ),
        "deniedRoundTrip": (
            "pooled across the denial cases, which refuse at different depths of "
            "the admission hook; each case's own distribution is under "
            "denied.cases[name].roundTrip"
        ),
        "cosignConnections": (
            "measured, not assumed: the receiver reports the QUIC connections its "
            "co-signer opened to the origin when a call's preparation began and "
            "again once it had decided, and the run fails closed unless every call "
            "of a scenario cost the same number. The span covers the preparation's "
            "DSSE hop as well as the hops the admission decision makes, so a denied "
            "case, which never reaches the decision's hops, isolates the "
            "preparation's share: see denied.cases[name].cosignConnectionsPerCall"
        ),
        "freshnessDenialsAbsorbed": (
            "calls the receiver denied because its revocation snapshot fell "
            "outside the kernel's freshness window. They are the clock rather "
            "than the treaty, so they are retried and excluded from every latency "
            "distribution above; the counts record how many were excluded"
        ),
        "revokeToDeny": (
            "control document written to first observing call, repeated "
            f"{revoke['repeats']} times. Each observation includes up to one "
            f"origin control-poll period ({tick_ms} ms, the epoch tick) and one "
            "call of polling resolution (the admitted round trip, p50 "
            f"{allow_stats['p50_ms']:.3f} ms)"
        ),
        "cutToDeny": (
            "control document written to the first freshness denial that persists "
            f"for {cut['confirmations']} further calls, repeated {cut['repeats']} "
            "times. Each observation includes the kernel's own freshness bound, "
            f"one origin control-poll period ({tick_ms} ms) and one call of "
            "polling resolution"
        ),
    },
}
pathlib.Path(result_json).write_text(
    json.dumps(document, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

macros = [
    ("PSFedAllowPFiftyMs", f"{allow_stats['p50_ms']:.3f}"),
    ("PSFedAllowPNinetyNineMs", f"{allow_stats['p99_ms']:.3f}"),
    ("PSFedAllowMeanMs", f"{allow_stats['mean_ms']:.3f}"),
    ("PSFedAllowCiLowMs", f"{allow_stats['ci_low_ms']:.3f}"),
    ("PSFedAllowCiHighMs", f"{allow_stats['ci_high_ms']:.3f}"),
    ("PSFedAllowSampleCount", str(allow_stats["samples"])),
    ("PSFedAllowAbsorbedCount", str(allow_absorbed)),
    ("PSFedAbsorbedCount", str(document["freshnessDenialsAbsorbed"]["total"])),
    ("PSFedDenyPFiftyMs", f"{deny_stats['p50_ms']:.3f}"),
    ("PSFedDenyPNinetyNineMs", f"{deny_stats['p99_ms']:.3f}"),
    ("PSFedDenySampleCount", str(deny_stats["samples"])),
    ("PSFedDenyCases", str(len(deny_cases))),
    ("PSFedRevokeToDenyMs", f"{revoke_stats['p50_ms']:.3f}"),
    ("PSFedRevokeCiLowMs", f"{revoke_stats['ci_low_ms']:.3f}"),
    ("PSFedRevokeCiHighMs", f"{revoke_stats['ci_high_ms']:.3f}"),
    ("PSFedRevokeRepeats", str(revoke_stats["samples"])),
    ("PSFedCutToDenyMs", f"{cut_stats['p50_ms']:.3f}"),
    ("PSFedCutCiLowMs", f"{cut_stats['ci_low_ms']:.3f}"),
    ("PSFedCutCiHighMs", f"{cut_stats['ci_high_ms']:.3f}"),
    ("PSFedCutRepeats", str(cut_stats["samples"])),
    ("PSFedHosts", str(int(host_count))),
    ("PSFedTransport", "iroh QUIC, relays disabled"),
    ("PSFedCosignConnections", str(cosign_connections)),
]
pathlib.Path(inline_out).write_text(
    "".join(f"\\newcommand{{\\{name}}}{{{value}}}\n" for name, value in macros),
    encoding="utf-8",
)
PY

trap - ERR
printf 'federated pair benchmark complete: %s\n' "$RESULT_JSON"
