#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/portable-mobile}"

ARTIFACT_DIR="${ARTIFACT_DIR:-target/release-qualification/mobile-kernel}"
mkdir -p "$ARTIFACT_DIR"

REPORT_JSON="$ARTIFACT_DIR/summary.json"
REPORT_MD="$ARTIFACT_DIR/report.md"

HOST_OS="$(uname -s)"
INSTALLED_TARGETS="$(rustup target list --installed)"
CARGO_NDK_BIN="$(command -v cargo-ndk || true)"
ANDROID_NDK_PATH="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"

FAILED=0

host_ffi_status="pass"
host_ffi_detail="ffi_roundtrip passed"
ios_device_status="environment_dependent"
ios_device_detail="requires a Darwin host with rustup target aarch64-apple-ios"
ios_sim_status="environment_dependent"
ios_sim_detail="requires a Darwin host with rustup target aarch64-apple-ios-sim"
android_arm64_status="environment_dependent"
android_arm64_detail="requires cargo-ndk plus ANDROID_NDK_HOME/ANDROID_NDK_ROOT"

run_with_log() {
  local lane="$1"
  shift
  local log_file="$ARTIFACT_DIR/${lane}.log"
  echo "[portable-mobile] running ${lane}: $*"
  if "$@" >"$log_file" 2>&1; then
    echo "[portable-mobile] ${lane}: pass"
    return 0
  fi
  cat "$log_file" >&2
  return 1
}

if ! run_with_log host_ffi cargo test -p arc-kernel-mobile --test ffi_roundtrip -- --nocapture; then
  host_ffi_status="fail"
  host_ffi_detail="ffi_roundtrip failed"
  FAILED=1
fi

if [[ "$HOST_OS" == "Darwin" ]] && printf '%s\n' "$INSTALLED_TARGETS" | grep -qx 'aarch64-apple-ios'; then
  if run_with_log ios_device cargo build -p arc-kernel-mobile --release --target aarch64-apple-ios; then
    ios_device_status="pass"
    ios_device_detail="aarch64-apple-ios release build passed"
  else
    ios_device_status="fail"
    ios_device_detail="aarch64-apple-ios release build failed"
    FAILED=1
  fi
elif [[ "$HOST_OS" != "Darwin" ]]; then
  ios_device_detail="requires a Darwin host for Apple SDK-backed mobile builds"
else
  ios_device_detail="rustup target aarch64-apple-ios is not installed"
fi

if [[ "$HOST_OS" == "Darwin" ]] && printf '%s\n' "$INSTALLED_TARGETS" | grep -qx 'aarch64-apple-ios-sim'; then
  if run_with_log ios_sim cargo build -p arc-kernel-mobile --release --target aarch64-apple-ios-sim; then
    ios_sim_status="pass"
    ios_sim_detail="aarch64-apple-ios-sim release build passed"
  else
    ios_sim_status="fail"
    ios_sim_detail="aarch64-apple-ios-sim release build failed"
    FAILED=1
  fi
elif [[ "$HOST_OS" != "Darwin" ]]; then
  ios_sim_detail="requires a Darwin host for Apple simulator SDK builds"
else
  ios_sim_detail="rustup target aarch64-apple-ios-sim is not installed"
fi

if printf '%s\n' "$INSTALLED_TARGETS" | grep -qx 'aarch64-linux-android'; then
  if [[ -n "$CARGO_NDK_BIN" && -n "$ANDROID_NDK_PATH" ]]; then
    if run_with_log android_arm64 \
      cargo ndk --target aarch64-linux-android -o "$ARTIFACT_DIR/android-jniLibs" \
      build --release -p arc-kernel-mobile; then
      android_arm64_status="pass"
      android_arm64_detail="aarch64-linux-android release build passed via cargo-ndk"
    else
      android_arm64_status="fail"
      android_arm64_detail="aarch64-linux-android release build failed under cargo-ndk"
      FAILED=1
    fi
  else
    missing_parts=()
    if [[ -z "$CARGO_NDK_BIN" ]]; then
      missing_parts+=("cargo-ndk")
    fi
    if [[ -z "$ANDROID_NDK_PATH" ]]; then
      missing_parts+=("ANDROID_NDK_HOME/ANDROID_NDK_ROOT")
    fi
    if [[ "${#missing_parts[@]}" -gt 1 ]]; then
      android_arm64_detail="requires ${missing_parts[0]} and ${missing_parts[1]} for a real NDK-backed link step"
    else
      android_arm64_detail="requires ${missing_parts[0]} for a real NDK-backed link step"
    fi
  fi
else
  android_arm64_detail="rustup target aarch64-linux-android is not installed"
fi

cat >"$REPORT_MD" <<EOF
# Mobile Kernel Qualification

Host: \`$HOST_OS\`

| Lane | Status | Detail |
|---|---|---|
| \`host_ffi\` | \`$host_ffi_status\` | $host_ffi_detail |
| \`ios_device\` | \`$ios_device_status\` | $ios_device_detail |
| \`ios_sim\` | \`$ios_sim_status\` | $ios_sim_detail |
| \`android_arm64\` | \`$android_arm64_status\` | $android_arm64_detail |

Artifacts:

- JSON summary: \`$REPORT_JSON\`
- Logs: \`$ARTIFACT_DIR/*.log\`
EOF

export HOST_OS CARGO_TARGET_DIR
export host_ffi_status host_ffi_detail
export ios_device_status ios_device_detail
export ios_sim_status ios_sim_detail
export android_arm64_status android_arm64_detail

python3 - "$REPORT_JSON" <<'PY'
import json
import os
import sys

summary_path = sys.argv[1]
data = {
    "schema": "arc.mobile-kernel-qualification.v1",
    "host": os.environ["HOST_OS"],
    "cargo_target_dir": os.environ["CARGO_TARGET_DIR"],
    "artifact_dir": os.path.dirname(summary_path),
    "lanes": {
        "host_ffi": {
            "status": os.environ["host_ffi_status"],
            "detail": os.environ["host_ffi_detail"],
        },
        "ios_device": {
            "status": os.environ["ios_device_status"],
            "detail": os.environ["ios_device_detail"],
        },
        "ios_sim": {
            "status": os.environ["ios_sim_status"],
            "detail": os.environ["ios_sim_detail"],
        },
        "android_arm64": {
            "status": os.environ["android_arm64_status"],
            "detail": os.environ["android_arm64_detail"],
        },
    },
}
with open(summary_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

echo "[portable-mobile] report_md=$REPORT_MD"
echo "[portable-mobile] report_json=$REPORT_JSON"

if [[ "$FAILED" -ne 0 ]]; then
  echo "[portable-mobile] one or more required lanes failed" >&2
  exit 1
fi

echo "[portable-mobile] ok"
