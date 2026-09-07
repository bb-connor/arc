#!/usr/bin/env bash
# Provision the signed manifest and native-launch policy an MCP edge needs
# for one exact wrapped command, and export the launch flags that bind them.
#
# Source this file, then call:
#
#   chio_provision_mcp_launch <chio> <output_dir> <server_id> <server_name> \
#     <server_version> <working_directory> <target> [target_arg...]
#
# The target is resolved through PATH when it carries no slash and then
# canonicalized, because the policy binds the exact executable the edge will
# run and the edge canonicalizes the wrapped command the same way. The tool
# surface is discovered from the target itself. The output directory must be
# an absolute path whose parent exists; a prior provision left there by this
# helper is replaced, because every provision binds the digest of the chio
# executable that made it and a rebuilt binary invalidates the old one.
#
# On success the following are exported:
#
#   CHIO_LAUNCH_SIGNED_MANIFEST      path of the signed manifest
#   CHIO_LAUNCH_MANIFEST_PUBLIC_KEY  hex public key that signed it
#   CHIO_LAUNCH_CAGE_POLICY          path of the signed native-launch policy
#   CHIO_LAUNCH_CAGE_POLICY_SIGNER   hex public key that signed the policy
#   CHIO_LAUNCH_TARGET               the canonical target executable
#   CHIO_LAUNCH_FLAGS                array of the four launch flags with values
#   CHIO_LAUNCH_COMMAND              array of the canonical target and its arguments
#
# Splice "${CHIO_LAUNCH_FLAGS[@]}" before `--` and "${CHIO_LAUNCH_COMMAND[@]}"
# after it so the launched command equals the bound one by construction.
#
# Migration stage Disabled is legacy-authorized demo mode, not cage
# containment; the execution identity recorded in the policy is the invoking
# user, which must not be root.

chio_canonical_path() {
  python3 - "$1" <<'PY'
import os
import sys

path = sys.argv[1]
if not os.path.isabs(path):
    path = os.path.abspath(path)
print(os.path.realpath(path))
PY
}

# A Python interpreter is resolved through the interpreter itself, because
# version managers put a shim on PATH whose canonical file is the manager,
# not the interpreter the edge must bind. The edge refuses an executable that
# other users can write, so a version-managed interpreter installed writable
# yields to the system interpreter when one exists.
chio_resolve_python() {
  "$1" - <<'PY'
import os
import stat
import sys

candidates = [sys.executable, "/usr/bin/python3", "/usr/local/bin/python3"]
seen = []
for candidate in candidates:
    if not candidate:
        continue
    path = os.path.realpath(candidate)
    if path in seen:
        continue
    seen.append(path)
    try:
        info = os.stat(path)
    except OSError:
        continue
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        continue
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        continue
    print(path)
    raise SystemExit(0)
raise SystemExit("no Python interpreter that other users cannot write: " + ", ".join(seen))
PY
}

chio_resolve_target() {
  local target="$1"
  case "$(basename -- "${target}")" in
    python|python3|python3.*)
      local interpreter
      interpreter="$(chio_resolve_python "${target}")" || {
        echo "chio_provision_mcp_launch: ${target} yields no usable interpreter: ${interpreter}" >&2
        return 1
      }
      target="${interpreter}"
      ;;
    *)
      case "${target}" in
        */*) ;;
        *)
          local resolved
          resolved="$(command -v -- "${target}" 2>/dev/null || true)"
          if [[ -z "${resolved}" ]]; then
            echo "chio_provision_mcp_launch: target ${target} is not on PATH" >&2
            return 1
          fi
          target="${resolved}"
          ;;
      esac
      ;;
  esac
  chio_canonical_path "${target}"
}

# The edge refuses a wrapped script that other users can write, because a
# writable script could change between provisioning and launch. Checkouts
# made under a permissive umask carry group-writable files, so the launcher
# removes the group and other write bits from the exact script it binds and
# says so. Git does not track those bits.
chio_bind_script_mode() {
  local script="$1"
  if [[ ! -f "${script}" ]]; then
    echo "chio_provision_mcp_launch: wrapped script ${script} does not exist" >&2
    return 1
  fi
  local writable_by_others
  writable_by_others="$(python3 -c 'import os, stat, sys; print(int(bool(os.stat(sys.argv[1]).st_mode & (stat.S_IWGRP | stat.S_IWOTH))))' "${script}")"
  if [[ "${writable_by_others}" == "1" ]]; then
    chmod go-w -- "${script}"
    echo "chio_provision_mcp_launch: removed group and other write access from ${script}" >&2
  fi
}

chio_provision_mcp_launch() {
  if [[ $# -lt 7 ]]; then
    echo "usage: chio_provision_mcp_launch <chio> <output_dir> <server_id> <server_name> <server_version> <working_directory> <target> [target_arg...]" >&2
    return 1
  fi
  local chio="$1" output_dir="$2" server_id="$3" server_name="$4" server_version="$5" working_directory="$6" target="$7"
  shift 7

  if [[ "$(id -u)" -eq 0 ]]; then
    echo "chio_provision_mcp_launch: refusing to bind a root execution identity; run the launch as an unprivileged user" >&2
    return 1
  fi
  if [[ ! -x "${chio}" ]]; then
    echo "chio_provision_mcp_launch: ${chio} is not an executable chio binary" >&2
    return 1
  fi

  local canonical_target canonical_workdir
  canonical_target="$(chio_resolve_target "${target}")" || return 1
  canonical_workdir="$(chio_canonical_path "${working_directory}")"
  if [[ ! -d "${canonical_workdir}" ]]; then
    echo "chio_provision_mcp_launch: working directory ${working_directory} does not exist" >&2
    return 1
  fi

  local parent
  parent="$(dirname -- "${output_dir}")"
  mkdir -p -- "${parent}"
  output_dir="$(chio_canonical_path "${parent}")/$(basename -- "${output_dir}")"
  if [[ -e "${output_dir}" ]]; then
    if [[ -f "${output_dir}/provision-report.json" ]]; then
      rm -rf -- "${output_dir}"
    else
      echo "chio_provision_mcp_launch: ${output_dir} exists and is not a prior provision" >&2
      return 1
    fi
  fi

  local -a target_args=("$@")
  local argument
  for argument in ${target_args[@]+"${target_args[@]}"}; do
    if [[ -f "${argument}" ]]; then
      chio_bind_script_mode "${argument}" || return 1
    fi
  done
  local -a provision=(
    "${chio}" security provision-native-mcp-demo
    --output-dir "${output_dir}"
    --discover-tools
    --target "${canonical_target}"
    --working-directory "${canonical_workdir}"
    --execution-uid "$(id -u)"
    --execution-gid "$(id -g)"
    --server-id "${server_id}"
    --server-name "${server_name}"
    --server-version "${server_version}"
  )
  for argument in ${target_args[@]+"${target_args[@]}"}; do
    provision+=(--target-arg "${argument}")
  done
  if ! "${provision[@]}" >"${output_dir}.provision-report.json"; then
    echo "chio_provision_mcp_launch: provisioning ${server_id} failed" >&2
    return 1
  fi

  CHIO_LAUNCH_SIGNED_MANIFEST="${output_dir}/signed-manifest.json"
  CHIO_LAUNCH_MANIFEST_PUBLIC_KEY="$(cat -- "${output_dir}/manifest-public-key")"
  CHIO_LAUNCH_CAGE_POLICY="${output_dir}/cage-launch-policy.json"
  CHIO_LAUNCH_CAGE_POLICY_SIGNER="$(cat -- "${output_dir}/cage-policy-signer")"
  CHIO_LAUNCH_TARGET="${canonical_target}"
  CHIO_LAUNCH_FLAGS=(
    --signed-manifest "${CHIO_LAUNCH_SIGNED_MANIFEST}"
    --manifest-public-key "${CHIO_LAUNCH_MANIFEST_PUBLIC_KEY}"
    --cage-policy "${CHIO_LAUNCH_CAGE_POLICY}"
    --cage-policy-signer "${CHIO_LAUNCH_CAGE_POLICY_SIGNER}"
  )
  CHIO_LAUNCH_COMMAND=("${canonical_target}" ${target_args[@]+"${target_args[@]}"})
  export CHIO_LAUNCH_SIGNED_MANIFEST CHIO_LAUNCH_MANIFEST_PUBLIC_KEY \
    CHIO_LAUNCH_CAGE_POLICY CHIO_LAUNCH_CAGE_POLICY_SIGNER CHIO_LAUNCH_TARGET
}

# Print the current public key of the capability authority behind a trust
# service, which an edge under that control URL must pin exactly.
chio_control_authority_public_key() {
  local control_url="$1" service_token="$2"
  curl --silent --fail --show-error \
    --header "Authorization: Bearer ${service_token}" \
    "${control_url%/}/v1/authority" | python3 -c '
import json
import sys

authority = json.load(sys.stdin)
key = authority.get("publicKey")
if not isinstance(key, str) or not key:
    raise SystemExit("the trust service reported no current authority public key")
print(key)
'
}

# Write a fresh resume HMAC keyring for an edge that keeps durable session
# state, as a private file, and print its path. The key is 32 random bytes;
# a keyring is never shared between edges.
chio_write_resume_hmac_keyring() {
  local path="$1"
  python3 - "${path}" <<'PY'
import base64
import json
import os
import sys

path = sys.argv[1]
key = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
keyring = {
    "schema": "chio.remote-mcp.resume-hmac-keyring.v1",
    "current": {"keyId": "launch-" + os.urandom(4).hex(), "version": 1, "keyBase64": key},
    "previous": [],
}
if os.path.lexists(path):
    os.remove(path)
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(keyring, handle, indent=2)
    handle.write("\n")
print(path)
PY
}

# Print a private directory for a launch's security state: session databases,
# resume keyrings and provisioned policies. The edge trusts session state only
# under directories that nobody else can write, so this lives under the user's
# runtime directory or a root-owned sticky temporary directory, never under a
# checkout, whose mode follows the umask that made it.
chio_launch_state_dir() {
  local name="$1"
  local root="${XDG_RUNTIME_DIR:-/tmp}/chio-launch-$(id -u)"
  (umask 077 && mkdir -p -- "${root}/${name}") || return 1
  chmod 0700 -- "${root}" "${root}/${name}"
  chio_canonical_path "${root}/${name}"
}
