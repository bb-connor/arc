#!/usr/bin/env bash
# Trust-control access configuration for the examples.

# write_trust_access_config <chio-bin> <path> <control-secret> [workload-secret] [extra-scope ...]
#
# Writes an access configuration holding a `kernel-host` role credential for
# <control-secret>, which the example's kernel hosts and its orchestrator
# present, widened by each extra scope, and, when <workload-secret> is
# non-empty, an `authority-workload` role credential (authority status and
# capability issuance) for it. Only SHA-256 digests of the secrets are
# written. The internal listener gets a free loopback port, exported as
# CHIO_CONTROL_INTERNAL_URL for the kernel hosts that follow.
write_trust_access_config() {
  local chio_bin="$1" path="$2" control_secret="$3" workload_secret="${4:-}"
  local extra_scopes=() scope internal_port
  if (($# > 4)); then
    for scope in "${@:5}"; do
      extra_scopes+=(--scope "${scope}")
    done
  fi
  internal_port="$(python3 -c "import socket; s = socket.socket(); s.bind((\"127.0.0.1\", 0)); print(s.getsockname()[1]); s.close()")"
  export CHIO_CONTROL_INTERNAL_URL="http://127.0.0.1:${internal_port}"
  (
    umask 077
    {
      printf "deployment = \"example\"\ninternal_listen = \"127.0.0.1:%s\"\n" "${internal_port}"
      CHIO_EXAMPLE_SECRET="${control_secret}" "${chio_bin}" trust config credential \
        --id kernel-host --role kernel-host --deployment example \
        ${extra_scopes[@]+"${extra_scopes[@]}"} --secret-env CHIO_EXAMPLE_SECRET
      if [[ -n "${workload_secret}" ]]; then
        CHIO_EXAMPLE_SECRET="${workload_secret}" "${chio_bin}" trust config credential \
          --id authority-workload --role authority-workload --deployment example \
          --secret-env CHIO_EXAMPLE_SECRET
      fi
    } >"${path}"
  )
}
