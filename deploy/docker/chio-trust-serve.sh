#!/bin/sh
# Starts the trust service and dashboard with one credential per role:
# CHIO_KERNEL_HOST_TOKEN is the secret of the `kernel-host` credential the
# hosted edge presents as its control token, CHIO_OPERATOR_TOKEN the secret of
# the `operator` credential the dashboard and the `chio trust` commands
# present, and CHIO_AUTHORITY_WORKLOAD_TOKEN the secret of the
# `authority-workload` credential (authority status and capability issuance).
# `chio trust config credential --role` writes each entry, so the access
# configuration holds only SHA-256 digests and each role's preset scopes. The
# demo tokens are public strings, so they are accepted only when CHIO_DEMO=1
# names a local demonstration. The listener serves TLS from CHIO_TLS_CERT and
# CHIO_TLS_KEY, or plaintext only under CHIO_DEMO=1 or CHIO_ALLOW_PLAINTEXT=1
# behind a protecting proxy.
set -eu

demo_kernel_host_token=demo-control-token
demo_operator_token=demo-operator-token
demo_workload_token=demo-workload-token
access_config=/var/lib/chio/trust-access.toml
deployment=chio-docker

refuse() {
  echo "chio-trust-serve: $1" >&2
  exit 64
}

if [ "${CHIO_DEMO:-}" = 1 ]; then
  : "${CHIO_KERNEL_HOST_TOKEN:=$demo_kernel_host_token}"
  : "${CHIO_OPERATOR_TOKEN:=$demo_operator_token}"
  : "${CHIO_AUTHORITY_WORKLOAD_TOKEN:=$demo_workload_token}"
else
  for token in "${CHIO_KERNEL_HOST_TOKEN:-}" "${CHIO_OPERATOR_TOKEN:-}" "${CHIO_AUTHORITY_WORKLOAD_TOKEN:-}"; do
    case "$token" in
      "" | "$demo_kernel_host_token" | "$demo_operator_token" | "$demo_workload_token")
        refuse "set CHIO_KERNEL_HOST_TOKEN, CHIO_OPERATOR_TOKEN and CHIO_AUTHORITY_WORKLOAD_TOKEN to private secrets, or CHIO_DEMO=1 for the local demo"
        ;;
    esac
  done
fi
[ "$CHIO_KERNEL_HOST_TOKEN" != "$CHIO_OPERATOR_TOKEN" ] \
  && [ "$CHIO_KERNEL_HOST_TOKEN" != "$CHIO_AUTHORITY_WORKLOAD_TOKEN" ] \
  && [ "$CHIO_OPERATOR_TOKEN" != "$CHIO_AUTHORITY_WORKLOAD_TOKEN" ] \
  || refuse "CHIO_KERNEL_HOST_TOKEN, CHIO_OPERATOR_TOKEN and CHIO_AUTHORITY_WORKLOAD_TOKEN must differ"

if [ -n "${CHIO_TLS_CERT:-}" ] || [ -n "${CHIO_TLS_KEY:-}" ]; then
  [ -n "${CHIO_TLS_CERT:-}" ] && [ -n "${CHIO_TLS_KEY:-}" ] \
    || refuse "set both CHIO_TLS_CERT and CHIO_TLS_KEY"
  set -- --tls-cert "$CHIO_TLS_CERT" --tls-key "$CHIO_TLS_KEY"
elif [ "${CHIO_DEMO:-}" = 1 ] || [ "${CHIO_ALLOW_PLAINTEXT:-}" = 1 ]; then
  set -- --allow-plaintext
else
  refuse "set CHIO_TLS_CERT and CHIO_TLS_KEY, or CHIO_ALLOW_PLAINTEXT=1 behind a protecting proxy"
fi

credential() {
  CHIO_CREDENTIAL_SECRET="$2" chio trust config credential \
    --id "$1" --role "$1" --deployment "$deployment" \
    --secret-env CHIO_CREDENTIAL_SECRET
}

umask 077
out="${CHIO_ACCESS_CONFIG_OUT:-$access_config}"
{
  printf 'deployment = "%s"\ninternal_listen = "0.0.0.0:8941"\n' "$deployment"
  credential kernel-host "$CHIO_KERNEL_HOST_TOKEN"
  credential operator "$CHIO_OPERATOR_TOKEN"
  credential authority-workload "$CHIO_AUTHORITY_WORKLOAD_TOKEN"
} > "$out"

exec chio \
  --receipt-db /var/lib/chio/receipts.sqlite \
  --authority-db /var/lib/chio/authority.sqlite \
  --session-db /var/lib/chio/trust-sessions.sqlite \
  trust serve \
  --listen 0.0.0.0:8940 \
  "$@" \
  --access-config "$out"
