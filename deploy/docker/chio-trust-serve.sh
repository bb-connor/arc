#!/bin/sh
# Starts the trust service and dashboard. The demo tokens are public strings,
# so they are accepted only when CHIO_DEMO=1 names a local demonstration. The
# listener serves TLS from CHIO_TLS_CERT and CHIO_TLS_KEY, or plaintext only
# under CHIO_DEMO=1 or CHIO_ALLOW_PLAINTEXT=1 behind a protecting proxy.
set -eu

demo_service_token=demo-control-token
demo_workload_token=demo-workload-token

refuse() {
  echo "chio-trust-serve: $1" >&2
  exit 64
}

if [ "${CHIO_DEMO:-}" = 1 ]; then
  : "${CHIO_SERVICE_TOKEN:=$demo_service_token}"
  : "${CHIO_AUTHORITY_WORKLOAD_TOKEN:=$demo_workload_token}"
else
  for token in "${CHIO_SERVICE_TOKEN:-}" "${CHIO_AUTHORITY_WORKLOAD_TOKEN:-}"; do
    case "$token" in
      "" | "$demo_service_token" | "$demo_workload_token")
        refuse "set CHIO_SERVICE_TOKEN and CHIO_AUTHORITY_WORKLOAD_TOKEN to private secrets, or CHIO_DEMO=1 for the local demo"
        ;;
    esac
  done
fi

if [ -n "${CHIO_TLS_CERT:-}" ] || [ -n "${CHIO_TLS_KEY:-}" ]; then
  [ -n "${CHIO_TLS_CERT:-}" ] && [ -n "${CHIO_TLS_KEY:-}" ] \
    || refuse "set both CHIO_TLS_CERT and CHIO_TLS_KEY"
  set -- --tls-cert "$CHIO_TLS_CERT" --tls-key "$CHIO_TLS_KEY"
elif [ "${CHIO_DEMO:-}" = 1 ] || [ "${CHIO_ALLOW_PLAINTEXT:-}" = 1 ]; then
  set -- --allow-plaintext
else
  refuse "set CHIO_TLS_CERT and CHIO_TLS_KEY, or CHIO_ALLOW_PLAINTEXT=1 behind a protecting proxy"
fi

exec chio \
  --receipt-db /var/lib/chio/receipts.sqlite \
  --authority-db /var/lib/chio/authority.sqlite \
  --session-db /var/lib/chio/trust-sessions.sqlite \
  trust serve \
  --listen 0.0.0.0:8940 \
  "$@" \
  --service-token "$CHIO_SERVICE_TOKEN" \
  --authority-workload-token "$CHIO_AUTHORITY_WORKLOAD_TOKEN"
