#!/bin/sh
# Starts the trust service and dashboard. CHIO_SERVICE_TOKEN is the secret of
# the control client credential (every caller scope) and
# CHIO_AUTHORITY_WORKLOAD_TOKEN the secret of the authority workload
# credential (authority status and capability issuance). The entrypoint writes
# the access configuration holding only their SHA-256 digests. The demo tokens
# are public strings, so they are accepted only when CHIO_DEMO=1 names a local
# demonstration. The listener serves TLS from CHIO_TLS_CERT and CHIO_TLS_KEY,
# or plaintext only under CHIO_DEMO=1 or CHIO_ALLOW_PLAINTEXT=1 behind a
# protecting proxy.
set -eu

demo_service_token=demo-control-token
demo_workload_token=demo-workload-token
access_config=/var/lib/chio/trust-access.toml
deployment=chio-docker

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
[ "$CHIO_SERVICE_TOKEN" != "$CHIO_AUTHORITY_WORKLOAD_TOKEN" ] \
  || refuse "CHIO_SERVICE_TOKEN and CHIO_AUTHORITY_WORKLOAD_TOKEN must differ"

if [ -n "${CHIO_TLS_CERT:-}" ] || [ -n "${CHIO_TLS_KEY:-}" ]; then
  [ -n "${CHIO_TLS_CERT:-}" ] && [ -n "${CHIO_TLS_KEY:-}" ] \
    || refuse "set both CHIO_TLS_CERT and CHIO_TLS_KEY"
  set -- --tls-cert "$CHIO_TLS_CERT" --tls-key "$CHIO_TLS_KEY"
elif [ "${CHIO_DEMO:-}" = 1 ] || [ "${CHIO_ALLOW_PLAINTEXT:-}" = 1 ]; then
  set -- --allow-plaintext
else
  refuse "set CHIO_TLS_CERT and CHIO_TLS_KEY, or CHIO_ALLOW_PLAINTEXT=1 behind a protecting proxy"
fi

digest() {
  printf '%s' "$1" | sha256sum | cut -d ' ' -f 1
}

umask 077
cat > "${CHIO_ACCESS_CONFIG_OUT:-$access_config}" <<ACCESS
deployment = "$deployment"
internal_listen = "0.0.0.0:8941"

[[credentials]]
id = "control-client"
kind = "deployment"
secret_sha256 = "$(digest "$CHIO_SERVICE_TOKEN")"
scopes = ["admin:emergency", "admission-authority:write", "attestation:write", "authority:admin", "authority:read", "budgets:read", "budgets:write", "capabilities:issue", "certifications:read", "certifications:write", "credit:read", "credit:write", "evidence:read", "evidence:write", "federation:read", "federation:write", "findings:read", "findings:write", "fiscal:read", "fiscal:write", "lineage:read", "lineage:write", "metrics:read", "passport:read", "passport:write", "receipt-openings:erase", "receipt-openings:read", "receipts:admin", "receipts:append", "receipts:read", "registry:write", "reports:read", "reputation:read", "reputation:write", "revocations:read", "revocations:write", "scim:write", "settlement:write"]
deployment = "$deployment"
tenant_authority = "deployment"

[[credentials]]
id = "authority-workload"
kind = "deployment"
secret_sha256 = "$(digest "$CHIO_AUTHORITY_WORKLOAD_TOKEN")"
scopes = ["authority:read", "capabilities:issue"]
deployment = "$deployment"
tenant_authority = "deployment"
ACCESS

exec chio \
  --receipt-db /var/lib/chio/receipts.sqlite \
  --authority-db /var/lib/chio/authority.sqlite \
  --session-db /var/lib/chio/trust-sessions.sqlite \
  trust serve \
  --listen 0.0.0.0:8940 \
  "$@" \
  --access-config "${CHIO_ACCESS_CONFIG_OUT:-$access_config}"
