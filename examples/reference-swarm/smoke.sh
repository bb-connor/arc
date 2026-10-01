#!/usr/bin/env bash
# The reference swarm end to end on one host: trust-control, three edges
# wrapping the reference tools, the orchestrator with its two workers, then
# an evidence export verified offline.
#
# Every edge launch uses the provisioner's explicitly Disabled demo profile.
# This remains unconfined on x86_64 too. It is a protocol integration exercise,
# not evidence for the Enforced Linux confinement or security launch gate.
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"
source "${ROOT}/examples/_shared/hello-http-common.sh"
source "${ROOT}/scripts/lib/provision-mcp-launch.sh"

echo "reference swarm: Disabled demo profile, not confinement qualification" >&2

ARTIFACT_ROOT="${EXAMPLE_ROOT}/artifacts/live/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
STATE_DIR="${ARTIFACT_ROOT}/state"
OUTPUT_DIR="${ARTIFACT_ROOT}/swarm"
mkdir -p "${LOG_DIR}" "${STATE_DIR}" "${OUTPUT_DIR}"

CHIO_BIN="$(ensure_chio_bin)"
TOOLS_DIR="${CHIO_REFERENCE_TOOLS_DIR:-$(dirname "${CHIO_BIN}")}"
for tool in chio-tool-repo-reader chio-tool-artifact-writer chio-tool-digest; do
  if [[ ! -x "${TOOLS_DIR}/${tool}" ]]; then
    (cd "${ROOT}" && cargo build -p chio-reference-tools)
    TOOLS_DIR="$(dirname "${CHIO_BIN}")"
    break
  fi
done
(cd "${ROOT}" && cargo build -p reference-swarm)
SWARM_BIN="$(dirname "${CHIO_BIN}")/reference-swarm"

SERVICE_TOKEN="${CHIO_SERVICE_TOKEN:-demo-control-token}"
EDGE_TOKEN="${CHIO_EDGE_TOKEN:-demo-token}"
ADMIN_TOKEN="${CHIO_ADMIN_TOKEN:-demo-admin-token}"
WORKLOAD_TOKEN="${CHIO_WORKLOAD_TOKEN:-demo-workload-token}"
PRIVATE_STATE="$(chio_launch_state_dir "reference-swarm-$$")"

REPOSITORY="${STATE_DIR}/repository"
mkdir -p "${REPOSITORY}/src"
printf '# reference repository\n\nRead by the reference swarm.\n' > "${REPOSITORY}/README.md"
printf 'pub fn answer() -> u8 {\n    42\n}\n' > "${REPOSITORY}/src/lib.rs"
ARTIFACT="${STATE_DIR}/report.txt"
: > "${ARTIFACT}"

TRUST_PORT="$(pick_free_port)"
READER_PORT="$(pick_free_port)"
WRITER_PORT="$(pick_free_port)"
DIGEST_PORT="$(pick_free_port)"
CONTROL_URL="http://127.0.0.1:${TRUST_PORT}"

BG_PIDS=()
cleanup() {
  for pid in "${BG_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ -f "${STATE_DIR}/reader.pid" ]]; then
    kill "$(cat "${STATE_DIR}/reader.pid")" 2>/dev/null || true
  fi
}
trap cleanup EXIT

"${CHIO_BIN}" --session-db "${PRIVATE_STATE}/trust-sessions.sqlite3" trust serve \
  --listen "127.0.0.1:${TRUST_PORT}" --service-token "${SERVICE_TOKEN}" \
  --authority-workload-token "${WORKLOAD_TOKEN}" \
  --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" \
  --authority-db "${STATE_DIR}/trust-authority.sqlite3" \
  >"${LOG_DIR}/trust.log" 2>&1 &
BG_PIDS+=($!)
wait_for_http "${CONTROL_URL}/health"

launch_edge() {
  local role="$1" port="$2" log="$3"
  CHIO_BIN="${CHIO_BIN}" \
  EDGE_ROLE="${role}" \
  EDGE_LISTEN="127.0.0.1:${port}" \
  EDGE_PRIVATE_STATE="${PRIVATE_STATE}/${role}" \
  EDGE_SESSION_DB="${PRIVATE_STATE}/${role}-sessions.sqlite3" \
  EDGE_TOOL="${TOOLS_DIR}/chio-tool-${4}" \
  EDGE_ROOT="${REPOSITORY}" \
  EDGE_ARTIFACT="${ARTIFACT}" \
  CHIO_CONTROL_URL="${CONTROL_URL}" \
  CHIO_CONTROL_TOKEN="${SERVICE_TOKEN}" \
  CHIO_WORKLOAD_TOKEN="${WORKLOAD_TOKEN}" \
  CHIO_EDGE_TOKEN="${EDGE_TOKEN}" \
  CHIO_ADMIN_TOKEN="${ADMIN_TOKEN}" \
    "${EXAMPLE_ROOT}/run-edge.sh" >>"${log}" 2>&1 &
  echo $!
}

READER_PID="$(launch_edge reader "${READER_PORT}" "${LOG_DIR}/reader-edge.log" repo-reader)"
echo "${READER_PID}" > "${STATE_DIR}/reader.pid"
WRITER_PID="$(launch_edge writer "${WRITER_PORT}" "${LOG_DIR}/writer-edge.log" artifact-writer)"
BG_PIDS+=("${WRITER_PID}")
DIGEST_PID="$(launch_edge digest "${DIGEST_PORT}" "${LOG_DIR}/digest-edge.log" digest)"
BG_PIDS+=("${DIGEST_PID}")
wait_for_port 127.0.0.1 "${READER_PORT}"
wait_for_port 127.0.0.1 "${WRITER_PORT}"
wait_for_port 127.0.0.1 "${DIGEST_PORT}"

# The recovery scenario's hook: kill the reader edge without a drain (a
# graceful stop ends its sessions on purpose), start it again with the same
# provisioned material, session store and keyring, and wait until it listens.
RESTART_HOOK="${STATE_DIR}/restart-reader.sh"
cat > "${RESTART_HOOK}" <<HOOK
#!/usr/bin/env bash
set -euo pipefail
source "${ROOT}/examples/_shared/hello-http-common.sh"
pid="\$(cat "${STATE_DIR}/reader.pid")"
sleep 1
kill -KILL "\${pid}" 2>/dev/null || true
for _ in \$(seq 1 100); do
  kill -0 "\${pid}" 2>/dev/null || break
  sleep 0.1
done
CHIO_PROVISION_REUSE=1 CHIO_BIN="${CHIO_BIN}" EDGE_ROLE=reader EDGE_LISTEN="127.0.0.1:${READER_PORT}" \\
EDGE_PRIVATE_STATE="${PRIVATE_STATE}/reader" EDGE_SESSION_DB="${PRIVATE_STATE}/reader-sessions.sqlite3" \\
EDGE_TOOL="${TOOLS_DIR}/chio-tool-repo-reader" EDGE_ROOT="${REPOSITORY}" \\
CHIO_CONTROL_URL="${CONTROL_URL}" CHIO_CONTROL_TOKEN="${SERVICE_TOKEN}" CHIO_WORKLOAD_TOKEN="${WORKLOAD_TOKEN}" \\
CHIO_EDGE_TOKEN="${EDGE_TOKEN}" CHIO_ADMIN_TOKEN="${ADMIN_TOKEN}" \\
  nohup "${EXAMPLE_ROOT}/run-edge.sh" >>"${LOG_DIR}/reader-edge.log" 2>&1 &
echo \$! > "${STATE_DIR}/reader.pid"
wait_for_port 127.0.0.1 "${READER_PORT}"
HOOK
chmod 0755 "${RESTART_HOOK}"

CHIO_SERVICE_TOKEN="${SERVICE_TOKEN}" CHIO_AUTH_TOKEN="${EDGE_TOKEN}" CHIO_ADMIN_TOKEN="${ADMIN_TOKEN}" \
  "${SWARM_BIN}" \
  --control-url "${CONTROL_URL}" \
  --reader-url "http://127.0.0.1:${READER_PORT}" \
  --writer-url "http://127.0.0.1:${WRITER_PORT}" \
  --digest-url "http://127.0.0.1:${DIGEST_PORT}" \
  --artifact "${ARTIFACT}" \
  --output "${OUTPUT_DIR}" \
  --restart-hook "${RESTART_HOOK}" | tee "${LOG_DIR}/swarm.log"

# Stop the edges before the export so every receipt is flushed.
cleanup
BG_PIDS=()
rm -f "${STATE_DIR}/reader.pid"
trap - EXIT

EVIDENCE_DIR="${ARTIFACT_ROOT}/evidence"
"${CHIO_BIN}" --receipt-db "${STATE_DIR}/trust-receipts.sqlite3" evidence export \
  --output "${EVIDENCE_DIR}" --admin-all > "${LOG_DIR}/evidence-export.log"
"${CHIO_BIN}" evidence verify --input "${EVIDENCE_DIR}" | tee "${LOG_DIR}/evidence-verify.log"
echo "reference swarm: artifacts under ${ARTIFACT_ROOT}"
