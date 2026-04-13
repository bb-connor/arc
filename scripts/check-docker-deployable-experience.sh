#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
example_dir="${repo_root}/examples/docker"

cleanup() {
  (cd "${example_dir}" && docker compose down -v >/dev/null 2>&1) || true
}
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required for the deployable experience check" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for the Docker smoke client" >&2
  exit 1
fi

(cd "${example_dir}" && docker compose up -d --build)

for _ in $(seq 1 120); do
  if curl --silent --fail http://127.0.0.1:8940/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl --silent --fail http://127.0.0.1:8940/health >/dev/null 2>&1; then
  echo "trust viewer service did not become healthy" >&2
  exit 1
fi

for _ in $(seq 1 120); do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8931/mcp || true)"
  if [[ "${status}" == "401" ]]; then
    break
  fi
  sleep 1
done

status="$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:8931/mcp || true)"
if [[ "${status}" != "401" ]]; then
  echo "hosted edge did not become ready" >&2
  exit 1
fi

python3 "${example_dir}/smoke_client.py" > /tmp/arc-docker-smoke.json

python3 - <<'PY'
from pathlib import Path
import json

payload = json.loads(Path("/tmp/arc-docker-smoke.json").read_text())
if not payload.get("receiptId"):
    raise SystemExit("smoke flow did not produce a receipt id")
if not payload.get("capabilityId"):
    raise SystemExit("smoke flow did not expose a capability id")
if not payload.get("viewerUrl"):
    raise SystemExit("smoke flow did not expose a viewer URL")
print("docker deployable experience smoke verified")
PY

curl --silent "http://127.0.0.1:8940/?token=demo-token" | grep -qi "ARC Receipt Dashboard"
