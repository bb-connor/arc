#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/spec/registries" "${TMP_DIR}/formal/lean4/Chio/Chio/Proofs" "${TMP_DIR}/formal"
touch "${TMP_DIR}/formal/lean4/Chio/Chio/Proofs/Safe.lean"

FORMAL_INV="${TMP_DIR}/formal/theorem-inventory.json"
SPEC_INV="${TMP_DIR}/spec/registries/theorem-inventory.v1.json"
SPEC_MANIFEST="${TMP_DIR}/spec/registries/proof-manifest.v1.json"
OUT="${TMP_DIR}/out"
ERR="${TMP_DIR}/err"

write_formal_inventory() {
  cat >"${FORMAL_INV}" <<'JSON'
{
  "schema": "chio.theorem-inventory.v1",
  "theorems": [
    {
      "id": "proof.safe",
      "leanName": "Chio.Proofs.safe",
      "file": "formal/lean4/Chio/Chio/Proofs/Safe.lean",
      "kind": "theorem",
      "rootImported": true,
      "mapsTo": ["P1"]
    }
  ]
}
JSON
}

write_spec_inventory_pass() {
  cat >"${SPEC_INV}" <<'JSON'
{
  "version": "v1",
  "theorems": [
    {
      "id": "proof.safe",
      "kind": "lean",
      "status": "proven",
      "proof_path": "formal/lean4/Chio/Chio/Proofs/Safe.lean",
      "statement": "Safe theorem.",
      "depends_on": []
    }
  ],
  "proposed_theorems": [
    {
      "id": "proof.future",
      "kind": "lean",
      "status": "proposed",
      "statement": "Future theorem.",
      "depends_on": ["proof.safe"]
    },
    {
      "id": "proof.assumed",
      "kind": "lean",
      "status": "assumed",
      "statement": "Assumed theorem.",
      "depends_on": ["proof.safe"]
    },
    {
      "id": "proof.advisory",
      "kind": "lean",
      "status": "advisory_only",
      "statement": "Advisory theorem.",
      "depends_on": ["proof.safe"]
    }
  ]
}
JSON
}

write_manifest_pass() {
  cat >"${SPEC_MANIFEST}" <<'JSON'
{
  "version": "v1",
  "manifests": [
    {
      "id": "manifest.safe",
      "claim_ref": "claim.safe",
      "evidence": [
        {"kind": "lean_theorem", "ref": "proof.safe"}
      ],
      "evidence_proposed": [
        {"kind": "lean_theorem", "ref": "proof.future"}
      ]
    }
  ],
  "proposed_manifests": []
}
JSON
}

run_gate() {
  CHIO_REPO_ROOT="${TMP_DIR}" \
  CHIO_SPEC_THEOREM_INVENTORY="${SPEC_INV}" \
  CHIO_SPEC_PROOF_MANIFEST="${SPEC_MANIFEST}" \
  CHIO_FORMAL_THEOREM_INVENTORY="${FORMAL_INV}" \
    bash "${REPO_ROOT}/scripts/check-formal-registries.sh" >"${OUT}" 2>"${ERR}"
}

assert_passes() {
  local label="$1"
  if ! run_gate; then
    echo "FAIL: expected pass for ${label}" >&2
    cat "${OUT}" >&2
    cat "${ERR}" >&2
    exit 1
  fi
}

assert_fails() {
  local label="$1"
  if run_gate; then
    echo "FAIL: expected failure for ${label}" >&2
    cat "${OUT}" >&2
    cat "${ERR}" >&2
    exit 1
  fi
}

write_formal_inventory
write_spec_inventory_pass
write_manifest_pass
assert_passes "valid proven/proposed split"

python3 - "${SPEC_MANIFEST}" <<'PY'
import json
import sys
path = sys.argv[1]
doc = json.load(open(path))
doc["manifests"][0]["evidence"].append({"kind": "lean_theorem", "ref": "proof.future"})
open(path, "w").write(json.dumps(doc, indent=2) + "\n")
PY
assert_fails "proposed theorem in release evidence"
grep -q "proposed theorem proof.future appears in release evidence" "${OUT}"

write_manifest_pass
python3 - "${SPEC_MANIFEST}" <<'PY'
import json
import sys
path = sys.argv[1]
doc = json.load(open(path))
doc["manifests"][0]["evidence"].append({"kind": "lean_theorem", "ref": "proof.assumed"})
open(path, "w").write(json.dumps(doc, indent=2) + "\n")
PY
assert_fails "assumed theorem in release evidence"
grep -q "assumed theorem proof.assumed appears in release evidence" "${OUT}"

write_manifest_pass
python3 - "${SPEC_MANIFEST}" <<'PY'
import json
import sys
path = sys.argv[1]
doc = json.load(open(path))
doc["manifests"][0]["evidence"].append({"kind": "lean_theorem", "ref": "proof.advisory"})
open(path, "w").write(json.dumps(doc, indent=2) + "\n")
PY
assert_fails "advisory theorem in release evidence"
grep -q "non-release theorem proof.advisory status=advisory_only appears in release evidence" "${OUT}"

write_manifest_pass
python3 - "${SPEC_INV}" <<'PY'
import json
import sys
path = sys.argv[1]
doc = json.load(open(path))
doc["theorems"][0].pop("proof_path")
open(path, "w").write(json.dumps(doc, indent=2) + "\n")
PY
assert_fails "proven theorem missing proof_path"
grep -q "status=proven requires proof_path" "${OUT}"

write_formal_inventory
write_spec_inventory_pass
write_manifest_pass
python3 - "${SPEC_INV}" "${SPEC_MANIFEST}" <<'PY'
import json
import sys
inventory_path = sys.argv[1]
manifest_path = sys.argv[2]
inventory = json.load(open(inventory_path))
inventory["theorems"].append(
    {
        "id": "proof.assumed",
        "kind": "lean",
        "status": "assumed",
        "proof_path": "formal/lean4/Chio/Chio/Proofs/Safe.lean",
        "statement": "Assumed theorem.",
        "depends_on": [],
    }
)
manifest = json.load(open(manifest_path))
manifest["manifests"][0]["evidence"].append(
    {"kind": "lean_theorem", "ref": "proof.assumed"}
)
open(inventory_path, "w").write(json.dumps(inventory, indent=2) + "\n")
open(manifest_path, "w").write(json.dumps(manifest, indent=2) + "\n")
PY
assert_fails "assumed theorem in release evidence"
grep -q "assumed theorem proof.assumed appears in release evidence" "${OUT}"

echo "PASS: formal registry validator self-test"
