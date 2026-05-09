#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
import json
import os
from pathlib import Path

repo = Path(os.environ.get("CHIO_REPO_ROOT", ".")).resolve()
spec_theorem_path = Path(
    os.environ.get(
        "CHIO_SPEC_THEOREM_INVENTORY",
        repo / "spec/registries/theorem-inventory.v1.json",
    )
)
spec_manifest_path = Path(
    os.environ.get(
        "CHIO_SPEC_PROOF_MANIFEST",
        repo / "spec/registries/proof-manifest.v1.json",
    )
)
formal_inventory_path = Path(
    os.environ.get(
        "CHIO_FORMAL_THEOREM_INVENTORY",
        repo / "formal/theorem-inventory.json",
    )
)


def load_json(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"formal registry validator: missing file {path}")
    return json.loads(path.read_text(encoding="utf-8"))


spec_theorems_doc = load_json(spec_theorem_path)
spec_manifest_doc = load_json(spec_manifest_path)
formal_inventory_doc = load_json(formal_inventory_path)

errors: list[str] = []
allowed_statuses = {
    "proven",
    "proven_partial",
    "advisory_only",
    "assumed",
    "proposed",
}

formal_theorems = {
    item.get("id"): item
    for item in formal_inventory_doc.get("theorems", [])
    if item.get("id")
}
spec_entries: list[tuple[str, dict]] = []
for section in ("theorems", "proposed_theorems"):
    for item in spec_theorems_doc.get(section, []):
        spec_entries.append((section, item))

spec_theorems: dict[str, dict] = {}
for section, item in spec_entries:
    theorem_id = item.get("id")
    if not theorem_id:
        errors.append(f"{section}: theorem entry missing id")
        continue
    if theorem_id in spec_theorems:
        errors.append(f"duplicate theorem id: {theorem_id}")
        continue
    spec_theorems[theorem_id] = item

for section, item in spec_entries:
    theorem_id = item.get("id", "<missing>")
    status = item.get("status")
    if status not in allowed_statuses:
        errors.append(f"{theorem_id}: invalid status {status!r}")

    statement = (item.get("statement") or "").strip()
    if not statement:
        errors.append(f"{theorem_id}: missing statement")

    for dep in item.get("depends_on", []):
        if dep not in spec_theorems:
            errors.append(f"{theorem_id}: depends_on unknown theorem {dep}")

    proof_path = (item.get("proof_path") or "").strip()
    if proof_path and not (repo / proof_path).exists():
        errors.append(f"{theorem_id}: proof_path does not exist: {proof_path}")

    if status == "proven":
        if not proof_path:
            errors.append(f"{theorem_id}: status=proven requires proof_path")
        formal = formal_theorems.get(theorem_id)
        if formal is None:
            errors.append(f"{theorem_id}: status=proven but id is absent from formal/theorem-inventory.json")
            continue
        formal_file = formal.get("file")
        if proof_path and formal_file != proof_path:
            errors.append(
                f"{theorem_id}: proof_path {proof_path} does not match formal inventory file {formal_file}"
            )
        if not formal.get("rootImported"):
            errors.append(f"{theorem_id}: proven theorem is not rootImported in formal inventory")


def validate_manifest_group(group_name: str, manifests: list[dict]) -> None:
    for manifest in manifests:
        manifest_id = manifest.get("id", "<missing>")
        for field_name in ("evidence", "evidence_proposed"):
            for evidence in manifest.get(field_name, []):
                if evidence.get("kind") != "lean_theorem":
                    continue
                ref = evidence.get("ref")
                theorem = spec_theorems.get(ref)
                if theorem is None:
                    errors.append(
                        f"{manifest_id}: {field_name} references unknown lean theorem {ref}"
                    )
                    continue
                status = theorem.get("status")
                if field_name == "evidence" and status == "proposed":
                    errors.append(
                        f"{manifest_id}: proposed theorem {ref} appears in release evidence; move it to evidence_proposed"
                    )
                if field_name == "evidence" and status == "assumed":
                    errors.append(
                        f"{manifest_id}: assumed theorem {ref} appears in release evidence; move it to evidence_proposed or promote it to proven with proof evidence"
                    )
                if field_name == "evidence" and status in {"advisory_only", "proven_partial"}:
                    errors.append(
                        f"{manifest_id}: non-release theorem {ref} status={status} appears in release evidence"
                    )


validate_manifest_group("manifests", spec_manifest_doc.get("manifests", []))
validate_manifest_group("proposed_manifests", spec_manifest_doc.get("proposed_manifests", []))

if errors:
    print("formal registry validator: FAIL")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print(
    "formal registry validator: PASS "
    f"({len(spec_theorems)} theorem entries, "
    f"{len(spec_manifest_doc.get('manifests', []))} active manifest entries)"
)
PY
