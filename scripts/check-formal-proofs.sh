#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

formal_root="formal/lean4/Pact"

if ! command -v lake >/dev/null 2>&1; then
  echo "formal proof check requires lake on PATH (install Lean 4 / elan first)" >&2
  exit 1
fi

echo "==> Lean 4 proof build"
(
  cd "${formal_root}"
  lake build
)

echo "==> Lean 4 placeholder scan"
if command -v rg >/dev/null 2>&1; then
  placeholder_scan=(rg -n '\bsorry\b' \
    "${formal_root}/Arc" \
    "${formal_root}/Pact" \
    "${formal_root}/Arc.lean" \
    "${formal_root}/Pact.lean" \
    -g '*.lean')
else
  placeholder_scan=(grep -RInw --include '*.lean' 'sorry' \
    "${formal_root}/Arc" \
    "${formal_root}/Pact" \
    "${formal_root}/Arc.lean" \
    "${formal_root}/Pact.lean")
fi

if "${placeholder_scan[@]}"; then
  echo "formal proof check failed: found literal sorry in shipped Lean modules" >&2
  exit 1
fi

echo "==> Proof manifest and theorem inventory sanity"
python3 - <<'PY'
import json
import re
from pathlib import Path

repo = Path(".")
manifest_path = repo / "formal" / "proof-manifest.toml"
inventory_path = repo / "formal" / "theorem-inventory.json"
claim_registry_path = repo / "docs" / "CLAIM_REGISTRY.md"

def parse_string(value):
    return json.loads(value)

def strip_toml_comment(line):
    in_string = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and in_string:
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if char == "#" and not in_string:
            return line[:index]
    return line

def parse_manifest_subset(text):
    manifest = {}
    array_key = None
    array_values = []
    for raw_line in text.splitlines():
        line = strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if array_key is not None:
            if line == "]":
                manifest[array_key] = array_values
                array_key = None
                array_values = []
                continue
            if line.endswith(","):
                line = line[:-1].strip()
            array_values.append(parse_string(line))
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise SystemExit(f"unsupported proof manifest line: {raw_line}")
        key = key.strip()
        value = value.strip()
        if value == "[":
            array_key = key
            array_values = []
        elif value.startswith('"'):
            manifest[key] = parse_string(value.rstrip(","))
        elif value.isdigit():
            manifest[key] = int(value)
        else:
            raise SystemExit(f"unsupported proof manifest value for {key}: {value}")
    if array_key is not None:
        raise SystemExit(f"unterminated proof manifest array: {array_key}")
    return manifest

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None

manifest_text = manifest_path.read_text(encoding="utf-8")
manifest = tomllib.loads(manifest_text) if tomllib else parse_manifest_subset(manifest_text)
if manifest.get("schema") != "arc.proof-manifest.v1":
    raise SystemExit("proof manifest schema mismatch")

for rel in manifest.get("root_modules", []):
    if not (repo / rel).exists():
        raise SystemExit(f"proof manifest root module missing: {rel}")

for rel in manifest.get("covered_rust_modules", []):
    if not (repo / rel).exists():
        raise SystemExit(f"proof manifest covered module missing: {rel}")

inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
if inventory.get("schema") != "arc.theorem-inventory.v1":
    raise SystemExit("theorem inventory schema mismatch")

assumptions = inventory.get("assumptions", [])
approved_axioms = manifest.get("allowed_axioms", [])
if not assumptions:
    raise SystemExit("theorem inventory assumptions list is empty")

if sorted(assumption.get("leanName") for assumption in assumptions) != sorted(approved_axioms):
    raise SystemExit("approved axiom list does not match theorem inventory assumptions")

for assumption in assumptions:
    if assumption.get("kind") != "axiom":
        raise SystemExit(f"assumption is not marked as axiom: {assumption.get('id')}")
    if not assumption.get("rootImported"):
        raise SystemExit(f"assumption not marked rootImported: {assumption.get('id')}")
    assumption_file = assumption.get("file")
    if not assumption_file or not (repo / assumption_file).exists():
        raise SystemExit(f"assumption file missing: {assumption.get('id')}")
    short_name = assumption.get("leanName", "").rsplit(".", 1)[-1]
    if not short_name:
        raise SystemExit(f"assumption leanName missing: {assumption.get('id')}")
    assumption_text = (repo / assumption_file).read_text(encoding="utf-8")
    if not re.search(rf"(?m)^\s*axiom\s+{re.escape(short_name)}\b", assumption_text):
        raise SystemExit(f"assumption definition missing from file: {assumption.get('id')}")

theorems = inventory.get("theorems", [])
if not theorems:
    raise SystemExit("theorem inventory is empty")

for theorem in theorems:
    if not theorem.get("rootImported"):
        raise SystemExit(f"theorem not marked rootImported: {theorem.get('id')}")
    theorem_file = theorem.get("file")
    if not theorem_file or not (repo / theorem_file).exists():
        raise SystemExit(f"theorem file missing: {theorem.get('id')}")

approved_axiom_names = {name.rsplit(".", 1)[-1] for name in approved_axioms}
found_axioms = []
for lean_file in (repo / "formal" / "lean4" / "Pact").rglob("*.lean"):
    text = lean_file.read_text(encoding="utf-8")
    for match in re.finditer(r"(?m)^\s*axiom\s+([A-Za-z0-9_']+)\b", text):
        found_axioms.append((match.group(1), lean_file.relative_to(repo).as_posix()))

unexpected_axioms = sorted(
    f"{name} ({file})"
    for name, file in found_axioms
    if name not in approved_axiom_names
)
if unexpected_axioms:
    raise SystemExit(f"unexpected Lean axioms found: {', '.join(unexpected_axioms)}")

if not claim_registry_path.exists():
    raise SystemExit("claim registry missing: docs/CLAIM_REGISTRY.md")
PY

echo "formal proof check passed"
