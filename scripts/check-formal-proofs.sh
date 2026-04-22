#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

formal_root="formal/lean4/Chio"

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
    "${formal_root}/Chio" \
    "${formal_root}/Chio.lean" \
    -g '*.lean')
else
  placeholder_scan=(grep -RInw --include '*.lean' 'sorry' \
    "${formal_root}/Chio" \
    "${formal_root}/Chio.lean")
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
claim_registry_path = repo / "docs" / "reference" / "CLAIM_REGISTRY.md"

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
if manifest.get("schema") != "chio.proof-manifest.v1":
    raise SystemExit("proof manifest schema mismatch")

for rel in manifest.get("root_modules", []):
    if not (repo / rel).exists():
        raise SystemExit(f"proof manifest root module missing: {rel}")

for rel in manifest.get("covered_rust_modules", []):
    if not (repo / rel).exists():
        raise SystemExit(f"proof manifest covered module missing: {rel}")

inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
if inventory.get("schema") != "chio.theorem-inventory.v1":
    raise SystemExit("theorem inventory schema mismatch")

assumptions = inventory.get("assumptions", [])
approved_axioms = manifest.get("allowed_axioms", [])
approved_open_modules = set(manifest.get("allowed_open_modules", []))
if not assumptions:
    raise SystemExit("theorem inventory assumptions list is empty")

if sorted(assumption.get("leanName") for assumption in assumptions) != sorted(approved_axioms):
    raise SystemExit("approved axiom list does not match theorem inventory assumptions")

def lean_axioms_in_file(lean_file):
    namespace_stack = []
    axioms = []
    text = lean_file.read_text(encoding="utf-8")
    for line in text.splitlines():
        namespace_match = re.match(r"^\s*namespace\s+([A-Za-z0-9_.']+)\b", line)
        if namespace_match:
            namespace_stack.append(namespace_match.group(1))
            continue
        end_match = re.match(r"^\s*end(?:\s+([A-Za-z0-9_.']+))?\s*$", line)
        if end_match and namespace_stack:
            namespace_stack.pop()
            continue
        axiom_match = re.match(r"^\s*axiom\s+([A-Za-z0-9_']+)\b", line)
        if axiom_match:
            prefix = ".".join(namespace_stack)
            short_name = axiom_match.group(1)
            full_name = f"{prefix}.{short_name}" if prefix else short_name
            axioms.append((full_name, lean_file.relative_to(repo).as_posix()))
    return axioms

def lean_surface_controls_in_file(lean_file):
    namespace_stack = []
    opens = []
    exports = []
    abbrevs = []
    for line_number, line in enumerate(lean_file.read_text(encoding="utf-8").splitlines(), 1):
        namespace_match = re.match(r"^\s*namespace\s+([A-Za-z0-9_.']+)\b", line)
        if namespace_match:
            namespace_stack.append(namespace_match.group(1))
            continue
        end_match = re.match(r"^\s*end(?:\s+([A-Za-z0-9_.']+))?\s*$", line)
        if end_match and namespace_stack:
            namespace_stack.pop()
            continue
        open_match = re.match(r"^\s*open\s+(.+)$", line)
        if open_match:
            for module in re.findall(r"[A-Za-z][A-Za-z0-9_.']*", open_match.group(1)):
                opens.append((module, lean_file.relative_to(repo).as_posix(), line_number))
            continue
        export_match = re.match(r"^\s*export\s+(.+)$", line)
        if export_match:
            exports.append((lean_file.relative_to(repo).as_posix(), line_number))
            continue
        abbrev_match = re.match(r"^\s*abbrev\s+([A-Za-z0-9_']+)\b", line)
        if abbrev_match:
            prefix = ".".join(namespace_stack)
            short_name = abbrev_match.group(1)
            full_name = f"{prefix}.{short_name}" if prefix else short_name
            abbrevs.append((full_name, short_name, lean_file.relative_to(repo).as_posix(), line_number))
    return opens, exports, abbrevs

for assumption in assumptions:
    if assumption.get("kind") != "axiom":
        raise SystemExit(f"assumption is not marked as axiom: {assumption.get('id')}")
    if not assumption.get("rootImported"):
        raise SystemExit(f"assumption not marked rootImported: {assumption.get('id')}")
    assumption_file = assumption.get("file")
    if not assumption_file or not (repo / assumption_file).exists():
        raise SystemExit(f"assumption file missing: {assumption.get('id')}")
    lean_name = assumption.get("leanName", "")
    if not lean_name:
        raise SystemExit(f"assumption leanName missing: {assumption.get('id')}")
    assumption_axioms = {name for name, _ in lean_axioms_in_file(repo / assumption_file)}
    if lean_name not in assumption_axioms:
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

approved_axiom_names = set(approved_axioms)
approved_axiom_short_names = {name.rsplit(".", 1)[-1] for name in approved_axioms}
found_axioms = []
found_open_modules = []
found_exports = []
found_abbrevs = []
for lean_file in (repo / "formal" / "lean4" / "Chio").rglob("*.lean"):
    found_axioms.extend(lean_axioms_in_file(lean_file))
    opens, exports, abbrevs = lean_surface_controls_in_file(lean_file)
    found_open_modules.extend(opens)
    found_exports.extend(exports)
    found_abbrevs.extend(abbrevs)

unexpected_axioms = sorted(
    f"{name} ({file})"
    for name, file in found_axioms
    if name not in approved_axiom_names
)
if unexpected_axioms:
    raise SystemExit(f"unexpected Lean axioms found: {', '.join(unexpected_axioms)}")

unexpected_open_modules = sorted(
    f"{module} ({file}:{line})"
    for module, file, line in found_open_modules
    if module not in approved_open_modules
)
if unexpected_open_modules:
    raise SystemExit(f"unexpected Lean open modules found: {', '.join(unexpected_open_modules)}")

if found_exports:
    formatted = ", ".join(f"{file}:{line}" for file, line in sorted(found_exports))
    raise SystemExit(f"unexpected Lean export declarations found: {formatted}")

shadowing_abbrevs = sorted(
    f"{full_name} ({file}:{line})"
    for full_name, short_name, file, line in found_abbrevs
    if full_name in approved_axiom_names or short_name in approved_axiom_short_names
)
if shadowing_abbrevs:
    raise SystemExit(f"Lean abbrevs shadow approved axioms: {', '.join(shadowing_abbrevs)}")

if not claim_registry_path.exists():
    raise SystemExit("claim registry missing: docs/reference/CLAIM_REGISTRY.md")
PY

echo "formal proof check passed"
