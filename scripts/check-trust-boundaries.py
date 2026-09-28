#!/usr/bin/env python3
"""Review tripwires for signed input, proof construction, and tenant SQL.

This is a source inventory, not a Rust/SQL verifier. Compile-fail tests enforce
the Rust API; owning runtime tests enforce authentication and row isolation.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "docs/security/trust-boundary-inventory.json"
STORE = "crates/platform/chio-store-sqlite/src"
LITERALS = re.compile(r'r(?P<hashes>#{0,16})"(?P<raw>.*?)"(?P=hashes)|"(?P<quoted>(?:\\.|[^"\\])*)"', re.S)
CREATE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(", re.I)


def production(path):
    return not any(part in {"tests", "test_support", "fuzz", "benches"} or part.endswith("_tests") for part in path.parts) and path.stem != "tests" and not any(
        marker in path.stem for marker in ("_tests", "_test_support", "_test_fixture")
    )


def sources(root):
    for path in sorted((root / "crates").rglob("*")):
        if path.suffix in {".rs", ".inc", ".sql"} and production(path):
            text = without_test_items(path.read_text())
            yield path.relative_to(root).as_posix(), text


def without_test_items(text):
    # Mask strings/comments before balancing a cfg(test) item. A test helper
    # can appear before production methods, so truncating at cfg(test) is wrong.
    syntax = list(text)
    for match in LITERALS.finditer(text):
        syntax[match.start():match.end()] = " " * (match.end() - match.start())
    masked = "".join(syntax)
    for match in re.finditer(r"//[^\n]*|/\*.*?\*/", masked, re.S):
        syntax[match.start():match.end()] = " " * (match.end() - match.start())
    syntax = "".join(syntax)
    output = list(text)
    for match in re.finditer(r"#\[cfg\(test\)\]", syntax):
        start = match.end()
        while start < len(syntax) and syntax[start] not in "{;":
            start += 1
        end = start + 1
        if start < len(syntax) and syntax[start] == "{":
            depth = 1
            while end < len(syntax) and depth:
                depth += (syntax[end] == "{") - (syntax[end] == "}")
                end += 1
        output[match.start():end] = " " * (end - match.start())
    return "".join(output)


def schema_tables(text):
    for match in CREATE.finditer(text):
        depth, end = 1, match.end()
        while end < len(text) and depth:
            depth += (text[end] == "(") - (text[end] == ")")
            end += 1
        if re.search(r"\btenant_id\b", text[match.end():end]):
            yield match.group(1), match.start()


def owner_at(text, offset):
    functions = list(re.finditer(r"\bfn\s+(\w+)\s*(?:<[^{};]*>)?\s*\(", text[:offset]))
    return functions[-1].group(1) if functions else "schema"


def sql_statements(path, text):
    literals = [(0, text)] if path.endswith(".sql") else [
        (m.start(), m.group("raw") if m.group("raw") is not None else m.group("quoted"))
        for m in LITERALS.finditer(text)
    ]
    for offset, literal in literals:
        for statement in literal.split(";"):
            normalized = " ".join(re.sub(r"--[^\n]*", "", statement).replace("\\\n", " ").split())
            if re.match(r"(?:SELECT|WITH|UPDATE|DELETE)\b", normalized, re.I):
                yield owner_at(text, offset), normalized


def scan(root, catalog):
    found = {"constructors": [], "raw_decoders": [], "schemas": {}, "unscoped_sql": []}
    files = dict(sources(root))
    decoder_owners = set(catalog["signed_input_files"])
    for path, text in files.items():
        for match in re.finditer(r"UntrustedJsonText::(new|from_wire)\s*\(", text):
            found["constructors"].append(f"{path}::{owner_at(text, match.start())}::{match.group(1)}")
        if path in decoder_owners:
            for match in re.finditer(r"serde_json::(from_str|from_slice|from_value)\b", text):
                found["raw_decoders"].append(f"{path}::{owner_at(text, match.start())}::{match.group(1)}")
        if path.startswith(STORE):
            for table, _ in schema_tables(text):
                found["schemas"].setdefault(table, []).append(path)
    for table in found["schemas"]:
        found["schemas"][table] = sorted(set(found["schemas"][table]))
    tables = set(found["schemas"])
    for path, text in files.items():
        if not path.startswith(STORE):
            continue
        for owner, sql in sql_statements(path, text):
            touched = sorted(set(re.findall(r"\b(?:FROM|JOIN|UPDATE)\s+(?:\w+\.)?(\w+)", sql, re.I)) & tables)
            if not touched:
                continue
            # tenant_id in a SELECT list is not a predicate. Dynamic predicates
            # and administrative statements require an explicit reviewed entry.
            if re.search(r"\b(?:WHERE|AND|ON)\s+(?:\w+\.)?tenant_id\s*=", sql, re.I):
                continue
            digest = hashlib.sha256(sql.encode()).hexdigest()
            found["unscoped_sql"].append({"path": path, "owner": owner, "sha256": digest, "tables": touched, "sql": sql})
    for name in ("constructors", "raw_decoders"):
        found[name].sort()
    found["unscoped_sql"].sort(key=lambda row: (row["path"], row["owner"], row["sha256"]))
    return found, files


def check(root, catalog):
    found, files = scan(root, catalog)
    errors = []
    for name in ("constructors", "raw_decoders", "schemas"):
        if found[name] != catalog[name]:
            errors.append(f"{name} changed; review and update {CATALOG}")
    if set(catalog["raw_decoder_contracts"]) != set(found["raw_decoders"]):
        errors.append("raw decoder contract coverage is incomplete")
    expected = [{k: row[k] for k in ("path", "owner", "sha256", "tables", "sql")} for row in catalog["unscoped_sql"]]
    if found["unscoped_sql"] != expected:
        errors.append("unscoped tenant SQL changed; tenant predicate or explicit principal review required")
    for row in catalog["unscoped_sql"]:
        if row.get("principal") not in catalog["principals"] or not row.get("contract"):
            errors.append(f"missing principal/contract: {row['path']}::{row['owner']}")
    if set(catalog["tables"]) != set(found["schemas"]):
        errors.append("tenant table classification is incomplete")
    for table, paths in found["schemas"].items():
        for path in paths:
            if f"tenant-read-contract: {table}" not in files[path]:
                errors.append(f"missing schema read contract: {path}:{table}")
    for proof in catalog["proofs"]:
        text = files[proof["path"]]
        match = re.search(r"pub struct " + proof["type"] + r"\s*\{([^}]+)\}", text, re.S)
        if not match or re.search(r"\bpub\b", match.group(1)):
            errors.append(f"proof fields are not sealed: {proof['type']}")
        if re.search(r"impl[^\n]*Deserialize[^\n]*" + proof["type"], text):
            errors.append(f"proof implements Deserialize: {proof['type']}")
    for path, text in files.items():
        if re.search(r"\.secret_bytes\s*\(", text) and path != catalog["frost_secret_owner"]:
            errors.append(f"FROST plaintext extracted outside encrypted custody: {path}")
        if "FrostAuthenticatedDkgPackage" in text:
            errors.append(f"removed shared FROST package reintroduced: {path}")
        if "with_strict_tenant_isolation" in text or "include_null_tenant" in text:
            errors.append(f"tenant compatibility fallback reintroduced: {path}")
    if len(re.findall(r"\.secret_bytes\s*\(", files[catalog["frost_secret_owner"]])) != catalog["frost_secret_extraction_sites"]:
        errors.append("encrypted custody FROST plaintext extraction inventory changed")
    return errors, found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--scan", action="store_true", help="print observations for manual review; never rewrites the approved catalog")
    args = parser.parse_args()
    catalog = json.loads((args.root / CATALOG).read_text())
    if args.scan:
        print(json.dumps(scan(args.root, catalog)[0], indent=2))
        return 0
    errors, found = check(args.root, catalog)
    if errors:
        print("\n".join(errors))
        return 1
    print(f"trust boundaries: {len(found['constructors'])} constructors, {len(found['schemas'])} tenant tables, {len(found['unscoped_sql'])} explicit SQL principal contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
