"""Probe the receipt_metadata_values DDL with a sqlite3 CLI: python3 -I values_probe.py <sqlite3> <ddl.sql>."""
import json, subprocess, sys
cli, ddl_path = sys.argv[1], sys.argv[2]
ddl = open(ddl_path).read()
R = "'" + "a" * 64 + "'"
T = "1792234800"
N = "char(0)"
seed = f"INSERT INTO receipt_metadata_values VALUES ({R}, 'metadata.financial.cost_breakdown', 'present', '{{\"a\":1}}', {T});\n"
inserts = [
    ("present_json", True, f"{R}, 'metadata.financial.cost_breakdown', 'present', '{{\"a\":1}}', {T}"),
    ("erased_null", True, f"{R}, 'metadata.governed_transaction.purpose', 'erased', NULL, {T}"),
    ("present_null", False, f"{R}, 'metadata.financial.cost_breakdown', 'present', NULL, {T}"),
    ("present_invalid_json", False, f"{R}, 'metadata.financial.cost_breakdown', 'present', 'not json', {T}"),
    ("present_blob", False, f"{R}, 'metadata.financial.cost_breakdown', 'present', zeroblob(4), {T}"),
    ("erased_with_value", False, f"{R}, 'metadata.financial.cost_breakdown', 'erased', '1', {T}"),
    ("salt_ref_not_metadata", False, f"{R}, 'params', 'present', '1', {T}"),
    ("salt_ref_embedded_nul", False, f"{R}, 'metadata.x' || {N} || 'y', 'present', '1', {T}"),
    ("receipt_id_embedded_nul", False, f"{R} || {N}, 'metadata.x', 'present', '1', {T}"),
    ("state_lost", False, f"{R}, 'metadata.x', 'lost', NULL, {T}"),
]
updates = [
    ("update_erase_clearing_value", True, "UPDATE receipt_metadata_values SET state = 'erased', value = NULL, state_at = 1792234801;"),
    ("update_erase_leaving_value", False, "UPDATE receipt_metadata_values SET state = 'erased', state_at = 1792234801;"),
    ("update_salt_ref_nul", False, f"UPDATE receipt_metadata_values SET salt_ref = salt_ref || {N};"),
]
results, ok = [], True
def run(name, expect, sql):
    global ok
    p = subprocess.run([cli, ":memory:"], input=ddl + sql, capture_output=True, text=True)
    accepted = p.returncode == 0 and "constraint failed" not in p.stderr
    results.append({"case": name, "expected_accept": expect, "accepted": accepted, "error": p.stderr.strip() or None})
    ok = ok and accepted == expect
for name, expect, values in inserts:
    run(name, expect, f"\nINSERT INTO receipt_metadata_values VALUES ({values});\n")
for name, expect, stmt in updates:
    run(name, expect, "\n" + seed + stmt + "\n")
version = subprocess.run([cli, "--version"], capture_output=True, text=True).stdout.strip()
print(json.dumps({"sqlite": version, "all_as_expected": ok, "results": results}, indent=1))
sys.exit(0 if ok else 1)
