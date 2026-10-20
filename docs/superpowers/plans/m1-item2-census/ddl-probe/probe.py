"""Probe the receipt_openings DDL with the sqlite3 CLI: python3 -I probe.py <sqlite3> <ddl.sql>."""
import json, subprocess, sys
cli, ddl_path = sys.argv[1], sys.argv[2]
ddl = open(ddl_path).read()
R = "'" + "a" * 64 + "'"
T = "1792234800"
NUL = "char(0)"
seed = f"INSERT INTO receipt_openings VALUES ({R}, 'params', 'present', zeroblob(32), {T});\n"
inserts = [
    ("present_blob32", True, f"{R}, 'params', 'present', zeroblob(32), {T}"),
    ("erased_null", True, f"{R}, 'params', 'erased', NULL, {T}"),
    ("claim_salt_ref_present", True, f"{R}, 'anchor.claims.client_id', 'present', zeroblob(32), {T}"),
    ("erased_blob1", False, f"{R}, 'params', 'erased', zeroblob(1), {T}"),
    ("erased_blob32", False, f"{R}, 'params', 'erased', zeroblob(32), {T}"),
    ("erased_text", False, f"{R}, 'params', 'erased', 'x', {T}"),
    ("present_text32", False, f"{R}, 'params', 'present', '{'x' * 32}', {T}"),
    ("present_null", False, f"{R}, 'params', 'present', NULL, {T}"),
    ("present_blob31", False, f"{R}, 'params', 'present', zeroblob(31), {T}"),
    ("present_blob33", False, f"{R}, 'params', 'present', zeroblob(33), {T}"),
    ("present_integer", False, f"{R}, 'params', 'present', 7, {T}"),
    ("state_lost", False, f"{R}, 'params', 'lost', NULL, {T}"),
    ("state_embedded_nul", False, f"{R}, 'params', 'erased' || {NUL} || 'x', NULL, {T}"),
    ("salt_ref_uppercase", False, f"{R}, 'Params', 'erased', NULL, {T}"),
    ("salt_ref_double_dot", False, f"{R}, 'anchor..sub', 'erased', NULL, {T}"),
    ("salt_ref_trailing_dot", False, f"{R}, 'anchor.', 'erased', NULL, {T}"),
    ("salt_ref_leading_digit", False, f"{R}, '1params', 'erased', NULL, {T}"),
    ("salt_ref_dash", False, f"{R}, 'anchor-sub', 'erased', NULL, {T}"),
    ("salt_ref_empty", False, f"{R}, '', 'erased', NULL, {T}"),
    ("salt_ref_65_chars", False, f"{R}, '{'a' * 65}', 'erased', NULL, {T}"),
    ("salt_ref_embedded_nul", False, f"{R}, 'params' || {NUL} || 'BAD', 'erased', NULL, {T}"),
    ("salt_ref_trailing_nul", False, f"{R}, 'params' || {NUL}, 'erased', NULL, {T}"),
    ("receipt_id_uppercase", False, f"'{'A' * 64}', 'params', 'erased', NULL, {T}"),
    ("receipt_id_63", False, f"'{'a' * 63}', 'params', 'erased', NULL, {T}"),
    ("receipt_id_embedded_nul", False, f"{R} || {NUL} || 'BAD', 'params', 'erased', NULL, {T}"),
    ("receipt_id_nul_inside_64", False, f"'{'a' * 32}' || {NUL} || '{'a' * 31}', 'params', 'erased', NULL, {T}"),
    ("state_at_text", False, f"{R}, 'params', 'erased', NULL, 'x'"),
    ("state_at_negative", False, f"{R}, 'params', 'erased', NULL, -1"),
]
updates = [
    ("update_erase_clearing_salt", True, "UPDATE receipt_openings SET state = 'erased', salt = NULL, state_at = 1792234801;"),
    ("update_erase_leaving_salt", False, "UPDATE receipt_openings SET state = 'erased', state_at = 1792234801;"),
    ("update_salt_ref_embedded_nul", False, f"UPDATE receipt_openings SET salt_ref = 'params' || {NUL} || 'BAD';"),
    ("update_receipt_id_embedded_nul", False, f"UPDATE receipt_openings SET receipt_id = receipt_id || {NUL} || 'BAD';"),
    ("update_state_embedded_nul", False, f"UPDATE receipt_openings SET state = 'present' || {NUL};"),
    ("update_salt_to_text32", False, f"UPDATE receipt_openings SET salt = '{'x' * 32}';"),
]
version = subprocess.run([cli, "--version"], capture_output=True, text=True).stdout.strip()
results, ok = [], True
def run(name, expect, sql):
    global ok
    p = subprocess.run([cli, ":memory:"], input=ddl + sql, capture_output=True, text=True)
    accepted = p.returncode == 0 and "constraint failed" not in p.stderr
    results.append({"case": name, "expected_accept": expect, "accepted": accepted, "error": p.stderr.strip() or None})
    ok = ok and accepted == expect
for name, expect, values in inserts:
    run(name, expect, f"\nINSERT INTO receipt_openings VALUES ({values});\n")
for name, expect, stmt in updates:
    run(name, expect, "\n" + seed + stmt + "\n")
print(json.dumps({"sqlite": version, "ddl": ddl, "all_as_expected": ok, "results": results}, indent=1))
sys.exit(0 if ok else 1)
