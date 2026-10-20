import json, subprocess, sys
ddl = open(sys.argv[1]).read()
R = "'" + "a" * 64 + "'"
T = "1792234800"
cases = [
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
    ("salt_ref_uppercase", False, f"{R}, 'Params', 'erased', NULL, {T}"),
    ("salt_ref_double_dot", False, f"{R}, 'anchor..sub', 'erased', NULL, {T}"),
    ("salt_ref_trailing_dot", False, f"{R}, 'anchor.', 'erased', NULL, {T}"),
    ("salt_ref_leading_digit", False, f"{R}, '1params', 'erased', NULL, {T}"),
    ("salt_ref_dash", False, f"{R}, 'anchor-sub', 'erased', NULL, {T}"),
    ("salt_ref_empty", False, f"{R}, '', 'erased', NULL, {T}"),
    ("salt_ref_65_chars", False, f"{R}, '{'a' * 65}', 'erased', NULL, {T}"),
    ("receipt_id_uppercase", False, f"'{'A' * 64}', 'params', 'erased', NULL, {T}"),
    ("receipt_id_63", False, f"'{'a' * 63}', 'params', 'erased', NULL, {T}"),
    ("state_at_text", False, f"{R}, 'params', 'erased', NULL, 'x'"),
    ("state_at_negative", False, f"{R}, 'params', 'erased', NULL, -1"),
]
out = {"sqlite": subprocess.run(["/usr/bin/sqlite3", "--version"], capture_output=True, text=True).stdout.strip(), "results": []}
ok = True
for name, expect, values in cases:
    sql = ddl + f"\nINSERT INTO receipt_openings VALUES ({values});\nSELECT state, typeof(salt), length(salt) FROM receipt_openings;\n"
    p = subprocess.run(["/usr/bin/sqlite3", ":memory:"], input=sql, capture_output=True, text=True)
    accepted = p.returncode == 0 and "constraint failed" not in p.stderr
    out["results"].append({"case": name, "expected_accept": expect, "accepted": accepted, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()})
    ok &= accepted == expect
out["all_as_expected"] = ok
print(json.dumps(out, indent=1))
sys.exit(0 if ok else 1)
