"""Probe the receipt_openings DDL, the store identity, the erasure log and the erasure facts with the sqlite3 CLI: python3 -I probe.py <sqlite3> <ddl.sql>."""
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
S = "'" + "0123456789abcdef" * 2 + "'"
S2 = "'" + "fedcba9876543210" * 2 + "'"
M = "'https://node-b.example'"
I = "INSERT INTO receipt_store_identity VALUES "
E = "INSERT INTO receipt_opening_erasures (receipt_id, origin_store_id, origin_openings_seq, erased_at) VALUES "
OVERFLOW = "abs(-9223372036854775808)"
log_cases = [
    ("store_identity_accepts", True, f"{I}(1, {S});"),
    ("store_identity_refuses_second_row", False, f"{I}(1, {S});\n{I}(2, {S2});"),
    ("store_identity_refuses_duplicate_singleton", False, f"{I}(1, {S});\n{I}(1, {S2});"),
    ("store_identity_refuses_uppercase", False, f"{I}(1, '{'A' * 32}');"),
    ("store_identity_refuses_31_chars", False, f"{I}(1, '{'a' * 31}');"),
    ("store_identity_refuses_33_chars", False, f"{I}(1, '{'a' * 33}');"),
    ("store_identity_refuses_embedded_nul", False, f"{I}(1, '{'a' * 31}' || {NUL});"),
    ("store_identity_refuses_url", False, f"{I}(1, {M});"),
    ("store_identity_update_refuses", False, f"{I}(1, {S});\nUPDATE receipt_store_identity SET store_id = {S2};"),
    ("store_identity_delete_refuses", False, f"{I}(1, {S});\nDELETE FROM receipt_store_identity;"),
    ("erasure_row_accepts", True, f"{E}({R}, {S}, 1, {T});"),
    ("erasure_row_accepts_same_receipt_two_origins", True, f"{E}({R}, {S}, 1, {T});\n{E}({R}, {S2}, 1, {T});"),
    ("erasure_row_refuses_duplicate_origin_pair", False, f"{E}({R}, {S}, 1, {T});\n{E}({R}, {S}, 1, {T});"),
    ("erasure_row_refuses_origin_seq_zero", False, f"{E}({R}, {S}, 0, {T});"),
    ("erasure_row_refuses_origin_seq_text", False, f"{E}({R}, {S}, 'x', {T});"),
    ("erasure_row_refuses_empty_origin", False, f"{E}({R}, '', 1, {T});"),
    ("erasure_row_refuses_origin_with_nul", False, f"{E}({R}, '{'a' * 31}' || {NUL}, 1, {T});"),
    ("erasure_row_refuses_origin_node_url", False, f"{E}({R}, {M}, 1, {T});"),
    ("erasure_row_refuses_origin_uppercase", False, f"{E}({R}, '{'A' * 32}', 1, {T});"),
    ("erasure_row_refuses_receipt_id_uppercase", False, f"{E}('{'A' * 64}', {S}, 1, {T});"),
    ("erasure_row_refuses_negative_erased_at", False, f"{E}({R}, {S}, 1, -1);"),
    ("erasure_row_refuses_text_openings_seq", False, f"INSERT INTO receipt_opening_erasures VALUES ('x', {R}, {S}, 1, {T});"),
    ("erasure_seq_never_reused_after_delete", True, f"{E}({R}, {S}, 1, {T});\n{E}({R}, {S}, 2, {T});\nDELETE FROM receipt_opening_erasures WHERE openings_seq = 2;\n{E}({R}, {S}, 3, {T});\nSELECT CASE WHEN max(openings_seq) = 3 THEN 1 ELSE {OVERFLOW} END FROM receipt_opening_erasures;"),
    ("watermark_accepts", True, f"INSERT INTO receipt_openings_watermarks VALUES ({S}, 5, 3);"),
    ("watermark_refuses_horizon_above_applied", False, f"INSERT INTO receipt_openings_watermarks VALUES ({S}, 3, 5);"),
    ("watermark_refuses_negative_applied", False, f"INSERT INTO receipt_openings_watermarks VALUES ({S}, -1, 0);"),
    ("watermark_refuses_text_horizon", False, f"INSERT INTO receipt_openings_watermarks VALUES ({S}, 5, 'x');"),
    ("watermark_refuses_origin_node_url", False, f"INSERT INTO receipt_openings_watermarks VALUES ({M}, 5, 3);"),
    ("watermark_update_refuses_horizon_past_applied", False, f"INSERT INTO receipt_openings_watermarks VALUES ({S}, 5, 3);\nUPDATE receipt_openings_watermarks SET gc_horizon = 6;"),
    ("member_watermark_accepts", True, f"INSERT INTO receipt_openings_member_watermarks VALUES ({M}, {S}, 4);"),
    ("member_watermark_refuses_negative", False, f"INSERT INTO receipt_openings_member_watermarks VALUES ({M}, {S}, -1);"),
    ("member_watermark_refuses_origin_node_url", False, f"INSERT INTO receipt_openings_member_watermarks VALUES ({M}, {M}, 4);"),
    ("peer_cursor_accepts", True, f"INSERT INTO receipt_openings_peer_cursors VALUES ({M}, 0);"),
    ("peer_cursor_refuses_negative", False, f"INSERT INTO receipt_openings_peer_cursors VALUES ({M}, -1);"),
    ("peer_cursor_refuses_text", False, f"INSERT INTO receipt_openings_peer_cursors VALUES ({M}, 'x');"),
]
PRESERVED = (
    "SELECT CASE WHEN (SELECT count(*) FROM receipt_store_identity) = 1"
    f" AND (SELECT store_id FROM receipt_store_identity) = {S}"
    " AND (SELECT count(*) FROM receipt_openings_watermarks) = 2"
    f" AND (SELECT applied_through FROM receipt_openings_watermarks WHERE origin_store_id = {S}) = 0"
    f" AND (SELECT applied_through FROM receipt_openings_watermarks WHERE origin_store_id = {S2}) = 4"
    " THEN 'state-preserved' ELSE 'state-changed' END;"
)
replace_cases = []
for mode, flag in (("off", "OFF"), ("on", "ON")):
    seed_identity = (
        f"PRAGMA recursive_triggers = {flag};\n"
        f"{I}(1, {S});\n"
        f"INSERT INTO receipt_openings_watermarks VALUES ({S}, 0, 0);\n"
        f"INSERT INTO receipt_openings_watermarks VALUES ({S2}, 4, 0);\n"
    )
    marker = "recursive_triggers=" + ("0" if flag == "OFF" else "1")
    show = "SELECT 'recursive_triggers=' || recursive_triggers FROM pragma_recursive_triggers;\n"
    for name, stmt in (
        ("store_identity_insert_or_replace_refuses", f"INSERT OR REPLACE INTO receipt_store_identity VALUES (1, {S2});"),
        ("store_identity_replace_refuses", f"REPLACE INTO receipt_store_identity VALUES (1, {S2});"),
        ("store_identity_second_insert_refuses", f"{I}(1, {S2});"),
    ):
        replace_cases.append((f"{name}_recursive_triggers_{mode}", seed_identity + show + stmt + "\n" + PRESERVED, (marker, "state-preserved")))
F = "INSERT INTO receipt_erasure_facts VALUES "
FACT_PRESERVED = (
    "SELECT CASE WHEN (SELECT count(*) FROM receipt_erasure_facts) = 1"
    f" AND (SELECT origin_store_id FROM receipt_erasure_facts WHERE receipt_id = {R}) = {S}"
    f" AND (SELECT origin_openings_seq FROM receipt_erasure_facts WHERE receipt_id = {R}) = 7"
    f" AND (SELECT conflicted FROM receipt_erasure_facts WHERE receipt_id = {R}) = 0"
    " THEN 'fact-preserved' ELSE 'fact-changed' END;"
)
fact_cases = [
    ("erasure_fact_accepts", True, f"{F}({R}, {S}, 7, {T}, {T}, 0);", ()),
    ("erasure_fact_accepts_conflicted", True, f"{F}({R}, {S}, 7, {T}, {T}, 1);", ()),
    ("erasure_fact_refuses_conflicted_2", False, f"{F}({R}, {S}, 7, {T}, {T}, 2);", ()),
    ("erasure_fact_refuses_conflicted_negative", False, f"{F}({R}, {S}, 7, {T}, {T}, -1);", ()),
    ("erasure_fact_refuses_conflicted_text", False, f"{F}({R}, {S}, 7, {T}, {T}, 'true');", ()),
    ("erasure_fact_refuses_conflicted_null", False, f"{F}({R}, {S}, 7, {T}, {T}, NULL);", ()),
    ("erasure_fact_refuses_receipt_id_uppercase", False, f"{F}('{'A' * 64}', {S}, 7, {T}, {T}, 0);", ()),
    ("erasure_fact_refuses_origin_node_url", False, f"{F}({R}, {M}, 7, {T}, {T}, 0);", ()),
    ("erasure_fact_refuses_origin_seq_zero", False, f"{F}({R}, {S}, 0, {T}, {T}, 0);", ()),
    ("erasure_fact_refuses_negative_erased_at", False, f"{F}({R}, {S}, 7, -1, {T}, 0);", ()),
    ("erasure_fact_refuses_negative_recorded_at", False, f"{F}({R}, {S}, 7, {T}, -1, 0);", ()),
    ("erasure_fact_refuses_second_insert", False, f"{F}({R}, {S}, 7, {T}, {T}, 0);\n{F}({R}, {S2}, 3, {T}, {T}, 1);\n{FACT_PRESERVED}", ("fact-preserved",)),
    ("erasure_fact_insert_or_replace_refuses_recursive_triggers_off", False, f"PRAGMA recursive_triggers = OFF;\n{F}({R}, {S}, 7, {T}, {T}, 0);\nINSERT OR REPLACE INTO receipt_erasure_facts VALUES ({R}, {S2}, 3, {T}, {T}, 1);\n{FACT_PRESERVED}", ("fact-preserved",)),
    ("erasure_fact_insert_or_replace_refuses_recursive_triggers_on", False, f"PRAGMA recursive_triggers = ON;\n{F}({R}, {S}, 7, {T}, {T}, 0);\nINSERT OR REPLACE INTO receipt_erasure_facts VALUES ({R}, {S2}, 3, {T}, {T}, 1);\n{FACT_PRESERVED}", ("fact-preserved",)),
    ("erasure_fact_update_marks_conflict_accepts", True, f"{F}({R}, {S}, 7, {T}, {T}, 0);\nUPDATE receipt_erasure_facts SET conflicted = 1;", ()),
    ("erasure_fact_update_clears_conflict_refuses", False, f"{F}({R}, {S}, 7, {T}, {T}, 1);\nUPDATE receipt_erasure_facts SET conflicted = 0;", ()),
    ("erasure_fact_update_changes_origin_refuses", False, f"{F}({R}, {S}, 7, {T}, {T}, 0);\nUPDATE receipt_erasure_facts SET origin_store_id = {S2};\n{FACT_PRESERVED}", ("fact-preserved",)),
    ("erasure_fact_update_changes_erased_at_refuses", False, f"{F}({R}, {S}, 7, {T}, {T}, 0);\nUPDATE receipt_erasure_facts SET erased_at = 1;\n{FACT_PRESERVED}", ("fact-preserved",)),
    ("erasure_fact_delete_refuses", False, f"{F}({R}, {S}, 7, {T}, {T}, 0);\nDELETE FROM receipt_erasure_facts;\n{FACT_PRESERVED}", ("fact-preserved",)),
]
version = subprocess.run([cli, "--version"], capture_output=True, text=True).stdout.strip()
results, ok = [], True
def run(name, expect, sql, must_print=()):
    global ok
    p = subprocess.run([cli, ":memory:"], input=ddl + sql, capture_output=True, text=True)
    accepted = p.returncode == 0 and "constraint failed" not in p.stderr
    printed = [m for m in must_print if m in p.stdout]
    result = {"case": name, "expected_accept": expect, "accepted": accepted, "error": p.stderr.strip() or None}
    if must_print:
        result["must_print"] = list(must_print)
        result["printed"] = printed
    results.append(result)
    ok = ok and accepted == expect and len(printed) == len(must_print)
for name, expect, values in inserts:
    run(name, expect, f"\nINSERT INTO receipt_openings VALUES ({values});\n")
for name, expect, stmt in updates:
    run(name, expect, "\n" + seed + stmt + "\n")
for name, expect, stmt in log_cases:
    run(name, expect, "\n" + stmt + "\n")
for name, stmt, marks in replace_cases:
    run(name, False, "\n" + stmt + "\n", marks)
for name, expect, stmt, marks in fact_cases:
    run(name, expect, "\n" + stmt + "\n", marks)
print(json.dumps({"sqlite": version, "ddl": ddl, "all_as_expected": ok, "results": results}, indent=1))
sys.exit(0 if ok else 1)
