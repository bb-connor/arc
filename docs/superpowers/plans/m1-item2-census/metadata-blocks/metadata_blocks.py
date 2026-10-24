"""Census of writers and readers of value-carrying receipt metadata blocks.

Usage:
  python3 -I metadata_blocks.py <repo> <rev> <rules.tsv> <out.tsv>
  python3 -I metadata_blocks.py --self-check <repo> <rev> <workdir>

For each block key in BLOCKS, finds every non-test line under crates and sdks that names the
key as a string literal, or names a constant whose value is that key, classifies the line's
role (writer, reader, constant, other), applies the first matching rule of <rules.tsv>
(key, path regex, line regex, role, needs_plaintext, note) and fails closed: exit 2 on a git
failure, exit 1 when the revision is not a commit, when any block has no lines, or when any
reader or writer line has no rule. A rule's role is writer, reader or any. A reader line takes
only a reader or any rule and a writer line only a writer or any rule, so a writer catch-all
never classifies a new reader and that reader stays unclassified. A line is a test line when its path is a test
path or it lies inside an item gated by #[cfg(test)] (a module, function or impl), including
an item whose cfg attribute is followed by further attributes that span several lines.
"""
import csv, os, re, subprocess, sys

BLOCKS = [
    "financial", "governed_transaction", "governed_transaction_diagnostics", "receipt_context",
    "stream", "memory_provenance", "post_invocation", "session_report", "chio_receipt_signing_nonce",
    "protocol_admission", "finding_pool_mutation", "otel", "active_defense_backfill_v1",
    "scimLifecycle", "mercury", "authorizationContext", "guardOutcome", "deniedAccessRecord",
    "acp", "batch_witness", "chio_http_receipt_v1", "delivery_contract", "cage_receipt",
    "active_defense_evidence_id", "protocol_refusal", "admission_operation", "policySnapshot",
    "keyEnterpriseReceipt", "submission_kind", "job_name", "job_uid",
]
# Typed accessors on ChioReceiptBody that read a block by key.
ACCESSORS = {
    "financial": ["financial_metadata"],
    "governed_transaction": ["governed_transaction_metadata"],
    "delivery_contract": ["delivery_contract"],
}
SCOPE = ["crates", "sdks"]
TEST_PATH = re.compile(r"(^|/)(tests?|benches|examples|fixtures)/|(_tests?|/tests)\.rs$|_tests/|test_support|test_hooks|\.test\.(ts|tsx)$|/test_[^/]*\.py$|_test\.go$|Test\.(kt|cs)$|Tests\.cs$|e2e_tests|/_generated/|\.md$|\.json$|\.snap$")

def run_git(repo, args, allow_no_match=False):
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return proc.stdout
    if allow_no_match and proc.returncode == 1 and not proc.stderr.strip():
        return ""
    sys.stderr.write(f"git {' '.join(args[:3])} failed ({proc.returncode}): {proc.stderr.strip()}\n")
    raise SystemExit(2)

CFG_TEST = re.compile(r"\s*#\[cfg\((test|all\(test.*|any\(test.*)\)\]")

def item_ends(text, depth, parens, opened):
    """A braced item ends when its braces close. Any other item (a statement, field or match
    arm) ends at its first line outside parentheses that ends in `;` or `,`, or when an
    enclosing brace closes."""
    if opened:
        return depth <= 0
    return depth < 0 or (parens <= 0 and text.rstrip().endswith((";", ",")))

def cfg_test_lines(src):
    """Line numbers inside items gated by #[cfg(test)]."""
    lines = set()
    pending, attr_depth, item, depth, parens, opened = False, 0, False, 0, 0, False
    for number, text in enumerate(src, 1):
        if item:
            lines.add(number)
            depth += text.count("{") - text.count("}")
            parens += text.count("(") - text.count(")")
            opened = opened or depth > 0
            item = not item_ends(text, depth, parens, opened)
            continue
        if attr_depth > 0:
            attr_depth += text.count("[") - text.count("]")
            continue
        cfg = CFG_TEST.match(text)
        if cfg:
            pending, text = True, text[cfg.end():]
        if not pending:
            continue
        stripped = text.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("#["):
            attr_depth = stripped.count("[") - stripped.count("]")
            continue
        pending, item = False, True
        lines.add(number)
        depth = text.count("{") - text.count("}")
        parens = text.count("(") - text.count(")")
        opened = depth > 0
        item = not ("{" in text and depth <= 0) and not item_ends(text, depth, parens, opened)
    return lines

def test_lines(repo, rev, path, cache={}):
    if path not in cache:
        cache[path] = cfg_test_lines(run_git(repo, ["show", f"{rev}:{path}"]).splitlines()) if path.endswith((".rs", ".inc")) else set()
    return cache[path]

def role(text, key, names):
    if re.search(r"const [A-Z0-9_]+: &str\s*=", text):
        return "constant"
    reader = r"(\.get\(|\.get_mut\(|\.pointer\(|\.remove\(|\.contains_key\(|\[\s*" + "|".join(re.escape(n) for n in names) + r")"
    if re.search(r"\.(get|get_mut|pointer|remove|contains_key)\(\s*\"?/?(" + "|".join(re.escape(n) for n in names) + r")", text) \
       or re.search(r"\[\s*\"(" + re.escape(key) + r")\"\s*\]", text) \
       or re.search(r"\.(get|get_mut|remove|contains_key)\(\s*([A-Za-z_]+::)*(" + "|".join(re.escape(n) for n in names) + r")\b", text) \
       or re.search(r"typed_block::<|typed_metadata\(", text) \
       or any(re.search(r"\." + a + r"\(\)", text) for a in ACCESSORS.get(key, [])):
        return "reader"
    if re.search(r"insert\(|json!|=>|:\s*serde_json|\"" + re.escape(key) + r"\"\s*:", text):
        return "writer"
    return "other"

ROLES = ("writer", "reader", "any")

def load_rules(rules_path):
    rules = []
    with open(rules_path) as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if row and not row[0].startswith("#"):
                if len(row) != 6 or row[3] not in ROLES:
                    sys.stderr.write(f"malformed rule (want key, path, line, role in {ROLES}, needs, note): {row}\n")
                    raise SystemExit(1)
                rules.append((row[0], re.compile(row[1]), re.compile(row[2]), row[3], row[4], row[5]))
    return rules

def match_rule(rules, key, path, text, line_role):
    """First rule for the key whose path and line match. A reader or writer line takes only a
    rule of its own role or `any`; a constant or other line takes any rule."""
    strict = line_role in ("reader", "writer")
    for rkey, path_re, line_re, rule_role, needs, note in rules:
        if rkey == key and (not strict or rule_role in ("any", line_role)) and path_re.search(path) and line_re.search(text):
            return (needs, note)
    return None

def census(repo, rev, rules_path, out_path):
    run_git(repo, ["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])
    rules = load_rules(rules_path)
    rows, missing, empty = [], 0, []
    for key in BLOCKS:
        consts = set()
        for raw in run_git(repo, ["grep", "-h", "-E", r"const [A-Z0-9_]+: &str\s*=\s*\"" + key + r"\"", rev, "--", *SCOPE], allow_no_match=True).splitlines():
            match = re.search(r"const ([A-Z0-9_]+): &str", raw)
            if match:
                consts.add(match.group(1))
        names = [f'"{key}"'] + sorted(consts)
        pattern = r"\"" + re.escape(key) + r"\"" + ("|\\b(" + "|".join(sorted(consts)) + r")\b" if consts else "")
        if ACCESSORS.get(key):
            pattern += "|" + "|".join(r"\." + a + r"\(\)" for a in ACCESSORS[key])
        hits = run_git(repo, ["grep", "-n", "-I", "-E", pattern, rev, "--", *SCOPE], allow_no_match=True).splitlines()
        count = 0
        for raw in hits:
            _, path, line, text = raw.split(":", 3)
            line = int(line)
            if TEST_PATH.search(path) or line in test_lines(repo, rev, path):
                continue
            text = text.strip()
            count += 1
            line_role = role(text, key, [n.strip('"') for n in names] + names)
            decision = match_rule(rules, key, path, text, line_role)
            if decision is None:
                if line_role in ("reader", "writer"):
                    missing += 1
                decision = ("UNCLASSIFIED" if line_role in ("reader", "writer") else "n/a", "")
            rows.append([key, path, line, line_role, decision[0], decision[1], text[:160]])
        if count == 0:
            empty.append(key)
    with open(out_path, "w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["block", "path", "line", "role", "needs_plaintext", "note", "text"])
        writer.writerows(rows)
    print(f"rev={rev} lines={len(rows)} blocks={len(BLOCKS)} empty_blocks={','.join(empty) or 'none'} unclassified={missing}")
    if not rows or missing or empty:
        raise SystemExit(1)

def self_check(repo, rev, workdir):
    failed = False
    gated = cfg_test_lines([
        "fn live() {}", "#[cfg(test)]", "#[allow(", "    clippy::unwrap_used,", ")]", "mod tests {",
        "    fn fixture() {}", "}", "fn live_again() {}", "#[cfg(test)]", "fn helper(", "    x: u8,", ") {", "}",
        "struct S {", "    #[cfg(test)]", "    hook: u8,", "    live: u8,", "}",
    ])
    gated_ok = gated == {6, 7, 8, 11, 12, 13, 14, 17}
    print(f"self-check multiline-attribute: {'excluded' if gated_ok else 'MISSED'} {sorted(gated)}")
    writer_only = [("financial", re.compile("."), re.compile("."), "writer", "writer", "")]
    reader_ok = match_rule(writer_only, "financial", "crates/x/new.rs", 'metadata.get("financial")', "reader") is None
    print(f"self-check reader-vs-writer-rule: {'unclassified' if reader_ok else 'ACCEPTED'}")
    failed = not (gated_ok and reader_ok)
    for name, rev_arg, rules_text in [
        ("bad-revision", "metadata-blocks-self-check-nonexistent-ref", ""),
        ("no-rules", rev, "# no rules\n"),
    ]:
        rules_path = os.path.join(workdir, f"selfcheck-{name}.rules.tsv")
        out_path = os.path.join(workdir, f"selfcheck-{name}.out.tsv")
        with open(rules_path, "w") as handle:
            handle.write(rules_text)
        proc = subprocess.run([sys.executable, "-I", __file__, repo, rev_arg, rules_path, out_path], capture_output=True, text=True, check=False)
        print(f"self-check {name}: exit {proc.returncode} {'refused' if proc.returncode else 'ACCEPTED'}")
        failed = failed or proc.returncode == 0
        for path in (rules_path, out_path):
            if os.path.exists(path):
                os.remove(path)
    raise SystemExit(1 if failed else 0)

if __name__ == "__main__":
    if sys.argv[1] == "--self-check":
        self_check(*sys.argv[2:5])
    census(*sys.argv[1:5])
