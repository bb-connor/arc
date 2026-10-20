"""Census of writers and readers of value-carrying receipt metadata blocks.

Usage:
  python3 -I metadata_blocks.py <repo> <rev> <rules.tsv> <out.tsv>
  python3 -I metadata_blocks.py --self-check <repo> <rev> <workdir>

For each block key in BLOCKS, finds every non-test line under crates and sdks that names the
key as a string literal, or names a constant whose value is that key, classifies the line's
role (writer, reader, constant, other), applies the first matching rule of <rules.tsv>
(key, path regex, line regex, needs_plaintext, note) and fails closed: exit 2 on a git
failure, exit 1 when the revision is not a commit, when any block has no lines, or when any
reader or writer line has no rule.
"""
import csv, os, re, subprocess, sys

BLOCKS = [
    "financial", "governed_transaction", "governed_transaction_diagnostics", "receipt_context",
    "stream", "memory_provenance", "post_invocation", "session_report", "chio_receipt_signing_nonce",
    "protocol_admission", "finding_pool_mutation", "otel", "active_defense_backfill_v1",
    "scimLifecycle", "mercury", "authorizationContext", "guardOutcome", "deniedAccessRecord",
    "acp", "batch_witness", "chio_http_receipt_v1", "delivery_contract", "cage_receipt",
    "active_defense_evidence_id", "protocol_refusal", "admission_operation",
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

def test_lines(repo, rev, path, cache={}):
    if path in cache:
        return cache[path]
    lines = set()
    if path.endswith((".rs", ".inc")):
        src = run_git(repo, ["show", f"{rev}:{path}"]).splitlines()
        start, depth, pending = None, 0, False
        for number, text in enumerate(src, 1):
            if start is None and re.match(r"\s*#\[cfg\((test|all\(test.*|any\(test.*)\)\]", text):
                pending = True
                continue
            if pending and start is None and re.match(r"\s*(pub(\(crate\))? )?mod \w+\s*\{", text):
                start, depth = number, 0
            pending = pending and start is None and text.strip().startswith("#")
            if start is not None:
                depth += text.count("{") - text.count("}")
                lines.add(number)
                if depth <= 0 and number > start:
                    start = None
    cache[path] = lines
    return lines

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

def census(repo, rev, rules_path, out_path):
    run_git(repo, ["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])
    rules = []
    with open(rules_path) as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if row and not row[0].startswith("#"):
                rules.append((row[0], re.compile(row[1]), re.compile(row[2]), row[3], row[4]))
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
            decision = None
            for rkey, path_re, line_re, needs, note in rules:
                if rkey == key and path_re.search(path) and line_re.search(text):
                    decision = (needs, note)
                    break
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
