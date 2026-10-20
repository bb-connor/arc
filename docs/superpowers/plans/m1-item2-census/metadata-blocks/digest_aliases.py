"""Census retained digests and copies of committed values that could confirm a committed field.

Usage: python3 -I digest_aliases.py <repo> <rev> <rules.tsv> <out.tsv>
       python3 -I digest_aliases.py --self-check <repo> <rev> <workdir>

Collects, at a commit, every non-test line of three kinds:
  field   a digest-named field (`*hash*`, `*digest*`, `*sha256*`) of a signed receipt metadata type
          under chio-core-types `receipt/`;
  intent  a struct field or JSON key that carries the governed intent binding hash
          (`intent_hash`, `governed_intent_hash`, `economic_intent_digest`, `intentHash`);
  copy    a read of a committed source value in a receipt producer file
          (`shared_payment_token_id`, `purpose`, `call_chain`, `authorization_resource`,
          `escalations`, `breakdown`, `principal`, `subject_key`, `user_name`, `user_id`,
          `provider_record_id`, `entitlements`).
Each line must match a rule (kind, path regex, line regex) that states the preimage, whether it
holds a committed field, and the decision. It exits 2 on a git failure other than an empty grep,
and 1 on a non-commit revision, a kind with no lines, or any unclassified line.
"""
import csv, os, re, subprocess, sys

TEST_PATH = re.compile(r"(/tests?/|tests?\.rs$|_tests?\b|test_support|/fixtures/|/_generated/|/benches/|/examples/)")

KINDS = {
    "field": (["crates/core/chio-core-types/src/receipt"],
              r"^\s*pub(\([a-z]+\))?\s+[a-z0-9_]*(hash|digest|sha256)[a-z0-9_]*\s*:"),
    "intent": (["crates", "sdks"],
               r"(^\s*(pub(\([a-z]+\))?\s+)?(governed_)?(intent_hash|economic_intent_digest)\s*:\s*[A-Z&']"
               r"|\"(intent_hash|governed_intent_hash|economic_intent_digest|intentHash|governedIntentHash)\"\s*:)"),
    "copy": (["crates/kernel/chio-kernel/src/receipt_support",
              "crates/kernel/chio-kernel/src/kernel/reconciliation.rs",
              "crates/kernel/chio-kernel/src/kernel/validation/tool_output.rs",
              "crates/kernel/chio-kernel/src/kernel/evaluation",
              "crates/platform/chio-control-plane/src/trust_control/config_and_public.rs",
              "crates/products/chio-wall/src/commands.rs",
              "crates/kernel/chio-kernel/src/kernel/responses"],
             r"\.(shared_payment_token_id|purpose|call_chain|authorization_resource|escalations|breakdown"
             r"|principal|subject_key|user_name|user_id|provider_record_id|entitlements)\b"),
}

def run_git(repo, args, allow_no_match=False):
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return proc.stdout
    if allow_no_match and proc.returncode == 1 and not proc.stderr.strip():
        return ""
    sys.stderr.write(f"git {' '.join(args[:3])} failed ({proc.returncode}): {proc.stderr.strip()}\n")
    sys.exit(2)

def collect(repo, rev):
    rows = []
    for kind, (paths, pattern) in KINDS.items():
        out = run_git(repo, ["grep", "-n", "-E", "-e", pattern, rev, "--", *paths], allow_no_match=True)
        count = 0
        for hit in out.splitlines():
            _, path, line_no, text = hit.split(":", 3)
            if TEST_PATH.search(path) or path.endswith((".md", ".json", ".sql")):
                continue
            if text.lstrip().startswith(("//", "///", "#", "*")):
                continue
            rows.append([kind, path, line_no, re.sub(r"\s+", " ", text.strip())])
            count += 1
        if count == 0:
            sys.stderr.write(f"kind {kind} matched no lines\n")
            sys.exit(1)
    return rows

def load_rules(path):
    rules = []
    with open(path) as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if not row or row[0].startswith("#"):
                continue
            kind, path_re, line_re, preimage, committed, decision = row
            rules.append((kind, re.compile(path_re), re.compile(line_re), preimage, committed, decision))
    return rules

def census(repo, rev, rules_path, out_path):
    run_git(repo, ["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])
    rules = load_rules(rules_path)
    out, unclassified = [], 0
    for kind, path, line_no, text in collect(repo, rev):
        match = next((r for r in rules if r[0] == kind and r[1].search(path) and r[2].search(text)), None)
        if match is None:
            unclassified += 1
            out.append([kind, path, line_no, "UNCLASSIFIED", "", "", text])
        else:
            out.append([kind, path, line_no, match[3], match[4], match[5], text])
    with open(out_path, "w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["kind", "path", "line", "preimage", "holds_committed", "decision", "text"])
        writer.writerows(out)
    counts = {k: sum(1 for r in out if r[0] == k) for k in KINDS}
    print(f"rev={rev} lines={len(out)} " + " ".join(f"{k}={v}" for k, v in counts.items()) + f" unclassified={unclassified}")
    sys.exit(1 if unclassified else 0)

def self_check(script, repo, rev, workdir):
    failed = False
    for name, rev_arg, rules_text in [("bad-revision", "digest-self-check-nonexistent-ref", ""),
                                      ("no-rules", rev, "# no rules\n")]:
        rules_path = os.path.join(workdir, f"digest-selfcheck-{name}.tsv")
        out_path = os.path.join(workdir, f"digest-selfcheck-{name}.out.tsv")
        with open(rules_path, "w") as handle:
            handle.write(rules_text)
        proc = subprocess.run([sys.executable, "-I", script, repo, rev_arg, rules_path, out_path],
                              capture_output=True, text=True, check=False)
        print(f"self-check {name}: exit {proc.returncode} {'refused' if proc.returncode else 'ACCEPTED'}")
        failed = failed or proc.returncode == 0
        for path in (rules_path, out_path):
            if os.path.exists(path):
                os.remove(path)
    sys.exit(1 if failed else 0)

if __name__ == "__main__":
    if sys.argv[1] == "--self-check":
        self_check(os.path.abspath(__file__), *sys.argv[2:5])
    census(*sys.argv[1:5])
