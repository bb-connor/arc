"""Census of receipt-hash and receipt-parameter consumers for the committed-receipt change.

Usage: python3 -I census.py <repo> <rev> <rules.tsv> <out.tsv>
Lists every line at <rev> that matches one of PATTERNS, or ends a MULTILINE match (rustfmt-split chains, JSON indexing), marks it test or production,
assigns it the first matching rule from <rules.tsv>, and exits 1 when any production
line has no rule.
"""
import csv, re, subprocess, sys

PATTERNS = {
    "hash": r"action\.parameter_hash|\.content_hash\b|ToolCallAction::from_parameters|verify_hash\(",
    "hash_key": r"\"content_hash\"|\"parameter_hash\"",
    "params": r"action\.parameters\b",
}
SCOPE = ["crates", "sdks", "xtask"]
# Patterns over whole file text, for chains rustfmt splits across lines and for JSON indexing.
MULTILINE = {
    "params_split": (r"\baction\s*\n\s*\.(parameters|parameter_hash)\b", ["crates", "xtask"], "*.rs"),
    "params_json": (r"(\[\s*[\"']action[\"']\s*\]|\baction)\s*(\[\s*[\"'](parameters|parameter_hash)[\"']\s*\]|\.get\(\s*[\"'](parameters|parameter_hash)[\"'])", ["sdks", "crates"], None),
}
TEST_PATH = re.compile(r"(^|/)(tests?|benches|examples|fixtures)/|(_tests?|/tests)\.rs$|_tests/|test_support|test_hooks|\.test\.(ts|tsx)$|/test_[^/]*\.py$|_test\.go$|Test\.(kt|cs)$|Tests\.cs$|e2e_tests")

def grep(repo, rev, pattern):
    out = subprocess.run(["git", "-C", repo, "grep", "-n", "-I", "-E", pattern, rev, "--", *SCOPE],
                         capture_output=True, text=True, check=False).stdout
    for raw in out.splitlines():
        _, path, line, text = raw.split(":", 3)
        yield path, int(line), text.strip()

def grep_multiline(repo, rev, pattern, scope, glob):
    paths = subprocess.run(["git", "-C", repo, "grep", "-l", "-I", "-E", r"parameters|parameter_hash", rev, "--", *scope],
                           capture_output=True, text=True, check=False).stdout.split()
    regex = re.compile(pattern)
    for entry in paths:
        path = entry.split(":", 1)[1]
        if glob == "*.rs" and not path.endswith(".rs"):
            continue
        text = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True, text=True).stdout
        lines = text.splitlines()
        for match in regex.finditer(text):
            line = text.count("\n", 0, match.end()) + 1
            yield path, line, lines[line - 1].strip()

def test_module_lines(repo, rev, path, cache={}):
    """Line numbers inside a `#[cfg(test)] mod` block of a Rust file."""
    if path in cache:
        return cache[path]
    lines = set()
    if path.endswith((".rs", ".inc")):
        src = subprocess.run(["git", "-C", repo, "show", f"{rev}:{path}"], capture_output=True, text=True).stdout.splitlines()
        depth, start = 0, None
        pending = False
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

def main():
    repo, rev, rules_path, out_path = sys.argv[1:5]
    rules = []
    with open(rules_path) as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if not row or row[0].startswith("#"):
                continue
            path_re, line_re, kind, replacement = row
            rules.append((re.compile(path_re), re.compile(line_re) if line_re else None, kind, replacement))
    hits = {}
    for name, pattern in PATTERNS.items():
        for path, line, text in grep(repo, rev, pattern):
            hits.setdefault((path, line), [text, set()])[1].add(name)
    for name, (pattern, scope, glob) in MULTILINE.items():
        for path, line, text in grep_multiline(repo, rev, pattern, scope, glob):
            hits.setdefault((path, line), [text, set()])[1].add(name)
    rows, unclassified = [], 0
    for (path, line), (text, names) in sorted(hits.items()):
        is_test = bool(TEST_PATH.search(path)) or line in test_module_lines(repo, rev, path)
        kind, replacement = "", ""
        for path_re, line_re, rule_kind, rule_replacement in rules:
            if path_re.search(path) and (line_re is None or line_re.search(text)):
                kind, replacement = rule_kind, rule_replacement
                break
        if not kind and is_test:
            kind, replacement = "T", "test site: rebuilt on ReceiptDraft or the receipt testing helper"
        if not kind:
            unclassified += 1
        rows.append([path, line, "test" if is_test else "prod", "+".join(sorted(names)), kind or "UNCLASSIFIED", replacement, text[:160]])
    with open(out_path, "w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["path", "line", "scope", "patterns", "kind", "replacement", "text"])
        writer.writerows(rows)
    prod = sum(1 for r in rows if r[2] == "prod")
    files = len({r[0] for r in rows})
    print(f"rev={rev} lines={len(rows)} files={files} prod_lines={prod} unclassified_prod={unclassified}")
    sys.exit(1 if unclassified else 0)

if __name__ == "__main__":
    main()
