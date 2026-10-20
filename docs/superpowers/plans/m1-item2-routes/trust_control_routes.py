"""Enumerate trust-control HTTP routes and their current authentication at a revision.

Usage: python3 -I trust_control_routes.py <repo> <rev> <scope_rules.tsv> <out.tsv>
Parses every `.route(` call in the trust-control router sources, resolves path constants,
records each method and handler, finds the authentication helpers the handler calls,
applies the first matching scope rule and exits 1 when a route has no rule.
"""
import csv, re, subprocess, sys

class GitError(SystemExit):
    pass

def run_git(repo, args, allow_no_match=False):
    """Run git and fail closed: any failure other than an empty grep exits 2."""
    proc = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return proc.stdout
    if allow_no_match and proc.returncode == 1 and not proc.stderr.strip():
        return ""
    sys.stderr.write(f"git {' '.join(args[:3])} failed ({proc.returncode}): {proc.stderr.strip()}\n")
    raise GitError(2)

def require_commit(repo, rev):
    run_git(repo, ["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])

def self_check(script, repo, rev, workdir, cases):
    """Run this script on known-bad inputs and require a nonzero exit for each."""
    import os
    failed = False
    for name, rev_arg, rules_text in cases:
        rules_path = os.path.join(workdir, f"selfcheck-{name}.rules.tsv")
        out_path = os.path.join(workdir, f"selfcheck-{name}.out.tsv")
        with open(rules_path, "w") as handle:
            handle.write(rules_text)
        proc = subprocess.run([sys.executable, "-I", script, repo, rev_arg or rev, rules_path, out_path],
                              capture_output=True, text=True, check=False)
        verdict = "refused" if proc.returncode != 0 else "ACCEPTED"
        print(f"self-check {name}: exit {proc.returncode} {verdict}")
        failed = failed or proc.returncode == 0
        for path in (rules_path, out_path):
            if os.path.exists(path):
                os.remove(path)
    sys.exit(1 if failed else 0)

CRATE = "crates/platform/chio-control-plane/src"
AUTH_HELPERS = [
    "validate_cluster_peer_auth", "validate_service_auth", "validate_authority_workload_auth",
    "validate_authority_mutation_auth", "validate_authority_issue_auth", "validate_control_token",
    "validate_control_secret", "tenant_read_tokens", "validate_token",
    "resolve_control_read_principal", "authorize_evidence_export_query", "seller_authentication_failed",
    "run_public_authority_trust_read", "bearer_token_from_headers", "redeem_pre_authorized_code",
    "authenticate",
]

def git(repo, *args):
    return run_git(repo, list(args), allow_no_match=args[0] == "grep")

def show(repo, rev, path):
    return git(repo, "show", f"{rev}:{path}")

def balanced(text, start):
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:index]
    return text[start + 1:]

def strip_comments(text):
    return re.sub(r"//[^\n]*", "", text)

def main():
    if sys.argv[1] == "--self-check":
        repo, rev, workdir = sys.argv[2:5]
        self_check(__file__, repo, rev, workdir, [
            ("bad-revision", "routes-self-check-nonexistent-ref", ".\t.\t.\tpublic\tcaller\tx:read\tDeployment only\n"),
            ("fallback-unmapped", None, ".\t.\t.\tpublic\tcaller\tUNMAPPED\tUNMAPPED\n"),
            ("no-rules", None, "# no rules\n"),
        ])
    repo, rev, rules_path, out_path = sys.argv[1:5]
    require_commit(repo, rev)
    files = git(repo, "grep", "-l", "-E", r"\.route\(", rev, "--", f"{CRATE}/trust_control").split()
    files = [f.split(":", 1)[1] for f in files]
    files = [f for f in files if "_tests" not in f and not f.endswith("tests.rs") and "/tests/" not in f]
    consts = {}
    aliases = {}
    const_files = git(repo, "grep", "-l", "-E", r"const [A-Z0-9_]+: &str =", rev, "--", "crates").split()
    for entry in const_files:
        text = show(repo, rev, entry.split(":", 1)[1])
        for match in re.finditer(r"const ([A-Z0-9_]+): &str =\s*\"(/[^\"]*)\"", text):
            consts.setdefault(match.group(1), set()).add(match.group(2))
        for match in re.finditer(r"const ([A-Z0-9_]+): &str =\s*([A-Z0-9_]+)\s*;", text):
            aliases[match.group(1)] = match.group(2)
    for _ in range(4):
        for name, target in aliases.items():
            if name not in consts and target in consts:
                consts[name] = set(consts[target])
    sources = {}
    for path in git(repo, "ls-tree", "-r", "--name-only", rev, "--", f"{CRATE}/trust_control").split():
        if path.endswith((".rs", ".inc")):
            sources[path] = strip_comments(show(repo, rev, path))
    fn_index = {}
    def fn_body(short):
        if short in fn_index:
            return fn_index[short]
        fn_index[short] = ("", None)
        for path, text in sources.items():
            match = re.search(r"\bfn " + re.escape(short) + r"\b[^{]*\{", text)
            if not match:
                continue
            depth, index = 0, match.end() - 1
            for index in range(match.end() - 1, len(text)):
                if text[index] == "{":
                    depth += 1
                elif text[index] == "}":
                    depth -= 1
                    if depth == 0:
                        break
            fn_index[short] = (path, text[match.end():index])
            return fn_index[short]
        return "", None
    def helpers_in(body, depth):
        found = [h for h in AUTH_HELPERS if re.search(r"\b" + h + r"\b", body)]
        found += sorted(set(m for m in re.findall(r"\b(resolve_[a-z_]*(?:principal|read_context|auth)[a-z_]*)\(", body) if m not in found))
        if found or depth == 0:
            return found
        for callee in sorted(set(re.findall(r"\b([a-z_][a-z0-9_]*)\(", body))):
            if callee in ("ok", "err", "some", "into", "clone", "map", "map_err", "new"):
                continue
            _, inner = fn_body(callee)
            if inner:
                nested = helpers_in(inner, depth - 1)
                if nested:
                    return [f"{callee}>{h}" for h in nested]
        return []
    def handler_auth(name):
        short = name.split("::")[-1]
        hpath, body = fn_body(short)
        if body is not None:
            found = helpers_in(body, 2)
            return hpath, ",".join(found) or "none"
        return "", "handler-not-found"
    def handler_auth_unused(name):
        short = name.split("::")[-1]
        for path, text in sources.items():
            match = re.search(r"\bfn " + re.escape(short) + r"\b[^{]*\{", text)
            if not match:
                continue
            depth, index = 0, match.end() - 1
            for index in range(match.end() - 1, len(text)):
                if text[index] == "{":
                    depth += 1
                elif text[index] == "}":
                    depth -= 1
                    if depth == 0:
                        break
            body = text[match.end():index]
            found = [h for h in AUTH_HELPERS if h in body]
            if not found:
                found = sorted(set(re.findall(r"\b([a-z_]*(?:principal|auth|token|secret|credential|session_key|bearer)[a-z_]*)\(", body)))
                found = [f"other:{h}" for h in found if not h.startswith("validate_")]
            return path, ",".join(found) or "none-in-handler"
        return "", "handler-not-found"
    rows = []
    for path in files:
        if not path.startswith(f"{CRATE}/trust_control"):
            continue
        text = strip_comments(show(repo, rev, path))
        for match in re.finditer(r"\.route\(", text):
            args = balanced(text, match.end() - 1)
            first, _, rest = args.partition(",")
            first = first.strip()
            if first.startswith('"'):
                route_paths = {first.strip('"')}
            elif first.startswith("&format!") or "format!" in first:
                route_paths = {first}
            else:
                route_paths = consts.get(first.split("::")[-1], {f"UNRESOLVED:{first}"})
            for method, handler in re.findall(r"\b(get|post|put|delete|patch)\(\s*([A-Za-z_][A-Za-z0-9_:]*)", rest):
                hpath, auth = handler_auth(handler)
                for route_path in sorted(route_paths):
                    rows.append([method.upper(), route_path, handler.split("::")[-1], path.replace(CRATE + "/", ""), hpath.replace(CRATE + "/", ""), auth])
    rules = []
    with open(rules_path) as handle:
        for row in csv.reader(handle, delimiter="\t"):
            if row and not row[0].startswith("#"):
                rules.append((re.compile(row[0]), re.compile(row[1]), re.compile(row[2]), row[3:]))
    out, missing = [], 0
    for row in sorted(rows, key=lambda r: (r[1], r[0])):
        method, route_path, handler, _, _, auth = row
        result = None
        for path_re, method_re, auth_re, cols in rules:
            if path_re.search(route_path) and method_re.search(method) and auth_re.search(auth):
                result = cols
                break
        if result is None:
            missing += 1
            result = ["UNRULED", "", "", ""]
        elif any("UNMAPPED" in c for c in result):
            missing += 1
        else:
            result = [c.replace("{rw}", "read" if method == "GET" else "write") for c in result]
        if route_path.startswith("UNRESOLVED:") or auth == "handler-not-found":
            missing += 1
        out.append(row + result)
    with open(out_path, "w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["method", "route", "handler", "router_file", "handler_file", "current_auth", "listener", "credential", "scope", "tenant_authority"])
        writer.writerows(out)
    print(f"rev={rev} routes={len(out)} unruled={missing}")
    if not out:
        sys.stderr.write("route census found no routes; refusing an empty census\n")
        sys.exit(1)
    sys.exit(1 if missing else 0)

if __name__ == "__main__":
    main()
