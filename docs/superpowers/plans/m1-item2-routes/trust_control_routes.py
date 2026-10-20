"""Enumerate trust-control HTTP routes and their current authentication at a revision.

Usage: python3 -I trust_control_routes.py <repo> <rev> <scope_rules.tsv> <out.tsv>
Parses every `.route(` call in the trust-control router sources, resolves path constants,
records each method and handler, writes routes whose router function no non-test code calls
to a separate `-unmounted.tsv` (they are not in the table), finds the authentication helpers the handler calls,
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
    failed = resolver_self_check()
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

CONTROL_CRATE = CRATE.split("/src", 1)[0]

def crate_of(path):
    return path.split("/src/", 1)[0]

def crate_ident(crate_dir):
    return crate_dir.rsplit("/", 1)[-1].replace("-", "_")

def resolve_const(name, defs, qualifier=None):
    """Resolve a path constant to its values, or None when unresolved or ambiguous.

    defs maps a constant name to {crate_dir: set(values)}. A qualifier names the
    crate the router imports the constant from; without one, the trust-control
    crate's own definition wins, and a name defined only in several other crates
    is ambiguous.
    """
    by_crate = defs.get(name, {})
    if qualifier is not None:
        matches = [c for c in by_crate if crate_ident(c) == qualifier]
        return set(by_crate[matches[0]]) if len(matches) == 1 else None
    if CONTROL_CRATE in by_crate:
        return set(by_crate[CONTROL_CRATE])
    if len(by_crate) == 1:
        return set(next(iter(by_crate.values())))
    return None

def resolver_self_check():
    """Same-named constants in other crates must not shadow the trust-control crate's own."""
    other = "crates/platform/chio-http-core"
    third = "crates/protocol/chio-mcp-remote"
    defs = {
        "STOP_PATH": {CONTROL_CRATE: {"/v1/admin/stop"}, other: {"/stop"}},
        "SHARED_PATH": {other: {"/a"}, third: {"/b"}},
    }
    cases = [
        ("same-name-other-crate", resolve_const("STOP_PATH", defs), {"/v1/admin/stop"}),
        ("qualified-other-crate", resolve_const("STOP_PATH", defs, "chio_http_core"), {"/stop"}),
        ("ambiguous-other-crates", resolve_const("SHARED_PATH", defs), None),
        ("unknown-name", resolve_const("MISSING_PATH", defs), None),
    ]
    failed = False
    for name, got, want in cases:
        ok = got == want
        print(f"self-check resolver {name}: " + ("ok" if ok else f"WRONG got {got} want {want}"))
        failed = failed or not ok
    return failed

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
    defs = {}
    aliases = {}
    const_files = git(repo, "grep", "-l", "-E", r"const [A-Z0-9_]+: &str =", rev, "--", "crates").split()
    for entry in const_files:
        source_path = entry.split(":", 1)[1]
        crate_dir = crate_of(source_path)
        text = show(repo, rev, source_path)
        for match in re.finditer(r"const ([A-Z0-9_]+): &str =\s*\"(/[^\"]*)\"", text):
            defs.setdefault(match.group(1), {}).setdefault(crate_dir, set()).add(match.group(2))
        for match in re.finditer(r"const ([A-Z0-9_]+): &str =\s*([A-Z0-9_]+)\s*;", text):
            aliases[(crate_dir, match.group(1))] = match.group(2)
    for _ in range(4):
        for (crate_dir, name), target in aliases.items():
            if crate_dir in defs.get(name, {}):
                continue
            if crate_dir in defs.get(target, {}):
                defs.setdefault(name, {})[crate_dir] = set(defs[target][crate_dir])
            else:
                imported = resolve_const(target, defs)
                if imported:
                    defs.setdefault(name, {})[crate_dir] = imported
    def route_consts(first, router_text):
        segments = first.split("::")
        name = segments[-1]
        qualifier = None
        if len(segments) > 1 and segments[0] not in ("crate", "super", "self"):
            qualifier = segments[0]
        elif len(segments) == 1:
            imported = re.search(r"\buse\s+([a-z_][a-z0-9_]*)::[^;]*\b" + re.escape(name) + r"\b[^;]*;", router_text)
            if imported and imported.group(1) not in ("crate", "super", "self"):
                qualifier = imported.group(1)
        return resolve_const(name, defs, qualifier)
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
    mounted_cache = {}
    def router_mounted(fn_name):
        """A router function is mounted when non-test code outside its definition names it."""
        if fn_name not in mounted_cache:
            hits = git(repo, "grep", "-n", "-w", fn_name, rev, "--", "crates").splitlines()
            uses = []
            for hit in hits:
                _, hit_path, _, line = hit.split(":", 3)
                if "/tests/" in hit_path or hit_path.endswith("tests.rs") or "_tests" in hit_path:
                    continue
                if re.search(r"\bfn\s+" + re.escape(fn_name) + r"\b", line):
                    continue
                uses.append(hit)
            mounted_cache[fn_name] = bool(uses)
        return mounted_cache[fn_name]
    rows = []
    unmounted = []
    for path in files:
        if not path.startswith(f"{CRATE}/trust_control"):
            continue
        text = strip_comments(show(repo, rev, path))
        for match in re.finditer(r"\.route\(", text):
            enclosing = re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", text[:match.start()])
            if not enclosing:
                sys.stderr.write(f"route outside any function in {path}\n")
                sys.exit(1)
            mounted = router_mounted(enclosing[-1])
            args = balanced(text, match.end() - 1)
            first, _, rest = args.partition(",")
            first = first.strip()
            if first.startswith('"'):
                route_paths = {first.strip('"')}
            elif first.startswith("&format!") or "format!" in first:
                route_paths = {first}
            else:
                route_paths = route_consts(first, text) or {f"UNRESOLVED:{first}"}
            for method, handler in re.findall(r"\b(get|post|put|delete|patch)\(\s*([A-Za-z_][A-Za-z0-9_:]*)", rest):
                hpath, auth = handler_auth(handler)
                for route_path in sorted(route_paths):
                    row = [method.upper(), route_path, handler.split("::")[-1], path.replace(CRATE + "/", ""), hpath.replace(CRATE + "/", ""), auth]
                    if mounted:
                        rows.append(row)
                    else:
                        unmounted.append([enclosing[-1]] + row)
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
    unmounted_path = out_path[:-4] + "-unmounted.tsv" if out_path.endswith(".tsv") else out_path + ".unmounted"
    with open(unmounted_path, "w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["router_fn", "method", "route", "handler", "router_file", "handler_file", "current_auth"])
        writer.writerows(sorted(unmounted, key=lambda r: (r[2], r[1])))
    print(f"rev={rev} routes={len(out) + len(unmounted)} mounted={len(out)} unmounted={len(unmounted)} unruled={missing}")
    if not out:
        sys.stderr.write("route census found no routes; refusing an empty census\n")
        sys.exit(1)
    sys.exit(1 if missing else 0)

if __name__ == "__main__":
    main()
