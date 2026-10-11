"""Lexical inventory of framework input and callers of shared input readers.

This is deliberately bounded source analysis, not Rust name resolution. Request
extractors are taken only from function parameters. Empty HTTP `.json()` calls
decode responses; `.json(&value)` serializes a request and is not an input site.
Resolved free-function calls retain helper consumers across module migrations.
Macros, trait dispatch and dynamically selected readers still require review.
"""
from collections import defaultdict
from functools import lru_cache
import hashlib
import json
import re

INVENTORY = "docs/security/http-ingress-contracts.json"
CONTROL_INPUT = "crates/platform/chio-control-plane/src/trust_control/json_ingress.rs"

FORMATS = {
    "serde_yaml": ("yaml", {"from_str", "from_slice", "from_reader"}),
    "serde_yml": ("yaml", {"from_str", "from_slice", "from_reader"}),
    "toml": ("toml", {"from_str", "from_slice"}),
    "ciborium": ("cbor", {"from_reader"}),
    "serde_cbor": ("cbor", {"from_reader", "from_slice"}),
    "bincode": ("bincode", {"deserialize", "deserialize_from", "decode_from_slice", "decode_from_std_read"}),
}
CALL = re.compile(r"(?<![\w.])([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)\s*(?:::<[^;{}]*?>\s*)?\(")
MIDDLEWARE = re.compile(
    r"\.route_layer\(\s*axum::middleware::from_fn\(\s*"
    r"super::super::json_ingress::validate\s*,?\s*\)\s*,?\s*\)"
)


def imports(code):
    """Expand ordinary and grouped use trees, preserving aliases and wildcards."""
    result = {}

    def walk(tree, prefix=""):
        depth, start = 0, 0
        for index, char in enumerate(tree + ","):
            depth += (char == "{") - (char == "}")
            if char == "," and depth == 0:
                item = tree[start:index].strip()
                start = index + 1
                if not item:
                    continue
                if "{" in item:
                    head, tail = item.split("{", 1)
                    walk(tail.rsplit("}", 1)[0], prefix + head.strip())
                    continue
                pieces = re.split(r"\s+as\s+", item)
                target = prefix + pieces[0].strip()
                if target.endswith("::self"):
                    target = target[:-6]
                name = pieces[-1].strip() if len(pieces) > 1 else target.split("::")[-1]
                result[name if name != "*" else target] = target

    for match in re.finditer(r"\buse\s+([^;]+);", code):
        walk(match.group(1))
    return result


def module(path):
    pieces = path.split("/")
    if "src" not in pieces:
        return None
    src = pieces.index("src")
    tail = pieces[src + 1:]
    if not tail:
        return None
    tail[-1] = tail[-1].rsplit(".", 1)[0]
    if tail[-1] in {"lib", "main", "mod"}:
        tail.pop()
    return (pieces[src - 1].replace("-", "_"), *tail)


def qualified(name, current):
    parts = name.split("::")
    if parts[0] == "crate":
        return (current[0], *parts[1:])
    if parts[0] == "self":
        return (*current, *parts[1:])
    if parts[0] == "super":
        base = list(current)
        while parts and parts[0] == "super":
            if len(base) > 1:
                base.pop()
            parts.pop(0)
        return (*base, *parts)
    return tuple(parts)


def route_bindings(code, contracts):
    """Bind method and route constants to handlers from actual router builders."""
    rows = []
    for match in re.finditer(r"\.route\s*\(", code):
        end = contracts.closing(code, match.end() - 1)
        block = code[match.end():end - 1]
        route = block.split(",", 1)[0].strip()
        if not re.fullmatch(r"[\w:]+", route):
            continue
        for handler in re.finditer(r"\b(get|post|put|delete|patch)\s*\(\s*([\w:]+)\s*\)", block):
            method, target = handler.groups()
            rows.append((method.upper(), route, target.split("::")[-1]))
    return sorted(rows)


def control_contracts(source):
    """Read explicit method/path/parser/bound arms, including rustfmt blocks."""
    pattern = r'\("(POST|PUT|PATCH|DELETE)",\s*(\w+)\)\s*=>\s*\{?\s*Some\(\(Mode::(Signed|Document),\s*([0-9 *]+)\)\)'
    rows = []
    for method, route, mode, bound in re.findall(pattern, source):
        factors = [int(piece.strip()) for piece in bound.split("*")]
        limit = 1
        for factor in factors:
            limit *= factor
        rows.append((method, route, mode.lower(), limit))
    return sorted(rows)


def router_digest(source, owner, contracts):
    """Pin the reviewed builder, including ordering, merges and literal paths.

    Method/path membership alone cannot establish which earlier routes an Axum
    route_layer wraps. Keep this a review tripwire, not a claim of Rust dataflow.
    """
    rows = [row for row in contracts.functions(source) if row[0] == owner]
    if len(rows) != 1:
        return None
    return hashlib.sha256(contracts.owner_code(source, rows[0]).encode()).hexdigest()


def check(root, census, files, contracts, blank_noise):
    """Require a disposition for every framework entry and preserve routing."""
    errors = []
    inventory_path = root / INVENTORY
    if not inventory_path.is_file():
        return ["framework ingress inventory is missing"]
    inventory = json.loads(inventory_path.read_text())
    observed = sorted((path, *row.split("::", 2)) for path, rows in census.items()
                      for row in rows if "::request-" in row)
    recorded = sorted((row["source"], row["owner"], "request-" + row["format"], row["request_type"])
                      for row in inventory.get("requests", []))
    if observed != recorded:
        errors.append("framework request dispositions are missing or changed")
    source = files.get(CONTROL_INPUT, "")
    actual = control_contracts(source)
    expected = []
    for entry in inventory.get("requests", []):
        kind = entry.get("disposition")
        if not entry.get("semantics") or not entry.get("authentication"):
            errors.append(f"framework ingress lacks its semantic owner: {entry['owner']}")
        if kind in {"bounded-signed-json", "bounded-document-json"}:
            expected.append((entry["method"], entry["route"], entry["reader"], entry["max_bytes"]))
            if entry["reader"] != ("signed" if kind == "bounded-signed-json" else "document"):
                errors.append(f"framework disposition and reader disagree: {entry['owner']}")
            router = files.get(entry.get("router"), "")
            route = (entry["method"], entry["route"], entry["owner"])
            if route not in route_bindings(blank_noise(router), contracts):
                errors.append(f"framework method/path/handler binding changed: {entry['owner']}")
            if not MIDDLEWARE.search(blank_noise(router)):
                errors.append(f"framework original-byte middleware is not installed: {entry['router']}")
        elif kind in {"format-specific-review", "remaining-json-gap"}:
            if not entry.get("remaining_risk"):
                errors.append(f"framework remaining risk lacks a disposition: {entry['owner']}")
        else:
            errors.append(f"unknown framework ingress disposition: {entry['owner']}")
    if actual != sorted(expected):
        errors.append("framework original-reader mode or body limit changed")
    routers = {entry["router"] for entry in inventory.get("requests", [])
               if entry.get("disposition") in {"bounded-signed-json", "bounded-document-json"}}
    reviewed_routers = inventory.get("router_compositions", {})
    if routers != set(reviewed_routers):
        errors.append("framework router composition coverage changed")
    for path, review in reviewed_routers.items():
        digest = router_digest(files.get(path, ""), review.get("owner"), contracts)
        if digest is None or digest != review.get("sha256"):
            errors.append(f"framework router composition changed: {path}")
    implementation = hashlib.sha256(blank_noise(source).encode()).hexdigest()
    if implementation != inventory.get("control_reader_sha256"):
        errors.append("framework original-reader implementation changed")
    formats = {path for path, rows in census.items() if any(
        "::format-" in row or "::http-response-json::" in row for row in rows)}
    dispositions = inventory.get("other_input_files", {})
    if set(dispositions) != formats:
        errors.append("response/alternate-format input dispositions are incomplete")
    for path, entry in dispositions.items():
        if not entry.get("semantics") or not entry.get("remaining_risk"):
            errors.append(f"response/alternate-format disposition is incomplete: {path}")
    return sorted(set(errors))


@lru_cache(maxsize=8192)
def file_sites(path, code, binding_items, contracts, json_decoders):
    census, index, calls, seeds = defaultdict(list), defaultdict(list), [], set()
    bindings = dict(binding_items)
    current = module(path)
    rows = contracts.functions(code)
    decoders = list(json_decoders(code))
    for row in rows:
        owner, start, body, end = row
        key = (path, owner)
        if current:
            index[(*current, owner.split("#")[0])].append(key)
        arguments_start = code.find("(", start)
        arguments_end = contracts.closing(code, arguments_start)
        arguments = code[arguments_start:arguments_end]
        names = {"Json": "json", "Form": "form"}
        for alias, target in bindings.items():
            if target.startswith("axum::") and target.split("::")[-1] in {"Json", "Form"}:
                names[alias] = target.split("::")[-1].lower()
        for name, kind in names.items():
            for match in re.finditer(r"\b" + re.escape(name) + r"\s*<", arguments):
                close = contracts.closing(arguments, match.end() - 1, "<", ">")
                target = re.sub(r"\s+", "", arguments[match.end():close - 1])
                census[path].append(f"{owner}::request-{kind}::{target}")
        content = contracts.owner_code(code, row)[body - start + 1:-1]
        original_reader = False
        for match in re.finditer(r"\.\s*(json|into_json)\s*(?:::<[^;{}]*?>\s*)?\(\s*\)", content):
            census[path].append(f"{owner}::http-response-json::{match.group(1)}")
            seeds.add(key)
        for match in CALL.finditer(content):
            name = match.group(1)
            first, *rest = name.split("::")
            expanded = "::".join([bindings.get(first, first), *rest])
            parts = expanded.split("::")
            if len(parts) >= 2 and parts[-2] == "UntrustedJsonText" and parts[-1] in {"new", "from_wire"}:
                original_reader = True
            if parts[0] in FORMATS and parts[-1] in FORMATS[parts[0]][1]:
                census[path].append(f"{owner}::format-{FORMATS[parts[0]][0]}::{parts[-1]}")
                seeds.add(key)
            if current:
                candidates = [qualified(expanded, current)]
                if "::" not in expanded:
                    candidates.append((*current, expanded))
                    for target in bindings.values():
                        if target.endswith("::*"):
                            candidates.append((*qualified(target[:-3], current), expanded))
                elif first not in bindings and first not in {"crate", "self", "super"}:
                    candidates.append((*current, *parts))
                calls.append((key, candidates))
        if original_reader:
            seeds.add(key)
            census[path].append(f"{owner}::original-json-reader::UntrustedJsonText")
        if any(body <= offset < end and decoder not in {"from_value", "custom_deserialize"}
               for offset, decoder in decoders):
            seeds.add(key)

    return census, index, calls, seeds


def scan(files, contracts, json_decoders):
    census = defaultdict(list)
    index, calls, seeds = defaultdict(list), [], set()
    by_module = {module(path): imports(code) for path, code in files.items() if module(path)}
    expanded = {}

    def inherited(current, visiting=frozenset()):
        if current in expanded:
            return expanded[current]
        local = by_module.get(current, {})
        result = {}
        if current in visiting:
            return local
        for target in local.values():
            if target.endswith("::*"):
                source = qualified(target[:-3], current)
                result.update(inherited(source, visiting | {current}))
        result.update(local)
        expanded[current] = result
        return result

    for path, code in files.items():
        if not path.endswith((".rs", ".inc")):
            continue
        bindings = inherited(module(path)) if module(path) else imports(code)
        observed, symbols, uses, input_readers = file_sites(
            path, code, tuple(sorted(bindings.items())), contracts, json_decoders
        )
        for source, rows in observed.items():
            census[source].extend(rows)
        for symbol, targets in symbols.items():
            index[symbol].extend(targets)
        calls.extend(uses)
        seeds.update(input_readers)
    # Only an alias proven to name a real source module may rewrite a path
    # prefix. Function reexports occupy Rust's value namespace and must never
    # be expanded as modules, even when they have the same spelling.
    module_aliases = {name: name for name in by_module}

    def normalize_modules(candidate):
        seen = set()
        while candidate not in seen:
            seen.add(candidate)
            for split in range(len(candidate), 0, -1):
                prefix = candidate[:split]
                target = module_aliases.get(prefix)
                if target is not None and target != prefix:
                    candidate = (*target, *candidate[split:])
                    break
            else:
                return candidate
        return candidate

    while True:
        before = len(module_aliases)
        for base in by_module:
            for name, target in inherited(base).items():
                if target.endswith("::*") or (*base, name) in module_aliases:
                    continue
                options = [qualified(target, base)]
                if not target.startswith(("crate::", "super::", "self::")):
                    options.append((*base, *target.split("::")))
                for option in options:
                    resolved = normalize_modules(option)
                    if resolved in by_module:
                        module_aliases[(*base, name)] = resolved
                        break
        if len(module_aliases) == before:
            break

    @lru_cache(maxsize=None)
    def resolve(candidate, visiting=frozenset()):
        candidate = normalize_modules(candidate)
        if candidate in visiting:
            return ()
        targets = index.get(candidate, [])
        if targets:
            return tuple(targets)
        if not candidate:
            return ()
        base, name = candidate[:-1], candidate[-1]
        bindings = inherited(base)
        options = []
        if name in bindings:
            options.append(qualified(bindings[name], base))
            if not bindings[name].startswith(("crate::", "super::", "self::")):
                options.append((*base, *bindings[name].split("::")))
        for target in bindings.values():
            if target.endswith("::*"):
                options.append((*qualified(target[:-3], base), name))
        for option in options:
            resolved = resolve(option, visiting | {candidate})
            if resolved:
                return resolved
        return ()

    edges = []
    for caller, candidates in calls:
        for candidate in candidates:
            targets = resolve(candidate)
            # Ambiguous duplicate method names are not evidence of a resolved
            # reader; the direct reader remains in its own inventory.
            if len(targets) == 1:
                if caller != targets[0]:
                    edges.append((caller, targets[0]))
                break
    readers = set(seeds)
    while True:
        callers = {caller for caller, target in edges if target in readers}
        updated = readers | callers
        if updated == readers:
            break
        readers = updated
    for (path, owner), (target_path, target_owner) in edges:
        if (target_path, target_owner) in readers:
            census[path].append(f"{owner}::shared-reader::{target_path}::{target_owner}")
    return {path: sorted(rows) for path, rows in sorted(census.items()) if rows}
