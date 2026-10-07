#!/usr/bin/env bash
# Structural coverage for production reqwest construction and dispatch.
# Tokens preserve Rust comments, literals, import aliases and multiline calls.
# Runtime policy, type binding and dataflow have separate acceptance contracts.
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="${CHIO_EGRESS_LINT_ROOT:-$(cd "$SCRIPT_ROOT/.." && pwd)}"
exec python3 - "$SCRIPT_ROOT/check-recovery-boundaries.py" "$REPO_ROOT" <<'PY'
from bisect import bisect_right
import importlib.util
from pathlib import Path
import re
import sys

ALLOWED_PATHS = (
    "crates/protocol/chio-egress-contract/",  # Owns the typed egress machinery.
    "crates/platform/chio-http-core/",       # Re-exports the typed contract.
    "crates/protocol/chio-mcp-adapter/",      # Owns its kernel protocol stack.
)
HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head"})
CLIENT_TYPES = frozenset({"Client", "ClientBuilder", "RequestBuilder"})
HELPER_MODULES = frozenset({"chio_egress_contract", "chio_http_core"})
MARKER = re.compile(r"\bCHIO_EGRESS_LINT_ALLOW_DIRECT_REQWEST:(.*)")


def imports(values):
    """Expand Rust use trees and retain local aliases."""
    def expand(tree, prefix=()):
        start = depth = 0
        parts = []
        for index, value in enumerate(tree):
            depth += (value == "{") - (value == "}")
            if value == "," and depth == 0:
                parts.append(tree[start:index])
                start = index + 1
        parts.append(tree[start:])
        result = []
        for part in parts:
            if not part:
                continue
            if "{" in part:
                opening = part.index("{")
                namespace = tuple(value for value in part[:opening] if value != ":")
                result.extend(expand(part[opening + 1:-1], prefix + namespace))
            else:
                alias_at = part.index("as") if "as" in part else len(part)
                path = prefix + tuple(value for value in part[:alias_at] if value != ":")
                if path and path[-1] == "self":
                    path = path[:-1]
                if path:
                    alias = part[alias_at + 1] if alias_at < len(part) else path[-1]
                    result.append((path, alias))
        return result

    result = []
    for index, value in enumerate(values):
        if value == "use":
            end = values.index(";", index + 1)
            result.extend(expand(values[index + 1:end]))
    return result


def source_tokens(lexer, source):
    tokens = lexer(source, with_spans=True)
    result = []
    index = 0
    while index < len(tokens):
        if (index + 2 < len(tokens) and tokens[index][1] == "r"
                and tokens[index + 1][1] == "#" and tokens[index + 2][0] == "identifier"):
            result.append(("identifier", tokens[index + 2][1], tokens[index][2], tokens[index + 2][3]))
            index += 3
        else:
            result.append(tokens[index])
            index += 1
    return result


def macro_ranges(values):
    """Separate known literal macros from conservative invocation token trees."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    all_ranges, candidates = [], []
    for index, value in enumerate(values[:-2]):
        if not value.isidentifier() or values[index + 1] != "!" or values[index + 2] not in pairs:
            continue
        stack = [pairs[values[index + 2]]]
        end = index + 3
        while stack and end < len(values):
            token = values[end]
            if token in pairs:
                stack.append(pairs[token])
            elif token == stack[-1]:
                stack.pop()
            end += 1
        if stack:
            raise ValueError("unterminated macro token tree")
        bounds = (index + 3, end - 1)
        all_ranges.append(bounds)
        unqualified = index < 2 or values[index - 2:index] != [":", ":"]
        standard = (index >= 3 and values[index - 3] in {"std", "core"}
                    and (index < 5 or values[index - 5:index - 3] != [":", ":"]))
        candidates.append((value, index, bounds, unqualified, standard))
    invocation_indices = {i for start, end in all_ranges for i in range(start, end)}
    declarations = imports(["<macro-token>" if i in invocation_indices else value
                            for i, value in enumerate(values)])
    literal_names = {"stringify", "concat"}
    standard_namespaces = {"std", "core"}
    shadowed = set()
    shadowed_namespaces = {alias for path, alias in declarations
                           if alias in standard_namespaces and path != (alias,)}
    known_literal_imports = {(namespace, name) for namespace in standard_namespaces
                             for name in literal_names}
    # Shadowing grows monotonically over four names. Ignore declarations quoted
    # by literal macros while retaining declarations in unknown token trees.
    for _ in range(len(literal_names) + len(standard_namespaces) + 1):
        data_ranges = [bounds for value, index, bounds, unqualified, standard in candidates
                       if value in literal_names and (
                           standard and values[index - 3] not in shadowed_namespaces
                           or unqualified and value not in shadowed)]
        data_indices = {i for start, end in data_ranges for i in range(start, end)}
        before = (len(shadowed), len(shadowed_namespaces))
        shadowed_namespaces.update(values[i + 1] for i, value in enumerate(values[:-1])
                                   if i not in data_indices and value == "mod"
                                   and values[i + 1] in standard_namespaces)
        shadowed.update(values[i + 2] for i, value in enumerate(values[:-2])
                        if i not in data_indices and value == "macro_rules" and values[i + 1] == "!"
                        and values[i + 2] in literal_names)
        shadowed.update(alias for path, alias in declarations if alias in literal_names
                        and (path not in known_literal_imports or path[0] in shadowed_namespaces))
        if before == (len(shadowed), len(shadowed_namespaces)):
            return all_ranges, data_ranges
    raise ValueError("literal macro bindings did not stabilize")


def comment_segments(source, tokens):
    """Return actual comment bodies, bounding each nested block separately."""
    previous = 0
    for start, end in [(token[2], token[3]) for token in tokens] + [(len(source), len(source))]:
        position = previous
        while position < start:
            if source.startswith("//", position):
                boundary = source.find("\n", position + 2, start)
                boundary = start if boundary == -1 else boundary
                yield position + 2, source[position + 2:boundary]
                position = boundary
            elif source.startswith("/*", position):
                content = position + 2
                position = content
                depth = 1
                while depth:
                    if source.startswith("/*", position):
                        depth += 1
                        position += 2
                    elif source.startswith("*/", position):
                        depth -= 1
                        position += 2
                    else:
                        position += 1
                yield content, source[content:position - 2]
            else:
                position += 1
        previous = end


def argument_count(values, opening):
    """Count call arguments across nested expressions and type arguments."""
    stack = [")"]
    commas = 0
    present = False
    trailing_comma = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index in range(opening + 1, len(values)):
        value = values[index]
        if value == stack[-1]:
            stack.pop()
            if not stack:
                return commas + (not trailing_comma) if present else 0
        elif value in pairs:
            stack.append(pairs[value])
        elif value == "<" and (stack[-1] == ">" or values[index - 2:index] == [":", ":"]):
            stack.append(">")
        elif len(stack) == 1 and value == ",":
            commas += 1
            trailing_comma = True
            continue
        if len(stack) == 1:
            present = True
            trailing_comma = False
    raise ValueError("unterminated call argument list")


def coverage(source, lexer):
    tokens = source_tokens(lexer, source)
    values = [value if kind != "literal" else "<literal>" for kind, value, _, _ in tokens]
    invocation_ranges, data_ranges = macro_ranges(values)
    data_indices = {index for start, end in data_ranges for index in range(start, end)}
    invocation_indices = {index for start, end in invocation_ranges for index in range(start, end)}
    for index in data_indices:
        values[index] = "<macro-data>"
    if "reqwest" not in values:
        return []
    import_values = ["<macro-token>" if i in invocation_indices else value for i, value in enumerate(values)]
    declarations = imports(import_values)
    namespaces = {name: (name,) for name in HELPER_MODULES | {"reqwest"}}
    for _ in range(len(declarations) + 1):
        for path, alias in declarations:
            canonical = namespaces.get(path[0], (path[0],)) + path[1:]
            if (canonical in {("reqwest",), ("reqwest", "blocking")}
                    or canonical in {(name,) for name in HELPER_MODULES}
                    or canonical[0] == "reqwest" and canonical[-1] in CLIENT_TYPES):
                namespaces[alias] = canonical
    request_functions = set()
    for path, alias in declarations:
        canonical = namespaces.get(path[0], (path[0],)) + path[1:]
        if canonical[0] == "reqwest" and canonical[-1] in HTTP_METHODS:
            request_functions.add(alias)
    candidate = bool(CLIENT_TYPES & set(values))

    def call(index):
        return (index + 1 < len(values) and values[index + 1] == "("
                and (index == 0 or values[index - 1] != "fn"))

    def path_at(index):
        path = [values[index]]
        while index >= 3 and values[index - 2:index] == [":", ":"]:
            index -= 3
            if values[index] == ">":
                opening = index - 1
                while opening >= 0 and values[opening] != "<":
                    opening -= 1
                inner = values[opening + 1:index]
                if opening < 0 or any(token not in {":"} and not token.isidentifier() for token in inner) or "as" in inner:
                    break
                path = [token for token in inner if token != ":"] + path
                break
            path.insert(0, values[index])
        return namespaces.get(path[0], (path[0],)) + tuple(path[1:])

    top_level = []
    for index, value in enumerate(values):
        if not call(index):
            continue
        path = path_at(index)
        if (path[0] == "reqwest" and path[-1] in HTTP_METHODS
                or value in request_functions and (index == 0 or values[index - 1] != ".")):
            top_level.append(index)
    candidate |= bool(top_level)
    if not candidate:
        return []

    helper_aliases = {name: set() for name in ("client_builder_with_contract", "send_with_contract")}
    for path, alias in declarations:
        canonical = namespaces.get(path[0], (path[0],)) + path[1:]
        if canonical[0] in HELPER_MODULES:
            for name in helper_aliases:
                if canonical[-1] == name:
                    helper_aliases[name].add(alias)
                elif canonical[-1] == "*":
                    helper_aliases[name].add(name)

    def helper_call(index, name):
        if not call(index) or index and values[index - 1] == ".":
            return False
        path = path_at(index)
        if len(path) > 1:
            return path[0] in HELPER_MODULES and path[-1] == name
        return values[index] in helper_aliases[name]

    builder_calls = [i for i in range(len(values))
                     if i not in invocation_indices and helper_call(i, "client_builder_with_contract")]
    contract_calls = [i for i in range(len(values)) if helper_call(i, "send_with_contract")]
    gaps = []
    if contract_calls and not builder_calls:
        gaps.extend((i, "contract dispatch has no actual client_builder_with_contract call")
                    for i in contract_calls)
    raw_dispatch = []
    for index, value in enumerate(values):
        if index and values[index - 1] == "." and call(index):
            # reqwest execute accepts one Request, while RequestBuilder send
            # accepts no arguments. SQL and channel methods have other arities.
            if value == "execute" and argument_count(values, index + 1) == 1:
                raw_dispatch.append(index)
            elif value == "send" and values[index + 2:index + 3] == [")"]:
                raw_dispatch.append(index)
        elif call(index):
            path = path_at(index)
            if len(path) >= 3 and path[0] == "reqwest":
                if path[-2:] == ("Client", "execute") and argument_count(values, index + 1) == 2:
                    raw_dispatch.append(index)
                elif path[-2:] == ("RequestBuilder", "send") and argument_count(values, index + 1) == 1:
                    raw_dispatch.append(index)
    if not (raw_dispatch or top_level or contract_calls):
        return gaps

    aliases = CLIENT_TYPES | {alias for path, alias in declarations
                              if namespaces.get(path[0], (path[0],))[0] == "reqwest"
                              and path[-1] in CLIENT_TYPES}
    construction = [i for i, value in enumerate(values)
                    if value in {"builder", "new", "default"} and call(i)
                    and i >= 3 and values[i - 2:i] == [":", ":"] and values[i - 3] in aliases]
    gaps.extend((i, "unclassified raw reqwest or unresolved HTTP-file dispatch")
                for i in sorted(set(raw_dispatch + top_level
                                    + (construction if raw_dispatch or top_level else []))))

    line_starts = [0, *(match.end() for match in re.finditer("\n", source))]
    failures = []
    classified_lines = set()
    data_spans = [(tokens[start - 1][3], tokens[end][2]) for start, end in data_ranges]
    for start, comment in comment_segments(source, tokens):
        if any(begin <= start < end for begin, end in data_spans):
            continue
        for marker in MARKER.finditer(comment):
            reason = marker[1].replace("/*", "").replace("*/", "").strip()
            if reason:
                classified_lines.add(bisect_right(line_starts, start + marker.start()))

    for index, reason in gaps:
        line = bisect_right(line_starts, tokens[index][2])
        if reason.startswith("contract dispatch") or not any(
                number in classified_lines for number in range(max(1, line - 4), line + 1)):
            failures.append((line, reason))
    return failures


def main():
    helper, root = Path(sys.argv[1]), Path(sys.argv[2]).resolve()
    spec = importlib.util.spec_from_file_location("egress_rust_tokens", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    crates = root / "crates"
    if not crates.is_dir():
        raise ValueError("crate source tree is missing")
    failed = []
    for path in sorted(crates.rglob("*.rs")):
        relative = path.relative_to(root).as_posix()
        if any(relative.startswith(prefix) for prefix in ALLOWED_PATHS):
            continue
        if path.name == "tests.rs" or path.name.endswith("-tests.rs") or "tests" in path.parts:
            continue
        for line, reason in coverage(path.read_text(encoding="utf-8"), module.rust_tokens):
            failed.append(f"{relative}:{line}: {reason}")
    if failed:
        print("HttpEgressContract coverage gap:", file=sys.stderr)
        print("\n".join("  " + line for line in failed), file=sys.stderr)
        print("Construct and dispatch with typed egress helpers, or document the exact direct call classification.",
              file=sys.stderr)
        return 1
    print("HttpEgressContract coverage OK across the workspace.")
    return 0


try:
    sys.exit(main())
except (OSError, UnicodeError, ValueError, IndexError, ImportError) as error:
    print(f"HttpEgressContract coverage cannot be validated: {type(error).__name__}", file=sys.stderr)
    sys.exit(1)
PY
