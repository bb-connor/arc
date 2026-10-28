#!/usr/bin/env python3
"""Find ureq and hyper client construction outside HttpEgressContract.

Every ureq request starts at an agent constructor, an agent configuration or a
top-level dispatch function, and every hyper client lives under a `client`
module. This scan resolves, to a fixed point, the names a source file binds to
those items: renamed Cargo dependencies, `extern crate` aliases, type aliases
and every `use` tree form, including multi-line groups, nested groups, `self`
renames and renames of the items themselves. A glob import from a client crate
is refused because it hides what it binds. Paths are matched over the whole
source, so a path split across lines or written from the crate root (`::ureq`)
still matches, and a client function named without a call still counts. A
constructor alias matches under any path prefix (`crate::`, `self::`,
`super::`, `::`), and a qualified path `<T>::` or `<T as Trait>::` counts when
its self type `T`, read with bracket depth and without transparent
parentheses, names an agent type or an alias of one.

A finding outside the kernel is accepted when one of the four lines above it
carries the classification marker for its crate. Kernel crates take no
classification and may not name ureq at all. Prints `path:line:text` per
finding and exits 1 when there is any.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "negative_assertions", Path(__file__).resolve().parent / "check-negative-assertions.py"
)
lexer = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lexer
_spec.loader.exec_module(lexer)

CONTRACT_OWNER = "crates/protocol/chio-egress-contract/"
KERNEL_ROOT = "crates/kernel/"
UREQ_MARKER = "CHIO_EGRESS_LINT_ALLOW_DIRECT_UREQ:"
HYPER_MARKER = "CHIO_EGRESS_LINT_ALLOW_DIRECT_HYPER_CLIENT:"
UREQ_FUNCTIONS = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "request", "request_url", "agent", "builder", "run"}
)
UREQ_CONSTRUCTORS = frozenset({"Agent", "AgentBuilder", "Config", "config"})
CLIENT_PACKAGES = {"ureq": "ureq", "hyper": "hyper", "hyper-util": "hyper"}
UNSCANNED_PACKAGES = frozenset(
    {"isahc", "surf", "attohttpc", "minreq", "curl", "awc", "http-req", "ehttp", "hyper-tls"}
)
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
USE_STATEMENT = re.compile(r"\b(pub(?:\([^)]*\))?\s+)?use\s+([^;]*);", re.S)
EXTERN_CRATE = re.compile(r"\bextern\s+crate\s+([A-Za-z_]\w*)\s+as\s+([A-Za-z_]\w*)\s*;")
QUALIFIED_PATH_START = re.compile(r"(?<![\w:])<")
TYPE_ALIAS = re.compile(r"\btype\s+([A-Za-z_]\w*)\s*(?:<[^=;]*>)?\s*=\s*([^;]+);")


def dependency_tables(manifest: dict):
    for name in DEPENDENCY_TABLES:
        yield manifest.get(name, {})
    yield manifest.get("workspace", {}).get("dependencies", {})
    for target in manifest.get("target", {}).values():
        for name in DEPENDENCY_TABLES:
            yield target.get(name, {})


def manifests(root: Path):
    paths = [root / "Cargo.toml"] if (root / "Cargo.toml").is_file() else []
    crates = root / "crates"
    if crates.is_dir():
        paths += sorted(p for p in crates.rglob("Cargo.toml") if "target" not in p.parts)
    return paths


def crate_roots(root: Path, findings: list[str]) -> dict[str, set[str]]:
    roots: dict[str, set[str]] = {"ureq": {"ureq"}, "hyper": {"hyper", "hyper_util"}}
    for manifest_path in manifests(root):
        rel = manifest_path.relative_to(root).as_posix()
        try:
            manifest = tomllib.loads(manifest_path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as error:
            findings.append(f"{rel}:1:unparseable manifest ({error})")
            continue
        for table in dependency_tables(manifest):
            for key, spec in table.items():
                package = spec.get("package", key) if isinstance(spec, dict) else key
                if package in UNSCANNED_PACKAGES:
                    findings.append(
                        f"{rel}:1:{key} -> {package} (HTTP client crate the egress lint does not scan)"
                    )
                family = CLIENT_PACKAGES.get(package)
                if family:
                    roots[family].add(key.replace("-", "_"))
    return roots


def split_top_level(body: str) -> list[str]:
    parts, depth, current = [], 0, []
    for char in body:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def expand_use_tree(tree: str, prefix: list[str]):
    """Yield (path segments, bound name or None for a glob)."""
    tree = re.sub(r"\s+", " ", tree).strip()
    brace = tree.find("{")
    if brace >= 0 and tree.endswith("}"):
        head = [s for s in tree[:brace].strip().rstrip(":").split("::") if s.strip()]
        for part in split_top_level(tree[brace + 1 : -1]):
            yield from expand_use_tree(part, prefix + [s.strip() for s in head])
        return
    alias = None
    match = re.fullmatch(r"(.*?)\s+as\s+([A-Za-z_]\w*)", tree)
    if match:
        tree, alias = match.group(1), match.group(2)
    segments = [s.strip() for s in tree.split("::") if s.strip()]
    if segments and segments[-1] == "*":
        yield prefix + segments[:-1], None
        return
    if segments and segments[-1] == "self":
        segments = segments[:-1]
    path = prefix + segments
    if path:
        yield path, alias or path[-1]


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def is_test_source(rel: str, first_line: str) -> bool:
    if rel.endswith("/tests.rs") or "/tests/" in rel or rel.endswith("-tests.rs"):
        return True
    if re.search(r"/[^/]*_tests/", rel):
        return first_line.strip() == "#![cfg(test)]"
    return False


def classified(lines: list[str], line_no: int, marker: str) -> bool:
    return any(marker in lines[n - 1] for n in range(max(1, line_no - 4), line_no + 1))


def alternation(names) -> str:
    return "|".join(sorted(map(re.escape, names)))


def bind_names(text: str, ureq_roots: set[str], hyper_roots: set[str]):
    """Resolve aliases to a fixed point, since Rust imports are order-independent.

    Returns the constructor names and the (offset, family) findings that come
    from the imports themselves.
    """
    uses = [(match.start(), list(expand_use_tree(match.group(2), []))) for match in USE_STATEMENT.finditer(text)]
    externs = [(match.group(1), match.group(2)) for match in EXTERN_CRATE.finditer(text)]
    type_aliases = [(match.group(1), match.group(2)) for match in TYPE_ALIAS.finditer(text)]
    constructors: set[str] = set()
    findings: set[tuple[int, str]] = set()
    while True:
        size = (len(ureq_roots), len(hyper_roots), len(constructors))
        for crate, alias in externs:
            if crate in ureq_roots:
                ureq_roots.add(alias)
            if crate in hyper_roots:
                hyper_roots.add(alias)
        for offset, trees in uses:
            for path, bound in trees:
                if path and path[0] == "":
                    path = path[1:]
                if not path:
                    continue
                crate = path[0]
                if crate in ureq_roots:
                    if bound is None or (len(path) == 2 and path[1] in UREQ_FUNCTIONS):
                        findings.add((offset, "ureq"))
                    elif len(path) == 1:
                        ureq_roots.add(bound)
                    elif any(segment in UREQ_CONSTRUCTORS for segment in path[1:]):
                        constructors.add(bound)
                elif crate in hyper_roots:
                    if bound is None or "client" in path[1:]:
                        findings.add((offset, "hyper"))
                    elif len(path) == 1:
                        hyper_roots.add(bound)
                elif crate in constructors and len(path) == 1:
                    constructors.add(bound)
        for name, target in type_aliases:
            if names_agent_type(target, ureq_roots, constructors):
                constructors.add(name)
        if size == (len(ureq_roots), len(hyper_roots), len(constructors)):
            return constructors, findings


def qualified_self_types(text: str):
    """Yield (offset, T) for each qualified path `<T>::` or `<T as Trait>`.

    T is read with bracket depth so generic arguments and parentheses inside
    it, or in the trait, do not end it early. A `<` that follows a path
    separator is a turbofish, not a qualified path.
    """
    for match in QUALIFIED_PATH_START.finditer(text):
        start = match.end()
        depth = 0
        index = start
        while index < len(text):
            char = text[index]
            if char in ";{}":
                break
            if char in "<([":
                depth += 1
            elif char in ">)]" and not (char == ">" and text[index - 1] == "-"):
                if depth == 0:
                    if char == ">" and re.match(r"\s*::", text[index + 1 :]):
                        yield match.start(), text[start:index]
                    break
                depth -= 1
            elif (
                depth == 0
                and text.startswith("as", index)
                and not re.match(r"\w", text[index - 1])
                and not re.match(r"\w", text[index + 2 : index + 3])
            ):
                yield match.start(), text[start:index]
                break
            index += 1


def names_agent_type(self_type: str, ureq_roots: set[str], constructors: set[str]) -> bool:
    """True when a type (a qualified path's self type or an alias target) names a
    ureq agent type or an alias of one."""
    self_type = self_type.strip()
    while self_type.startswith("(") and self_type.endswith(")"):
        self_type = self_type[1:-1].strip()
    self_type = re.sub(r"<.*", "", self_type, flags=re.S)
    segments = [s.strip() for s in self_type.split("::") if s.strip()]
    if segments and segments[-1] in constructors:
        return True
    return any(
        segment in ureq_roots and any(later in UREQ_CONSTRUCTORS for later in segments[index + 1 :])
        for index, segment in enumerate(segments)
    )


def scan_file(rel: str, raw: str, roots: dict[str, set[str]]) -> list[tuple[int, str]]:
    text = lexer.blank_rust_noise(raw)
    ureq_roots = set(roots["ureq"])
    hyper_roots = set(roots["hyper"])
    constructors, found = bind_names(text, ureq_roots, hyper_roots)
    patterns = [
        (
            "ureq",
            re.compile(
                r"(?<!\w)(?:" + alternation(ureq_roots) + r")\s*::\s*(?:"
                r"(?:" + "|".join(sorted(UREQ_FUNCTIONS)) + r")\b(?!\s*::)"
                r"|(?:Agent|AgentBuilder)\s*::\s*\w+|config\b)"
            ),
        ),
        ("hyper", re.compile(r"(?<!\w)(?:" + alternation(hyper_roots) + r")\s*::\s*client\b")),
    ]
    if constructors:
        patterns.append(("ureq", re.compile(r"(?<!\w)(?:" + alternation(constructors) + r")\s*::\s*\w+")))
    in_kernel = rel.startswith(KERNEL_ROOT)
    if in_kernel:
        patterns.append(("kernel", re.compile(r"(?<!\w)(?:" + alternation(ureq_roots) + r")\b")))
    for family, pattern in patterns:
        for match in pattern.finditer(text):
            found.add((match.start(), family))
    for offset, self_type in qualified_self_types(text):
        if names_agent_type(self_type, ureq_roots, constructors):
            found.add((offset, "ureq"))
    raw_lines = raw.split("\n")
    result = set()
    for offset, family in found:
        line_no = line_of(text, offset)
        if in_kernel and family in ("ureq", "kernel"):
            result.add((line_no, raw_lines[line_no - 1]))
            continue
        marker = UREQ_MARKER if family == "ureq" else HYPER_MARKER
        if not classified(raw_lines, line_no, marker):
            result.add((line_no, raw_lines[line_no - 1]))
    return sorted(result)


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parents[1]
    findings: list[str] = []
    roots = crate_roots(root, findings)
    crates = root / "crates"
    sources = sorted(crates.rglob("*.rs")) if crates.is_dir() else []
    all_roots = roots["ureq"] | roots["hyper"]
    for path in sources:
        rel = path.relative_to(root).as_posix()
        if "target" in path.parts or rel.startswith(CONTRACT_OWNER):
            continue
        raw = path.read_text(errors="replace")
        if not any(name in raw for name in all_roots):
            continue
        if is_test_source(rel, raw.split("\n", 1)[0]):
            continue
        for line_no, line in scan_file(rel, raw, roots):
            findings.append(f"{rel}:{line_no}:{line}")
    for finding in findings:
        print(finding)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
