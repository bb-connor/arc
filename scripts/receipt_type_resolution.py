"""Resolve lexical Rust type references without merging unrelated namespaces."""
from collections import defaultdict
from pathlib import Path
import re
import tomllib

PATH = re.compile(r"(?<![\w])(?:::)?[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*")
MODULE = re.compile(r"\bmod\s+(\w+)\s*\{")
ALIAS = re.compile(r"\btype\s+(\w+)\b[^=;]*=\s*([^;]+);")


def use_leaves(text, prefix=()):
    """Flatten a use tree, retaining its full source path and local name."""
    depth = 0
    start = 0
    parts = []
    for index, char in enumerate(text):
        depth += (char == "{") - (char == "}")
        if char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "{" in part:
            opening = part.index("{")
            source = part[:opening].strip().removesuffix("::")
            stem = tuple(x.strip() for x in source.split("::")) if source else ()
            yield from use_leaves(part[opening + 1:part.rfind("}")], prefix + stem)
            continue
        original, *rename = re.split(r"\s+as\s+", part)
        path = prefix + tuple(x.strip() for x in original.split("::"))
        if path and path[-1] == "self":
            path = path[:-1]
        if path:
            yield path, rename[0].strip() if rename else path[-1]


class TypeResolver:
    def __init__(self, root, files, gate):
        self.root, self.gate = root, gate
        self.files = dict(files)
        self.bases = {}
        self.spans = {}
        self.definitions = defaultdict(list)
        self.imports = defaultdict(dict)
        self.globs = defaultdict(list)
        self.crates = {}
        self.dependencies = {}
        manifest = root / "Cargo.toml"
        workspace = tomllib.loads(manifest.read_text()).get("workspace", {}) if manifest.is_file() else {}
        workspace_dependencies = workspace.get("dependencies", {})
        for rel, code in files:
            crate = gate.crate_of(rel)
            suffix = rel.split("/src/", 1)[-1]
            parts = list(Path(suffix).with_suffix("").parts)
            if parts[-1] in {"lib", "main", "mod"}:
                parts.pop()
            self.bases[rel] = (crate, *parts)
            self.crates[Path(crate).name.replace("-", "_")] = crate
            manifest = root / crate / "Cargo.toml"
            if manifest.is_file() and crate not in self.dependencies:
                data = tomllib.loads(manifest.read_text())
                name = data.get("lib", {}).get("name", data.get("package", {}).get("name"))
                if name:
                    self.crates[name.replace("-", "_")] = crate
                deps = dict(data.get("dependencies", {}))
                for target in data.get("target", {}).values():
                    deps.update(target.get("dependencies", {}))
                deps = {
                    name: workspace_dependencies.get(name, value)
                    if isinstance(value, dict) and value.get("workspace") else value
                    for name, value in deps.items()
                }
                self.dependencies[crate] = deps
            spans = []
            for match in MODULE.finditer(code):
                end = gate._contracts.closing(code, match.end() - 1, "{", "}")
                spans.append((match.start(), end, match.group(1)))
            pairs = gate.brace_pairs(code)
            for row in gate._contracts.functions(code):
                spans.append((row[2], row[3], "@" + str(row[1])))
                for opening, closing in pairs.items():
                    if row[2] < opening < closing < row[3]:
                        spans.append((opening, closing, "@block" + str(opening)))
            self.spans[rel] = sorted(spans)
        self._module_paths()
        for rel, code in files:
            for statement in gate.USE_STATEMENT.finditer(code):
                scope = self.scope(rel, statement.start())
                for path, alias in use_leaves(statement.group()[3:-1]):
                    if alias == "*":
                        self.globs[scope].append(path[:-1])
                    else:
                        self.imports[scope][alias] = path
            for match in gate.TYPE_DEFINITION.finditer(code):
                opening = match.end(2) - 1
                closing = ")" if code[opening] == "(" else "}"
                end = gate._contracts.closing(code, opening, code[opening], closing)
                body = code[opening:end]
                if match.group().startswith("enum"):
                    body = gate.VARIANT_NAME.sub(r"\1", body)
                body = re.sub(r"\b\w+\s*:(?!:)", "", body)
                if not match.group(1).endswith("Error"):
                    scope = self.scope(rel, match.start())
                    self.definitions[scope + (match.group(1),)].append((body, scope))
            for match in ALIAS.finditer(code):
                if not any(a < match.start() < b for a, b, _ in gate.block_spans(code)):
                    scope = self.scope(rel, match.start())
                    self.definitions[scope + (match.group(1),)].append((match.group(2), scope))
        self.strict = {
            key for key in self.definitions
            if key[-1] in gate.STRICT_TYPES
            and key[0].endswith("/chio-core-types") and key[1:2] == ("receipt",)
        }
        self.seeds = {(":seed", name) for name in gate.STRICT_TYPES}
        self.strict |= self.seeds
        self.resolve_cache = {}
        edges = {
            key: set().union(*(self.references(body, scope) for body, scope in bodies))
            for key, bodies in self.definitions.items()
        }
        changed = True
        while changed:
            additions = {key for key, refs in edges.items() if refs & self.strict} - self.strict
            self.strict.update(additions)
            changed = bool(additions)

    def _module_paths(self):
        """Bind out-of-line files to declared modules, including path attributes."""
        declarations = re.compile(
            r'(?:#\[path\s*=\s*"([^"\n]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;'
        )
        for _ in range(len(self.files)):
            changed = False
            for rel, code in self.files.items():
                raw = (self.root / rel).read_text()
                parent = Path(rel).parent
                if Path(rel).stem not in {"lib", "main", "mod"}:
                    parent /= Path(rel).stem
                for match in declarations.finditer(raw):
                    keyword = raw.rfind("mod", match.start(), match.end())
                    if code[keyword:keyword + 3] != "mod":
                        continue
                    scope = self.scope(rel, match.start())
                    inline = scope[len(self.bases[rel]):]
                    directory = parent.joinpath(*inline)
                    if match.group(1):
                        directory = directory if inline else Path(rel).parent
                        candidates = [directory / match.group(1)]
                    else:
                        candidates = [directory / (match.group(2) + ".rs"), directory / match.group(2) / "mod.rs"]
                    for child in candidates:
                        child = child.as_posix()
                        if child in self.bases:
                            base = scope + (match.group(2),)
                            if self.bases[child] != base:
                                self.bases[child] = base
                                changed = True
            if not changed:
                return
        raise ValueError("cyclic Rust module path declarations")

    def scope(self, rel, offset):
        return self.bases[rel] + tuple(name for a, b, name in self.spans[rel] if a < offset < b)

    @staticmethod
    def module(scope):
        return tuple(part for part in scope if not part.startswith("@"))

    def absolute(self, path, scope):
        module = self.module(scope)
        if path[0] == "crate":
            return (scope[0],) + path[1:]
        if path[0] == "self":
            return module + path[1:]
        if path[0] == "super":
            while path and path[0] == "super":
                module, path = module[:-1], path[1:]
            return module + path
        dependency = self.dependencies.get(scope[0], {}).get(path[0].replace("_", "-"))
        dependency = self.dependencies.get(scope[0], {}).get(path[0], dependency)
        external = dependency.get("package", path[0]) if isinstance(dependency, dict) else path[0]
        if external.replace("-", "_") in self.crates:
            return (self.crates[external.replace("-", "_")],) + path[1:]
        return None

    def resolve(self, path, scope, seen=None):
        if seen is None:
            seen = set()
        marker = (path, scope)
        if marker in seen:
            return set()
        seen.add(marker)
        if path[0] == "":
            external = self.absolute(path[1:], scope)
            return self.lookup(external, seen) if external else set()
        direct = self.absolute(path, scope) if path[0] in {"crate", "self", "super"} else None
        if direct:
            return self.lookup(direct, seen)
        current = scope
        while current:
            key = current + path
            if key in self.definitions:
                return {key}
            alias = self.imports[current].get(path[0])
            edge = (("@use", path[0]), current)
            if alias and edge not in seen:
                seen.add(edge)
                return self.resolve(alias + path[1:], current, seen)
            found = self.lookup(key, seen)
            if found:
                return found
            found = set()
            for glob in self.globs[current]:
                edge = (("*",) + glob, current)
                if edge not in seen:
                    seen.add(edge)
                    found |= self.resolve(glob + path, current, seen)
            if found:
                return found
            if not current[-1].startswith("@"):
                break
            current = current[:-1]
        external = self.absolute(path, scope)
        if external:
            return self.lookup(external, seen)
        if path[-1] in self.gate.STRICT_TYPES:
            return {(":seed", path[-1])}
        return set()

    def lookup(self, key, seen):
        if key in self.definitions:
            return {key}
        for split in range(len(key) - 1, 0, -1):
            scope, tail = key[:split], key[split:]
            alias = self.imports[scope].get(tail[0])
            edge = (("@use", tail[0]), scope)
            if alias and edge not in seen:
                seen.add(edge)
                return self.resolve(alias + tail[1:], scope, seen)
        found = set()
        if len(key) > 1:
            for glob in self.globs[key[:-1]]:
                edge = (("*",) + glob, key[:-1])
                if edge not in seen:
                    seen.add(edge)
                    found |= self.resolve(glob + key[-1:], key[:-1], seen)
        return found

    def references(self, text, scope):
        found = set()
        for match in PATH.finditer(text):
            path = tuple(x.strip() for x in match.group().split("::"))
            marker = (path, scope)
            if marker not in self.resolve_cache:
                self.resolve_cache[marker] = self.resolve(path, scope)
            found |= self.resolve_cache[marker]
        return found

    def mentions(self, text, rel, offset):
        return bool(self.references(text, self.scope(rel, offset)) & self.strict)
