"""Resolve lexical Rust type references without merging unrelated namespaces."""
from collections import defaultdict
from pathlib import Path
import re
import posixpath
import tomllib

PATH = re.compile(r"(?<![\w])(?:::)?[A-Za-z_]\w*(?:\s*::\s*[A-Za-z_]\w*)*")
MODULE = re.compile(r"\bmod\s+(\w+)\s*\{")
ALIAS = re.compile(r"\btype\s+(\w+)\b[^=;]*=\s*([^;]+);")


PRIMITIVES = frozenset({
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize",
    "i8", "i16", "i32", "i64", "i128", "isize", "f32", "f64",
})
PRELUDE_TYPES = frozenset({
    "Box", "String", "Vec", "Option", "Result", "Send", "Sync", "Sized",
    "Unpin", "Clone", "Copy", "Default", "Drop", "Eq", "PartialEq", "Ord",
    "PartialOrd", "Iterator", "IntoIterator", "From", "Into", "TryFrom", "TryInto",
    "AsRef", "AsMut", "ToOwned", "ToString", "Fn", "FnMut", "FnOnce",
})
EXTERNAL_ROOTS = {
    "std": "Rust standard library; generic arguments are resolved separately.",
    "core": "Rust core library; generic arguments are resolved separately.",
    "alloc": "Rust allocation library; generic arguments are resolved separately.",
    "serde": "Serialization traits cannot contain Chio receipt fields.",
    "serde_json": "JSON library types are not typed Chio receipt wrappers.",
    "axum": "HTTP extractor types; generic arguments are resolved separately.",
}

def split_arguments(text):
    start = depth = 0
    parts = []
    for index, char in enumerate(text):
        depth += char in "([{<"
        depth -= char in ")]}>" and depth > 0
        if char == "," and depth == 0:
            if text[start:index].strip():
                parts.append(text[start:index].strip())
            start = index + 1
    if text[start:].strip():
        parts.append(text[start:].strip())
    return parts


def production_module_files(root, files, gate):
    known = {rel for rel, _ in files}
    incoming = defaultdict(list)
    declarations = re.compile(r'(?:#\[path\s*=\s*"([^"\n]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;')
    for rel, code in files:
        raw = (root / rel).read_text()
        original = gate._lexer.blank_rust_noise(raw)
        inline = [(match.start(), gate._contracts.closing(original, match.end() - 1, "{", "}"), match.group(1)) for match in MODULE.finditer(original)]
        parent = Path(rel).parent
        if Path(rel).stem not in {"lib", "main", "mod"}:
            parent /= Path(rel).stem
        for match in declarations.finditer(raw):
            keyword = raw.rfind("mod", match.start(), match.end())
            if original[keyword:keyword + 3] != "mod":
                continue
            scope = tuple(name for start, end, name in inline if start < keyword < end)
            directory = parent.joinpath(*scope)
            candidates = [((directory if scope else Path(rel).parent) / match.group(1))] if match.group(1) else [directory / (match.group(2) + ".rs"), directory / match.group(2) / "mod.rs"]
            for child in candidates:
                child = posixpath.normpath(child.as_posix())
                if child in known:
                    incoming[child].append((rel, code[keyword:keyword + 3] == "mod"))
        for _, child, _ in include_paths(root, rel, code, gate._contracts, gate.crate_of):
            if child in known:
                incoming[child].append((rel, True))
    excluded = set()
    while True:
        additions = {child for child, parents in incoming.items() if all(not enabled or parent in excluded for parent, enabled in parents)} - excluded
        if not additions:
            return [(rel, code) for rel, code in files if rel not in excluded]
        excluded.update(additions)


def include_paths(root, rel, code, contracts, crate_of):
    raw = (root / rel).read_text()
    for included in re.finditer(r"\binclude\s*!\s*\(", code):
        opening = included.end() - 1
        closing = contracts.closing(code, opening, "(", ")")
        expression = raw[opening + 1:closing - 1].strip()
        literal = re.fullmatch(r'"([^"\n]+)"', expression)
        manifest = re.fullmatch(
            r'concat!\(\s*env!\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"([^"\n]+)"\s*,?\s*\)', expression
        )
        child = None
        if literal:
            child = Path(rel).parent / literal.group(1)
        elif manifest:
            child = Path(crate_of(rel)) / manifest.group(1).lstrip("/")
        yield included.start(), posixpath.normpath(child.as_posix()) if child else None, re.sub(r"\s+", "", expression)


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
        self.definition_sources = {}
        self.unresolved = set()
        self.parameters = defaultdict(set)
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
            if parts[0] == "bin" and (len(parts) == 2 or len(parts) == 3 and parts[-1] == "main"):
                parts = [":bin:" + parts[1]]
            elif parts == ["main"]:
                parts = [":bin:main"]
            elif parts[-1] in {"lib", "mod"}:
                parts.pop()
            self.bases[rel] = (crate, *parts)
            manifest = root / crate / "Cargo.toml"
            if not manifest.is_file():
                self.crates[Path(crate).name.replace("-", "_")] = crate
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
                spans.append((row[2], row[3], "@" + rel + ":" + str(row[1])))
                for opening, closing in pairs.items():
                    if row[2] < opening < closing < row[3]:
                        spans.append((opening, closing, "@block" + rel + ":" + str(opening)))
            self.spans[rel] = sorted(spans)
        self._module_paths()
        for rel, code in files:
            template_spans = [(match.start(), gate._contracts.closing(code, match.end() - 1, "{", "}")) for match in re.finditer(r"\bmacro_rules!\s*\w+\s*\{", code)]
            for row in gate._contracts.functions(code):
                names = self.generic_names(code[row[1]:row[2]])
                for scope in self.scopes(rel, row[2] + 1):
                    self.parameters[scope].update(names)
            for statement in gate.USE_STATEMENT.finditer(code):
                for scope in self.scopes(rel, statement.start()):
                    for path, alias in use_leaves(statement.group()[3:-1]):
                        if alias == "*":
                            self.globs[scope].append(path[:-1])
                        else:
                            self.imports[scope][alias] = path
            for match in re.finditer(r"\b(?:struct\s+(\w+)\s*;|trait\s+(\w+)|const\s+(\w+)\s*:)", code):
                self.define(rel, match.start(), next(name for name in match.groups() if name), "")
            for match in gate.TYPE_DEFINITION.finditer(code):
                if any(start < match.start() < end for start, end in template_spans):
                    continue
                opening = match.end(2) - 1
                closing = ")" if code[opening] == "(" else "}"
                end = gate._contracts.closing(code, opening, code[opening], closing)
                body = code[opening:end]
                if match.group().startswith("enum"):
                    body = self.enum_fields(body)
                body = re.sub(r"\bpub(?:\([^)]*\))?\s+", "", body)
                body = re.sub(r"\b\w+\s*:(?!:)", "", body)
                self.define(rel, match.start(), match.group(1), "" if match.group(1).endswith("Error") else body, self.generic_names(code[match.start():opening]))
            for match in ALIAS.finditer(code):
                if any(start < match.start() < end for start, end in template_spans):
                    continue
                if not any(a < match.start() < b for a, b, _ in gate.block_spans(code)):
                    self.define(rel, match.start(), match.group(1), match.group(2), self.generic_names(match.group().split("=", 1)[0]))
        self.modules = {key[:end] for key in self.definitions for end in range(1, len(key))}
        self.macro_types(files)
        self.strict = {
            key for key in self.definitions
            if key[-1] in gate.STRICT_TYPES
            and key[0].endswith("/chio-core-types") and key[1:2] == ("receipt",)
        }
        self.seeds = {(":seed", name) for name in gate.STRICT_TYPES}
        self.strict |= self.seeds
        self.resolve_cache = {}
        edges = {
            key: set().union(*(self.references(re.sub(r"\bSelf\b", key[-1], body), scope, rel, parameters) for body, scope, rel, parameters in bodies))
            for key, bodies in self.definitions.items()
        }
        changed = True
        while changed:
            additions = {key for key, refs in edges.items() if refs & self.strict} - self.strict
            self.strict.update(additions)
            changed = bool(additions)

    def macro_types(self, files):
        templates = {}
        for rel, code in files:
            for macro in re.finditer(r"\bmacro_rules!\s*(\w+)\s*\{", code):
                end = self.gate._contracts.closing(code, macro.end() - 1, "{", "}")
                template = code[macro.end():end]
                matcher = template.split("=>", 1)[0]
                captures = re.findall(r"\$(\w+)\s*:\s*(ident|ty|expr)", matcher)
                if not captures:
                    continue
                for item in re.finditer(r"\b(?:struct|enum)\s+(\$?\w+)\s*([({])", template):
                    parameter = item.group(1).removeprefix("$")
                    fixed = not item.group(1).startswith("$")
                    if not fixed and parameter not in {name for name, _ in captures}:
                        continue
                    opening = item.end(2) - 1
                    closing = ")" if template[opening] == "(" else "}"
                    stop = self.gate._contracts.closing(template, opening, template[opening], closing)
                    body = re.sub(r"#\[[^\]]*\]", "", template[opening:stop])
                    if fixed:
                        if not item.group().startswith("enum") or not re.fullmatch(r"\{\s*\$\(\s*\$\w+\s*\)\s*,\s*[+*]\s*\}", body):
                            continue
                        body = ""
                        parameter = ":fixed:" + parameter
                    elif item.group().startswith("enum"):
                        body = self.enum_fields(body)
                    repeated = bool(re.search(r"\$\(\s*\$" + parameter + r"\s*:\s*ident\s*\)\s*,\s*[+*]", matcher))
                    for scope in self.scopes(rel, macro.start()):
                        key = scope + (macro.group(1),)
                        self.definitions[key].append(("", scope, rel, frozenset()))
                        templates[key] = (body, captures, repeated, parameter)
        names = {key[-1] for key in templates}
        names |= {alias for imports in self.imports.values() for alias, path in imports.items() if path[-1] in names}
        for rel, code in files:
            for call in re.finditer(r"\b(\w+(?:::\w+)*)!\s*([({])", code):
                if call.group(1).split("::")[-1] not in names:
                    continue
                opening = call.end(2) - 1
                closing = ")" if code[opening] == "(" else "}"
                end = self.gate._contracts.closing(code, opening, code[opening], closing)
                arguments = re.sub(r"#\[[^\]]*\]", "", code[opening + 1:end - 1]).strip()
                keys = set().union(*(self.resolve(tuple(call.group(1).split("::")), scope) for scope in self.scopes(rel, call.start())))
                for key in keys & templates.keys():
                    body, captures, repeated, name_parameter = templates[key]
                    repeated_arguments = arguments.split(";", 1)[-1]
                    if name_parameter.startswith(":fixed:"):
                        bindings = [{name_parameter: name_parameter.removeprefix(":fixed:")}]
                    elif repeated and re.fullmatch(r"[\w\s,]+", repeated_arguments):
                        bindings = [{name_parameter: name} for name in re.findall(r"\w+", repeated_arguments)]
                    else:
                        match = re.match(r"(\w+)\s*(?:\(\s*([\w:]+)\s*\)|,\s*([\w:]+))?", arguments)
                        if not match:
                            continue
                        values = split_arguments(arguments) if re.match(r"\w+\s*,", arguments) else [match.group(1), match.group(2) or match.group(3)]
                        bindings = [{name: value for (name, _), value in zip(captures, values) if value}]
                    for binding in bindings:
                        expanded = body
                        fields = re.fullmatch(r"\w+\s*\{(.*)\}", arguments, re.S)
                        field_capture = next((name for name, kind in captures if kind == "ident" and name != name_parameter), None)
                        type_capture = next((name for name, kind in captures if kind == "ty"), None)
                        if fields and field_capture and type_capture:
                            replacements = []
                            for field in split_arguments(fields.group(1)):
                                field_name, separator, field_type = field.partition(":")
                                if not separator:
                                    break
                                replacements.append({field_capture: field_name.strip(), type_capture: field_type.strip()})
                            else:
                                repeat = re.search(r"\$\(", expanded)
                                if repeat:
                                    end = self.gate._contracts.closing(expanded, repeat.end() - 1, "(", ")")
                                    suffix = re.match(r"[,;]?[+*]", expanded[end:])
                                    if suffix:
                                        pieces = []
                                        for replacement in replacements:
                                            piece = expanded[repeat.end():end - 1]
                                            for name, value in replacement.items():
                                                piece = re.sub(r"\$" + name + r"\b", lambda _: value, piece)
                                            pieces.append(piece)
                                        expanded = expanded[:repeat.start()] + " ".join(pieces) + expanded[end + suffix.end():]
                        for name, value in binding.items():
                            expanded = re.sub(r"\$" + name + r"\b", value, expanded)
                        if re.search(r"\$(?!crate\b)\w+", expanded):
                            continue
                        expanded = re.sub(r"\bpub(?:\([^)]*\))?\s+", "", expanded)
                        expanded = re.sub(r"\b\w+\s*:(?!:)", "", expanded)
                        self.define(rel, call.start(), binding[name_parameter], expanded)

    def without_attributes(self, text):
        output = list(text)
        for match in re.finditer(r"#!?\[", text):
            end = self.gate._contracts.closing(text, match.end() - 1, "[", "]")
            output[match.start():end] = " " * (end - match.start())
        return "".join(output)

    @staticmethod
    def enum_fields(body):
        output = []
        start = 1
        depth = 0
        for index, char in enumerate(body[1:-1], 1):
            depth += char in "([{<"
            depth -= char in ")]}>" and depth > 0
            if char == "," and depth == 0:
                output.append(re.sub(r"^\s*(?:#\[[^\]]*\]\s*)*\w+", "", body[start:index]))
                start = index + 1
        output.append(re.sub(r"^\s*(?:#\[[^\]]*\]\s*)*\w+", "", body[start:-1]))
        return ",".join(output)

    def generic_names(self, header):
        match = re.search(r"\b(?:fn|struct|enum|type|trait)\s+\w+\s*<", header)
        if not match:
            return set()
        content, _ = self.gate.angle_argument(header, match.end() - 1)
        parts = []
        start = depth = 0
        for index, char in enumerate(content):
            depth += char in "<(["
            depth -= char in ">)]" and depth > 0
            if char == "," and depth == 0:
                parts.append(content[start:index])
                start = index + 1
        parts.append(content[start:])
        return {match.group(1) for part in parts if (match := re.match(r"\s*(?:const\s+)?(\w+)", part))}

    def define(self, rel, offset, name, body, parameters=frozenset()):
        if self.excluded(rel):
            body = ""
        for scope in self.scopes(rel, offset):
            self.definitions[scope + (name,)].append((body, scope, rel, parameters))

    def _module_paths(self):
        """Propagate every module and include context without conflating shared files."""
        declarations = re.compile(
            r'(?:#\[path\s*=\s*"([^"\n]+)"\]\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;'
        )
        edges = []
        for rel, code in self.files.items():
            raw = (self.root / rel).read_text()
            parent = Path(rel).parent
            if Path(rel).stem not in {"lib", "main", "mod"}:
                parent /= Path(rel).stem
            for offset, child, expression in include_paths(self.root, rel, code, self.gate._contracts, self.gate.crate_of):
                if (rel, expression) in self.gate.ALLOWED_INCLUDES:
                    continue
                if child in self.bases:
                    edges.append((rel, offset, child, ()))
                else:
                    self.unresolved.add((rel, "include source " + (child or expression)))
            for match in declarations.finditer(raw):
                keyword = raw.rfind("mod", match.start(), match.end())
                if code[keyword:keyword + 3] != "mod":
                    continue
                inline = self.local_scope(rel, match.start())
                directory = parent.joinpath(*inline)
                if match.group(1):
                    directory = directory if inline else Path(rel).parent
                    candidates = [directory / match.group(1)]
                else:
                    candidates = [directory / (match.group(2) + ".rs"), directory / match.group(2) / "mod.rs"]
                for child in candidates:
                    child = posixpath.normpath(child.as_posix())
                    if child in self.bases:
                        edges.append((rel, match.start(), child, (match.group(2),)))
        incoming = {child for _, _, child, _ in edges}
        contexts = {rel: {base} if rel not in incoming else set() for rel, base in self.bases.items()}
        for _ in range(len(self.files) + 1):
            changed = False
            for rel, offset, child, suffix in edges:
                targets = {base + self.local_scope(rel, offset) + suffix for base in contexts[rel]}
                additions = targets - contexts[child]
                contexts[child].update(additions)
                changed |= bool(additions)
            if not changed:
                for rel, scopes in contexts.items():
                    if not scopes:
                        self.unresolved.add((rel, "cyclic module/include binding"))
                self.bases = contexts
                return
        raise ValueError("cyclic Rust module/include declarations")

    def local_scope(self, rel, offset):
        return tuple(name for a, b, name in self.spans[rel] if a < offset < b)

    def scopes(self, rel, offset):
        return {base + self.local_scope(rel, offset) for base in self.bases[rel]}

    @staticmethod
    def module(scope):
        return tuple(part for part in scope if not part.startswith("@"))

    def absolute(self, path, scope):
        module = self.module(scope)
        if path[0] == "crate":
            root = scope[:2] if len(scope) > 1 and scope[1].startswith(":bin:") else scope[:1]
            return root + path[1:]
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
        if path[0] in EXTERNAL_ROOTS or dependency is not None and not (isinstance(dependency, dict) and "path" in dependency):
            return (":external", external) + path[1:]
        return None

    def external_glob(self, path, scope):
        visited = set()
        while (path, scope) not in visited:
            visited.add((path, scope))
            current = scope
            while current:
                alias = self.imports[current].get(path[0])
                if alias:
                    path, scope = alias + path[1:], current
                    break
                if not current[-1].startswith("@"):
                    target = self.absolute(path, scope)
                    return bool(target and target[0] == ":external")
                current = current[:-1]
            else:
                return False
        return False

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
            if len(path) == 1 and path[0] in self.parameters[current]:
                return {(":parameter", *current, path[0])}
            key = current + path
            if key in self.definitions:
                return {key}
            alias = self.imports[current].get(path[0])
            edge = (("@use", path[0]), current)
            if alias and edge not in seen:
                seen.add(edge)
                return self.resolve(alias + path[1:], current, seen)
            if len(path) > 1 and current + path[:1] in self.modules:
                return self.lookup(key, seen)
            external = self.absolute(path, scope) if not current[-1].startswith("@") else None
            if external:
                return self.lookup(external, seen)
            found = self.lookup(key, seen)
            if found:
                return found
            found = set()
            for glob in self.globs[current]:
                if self.external_glob(glob, current):
                    continue
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
        if len(path) == 1 and path[0] in PRIMITIVES | PRELUDE_TYPES:
            return {(":prelude", path[0])}
        if len(path) == 1 and path[0] in self.gate.STRICT_TYPES:
            return {(":seed", path[-1])}
        return set()

    def lookup(self, key, seen):
        if key[0] == ":external":
            return {key}
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
        for split in range(len(key) - 1, 0, -1):
            scope, tail = key[:split], key[split:]
            if any(part.startswith("@") for part in tail) or scope + tail[:1] in self.modules:
                continue
            for glob in self.globs[scope]:
                if self.external_glob(glob, scope):
                    continue
                edge = (("*",) + glob, scope)
                if edge not in seen:
                    seen.add(edge)
                    found |= self.resolve(glob + tail, scope, seen)
        return found

    def excluded(self, rel):
        return any(rel == prefix + ".rs" or rel.startswith(prefix + "/") for prefix in self.gate.EXCLUDED_TYPE_MODULES)

    def references(self, text, scope, rel=None, parameters=frozenset()):
        found = set()
        text = self.without_attributes(text)
        text = re.sub(r"\'\w+|\b\w+\s*=(?!=)", " ", text)
        stack = []
        masked = list(text)
        for index, char in enumerate(text):
            if char == "[":
                stack.append(None)
            elif char == ";" and stack:
                stack[-1] = index
            elif char == "]" and stack:
                length = stack.pop()
                if length is not None:
                    masked[length:index] = " " * (index - length)
        text = "".join(masked)
        for match in PATH.finditer(text):
            path = tuple(x.strip() for x in match.group().split("::"))
            if len(path) == 1 and path[0] in parameters | {"mut", "dyn", "fn", "unsafe", "extern", "impl", "const", "_", "as", "for"}:
                continue
            marker = (path, scope)
            if marker not in self.resolve_cache:
                self.resolve_cache[marker] = self.resolve(path, scope)
            refs = self.resolve_cache[marker]
            if not refs and rel:
                exception = self.gate.ALLOWED_TYPE_PATHS.get((rel, "::".join(path)), "")
                if not self.excluded(rel) and not exception.strip():
                    self.unresolved.add((rel, "::".join(path)))
            found |= refs
        return found

    def mentions(self, text, rel, offset):
        if self.excluded(rel):
            return False
        references = [self.references(text, scope, rel) for scope in self.scopes(rel, offset)]
        return any(refs & self.strict for refs in references)
