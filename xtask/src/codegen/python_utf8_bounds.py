"""Enforce schema UTF-8 facets while retaining ordinary generated model identities.

The title-scoped generator output supplies pointer names, not implementations.
The ordinary/oracle class plan establishes exact correspondence. Unsupported
or ambiguous facets fail before any caller staging output is changed.
"""
from __future__ import annotations

import argparse
import ast
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import urllib.parse


MAX_INTEROPERABLE_INTEGER = 9007199254740991


def api_helper():
    path = Path(__file__).with_name("python_api_stability.py")
    spec = importlib.util.spec_from_file_location("chio_python_api_stability", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FacetError(ValueError):
    pass


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def pointer_tokens(pointer):
    if pointer == "#":
        return ()
    if not pointer.startswith("#/"):
        raise FacetError(f"unsupported schema anchor: {pointer}")
    tokens = pointer[2:].split("/")
    if any("~" in token.replace("~0", "").replace("~1", "") for token in tokens):
        raise FacetError(f"invalid JSON pointer escape: {pointer}")
    return tuple(token.replace("~1", "/").replace("~0", "~") for token in tokens)


def pointer_text(tokens):
    return "#" + "".join("/" + token.replace("~", "~0").replace("/", "~1") for token in tokens)


class Schemas:
    def __init__(self, root):
        self.root = root
        self.values = {path.relative_to(root).as_posix(): read_json(path) for path in sorted(root.rglob("*.schema.json"))}
        if not self.values:
            raise FacetError("empty schema mirror")
        self.ids = {value["$id"]: name for name, value in self.values.items() if "$id" in value}

    def node(self, schema, tokens):
        value = self.values[schema]
        try:
            for token in tokens:
                value = value[int(token)] if isinstance(value, list) else value[token]
        except (KeyError, IndexError, ValueError, TypeError) as error:
            raise FacetError(f"unresolved schema pointer: {schema}:{pointer_text(tokens)}") from error
        if isinstance(value, bool):
            return value
        if not isinstance(value, dict):
            raise FacetError(f"schema pointer is not an object: {schema}:{pointer_text(tokens)}")
        return value

    def reference(self, schema, reference):
        resource, fragment = urllib.parse.urldefrag(reference)
        if not resource:
            owner = schema
        elif resource in self.ids:
            owner = self.ids[resource]
        else:
            path = (self.root / schema).parent / resource
            try:
                owner = path.resolve().relative_to(self.root.resolve()).as_posix()
            except ValueError as error:
                raise FacetError("schema reference escapes the mirror") from error
        if owner not in self.values:
            raise FacetError(f"external schema reference is not mirrored: {reference}")
        return owner, pointer_tokens("#" + fragment)

    def bound(self, schema, tokens, active=()):
        key = schema, tokens
        if key in active:
            raise FacetError(f"cyclic byte-facet reference: {schema}:{pointer_text(tokens)}")
        node = self.node(schema, tokens)
        if isinstance(node, bool):
            return []
        result = []
        if "x-maxUtf8Bytes" in node:
            maximum = node["x-maxUtf8Bytes"]
            if type(maximum) is not int or not 1 <= maximum <= MAX_INTEROPERABLE_INTEGER:
                raise FacetError(f"invalid byte facet: {schema}:{pointer_text(tokens)}")
            result.append((maximum, key))
        if "$ref" in node:
            result += self.bound(*self.reference(schema, node["$ref"]), active + (key,))
        for index, _ in enumerate(node.get("allOf", [])):
            result += self.bound(schema, tokens + ("allOf", str(index)), active + (key,))
        return result

    def walk(self, schema, tokens=()):
        node = self.node(schema, tokens)
        if isinstance(node, bool):
            return
        yield tokens, node
        for keyword in ("properties", "patternProperties", "$defs", "definitions"):
            for name in node.get(keyword, {}):
                yield from self.walk(schema, tokens + (keyword, name))
        for keyword in ("oneOf", "anyOf", "allOf", "prefixItems"):
            for index, _ in enumerate(node.get(keyword, [])):
                yield from self.walk(schema, tokens + (keyword, str(index)))
        for keyword in ("items", "additionalProperties", "propertyNames", "not", "if", "then", "else"):
            if isinstance(node.get(keyword), dict):
                yield from self.walk(schema, tokens + (keyword,))


class Models:
    def __init__(self, root):
        self.root = root
        self.trees = {path.relative_to(root).as_posix(): ast.parse(path.read_text(), filename=str(path))
                      for path in sorted(root.rglob("*.py"))}
        self.classes = {}
        self.imports = {}
        for relative, tree in self.trees.items():
            imports = {}
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    key = relative, node.name
                    if key in self.classes:
                        raise FacetError(f"duplicate actual model class: {key}")
                    self.classes[key] = node
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        if alias.name == "*":
                            raise FacetError("star imports do not establish exact model bindings")
                        imports[alias.asname or alias.name] = (node.level, node.module or "", alias.name)
            self.imports[relative] = imports

    def resolve(self, relative, symbol):
        if "." in symbol:
            prefix, member = symbol.split(".", 1)
            item = self.imports[relative].get(prefix)
            if item and item[0]:
                level, module, imported = item
                parent = list(Path(relative).parent.parts)
                if level - 1 > len(parent):
                    raise FacetError("model import escapes generated tree")
                if level > 1:
                    parent = parent[:-(level - 1)]
                owner = "/".join(parent + ([part for part in module.split(".") if part]) + [imported]) + ".py"
                if (owner, member) in self.classes:
                    return owner, member
            raise FacetError(f"unresolved qualified actual model: {relative}:{symbol}")
        if (relative, symbol) in self.classes:
            return relative, symbol
        item = self.imports[relative].get(symbol)
        if item and item[0]:
            level, module, name = item
            parent = list(Path(relative).parent.parts)
            if level - 1 > len(parent):
                raise FacetError("model import escapes generated tree")
            if level > 1:
                parent = parent[:-(level - 1)]
            owner = "/".join(parent + module.split(".")) + ".py"
            if (owner, name) in self.classes:
                return owner, name
        raise FacetError(f"unresolved actual model binding: {relative}:{symbol}")

    def fields(self, binding, active=()):
        if binding in active:
            raise FacetError("cyclic generated class inheritance")
        node = self.classes[binding]
        result = []
        for base in node.bases:
            value = base.value if isinstance(base, ast.Subscript) else base
            if isinstance(value, ast.Name):
                try:
                    parent = self.resolve(binding[0], value.id)
                except FacetError:
                    if value.id not in {"BaseModel", "RootModel"} and value.id not in self.imports[binding[0]]:
                        raise
                else:
                    result += self.fields(parent, active + (binding,))
        for field in node.body:
            if not isinstance(field, ast.AnnAssign) or not isinstance(field.target, ast.Name):
                continue
            wire = field.target.id
            if isinstance(field.value, ast.Call):
                aliases = [keyword.value for keyword in field.value.keywords if keyword.arg == "alias"]
                if aliases:
                    if len(aliases) != 1 or not isinstance(aliases[0], ast.Constant) or not isinstance(aliases[0].value, str):
                        raise FacetError("unsupported generated field alias")
                    wire = aliases[0].value
            result = [item for item in result if item[0] != field.target.id]
            result.append((field.target.id, wire, binding[0], field.annotation))
        return result

    def is_root(self, binding, active=()):
        if binding in active:
            raise FacetError("cyclic generated RootModel inheritance")
        for base in self.classes[binding].bases:
            value = base.value if isinstance(base, ast.Subscript) else base
            if not isinstance(value, ast.Name):
                continue
            if self.imports[binding[0]].get(value.id) == (0, "pydantic", "RootModel"):
                return True
            try:
                parent = self.resolve(binding[0], value.id)
            except FacetError:
                continue
            if self.is_root(parent, active + (binding,)):
                return True
        return False

    def field(self, binding, wire):
        found = [item for item in self.fields(binding) if item[1] == wire]
        if len(found) != 1:
            raise FacetError(f"ambiguous or unmapped model field: {binding}:{wire}")
        return found[0]

    def string_kind(self, relative, annotation, scalar_bindings, active=()):
        if isinstance(annotation, ast.Name) and annotation.id == "str":
            return "string"
        if isinstance(annotation, ast.Call) and isinstance(annotation.func, ast.Name):
            imported = self.imports[relative].get(annotation.func.id)
            if annotation.func.id == "constr" or imported == (0, "pydantic", "constr"):
                return "string"
        if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
            branches = [item for item in (annotation.left, annotation.right)
                        if not (isinstance(item, ast.Constant) and item.value is None)]
            if len(branches) == 1:
                return self.string_kind(relative, branches[0], scalar_bindings, active)
        if isinstance(annotation, ast.Name):
            binding = self.resolve(relative, annotation.id)
            if binding in scalar_bindings:
                return "wrapped_string"
        raise FacetError(f"unsupported byte-facet field annotation: {relative}:{ast.unparse(annotation)}")


def discover_bindings(schema_root, raw_root, oracle_root, name_plan):
    """Resolve schema pointers through the same title annotations as the API oracle."""
    api = api_helper()
    if name_plan.get("format") != api.PLAN_FORMAT or not isinstance(name_plan.get("modules"), dict):
        raise FacetError("invalid ordinary/oracle name plan")
    schemas, models = Schemas(schema_root), Models(raw_root)
    raw, oracle = api.ApiTree(raw_root), api.ApiTree(oracle_root)
    oracle_models = Models(oracle_root)
    plans = name_plan["modules"]
    if set(plans) != {name for name in raw.modules if not name.endswith("__init__.py")}:
        raise FacetError("ordinary class plan does not match raw defining modules")
    for relative, mapping in plans.items():
        if relative not in oracle.modules or set(mapping) != set(raw.modules[relative].classes):
            raise FacetError(f"ordinary/oracle class inventory mismatch: {relative}")
    bindings, evidence = [], []
    for schema, source in schemas.values.items():
        relative = schema.removesuffix(".schema.json").replace("-", "_") + "_schema.py"
        if relative not in plans:
            if any("x-maxUtf8Bytes" in node for _, node in schemas.walk(schema)):
                raise FacetError(f"byte-facet schema has no ordinary defining module: {schema}")
            continue
        annotated = copy.deepcopy(source)
        api.annotate_schema(annotated, api.pascal(schema.removesuffix(".schema.json")))
        scoped_schema = copy.copy(schemas)
        scoped_schema.values = {**schemas.values, schema: annotated}
        for tokens, node in scoped_schema.walk(schema):
            is_object = "properties" in node
            is_scalar = bool(schemas.bound(schema, tokens)) and not is_object and (
                node.get("type") == "string" and (not tokens or len(tokens) == 2 and tokens[0] in {"$defs", "definitions"}))
            if not is_object and not is_scalar:
                continue
            title = node.get("title")
            if not title and is_scalar:
                title = api.pascal(tokens[-1]) if tokens else api.pascal(source.get("title", Path(schema).stem))
            if not title:
                continue
            scoped = oracle.modules[relative]
            target_names = [name for name in scoped.classes if name == title]
            if not target_names:
                target_names = [name for name in scoped.classes if name.startswith(title) and name[len(title):].isdigit()]
            candidates = set()
            for target in target_names:
                expected = set(node.get("properties", {}))
                if is_object and not expected <= {field[1] for field in oracle_models.fields((relative, target))}:
                    continue
                signature = scoped.signature(target, ignore_defaults=True)
                for actual, stable in plans[relative].items():
                    if raw.modules[relative].signature(actual, ignore_defaults=True) != signature:
                        continue
                    permitted = {target, api.module_prefix(relative) + target,
                                 target + "Referenced", api.module_prefix(relative) + target + "Referenced"}
                    if stable in permitted:
                        candidates.add(actual)
            if not candidates:
                continue
            # Multiple actual copies are allowed only when they are the named
            # ordinary/oracle copies of the same pointer. All stay distinct.
            for actual in sorted(candidates):
                binding = {"schema": schema, "pointer": pointer_text(tokens), "module": relative, "class": actual}
                bindings.append(binding)
                evidence.append({**binding, "oracle_title": title, "oracle_candidates": sorted(target_names),
                                 "stable_identity": relative + ":" + plans[relative][actual]})
    return {"format": "chio.python.schema-model-bindings.v1", "bindings": bindings}, evidence


def compile_plan(schema_root, model_root, bindings):
    schemas, models = Schemas(schema_root), Models(model_root)
    if bindings.get("format") != "chio.python.schema-model-bindings.v1":
        raise FacetError("invalid schema/model binding table")
    table = {}
    for item in bindings.get("bindings", []):
        key = item["schema"], pointer_tokens(item["pointer"])
        binding = item["module"], item["class"]
        if not isinstance(schemas.node(*key), dict):
            raise FacetError("boolean schema cannot bind to an actual generated model class")
        if binding not in models.classes or binding in table.get(key, []):
            raise FacetError(f"ambiguous or unmapped schema/model binding: {key}")
        table.setdefault(key, []).append(binding)
    owned_facets = {(schema, tokens) for schema in schemas.values for tokens, node in schemas.walk(schema)
                    if "x-maxUtf8Bytes" in node}
    if any(any(token in {"if", "then", "else", "not", "patternProperties", "prefixItems"}
               and (not index or tokens[index - 1] not in {"properties", "patternProperties", "$defs", "definitions"})
               for index, token in enumerate(tokens))
           for _, tokens in owned_facets):
        raise FacetError("conditional or patterned byte facets require an explicit supported mapping")
    scalar = {}
    operations, covered = {}, set()

    def add(binding, field, kind, bounds, pointer, key_model=None):
        if not bounds:
            return
        maximum = min(value for value, _ in bounds)
        key = binding + (field, kind)
        value = {"module": binding[0], "class": binding[1], "field": field, "kind": kind,
                 "maximum": maximum, "schema_locations": [source + ":" + pointer_text(tokens) for _, (source, tokens) in bounds],
                 "consumer_pointer": pointer}
        if key_model:
            if key_model[0] != binding[0]:
                raise FacetError("cross-module key models need an explicit supported import binding")
            value["key_model"] = key_model[1]
        if key in operations and operations[key] != value:
            raise FacetError(f"conflicting facet mappings: {key}")
        operations[key] = value
        covered.update(location for _, location in bounds)

    for key, model_bindings in table.items():
        node = schemas.node(*key)
        bounds = schemas.bound(*key)
        if bounds:
            if node.get("type") != "string":
                raise FacetError(f"non-string scalar facet mapping: {key}")
            for binding in model_bindings:
                if not models.is_root(binding):
                    raise FacetError(f"scalar byte facet is not backed by an ordinary RootModel: {binding}")
                field, _, relative, annotation = models.field(binding, "root")
                if models.string_kind(relative, annotation, {}) != "string":
                    raise FacetError("scalar byte facet is not backed by an ordinary string RootModel")
                scalar[binding] = min(value for value, _ in bounds)
                add(binding, field, "string", bounds, key[0] + ":" + pointer_text(key[1]))
    for (schema, tokens), model_bindings in table.items():
        node = schemas.node(schema, tokens)
        for binding in model_bindings:
          for wire, property_schema in node.get("properties", {}).items():
            if isinstance(property_schema, bool):
                continue
            location = tokens + ("properties", wire)
            bounds = schemas.bound(schema, location)
            if bounds:
                field, _, owner, annotation = models.field(binding, wire)
                kind = models.string_kind(owner, annotation, scalar)
                add(binding, field, kind, bounds, schema + ":" + pointer_text(location))
            keys = property_schema.get("propertyNames")
            if keys is not None:
                key_location = location + ("propertyNames",)
                key_bounds = schemas.bound(schema, key_location)
                if not key_bounds:
                    continue
                field, _, owner, annotation = models.field(binding, wire)
                if not (isinstance(annotation, ast.Subscript) and isinstance(annotation.value, ast.Name)
                        and annotation.value.id == "dict" and isinstance(annotation.slice, ast.Tuple)
                        and isinstance(annotation.slice.elts[0], ast.Name) and annotation.slice.elts[0].id == "str"):
                    raise FacetError("owner-key byte facet is not backed by dict[str, ...]")
                key_models = table.get(schemas.reference(schema, keys["$ref"]), []) if "$ref" in keys else []
                key_model = key_models[0] if len(key_models) == 1 else None
                if "$ref" in keys and key_model not in scalar:
                    raise FacetError("propertyNames string reference has no exact validated scalar binding")
                add(binding, field, "keys", key_bounds, schema + ":" + pointer_text(key_location), key_model)
    missing = owned_facets - covered
    if missing:
        raise FacetError("unmapped UTF-8 facets: " + ", ".join(schema + ":" + pointer_text(tokens) for schema, tokens in sorted(missing)))
    return {"format": "chio.python.utf8-facet-plan.v1", "operations": list(operations.values()),
            "covered_facet_count": len(covered), "source_facet_count": len(owned_facets)}, models


def validator(operation):
    field, maximum, kind = operation["field"], operation["maximum"], operation["kind"]
    suffix = "keys_" if kind == "keys" else ""
    name = f"_require_{field}_{suffix}utf8_bytes"
    if kind == "keys":
        check = "        for key in value:\n"
        if "key_model" in operation:
            check += f"            {operation['key_model']}.model_validate(key)\n"
        check += f"            _require_utf8_bound(key, {maximum})\n"
        body = "    if value is not None:\n" + check
    elif kind == "wrapped_string":
        body = f"    if value is not None:\n        _require_utf8_bound(value.root, {maximum})\n"
    else:
        body = f"    if isinstance(value, str):\n        _require_utf8_bound(value, {maximum})\n"
    level = len(Path(operation["module"]).parent.parts) + 2
    local_import = "    from " + "." * level + "recovery_wire import require_utf8_bound as _require_utf8_bound\n"
    source = f"@_facet_field_validator({field!r}, mode='after')\n@classmethod\ndef {name}(cls, value: object) -> object:\n" + local_import + body + "    return value\n"
    return ast.parse(source).body[0]


def apply(schema_root, model_root, bindings, report=None, binding_evidence=None):
    if report and any(report.resolve().is_relative_to(root.resolve()) for root in (schema_root, model_root)):
        raise FacetError("UTF-8 report must be outside the schema and generated model trees")
    plan, models = compile_plan(schema_root, model_root, bindings)
    trees = copy.deepcopy(models.trees)
    reserved = {"_facet_field_validator"}
    for relative in {operation["module"] for operation in plan["operations"]}:
        for node in models.trees[relative].body:
            names = set()
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names.update(child.id for target in targets for child in ast.walk(target) if isinstance(child, ast.Name))
            if names & reserved:
                raise FacetError(f"UTF-8 helper binding would overwrite existing source: {relative}")
    added = {}
    for operation in plan["operations"]:
        relative, name = operation["module"], operation["class"]
        model = next(node for node in trees[relative].body if isinstance(node, ast.ClassDef) and node.name == name)
        method = validator(operation)
        bound = set()
        for node in model.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                bound.update(child.id for target in targets for child in ast.walk(target) if isinstance(child, ast.Name))
        if bound & (reserved | {method.name}):
            raise FacetError("model class binding would shadow this UTF-8 validator")
        model.body.append(method)
        added.setdefault((relative, name), set()).add(method.name)
    for relative in {operation["module"] for operation in plan["operations"]}:
        imports = ast.parse("from pydantic import field_validator as _facet_field_validator\n").body
        tree = trees[relative]
        insertion = next((index for index, node in enumerate(tree.body) if isinstance(node, ast.ClassDef)), len(tree.body))
        tree.body[insertion:insertion] = imports
    bodies = 0
    for relative, tree in trees.items():
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            key = relative, node.name
            stripped = copy.deepcopy(node)
            stripped.body = [item for item in stripped.body if not (isinstance(item, ast.FunctionDef) and item.name in added.get(key, set()))]
            if ast.dump(stripped, include_attributes=False) != ast.dump(models.classes[key], include_attributes=False):
                raise FacetError(f"UTF-8 hardening changed an existing class body: {key}")
            bodies += 1
    if bodies != len(models.classes):
        raise FacetError("UTF-8 hardening changed actual class inventory")
    changed = {}
    for relative in {operation["module"] for operation in plan["operations"]}:
        tree = trees[relative]
        source = (model_root / relative).read_text(encoding="utf-8")
        header = []
        for line in source.splitlines():
            if line.startswith("#") or not line.strip():
                header.append(line)
            else:
                break
        changed[relative] = "\n".join(header).rstrip() + "\n\n" + ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    plan["preserved_class_bodies_excluding_intended_validators"] = bodies
    plan["field_annotations_changed"] = 0
    plan["class_declarations_added_or_removed"] = 0
    plan["changed_modules"] = sorted(changed)
    if binding_evidence is not None:
        plan["binding_evidence"] = binding_evidence
    report_temporary = None
    if report:
        if report.exists() and not report.is_file():
            raise FacetError("UTF-8 report destination is not a file")
        report.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix="chio-utf8-report-", dir=report.parent)
        report_temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    with tempfile.TemporaryDirectory(prefix="chio-utf8-bounds-", dir=model_root.parent) as temporary:
        staging = Path(temporary)
        for relative, source in changed.items():
            destination = staging / "new" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(source, encoding="utf-8")
            ast.parse(source, filename=relative)
            backup = staging / "old" / relative
            backup.parent.mkdir(parents=True, exist_ok=True)
            backup.write_bytes((model_root / relative).read_bytes())
        # No writes precede complete discovery and all AST invariant checks.
        committed = []
        try:
            for relative in sorted(changed):
                os.replace(staging / "new" / relative, model_root / relative)
                committed.append(relative)
            if report_temporary:
                os.replace(report_temporary, report)
        except OSError:
            for relative in reversed(committed):
                os.replace(staging / "old" / relative, model_root / relative)
            raise
        finally:
            if report_temporary and report_temporary.exists():
                report_temporary.unlink()
    return plan


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema-dir", type=Path, required=True)
    parser.add_argument("--models-dir", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--oracle-dir", type=Path, required=True)
    parser.add_argument("--name-plan", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        if args.report and any(args.report.resolve().is_relative_to(root.resolve())
                               for root in (args.raw_dir, args.oracle_dir)):
            raise FacetError("UTF-8 report must be outside immutable ordinary and oracle trees")
        if args.report and args.report.resolve() == args.name_plan.resolve():
            raise FacetError("UTF-8 report cannot overwrite the class binding plan")
        bindings, evidence = discover_bindings(args.schema_dir, args.raw_dir, args.oracle_dir, read_json(args.name_plan))
        apply(args.schema_dir, args.models_dir, bindings, args.report, evidence)
    except (FacetError, OSError, SyntaxError, ValueError) as error:
        parser.exit(2, f"Python UTF-8 bounds refused: {error}\n")
