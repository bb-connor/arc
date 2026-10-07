#!/usr/bin/env python3
"""Stable generated model bindings using only public Python AST and generator CLI.

The ordinary generator tree supplies the model implementations. A second,
title-scoped generator tree supplies names only. Existing hardeners run before
``apply``. Compatibility approvals bind complete records and SDK versions.
"""
from __future__ import annotations

import argparse
import ast
import copy
from functools import cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import SimpleNamespace


_DEPENDENCY_SPEC = importlib.util.spec_from_file_location(
    "chio_python_enforcement_dependencies", Path(__file__).with_name("python_enforcement_dependencies.py"))
enforcement = importlib.util.module_from_spec(_DEPENDENCY_SPEC)
_DEPENDENCY_SPEC.loader.exec_module(enforcement)


FORMAT = "chio.sdk.python.generated-api.v1"
PLAN_FORMAT = "chio.sdk.python.model-bindings.v1"
COMPATIBILITY_FORMAT = "chio.sdk.python.generated-api-compatibility.v1"


class StabilityError(ValueError):
    pass


def read_json(path: Path):
    with path.open("rb") as stream:
        body = stream.read(32 * 1024 * 1024 + 1)
    if len(body) > 32 * 1024 * 1024:
        raise StabilityError("API JSON input exceeds the source ceiling")
    return json.loads(body)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def canonical_ast(value):
    if isinstance(value, ast.AST):
        return {"kind": type(value).__name__, **{
            field: canonical_ast(child) for field, child in ast.iter_fields(value)
            if not (field == "type_params" and not child)
        }}
    if isinstance(value, list):
        return [canonical_ast(child) for child in value]
    if value is Ellipsis:
        return {"constant": "ellipsis"}
    if isinstance(value, bytes):
        return {"constant": "bytes", "hex": value.hex()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise StabilityError(f"unsupported AST constant {type(value).__name__}")


def pascal(value: str) -> str:
    result = "".join(part[:1].upper() + part[1:] for part in re.findall(r"[A-Za-z0-9]+", value))
    if not result:
        raise StabilityError(f"schema path has no usable name segment: {value!r}")
    return result


def module_prefix(relative: str) -> str:
    return pascal(relative.removesuffix("_schema.py"))


def branch_name(value, index):
    if not isinstance(value, dict):
        raise StabilityError("non-object schema union branch")
    for key in ("kind", "type", "verdict", "status", "state", "stage"):
        field = value.get("properties", {}).get(key, {})
        if "const" in field:
            return pascal(str(field["const"]))
        if len(field.get("enum", [])) == 1:
            return pascal(str(field["enum"][0]))
    return f"Variant{index}"


def annotate_schema(value, prefix, path=()):
    if not isinstance(value, dict):
        return
    if "title" in value:
        value["title"] = pascal(value["title"])
    class_shape = "properties" in value or len(value.get("enum", [])) > 1 or "oneOf" in value or "anyOf" in value
    if path and "$ref" not in value and class_shape and "title" not in value:
        value["title"] = prefix + "".join(path)
    for keyword in ("properties", "patternProperties", "$defs", "definitions"):
        for name, child in value.get(keyword, {}).items():
            segment = (("Definitions",) if keyword in ("$defs", "definitions") else ()) + (pascal(name),)
            annotate_schema(child, prefix, path + segment)
    for keyword in ("oneOf", "anyOf", "allOf", "prefixItems"):
        for index, child in enumerate(value.get(keyword, [])):
            annotate_schema(child, prefix, path + (branch_name(child, index),))
    for keyword in ("items", "additionalProperties", "not", "if", "then", "else"):
        if isinstance(value.get(keyword), dict):
            annotate_schema(value[keyword], prefix, path + (pascal(keyword),))


def annotate(input_dir: Path, output_dir: Path):
    if input_dir.resolve() == output_dir.resolve() or output_dir.exists():
        raise StabilityError("scoped mirror must be a new directory distinct from the input")
    files = sorted(input_dir.rglob("*.schema.json"))
    if not files:
        raise StabilityError("ordinary schema mirror is empty")
    for source in files:
        relative = source.relative_to(input_dir)
        value = read_json(source)
        annotate_schema(value, pascal(relative.as_posix().removesuffix(".schema.json")))
        destination = output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def resolve_import_path(relative: str, level: int, module: str | None) -> str:
    parent = list(Path(relative).parent.parts)
    if level - 1 > len(parent):
        raise StabilityError(f"relative import escapes generated tree in {relative}")
    if level > 1:
        parent = parent[:-(level - 1)]
    return "/".join(parent + (module or "").split(".")).strip("/")


class ScopeAwareTransformer(ast.NodeTransformer):
    """Visit type expressions and runtime bindings without rewriting wire data."""
    def __init__(self, module):
        self.module = module
        self.shadowed = [set()]
        self.annotation_depth = 0

    def is_shadowed(self, name):
        return any(name in scope for scope in self.shadowed)

    def annotation(self, node):
        if node is None:
            return None
        self.annotation_depth += 1
        try:
            return self.visit(node)
        finally:
            self.annotation_depth -= 1

    def ordinary_expression(self, node):
        depth, self.annotation_depth = self.annotation_depth, 0
        try:
            return self.visit(node)
        finally:
            self.annotation_depth = depth

    def class_body(self, node):
        rebound, result = set(), []
        for statement in node.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                runtime = statement.decorator_list + statement.args.defaults + [item for item in statement.args.kw_defaults if item]
            elif isinstance(statement, (ast.Assign, ast.AnnAssign, ast.Expr)):
                runtime = [statement.value] if statement.value is not None else []
            elif isinstance(statement, ast.Pass):
                runtime = []
            else:
                raise StabilityError(f"unsupported class namespace statement in {self.module.relative}")
            used = {child.id for expression in runtime for child in ast.walk(expression)
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)}
            if used & rebound:
                raise StabilityError(f"class namespace shadows a generated model binding in {self.module.relative}")
            result.append(self.visit(statement))
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target] if isinstance(statement, ast.AnnAssign) and statement.value is not None else []
            rebound.update(child.id for target in targets for child in ast.walk(target)
                           if isinstance(child, ast.Name) and child.id in self.module.references)
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)) and statement.name in self.module.references:
                rebound.add(statement.name)
        return result

    def typing_form(self, node):
        if isinstance(node, ast.Name) and not self.is_shadowed(node.id):
            imported = self.module.external.get(node.id, "")
            if imported.startswith("typing.") or imported.startswith("typing_extensions."):
                return imported.rsplit(".", 1)[1]
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and not self.is_shadowed(node.value.id):
            if self.module.external.get(node.value.id) in {"typing", "typing_extensions"}:
                return node.attr
        return ""

    def visit_AnnAssign(self, node):
        # A field target may deliberately equal a model's name. It is wire data.
        node.annotation = self.annotation(node.annotation)
        if node.value is not None:
            node.value = self.visit(node.value)
        return node

    def visit_FunctionDef(self, node):
        if getattr(node, "type_params", []):
            raise StabilityError(f"generic function parameters are unsupported in {self.module.relative}")
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            argument.annotation = self.annotation(argument.annotation)
        for argument in (node.args.vararg, node.args.kwarg):
            if argument:
                argument.annotation = self.annotation(argument.annotation)
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        node.args.kw_defaults = [self.visit(item) if item else None for item in node.args.kw_defaults]
        node.returns = self.annotation(node.returns)
        self.shadowed.append(bound_names(node))
        try:
            node.body = [self.visit(item) for item in node.body]
        finally:
            self.shadowed.pop()
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Global(self, node):
        raise StabilityError(f"global declaration is unsupported in {self.module.relative}")

    def visit_Nonlocal(self, node):
        raise StabilityError(f"nonlocal declaration is unsupported in {self.module.relative}")

    def visit_Match(self, node):
        raise StabilityError(f"pattern binding is unsupported in {self.module.relative}")

    def visit_Lambda(self, node):
        node.args.defaults = [self.visit(item) for item in node.args.defaults]
        node.args.kw_defaults = [self.visit(item) if item else None for item in node.args.kw_defaults]
        names = {argument.arg for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs}
        if node.args.vararg:
            names.add(node.args.vararg.arg)
        if node.args.kwarg:
            names.add(node.args.kwarg.arg)
        self.shadowed.append(names)
        try:
            node.body = self.visit(node.body)
        finally:
            self.shadowed.pop()
        return node

    def visit_ListComp(self, node):
        node.generators[0].iter = self.visit(node.generators[0].iter)
        self.shadowed.append(set())
        try:
            for index, generator in enumerate(node.generators):
                if index:
                    generator.iter = self.visit(generator.iter)
                self.shadowed[-1].update(child.id for child in ast.walk(generator.target) if isinstance(child, ast.Name))
                generator.ifs = [self.visit(item) for item in generator.ifs]
            if isinstance(node, ast.DictComp):
                node.key, node.value = self.visit(node.key), self.visit(node.value)
            else:
                node.elt = self.visit(node.elt)
        finally:
            self.shadowed.pop()
        return node

    visit_SetComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp
    visit_DictComp = visit_ListComp

    def visit_Subscript(self, node):
        form = self.typing_form(node.value)
        if self.annotation_depth and form == "Literal":
            node.value = self.visit(node.value)
            node.slice = self.ordinary_expression(node.slice)
            return node
        if self.annotation_depth and form == "Annotated":
            if not isinstance(node.slice, ast.Tuple) or len(node.slice.elts) < 2:
                raise StabilityError(f"unsupported Annotated form in {self.module.relative}")
            node.value = self.visit(node.value)
            node.slice.elts = [self.visit(node.slice.elts[0])] + [self.ordinary_expression(item) for item in node.slice.elts[1:]]
            return node
        return self.generic_visit(node)

    def visit_Constant(self, node):
        if self.annotation_depth and isinstance(node.value, str):
            try:
                expression = ast.parse(node.value, mode="eval")
            except SyntaxError as error:
                raise StabilityError(f"unsupported string annotation in {self.module.relative}: {node.value!r}") from error
            expression.body = self.visit(expression.body)
            node.value = ast.unparse(ast.fix_missing_locations(expression.body))
        return node

    def visit_Call(self, node):
        if self.annotation_depth and self.typing_form(node.func) == "ForwardRef":
            if len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                raise StabilityError(f"unsupported ForwardRef form in {self.module.relative}")
            node.args[0] = self.visit(node.args[0])
            node.func = self.visit(node.func)
            return node
        # Arguments to constrained types and Field are runtime data. Only
        # explicit ForwardRef accepts a quoted annotation inside a call.
        return self.ordinary_call(node)

    def ordinary_call(self, node):
        node.func = self.visit(node.func)
        node.args = [self.ordinary_expression(item) for item in node.args]
        node.keywords = [self.ordinary_expression(item) for item in node.keywords]
        return node


class ModelModule:
    def __init__(self, relative: str, source: str, tree=None):
        self.relative = relative
        self.source = source
        self.tree = tree if tree is not None else ast.parse(source, filename=relative)
        self.classes = {node.name: node for node in self.tree.body if isinstance(node, ast.ClassDef)}
        if len(self.classes) != sum(isinstance(node, ast.ClassDef) for node in self.tree.body):
            raise StabilityError(f"duplicate actual class declaration in {relative}")
        self.namespace, self.aliases, self.explicit_all = self.account_namespace()
        for name in self.classes:
            if self.namespace.get(name) != (relative, name, "class"):
                raise StabilityError(f"actual class binding is overwritten in {relative}:{name}")
        self.imported = {name for name, binding in self.namespace.items() if binding[2] == "import"}
        self.references = set(self.classes) | {name for name, binding in self.namespace.items()
                                                if binding[2] in {"class", "import"}}
        self.external = {name: binding[1] for name, binding in self.namespace.items() if binding[2] == "external"}

    def account_namespace(self):
        """Account for every supported module binding in execution order.

        Value and function bindings cannot resolve as model classes. Aliases
        capture the existing binding at their assignment, as Python does.
        Dynamic module execution is outside the generated-source contract.
        """
        namespace, aliases, explicit_all, consumed = {}, [], None, set()

        def bind(name, value):
            if name == "SCHEMA_SHA256" and value[2] != "value":
                raise StabilityError(f"schema digest cannot be rebound as a model or dependency in {self.relative}")
            previous = namespace.get(name)
            if previous and name in consumed and previous != value:
                raise StabilityError(f"model declaration dependency is rebound in {self.relative}:{name}")
            if previous and previous[2] == "external" and previous != value:
                raise StabilityError(f"external dependency binding is overwritten in {self.relative}:{name}")
            namespace[name] = value

        def static_value(value):
            try:
                ast.literal_eval(value)
                return
            except (ValueError, TypeError):
                pass
            if (isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                    and isinstance(value.func.value, ast.Name) and value.func.attr == "compile"
                    and namespace.get(value.func.value.id) == ("", "re", "external")
                    and not value.keywords and len(value.args) == 1
                    and isinstance(value.args[0], ast.Constant) and isinstance(value.args[0].value, str)):
                return
            raise StabilityError(f"dynamic module assignment is unsupported in {self.relative}")

        for node in self.tree.body:
            if isinstance(node, ast.ClassDef):
                if node.decorator_list or node.keywords:
                    raise StabilityError(f"generated class decorators or metaclass keywords are unsupported in {self.relative}")
                if node.name in namespace:
                    raise StabilityError(f"model declaration shadows a preceding binding in {self.relative}:{node.name}")
                bind(node.name, (self.relative, node.name, "class"))
                context = copy.copy(self)
                context.references = {name for name, binding in namespace.items() if binding[2] in {"class", "import"}}
                context.imported = {name for name, binding in namespace.items() if binding[2] == "import"}
                context.external = {name: binding[1] for name, binding in namespace.items() if binding[2] == "external"}
                used = set()

                class Dependencies(ScopeAwareTransformer):
                    def visit_ClassDef(self, declaration):
                        declaration.decorator_list = [self.visit(item) for item in declaration.decorator_list]
                        declaration.bases = [self.visit(item) for item in declaration.bases]
                        declaration.keywords = [self.visit(item) for item in declaration.keywords]
                        declaration.body = self.class_body(declaration)
                        return declaration

                    def visit_Name(self, reference):
                        if isinstance(reference.ctx, ast.Load) and not self.is_shadowed(reference.id):
                            used.add(reference.id)
                        return reference

                Dependencies(context).visit(copy.deepcopy(node))
                consumed.update(used & context.references)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.decorator_list or node.args.defaults or any(node.args.kw_defaults):
                    raise StabilityError(f"module function executes unsupported namespace expressions in {self.relative}")
                bind(node.name, (self.relative, node.name, "function"))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    bind(name, ("", alias.name if alias.asname else alias.name.split(".")[0], "external"))
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        raise StabilityError(f"star import cannot resolve exact public identities in {self.relative}")
                    name = alias.asname or alias.name
                    value = ((resolve_import_path(self.relative, node.level, node.module), alias.name, "import")
                             if node.level else ("", (node.module or "") + "." + alias.name, "external"))
                    bind(name, value)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if not targets or any(not isinstance(target, ast.Name) for target in targets):
                    raise StabilityError(f"dynamic module assignment target is unsupported in {self.relative}")
                if node.value is None:
                    continue
                if any(target.id == "SCHEMA_SHA256" for target in targets) and not (
                        isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                    raise StabilityError(f"schema digest must be literal string metadata in {self.relative}")
                if any(target.id == "__all__" for target in targets):
                    if len(targets) != 1:
                        raise StabilityError(f"multiple-target __all__ is unsupported in {self.relative}")
                    try:
                        explicit_all = ast.literal_eval(node.value)
                    except (ValueError, TypeError) as error:
                        raise StabilityError(f"non-literal __all__ in {self.relative}") from error
                    if not isinstance(explicit_all, list) or any(not isinstance(name, str) for name in explicit_all):
                        raise StabilityError(f"non-literal __all__ in {self.relative}")
                    bind("__all__", (self.relative, "__all__", "value"))
                elif isinstance(node.value, ast.Name):
                    if node.value.id not in namespace:
                        raise StabilityError(f"unresolved module alias in {self.relative}:{node.value.id}")
                    value = namespace[node.value.id]
                    for target in targets:
                        bind(target.id, value)
                        if value[2] in {"class", "import"}:
                            aliases.append(target.id)
                else:
                    static_value(node.value)
                    for target in targets:
                        bind(target.id, (self.relative, target.id, "value"))
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                continue
            elif isinstance(node, ast.Pass):
                continue
            else:
                raise StabilityError(f"unsupported module namespace statement {type(node).__name__} in {self.relative}")
        return namespace, aliases, explicit_all

    def normalized(self, name, reference_names=None, ignore_defaults=False):
        references, imported, external = self.references, self.imported, self.external

        class Normalize(ScopeAwareTransformer):
            def visit_ClassDef(self, node):
                node.name = "Model"
                node.decorator_list = [self.visit(item) for item in node.decorator_list]
                node.bases = [self.visit(item) for item in node.bases]
                node.keywords = [self.visit(item) for item in node.keywords]
                node.body = self.class_body(node)
                node.body = [child for child in node.body if not (
                    isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant)
                    and isinstance(child.value.value, str)
                )]
                return node

            def visit_Name(self, node):
                if not isinstance(node.ctx, ast.Load):
                    return node
                if self.is_shadowed(node.id):
                    return node
                if node.id in references:
                    node.id = reference_names(node.id) if reference_names else "ModelReference"
                elif node.id in external:
                    node.id = "External_" + external[node.id].replace(".", "_")
                return node

            def visit_Attribute(self, node):
                if (isinstance(node.value, ast.Name) and node.value.id in imported and node.attr[:1].isupper()
                        and not self.is_shadowed(node.value.id)):
                    symbol = node.value.id + "." + node.attr
                    return ast.Name(id=reference_names(symbol) if reference_names else "ModelReference", ctx=ast.Load())
                return self.generic_visit(node)

            def visit_Call(self, node):
                node = super().visit_Call(node)
                if isinstance(node.func, ast.Name) and node.func.id in {"Field", "External_pydantic_Field"}:
                    node.keywords = [keyword for keyword in node.keywords if keyword.arg not in {"title", "description"}]
                return node

            def visit_AnnAssign(self, node):
                node = super().visit_AnnAssign(node)
                value = node.value
                if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                        and value.func.id in {"Field", "External_pydantic_Field"}
                        and not value.keywords and len(value.args) == 1):
                    node.value = None if isinstance(value.args[0], ast.Constant) and value.args[0].value is Ellipsis else value.args[0]
                if ignore_defaults:
                    node.value = None
                return node

        return Normalize(self).visit(copy.deepcopy(self.classes[name]))

    def signature(self, name, reference_names=None, ignore_defaults=False):
        return json.dumps(canonical_ast(self.normalized(name, reference_names, ignore_defaults)), sort_keys=True, separators=(",", ":"))

    def class_references(self, name):
        node = self.normalized(name, lambda value: value)
        return [child.id for child in ast.walk(node) if isinstance(child, ast.Name)
                and isinstance(child.ctx, ast.Load) and child.id in self.references]


class ApiTree:
    def __init__(self, root: Path, identities=None, *, sdk_root=None, limits=None):
        self.root = root
        self.identities = identities or {}
        self.sdk_root = sdk_root if sdk_root is not None else (root.parent if root.name == "_generated" else None)
        self.dependency_budget = enforcement.Budget(limits)
        self.modules = {}
        for path in sorted(root.rglob("*.py")):
            body, tree = self.dependency_budget.source(path)
            relative = str(path.relative_to(root))
            self.modules[relative] = ModelModule(relative, body.decode("utf-8"), tree)
        self._enforcement_inventory = None
        if not self.modules:
            raise StabilityError("generated Python tree is empty")
        self.validate_import_graph()
        self.namespaces = {}
        self.public = {}
        for relative, module in self.modules.items():
            namespace = {}
            for name, (owner, symbol, kind) in module.namespace.items():
                if kind == "import":
                    owner = owner + ".py" if owner + ".py" in self.modules else owner + "/__init__.py"
                    kind = "ref"
                namespace[name] = owner, symbol, kind
            self.namespaces[relative] = namespace
            self.public[relative] = module.explicit_all if module.explicit_all is not None else list(module.classes) + module.aliases

    def validate_import_graph(self):
        """Generated bindings cannot depend on partial module initialization."""
        edges = {relative: set() for relative in self.modules}
        for relative, module in self.modules.items():
            for node in module.tree.body:
                if not isinstance(node, ast.ImportFrom) or not node.level:
                    continue
                owner = resolve_import_path(relative, node.level, node.module)
                for alias in node.names:
                    child = str(Path(owner) / alias.name)
                    candidates = ([child + ".py", str(Path(child) / "__init__.py")]
                                  if not node.module else [])
                    candidates += [owner + ".py", str(Path(owner) / "__init__.py")]
                    target = next((path for path in candidates if path in self.modules), None)
                    if target is None:
                        raise StabilityError(f"unresolved generated import in {relative}:{alias.name}")
                    package = Path(target).parent
                    parent = Path(relative).parent
                    if target == relative or (Path(target).name == "__init__.py"
                                              and (package == parent or package in parent.parents)):
                        raise StabilityError(f"generated import uses a partial self or ancestor namespace in {relative}")
                    edges[relative].add(target)
        pending = {relative: len(targets) for relative, targets in edges.items()}
        importers = {relative: set() for relative in edges}
        for relative, targets in edges.items():
            for target in targets:
                importers[target].add(relative)
        ready = [relative for relative, count in pending.items() if not count]
        checked = 0
        while ready:
            target = ready.pop()
            checked += 1
            for relative in importers[target]:
                pending[relative] -= 1
                if not pending[relative]:
                    ready.append(relative)
        if checked != len(edges):
            raise StabilityError("generated module import cycle is unsupported")

    def resolve(self, relative, name, active=()):
        if "." in name:
            prefix, member = name.split(".", 1)
            imported = self.namespaces.get(relative, {}).get(prefix)
            if imported and imported[2] == "ref":
                owner, symbol, _ = imported
                module = str(Path(owner).parent / (symbol + ".py"))
                if module in self.modules:
                    return self.resolve(module, member, active)
        key = relative, name
        if key in active:
            raise StabilityError(f"cyclic export alias: {relative}:{name}")
        binding = self.namespaces.get(relative, {}).get(name)
        if binding is None:
            raise StabilityError(f"unresolved export: {relative}:{name}")
        module, symbol, kind = binding
        if kind == "class":
            return module, symbol
        if kind != "ref":
            raise StabilityError(f"export is not an actual generated model class: {relative}:{name}")
        return self.resolve(module, symbol, active + (key,))

    def binding_descriptors(self):
        """Resolve nominal public identities without traversing class shapes."""
        exports = {}
        for relative, names in sorted(self.public.items()):
            for name in sorted(set(names)):
                if name.startswith("_") or name == "SCHEMA_SHA256":
                    continue
                module, actual = self.resolve(relative, name)
                nominal = self.identities.get((module, actual), module + ":" + actual)
                owner, stable = nominal.rsplit(":", 1)
                exports[relative + ":" + name] = {"module": owner, "class": stable, "contract": nominal}
        return exports

    def enforcement_inventory(self):
        if self._enforcement_inventory is None:
            interfaces = SimpleNamespace(ApiTree=ApiTree, ScopeAwareTransformer=ScopeAwareTransformer,
                                         canonical_ast=canonical_ast)
            checker = enforcement.Dependencies(self.root, api=interfaces, tree=self, sdk_root=self.sdk_root,
                                               budget=self.dependency_budget)
            inventory = checker.inventory(self.binding_descriptors())
            # A direct fingerprint call can select a private defining class.
            # Bound those roots too, before any legacy recursive traversal.
            for relative, module in self.modules.items():
                for name in module.classes:
                    checker.contract((relative, name))
            self._enforcement_inventory = inventory
        return self._enforcement_inventory

    @cache
    def fingerprint(self, binding, active=()):
        self.enforcement_inventory()
        relative, name = binding
        identity = self.identities.get(binding, relative + ":" + name)
        if binding in active:
            return "recursive:" + identity

        def reference(symbol):
            dependency = self.resolve(relative, symbol)
            nominal = self.identities.get(dependency, dependency[0] + ":" + dependency[1])
            return "Contract_" + nominal + "_Shape_" + self.fingerprint(dependency, active + (binding,))

        return hashlib.sha256(self.modules[relative].signature(name, reference).encode()).hexdigest()

    def inventory(self):
        self.enforcement_inventory()
        exports = {}
        for relative, names in sorted(self.public.items()):
            for name in sorted(set(names)):
                if name.startswith("_") or name == "SCHEMA_SHA256":
                    continue
                module, actual = self.resolve(relative, name)
                nominal = self.identities.get((module, actual), module + ":" + actual)
                owner, stable = nominal.rsplit(":", 1)
                exports[relative + ":" + name] = {"module": owner, "class": stable,
                                                   "contract": nominal,
                                                   "fingerprint": self.fingerprint((module, actual))}
        return exports


def validate_baseline(value):
    if (not isinstance(value, dict) or value.get("format") != FORMAT
            or not isinstance(value.get("sdk_version"), str) or not isinstance(value.get("exports"), dict)):
        raise StabilityError("invalid generated API baseline format")
    for export, binding in value["exports"].items():
        if (not isinstance(export, str) or ":" not in export or not isinstance(binding, dict)
                or set(binding) != {"module", "class", "contract", "fingerprint"}
                or any(not isinstance(item, str) for item in binding.values())):
            raise StabilityError(f"invalid protected binding: {export}")
        relative, name = export.rsplit(":", 1)
        if (not name.isidentifier() or not binding["class"].isidentifier()
                or any(Path(path).is_absolute() or ".." in Path(path).parts or not path.endswith(".py")
                       for path in (relative, binding["module"]))):
            raise StabilityError(f"invalid protected module path or class name: {export}")
        if binding["contract"] != binding["module"] + ":" + binding["class"]:
            raise StabilityError(f"inconsistent protected identity: {export}")
        if not re.fullmatch(r"[0-9a-f]{64}", binding["fingerprint"]):
            raise StabilityError(f"invalid protected fingerprint: {export}")
    return value


def compatibility_violations(baseline, candidate, compatibility, sdk_version):
    validate_baseline(baseline)
    if not isinstance(sdk_version, str) or not sdk_version.strip():
        raise StabilityError("a fixed nonempty SDK version is required")
    if not isinstance(compatibility, dict) or compatibility.get("format") != COMPATIBILITY_FORMAT:
        raise StabilityError("invalid generated API compatibility format")
    approvals = compatibility.get("approved_transitions", [])
    if not isinstance(approvals, list):
        raise StabilityError("approved transitions must be a list")
    problems = []
    for export, before in sorted(baseline["exports"].items()):
        after = candidate.get(export)
        if after == before:
            continue
        accepted = any(
            transition.get("export") == export and transition.get("before") == before
            and transition.get("after") == after
            and transition.get("version_scope") == {"from": baseline["sdk_version"], "to": sdk_version}
            and isinstance(transition.get("reason"), str) and bool(transition["reason"].strip())
            for transition in approvals if isinstance(transition, dict)
        )
        if not accepted:
            problems.append({"export": export, "kind": "removed" if after is None else "rebound_or_contract_changed",
                             "before": before, "after": after})
    return problems


def discover_plan(raw_dir: Path, oracle_dir: Path, baseline):
    validate_baseline(baseline)
    raw, oracle = ApiTree(raw_dir), ApiTree(oracle_dir)
    modules, provenance = {}, {}
    protected = {}
    for export in baseline["exports"]:
        module, name = export.rsplit(":", 1)
        if not module.endswith("__init__.py"):
            protected.setdefault(module, set()).add(name)
    for relative, original in raw.modules.items():
        if relative.endswith("__init__.py"):
            continue
        if relative not in oracle.modules:
            raise StabilityError(f"oracle removed defining module: {relative}")
        scoped = oracle.modules[relative]
        signatures = {}
        for name in scoped.classes:
            signatures.setdefault(scoped.signature(name, ignore_defaults=True), []).append(name)
        candidates = {name: signatures.get(original.signature(name, ignore_defaults=True), []) for name in original.classes}
        chosen, reasons = {}, {}
        for name, options in candidates.items():
            if not options:
                raise StabilityError(f"no identity oracle candidate: {relative}:{name}")
            suffixes = [candidate for candidate in options if candidate.endswith(name)]
            if len(options) == 1:
                chosen[name], reasons[name] = options[0], "unique_type_shape"
            elif name in options:
                chosen[name], reasons[name] = name, "retained_declared_name"
            elif len(suffixes) == 1:
                chosen[name], reasons[name] = suffixes[0], "declared_name_suffix"
        observed = {}
        for parent, target in chosen.copy().items():
            old_refs, new_refs = original.class_references(parent), scoped.class_references(target)
            if len(old_refs) != len(new_refs):
                continue
            for old, new in zip(old_refs, new_refs):
                if old in candidates and new in candidates[old]:
                    observed.setdefault(old, set()).add(new)
        for name, options in candidates.items():
            if len(options) == 1:
                continue
            references = sorted(observed.get(name, set()))
            if references:
                chosen[name], reasons[name] = references[0], "matched_parent_reference" if len(references) == 1 else "shared_class_canonical_pointer"
        while True:
            progress = False
            for name, options in candidates.items():
                if name not in chosen:
                    available = [candidate for candidate in options if candidate not in chosen.values()]
                    if len(available) == 1:
                        chosen[name], reasons[name] = available[0], "remaining_distinct_schema_pointer"
                        progress = True
            if not progress:
                break
        missing = set(candidates) - set(chosen)
        if missing:
            raise StabilityError(f"unexplained oracle ambiguity: {relative}:{','.join(sorted(missing))}")
        consumers = {name: [parent for parent in original.classes if name in original.class_references(parent)] for name in original.classes}
        collision_groups = {}
        for old, new in chosen.items():
            collision_groups.setdefault(new, []).append(old)
        for new, old_names in collision_groups.items():
            inline, referenced = [name for name in old_names if consumers[name]], [name for name in old_names if not consumers[name]]
            if len(old_names) == 2 and len(inline) == len(referenced) == 1:
                # A separate actual reference copy has a separate nominal
                # identity. Its implementation remains the ordinary class.
                chosen[referenced[0]], reasons[referenced[0]] = new + "Referenced", "distinct_reference_copy_preserved"
        reserved = set(original.classes) | protected.get(relative, set())
        for old, new in chosen.copy().items():
            if new in reserved and new != old:
                chosen[old], reasons[old] = module_prefix(relative) + new, reasons[old] + "+historical_alias_reserved"
        if len(set(chosen.values())) != len(chosen):
            raise StabilityError(f"oracle would collapse distinct actual classes: {relative}")
        modules[relative], provenance[relative] = chosen, reasons
    return {"format": PLAN_FORMAT, "modules": modules, "provenance": provenance,
            "ordinary_class_count": sum(len(module.classes) for module in raw.modules.values())}


def bound_names(node):
    result = set()

    class Collect(ast.NodeVisitor):
        def visit_Name(self, child):
            if isinstance(child.ctx, (ast.Store, ast.Del)):
                result.add(child.id)

        def visit_FunctionDef(self, child):
            result.add(child.name)

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, child):
            result.add(child.name)

        def visit_Import(self, child):
            result.update(alias.asname or alias.name.split(".")[0] for alias in child.names)

        def visit_ImportFrom(self, child):
            result.update(alias.asname or alias.name for alias in child.names)

        def visit_ListComp(self, child):
            for generator in child.generators:
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)
            if isinstance(child, ast.DictComp):
                self.visit(child.key)
                self.visit(child.value)
            else:
                self.visit(child.elt)

        visit_SetComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp
        visit_DictComp = visit_ListComp

    visitor = Collect()
    for child in node.body:
        visitor.visit(child)
    arguments = node.args
    result.update(argument.arg for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs)
    if arguments.vararg:
        result.add(arguments.vararg.arg)
    if arguments.kwarg:
        result.add(arguments.kwarg.arg)
    return result


class BindingRewriter(ScopeAwareTransformer):
    def __init__(self, module: ModelModule, plans):
        super().__init__(module)
        self.module, self.plans = module, plans
        self.local = plans[module.relative]
        self.names, self.import_modules, self.import_specs = {}, {}, {}
        for node in module.tree.body:
            if not isinstance(node, ast.ImportFrom) or not node.level:
                continue
            base = resolve_import_path(module.relative, node.level, node.module)
            target = plans.get(base + ".py", {})
            for alias in node.names:
                if alias.name == "*":
                    raise StabilityError(f"unsupported star import in {module.relative}")
                module_target = base + "/" + alias.name + ".py"
                if module_target in plans:
                    self.import_modules[alias.asname or alias.name] = module_target
                if alias.name in target:
                    self.names[alias.asname or alias.name] = target[alias.name]
                    self.import_specs[(node.lineno, alias.name)] = target[alias.name]
        self.names.update(self.local)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            replacement = self.import_specs.get((node.lineno, alias.name))
            if replacement:
                alias.name, alias.asname = replacement, None
        return node

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and not self.is_shadowed(node.id):
            node.id = self.names.get(node.id, node.id)
        return node

    def visit_Attribute(self, node):
        if isinstance(node.value, ast.Name) and not self.is_shadowed(node.value.id) and node.value.id in self.import_modules:
            node.attr = self.plans[self.import_modules[node.value.id]].get(node.attr, node.attr)
            return node
        return self.generic_visit(node)

    def visit_ClassDef(self, node):
        if node not in self.module.tree.body:
            raise StabilityError(f"nested generated class is unsupported in {self.module.relative}")
        node.name = self.local[node.name]
        node.decorator_list = [self.visit(item) for item in node.decorator_list]
        node.bases = [self.visit(item) for item in node.bases]
        node.keywords = [self.visit(item) for item in node.keywords]
        node.body = self.class_body(node)
        return node


def rewrite_module(module: ModelModule, plans):
    # Header bytes are retained independently of deterministic AST printing.
    header = []
    for line in module.source.splitlines():
        if line.startswith("#") or not line.strip():
            header.append(line)
        else:
            break
    tree = copy.deepcopy(module.tree)
    rewriter = BindingRewriter(module, plans)
    # Class membership is checked against the original top-level declarations.
    rewriter.module = ModelModule(module.relative, ast.unparse(tree))
    rewriter.module.tree = tree
    tree = rewriter.visit(tree)
    ast.fix_missing_locations(tree)
    return "\n".join(header).rstrip() + "\n\n" + ast.unparse(tree) + "\n"


def package_prefix(module: ModelModule):
    first = next((node for node in module.tree.body if isinstance(node, ast.ImportFrom) and node.level), None)
    # Metadata can occur before or after imports. Preserve the final literal
    # value, not merely the initial pre-import prefix.
    digest = next((node.value.value for node in reversed(module.tree.body)
                   if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Constant)
                   and isinstance(node.value.value, str) and any(
                       isinstance(target, ast.Name) and target.id == "SCHEMA_SHA256"
                       for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))), None)
    if first is not None:
        prefix = "\n".join(module.source.splitlines()[:first.lineno - 1]).rstrip()
        if digest is not None:
            prefix_digest = next((node.value.value for node in reversed(ast.parse(prefix).body)
                                  if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Constant)
                                  and any(isinstance(target, ast.Name) and target.id == "SCHEMA_SHA256"
                                          for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))), None)
            if prefix_digest != digest:
                prefix += "\nSCHEMA_SHA256 = " + repr(digest)
        return prefix
    keep = []
    for node in module.tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            keep.append(node)
        elif isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "SCHEMA_SHA256" for target in node.targets):
            keep.append(node)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            keep.append(node)
    header = []
    for line in module.source.splitlines():
        if line.startswith("#") or not line.strip():
            header.append(line)
        else:
            break
    return "\n".join(header).rstrip() + "\n\n" + "\n".join(ast.unparse(node) for node in keep)


def validate_output_path(path, models_dir, protected_paths=()):
    if path is None:
        return
    resolved = path.resolve()
    if (resolved == models_dir.resolve() or models_dir.resolve() in resolved.parents
            or resolved in {Path(item).resolve() for item in protected_paths}):
        raise StabilityError("API report must be outside model sources and protected inputs")


def publish(staging, models_dir, original, report_path, report):
    """Prepare every replacement and roll back ordinary publication failures."""
    if {str(path.relative_to(models_dir)) for path in models_dir.rglob("*.py")} != set(original.modules):
        raise StabilityError("model module inventory changed before publication")
    original.dependency_budget.verify_sources()
    for relative, module in original.modules.items():
        if (models_dir / relative).read_bytes() != module.source.encode("utf-8"):
            raise StabilityError("model source changed before publication: " + relative)
    replacements = {models_dir / path.relative_to(staging): path.read_bytes()
                    for path in sorted(staging.rglob("*.py"))}
    if report_path is not None:
        replacements[report_path] = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    originals = {path: path.read_bytes() if path.exists() else None for path in replacements}
    committed, directories = [], []
    with tempfile.TemporaryDirectory(prefix="chio-python-api-publish-", dir=models_dir.parent) as temporary:
        prepared, backups = {}, {}
        for index, (path, body) in enumerate(replacements.items()):
            prepared[path] = Path(temporary) / f"next-{index}"
            prepared[path].write_bytes(body)
            if originals[path] is not None:
                backups[path] = Path(temporary) / f"before-{index}"
                backups[path].write_bytes(originals[path])
        try:
            for path, prepared_path in prepared.items():
                missing = []
                parent = path.parent
                while not parent.exists():
                    missing.append(parent)
                    parent = parent.parent
                for directory in reversed(missing):
                    directory.mkdir()
                    directories.append(directory)
                os.replace(prepared_path, path)
                committed.append(path)
        except OSError:
            for path in reversed(committed):
                if path in backups:
                    os.replace(backups[path], path)
                else:
                    path.unlink()
            for directory in reversed(directories):
                directory.rmdir()
            raise


def apply(models_dir: Path, plan, baseline, compatibility, sdk_version, inventory_output=None,
          *, sdk_root=None, protected_paths=(), inspect_only=False):
    validate_baseline(baseline)
    old_dependencies = enforcement.validate_ledger(baseline.get("enforcement_dependencies"), baseline["exports"])
    if not isinstance(compatibility, dict) or compatibility.get("format") != COMPATIBILITY_FORMAT:
        raise StabilityError("invalid generated API compatibility format")
    transitions = compatibility.get("enforcement_dependencies_transitions", [])
    if not isinstance(transitions, list):
        raise StabilityError("enforcement dependency transitions must be a list")
    validate_output_path(inventory_output, models_dir, protected_paths)
    if not isinstance(plan, dict) or plan.get("format") != PLAN_FORMAT or not isinstance(plan.get("modules"), dict):
        raise StabilityError("invalid generated model binding plan")
    plans = plan["modules"]
    original = ApiTree(models_dir, sdk_root=sdk_root)
    original.enforcement_inventory()
    defining_modules = {relative for relative in original.modules if not relative.endswith("__init__.py")}
    if set(plans) != defining_modules:
        raise StabilityError("hardener changed the defining module inventory")
    for relative, names in plans.items():
        if relative not in original.modules or set(names) != set(original.modules[relative].classes):
            raise StabilityError(f"hardener changed class inventory: {relative}")
        if len(set(names.values())) != len(names):
            raise StabilityError(f"binding plan collapses classes: {relative}")
    exports, conflicts = {}, []
    for export, binding in baseline["exports"].items():
        relative, name = export.rsplit(":", 1)
        if binding["module"] not in plans or binding["class"] not in plans[binding["module"]].values():
            raise StabilityError(f"protected actual contract disappeared: {export}")
        exports.setdefault(relative, {})[name] = (binding["module"], binding["class"])
    for relative, names in original.public.items():
        for name in names:
            if name.startswith("_") or name == "SCHEMA_SHA256":
                continue
            owner, raw_name = original.resolve(relative, name)
            target = owner, plans[owner][raw_name]
            public = exports.setdefault(relative, {})
            if name in public and public[name] != target:
                conflicts.append({"export": relative + ":" + name, "protected": public[name], "unreleased": target})
            else:
                public[name] = target
    for relative, names in plans.items():
        for stable in names.values():
            canonical = stable if stable.startswith(module_prefix(relative)) else module_prefix(relative) + stable
            target = relative, stable
            for public_module in (relative, str(Path(relative).parent / "__init__.py"), "__init__.py"):
                public = exports.setdefault(public_module, {})
                if canonical in public and public[canonical] != target:
                    raise StabilityError(f"canonical export collides with protected identity: {public_module}:{canonical}")
                public[canonical] = target
            if stable in exports.setdefault(relative, {}) and exports[relative][stable] != target:
                raise StabilityError(f"actual class collides with protected alias: {relative}:{stable}")
            exports[relative][stable] = target
    with tempfile.TemporaryDirectory(prefix="chio-python-api-", dir=models_dir.parent) as temporary:
        staging = Path(temporary) / "output"
        shutil.copytree(models_dir, staging, ignore=shutil.ignore_patterns("__pycache__"))
        for relative in plans:
            body = rewrite_module(original.modules[relative], plans)
            aliases = [name + " = " + target[1] for name, target in sorted(exports[relative].items()) if name != target[1]]
            (staging / relative).write_text(body.rstrip() + "\n\n# Public compatibility aliases reference the actual current model classes.\n" + "\n".join(aliases) + "\n", encoding="utf-8")
        for relative, public in exports.items():
            if not relative.endswith("__init__.py"):
                continue
            prefix = package_prefix(original.modules[relative]) if relative in original.modules else "from __future__ import annotations"
            lines = [prefix, ""]
            for name, (owner, stable) in sorted(public.items()):
                path = Path(owner).relative_to(Path(relative).parent).with_suffix("")
                module = ".".join(path.parts)
                lines.append(f"from .{module} import {stable}" + (f" as {name}" if name != stable else ""))
            lines += ["", "__all__ = ["] + [f'    "{name}",' for name in sorted(public)] + ["]", ""]
            # The schema digest is public metadata, with no model fingerprint.
            # Preserve existing star-import membership while its value follows
            # the current authoritative schema digest.
            if relative in original.modules and "SCHEMA_SHA256" in (original.modules[relative].explicit_all or []):
                if original.modules[relative].namespace.get("SCHEMA_SHA256", (None, None, None))[2] != "value":
                    raise StabilityError(f"schema digest is not metadata in {relative}")
                lines.insert(len(lines) - 2, '    "SCHEMA_SHA256",')
            (staging / relative).write_text("\n".join(lines), encoding="utf-8")
        candidate = ApiTree(staging, sdk_root=original.sdk_root)
        for relative, names in plans.items():
            for before, after in names.items():
                if original.modules[relative].signature(before) != candidate.modules[relative].signature(after):
                    raise StabilityError(f"renaming changed hardened class body: {relative}:{before}")
        if sum(len(module.classes) for module in original.modules.values()) != sum(len(module.classes) for module in candidate.modules.values()):
            raise StabilityError("renaming added or removed actual class definitions")
        dependencies = candidate.enforcement_inventory()
        inventory = candidate.inventory()
        problems = compatibility_violations(baseline, inventory, compatibility, sdk_version)
        dependency_problems = enforcement.violations(
            baseline, {"exports": inventory}, old_dependencies, dependencies, compatibility, sdk_version)
        report = {"format": FORMAT, "sdk_version": sdk_version, "exports": inventory,
                  "enforcement_dependencies": dependencies, "unreleased_spelling_conflicts": conflicts,
                  "violations": problems, "enforcement_dependency_violations": dependency_problems}
        if inspect_only:
            return report
        if problems or dependency_problems:
            refused = sorted({problem["export"] for problem in problems + dependency_problems})
            raise StabilityError("unapproved generated API or enforcement dependency changes: " + ", ".join(refused))
        validate_output_path(inventory_output, models_dir, tuple(protected_paths) + tuple(
            Path(path) for path in candidate.dependency_budget.sources))
        candidate.dependency_budget.verify_sources()
        publish(staging, models_dir, original, inventory_output, report)
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scoped = commands.add_parser("annotate", help="create a title-scoped naming mirror")
    scoped.add_argument("--input-dir", type=Path, required=True)
    scoped.add_argument("--output-dir", type=Path, required=True)
    discovery = commands.add_parser("plan", help="discover names from ordinary and scoped un-hardened output")
    discovery.add_argument("--raw-dir", type=Path, required=True)
    discovery.add_argument("--oracle-dir", type=Path, required=True)
    discovery.add_argument("--baseline", type=Path, required=True)
    discovery.add_argument("--output", type=Path, required=True)
    for command, help_text in (("apply", "rename staged models after both protected compatibility gates pass"),
                               ("inspect", "report candidate class and dependency changes without modifying inputs")):
        migration = commands.add_parser(command, help=help_text)
        migration.add_argument("--models-dir", type=Path, required=True)
        migration.add_argument("--plan", type=Path, required=True)
        migration.add_argument("--baseline", type=Path, required=True)
        migration.add_argument("--compatibility", type=Path, required=True)
        migration.add_argument("--sdk-version", required=True)
        migration.add_argument("--sdk-root", type=Path, help="actual chio_sdk package containing explicitly owned guards")
        if command == "apply":
            migration.add_argument("--inventory-output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "annotate":
            annotate(args.input_dir, args.output_dir)
        elif args.command == "plan":
            validate_output_path(args.output, args.raw_dir, (args.baseline, Path(__file__), Path(enforcement.__file__)))
            validate_output_path(args.output, args.oracle_dir)
            write_json(args.output, discover_plan(args.raw_dir, args.oracle_dir, read_json(args.baseline)))
        else:
            report = apply(args.models_dir, read_json(args.plan), read_json(args.baseline), read_json(args.compatibility),
                           args.sdk_version, getattr(args, "inventory_output", None), sdk_root=args.sdk_root,
                           protected_paths=(args.plan, args.baseline, args.compatibility, Path(__file__), Path(enforcement.__file__)),
                           inspect_only=args.command == "inspect")
            if args.command == "inspect":
                print(json.dumps(report, indent=2, sort_keys=True))
    except (StabilityError, enforcement.Refusal, OSError, SyntaxError, json.JSONDecodeError, RecursionError) as error:
        print(f"python API stability: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
