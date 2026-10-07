"""Bounded enforcement dependencies of public generated model contracts.

Existing public class records and their fingerprint algorithm remain unchanged.
Only explicitly owned SDK guards and declared stdlib/Pydantic imports are in
scope. Unsupported or dynamic dependency forms refuse before publication.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

FORMAT = "chio.sdk.python.enforcement-dependencies.v1"
OWNED_GUARDS = {
    ("recovery_wire.py", "MAX_WIRE_BYTES"): {
        "owner": "python-sdk",
        "source": "sdks/python/chio-sdk-python/src/chio_sdk/recovery_wire.py",
        "contract": "chio_sdk.recovery_wire:MAX_WIRE_BYTES",
        "kind": "integer_literal",
    },
    ("recovery_wire.py", "assert_foundation_wire"): {
        "owner": "python-sdk",
        "source": "sdks/python/chio-sdk-python/src/chio_sdk/recovery_wire.py",
        "contract": "chio_sdk.recovery_wire:assert_foundation_wire",
        "kind": "module_function",
    },
    ("recovery_wire.py", "require_utf8_bound"): {
        "owner": "python-sdk",
        "source": "sdks/python/chio-sdk-python/src/chio_sdk/recovery_wire.py",
        "contract": "chio_sdk.recovery_wire:require_utf8_bound",
        "kind": "function",
    },
    ("_manifest_wire.py", "SecurityWireModel"): {
        "owner": "python-sdk",
        "source": "sdks/python/chio-sdk-python/src/chio_sdk/_manifest_wire.py",
        "contract": "chio_sdk._manifest_wire:SecurityWireModel",
        "kind": "class",
    }
}
TRUSTED_LIBRARIES = {"pydantic", "typing_extensions"} | sys.stdlib_module_names
DECLARED_FROM_IMPORTS = {("pydantic_core", "core_schema")}
UNSUPPORTED_DYNAMIC = {"exec", "eval", "globals", "locals", "vars", "__import__", "compile",
                       "getattr", "setattr", "delattr"}
UNSUPPORTED_ATTRIBUTES = {"__globals__", "__dict__", "__getattribute__", "__subclasses__", "__builtins__"}
DEFAULT_LIMITS = {
    "sources": 512, "file_bytes": 512 * 1024, "source_bytes": 16 * 1024 * 1024,
    "file_nodes": 50000, "ast_nodes": 300000, "ast_depth": 80, "classes": 4096,
    "graph_steps": 100000, "graph_edges": 100000, "model_depth": 48, "value_depth": 32,
    "graph_bytes": 2 * 1024 * 1024, "serialized_bytes": 64 * 1024 * 1024,
    "serialization_steps": 1000000, "exports": 20000,
    "construction_nodes": 1000000,
}
DEFINITION_BUILDERS = {"pydantic.ConfigDict", "pydantic.Field", "pydantic.constr", "pydantic.conint"}
MODEL_DECORATORS = {"pydantic.field_validator", "pydantic.model_validator",
                    "pydantic.field_serializer", "pydantic.model_serializer"}
METHOD_BUILTINS = {"classmethod", "staticmethod", "property"}
MAX_ANNOTATION_BYTES = 4096
MAX_ANNOTATION_QUOTE_DEPTH = 16


def trusted_from_import(node):
    return (not node.level and ((node.module or "").split(".")[0] in TRUSTED_LIBRARIES
            or all((node.module, alias.name) in DECLARED_FROM_IMPORTS for alias in node.names)))


class Refusal(ValueError):
    pass


def annotation_preflight(tree, budget):
    """Bound type expression decoding before any class normalization.

    Literal arguments and Annotated metadata remain ordinary data. Quoted type
    expressions admit references, generic arguments, and unions, never calls.
    """
    external = {}

    def bind(name, qualified):
        previous = external.get(name)
        if (previous and (previous == "typing" or previous == "typing_extensions"
                          or previous.startswith("typing.") or previous.startswith("typing_extensions."))
                and previous != qualified):
            raise Refusal("annotation typing binding is overwritten: " + name)
        if qualified is None:
            external.pop(name, None)
        else:
            external[name] = qualified

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bind(alias.asname or alias.name.split(".")[0], alias.name if alias.asname else alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and not node.level:
            for alias in node.names:
                bind(alias.asname or alias.name, (node.module or "") + "." + alias.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            qualified = external.get(node.value.id) if isinstance(node.value, ast.Name) else None
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    bind(target.id, qualified)
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            bind(node.name, None)
    allocated = 0

    def check(root, bindings):
        nonlocal allocated
        todo = [(root, 1, 0, False)]
        while todo:
            node, depth, quotes, decoded = todo.pop()
            if node is None:
                continue
            budget.charge("construction_nodes")
            budget.ceiling("ast_depth", depth)
            if isinstance(node, ast.Constant):
                if isinstance(node.value, str):
                    try:
                        encoded_bytes = len(node.value.encode("utf-8"))
                    except UnicodeError as error:
                        raise Refusal("quoted annotation must contain valid UTF-8 text") from error
                    if encoded_bytes > MAX_ANNOTATION_BYTES:
                        raise Refusal("quoted annotation exceeds the UTF-8 source ceiling")
                    if quotes >= MAX_ANNOTATION_QUOTE_DEPTH:
                        raise Refusal("quoted annotation exceeds the decoding depth ceiling")
                    if node.value not in budget.annotation_cache:
                        try:
                            expression = ast.parse(node.value, mode="eval")
                        except (SyntaxError, ValueError, RecursionError, UnicodeError) as error:
                            raise Refusal("quoted annotation is not a supported type expression") from error
                        pending = [(expression, 1)]
                        while pending:
                            part, part_depth = pending.pop()
                            allocated += 1
                            budget.charge("ast_nodes")
                            budget.ceiling("ast_depth", part_depth)
                            pending.extend((child, part_depth + 1) for child in ast.iter_child_nodes(part))
                        budget.annotation_cache[node.value] = expression.body
                    todo.append((budget.annotation_cache[node.value], depth + 1, quotes + 1, True))
                elif decoded and node.value not in (None, Ellipsis):
                    raise Refusal("unsupported literal in a quoted type expression")
                continue
            if isinstance(node, ast.Name):
                if decoded and node.id in UNSUPPORTED_DYNAMIC:
                    raise Refusal("dynamic name in a quoted type expression")
                continue
            if isinstance(node, ast.Attribute):
                if node.attr in UNSUPPORTED_ATTRIBUTES:
                    raise Refusal("dynamic attribute in a type expression")
                children = [node.value]
            elif isinstance(node, ast.Subscript):
                if decoded and not isinstance(node.value, (ast.Name, ast.Attribute)):
                    raise Refusal("unsupported quoted type subscript target")
                form = qualified_expression(node.value, bindings)
                if form in {"typing.Literal", "typing_extensions.Literal"}:
                    declaration_expression(node.slice, bindings, builders=True)
                    children = [node.value]
                elif form in {"typing.Annotated", "typing_extensions.Annotated"}:
                    if not isinstance(node.slice, ast.Tuple) or len(node.slice.elts) < 2:
                        raise Refusal("unsupported Annotated type expression")
                    for metadata in node.slice.elts[1:]:
                        declaration_expression(metadata, bindings, builders=True)
                    children = [node.value, node.slice.elts[0]]
                else:
                    children = [node.value, node.slice]
            elif isinstance(node, (ast.Tuple, ast.List)):
                children = node.elts
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                children = [node.left, node.right]
            elif isinstance(node, ast.Call) and not decoded:
                form = qualified_expression(node.func, bindings)
                if form in {"typing.ForwardRef", "typing_extensions.ForwardRef"}:
                    if (len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Constant)
                            or not isinstance(node.args[0].value, str)):
                        raise Refusal("ForwardRef must contain exactly one literal annotation")
                    children = node.args
                else:
                    # Constrained type and Field arguments are ordinary values.
                    continue
            elif decoded:
                raise Refusal("unsupported quoted type expression: " + type(node).__name__)
            else:
                # The declaration grammar separately qualifies nonquoted forms.
                continue
            todo.extend((child, depth + 1, quotes, decoded) for child in children)

    class Contexts(ast.NodeVisitor):
        def __init__(self):
            self.bindings = external

        def visit_AnnAssign(self, node):
            check(node.annotation, self.bindings)

        def visit_FunctionDef(self, node):
            arguments = node.args
            annotations = [argument.annotation for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs]
            annotations += [node.returns] + [argument.annotation for argument in (arguments.vararg, arguments.kwarg) if argument]
            for annotation in annotations:
                check(annotation, self.bindings)
            bound = {argument.arg for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs}
            bound.update(argument.arg for argument in (arguments.vararg, arguments.kwarg) if argument)
            bound.update(part.id for part in ast.walk(node) if isinstance(part, ast.Name) and isinstance(part.ctx, (ast.Store, ast.Del)))
            previous = self.bindings
            self.bindings = {name: value for name, value in previous.items() if name not in bound}
            try:
                for statement in node.body:
                    self.visit(statement)
            finally:
                self.bindings = previous

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            previous = self.bindings
            for base in node.bases:
                check(base, previous)
            self.bindings = dict(previous)
            try:
                for statement in node.body:
                    self.visit(statement)
                    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        self.bindings.pop(statement.name, None)
                    elif isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None:
                        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                        for target in targets:
                            if isinstance(target, ast.Name):
                                self.bindings.pop(target.id, None)
            finally:
                self.bindings = previous

    Contexts().visit(tree)
    return allocated


class Budget:
    def __init__(self, limits=None):
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}
        if set(self.limits) != set(DEFAULT_LIMITS) or any(
                type(value) is not int or value < 1 or value > DEFAULT_LIMITS[name]
                for name, value in self.limits.items()):
            raise Refusal("invalid explicit dependency resource limits")
        self.usage, self.sources, self.annotation_cache = {}, {}, {}

    def ceiling(self, name, value):
        self.usage[name] = max(self.usage.get(name, 0), value)
        if value > self.limits[name]:
            raise Refusal("dependency resource ceiling exceeded: " + name)

    def charge(self, name, amount=1):
        self.ceiling(name, self.usage.get(name, 0) + amount)

    def source(self, path):
        identity = str(path.resolve())
        if identity in self.sources:
            return self.sources[identity]
        self.charge("sources")
        with path.open("rb") as stream:
            body = stream.read(self.limits["file_bytes"] + 1)
        self.ceiling("file_bytes", len(body))
        self.charge("source_bytes", len(body))
        try:
            tree = ast.parse(body, filename=str(path))
        except (SyntaxError, ValueError, RecursionError) as error:
            raise Refusal("source cannot be parsed within the dependency grammar: " + str(path)) from error
        nodes, todo = 0, [(tree, 1)]
        while todo:
            node, depth = todo.pop()
            nodes += 1
            self.ceiling("ast_depth", depth)
            self.ceiling("file_nodes", nodes)
            self.charge("ast_nodes")
            if isinstance(node, ast.ClassDef):
                self.charge("classes")
            todo.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
        self.ceiling("file_nodes", nodes + annotation_preflight(tree, self))
        self.sources[identity] = body, tree
        return body, tree

    def fingerprint(self, value):
        digest, size = hashlib.sha256(), 0
        encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"))
        for chunk in encoder.iterencode(value):
            self.charge("serialization_steps")
            body = chunk.encode()
            size += len(body)
            self.ceiling("graph_bytes", size)
            self.charge("serialized_bytes", len(body))
            digest.update(body)
        return digest.hexdigest()

    def verify_sources(self):
        for identity, (expected, _) in self.sources.items():
            with Path(identity).open("rb") as stream:
                actual = stream.read(self.limits["file_bytes"] + 1)
            if actual != expected:
                raise Refusal("dependency source changed after bounded preflight: " + identity)


def single_definition_namespace(tree, source, allow_reexports=False):
    """Keep aliases tied to one source definition, before any model exists."""
    def metadata(node):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            return False
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        return all(isinstance(target, ast.Name) and target.id in {"__all__", "SCHEMA_SHA256"}
                   for target in targets)

    def docstring(node):
        return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)

    reexports_only = allow_reexports and all(
        isinstance(node, ast.Pass) or docstring(node) or metadata(node)
        or (isinstance(node, ast.ImportFrom) and node.level and all(alias.name != "*" for alias in node.names))
        or (isinstance(node, ast.ImportFrom) and not node.level and node.module == "__future__"
            and all(alias.name == "annotations" and alias.asname is None for alias in node.names))
        for node in tree.body)
    bound = {}
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names, kind = [node.name], "definition"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            if node.value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(not isinstance(target, ast.Name) for target in targets):
                raise Refusal("dynamic dependency assignment targets: " + source)
            names, kind = [target.id for target in targets], "value-or-alias"
        elif isinstance(node, ast.Import):
            names = [alias.asname or alias.name.split(".")[0] for alias in node.names]
            kind = "import"
        elif isinstance(node, ast.ImportFrom):
            names = [alias.asname or alias.name for alias in node.names]
            kind = "relative-import" if node.level else "import"
        else:
            continue
        for name in names:
            if name in bound and not (reexports_only and kind == bound[name] == "relative-import"):
                raise Refusal("dependency binding has multiple definitions: " + source + ":" + name)
            bound[name] = kind


def qualified_expression(node, external):
    if isinstance(node, ast.Name):
        return external.get(node.id)
    if isinstance(node, ast.Attribute):
        owner = qualified_expression(node.value, external)
        return owner + "." + node.attr if owner else None
    return None


def declaration_expression(node, external, shadowed=(), *, builders=False):
    """Closed nonexecuting expressions plus declared pure type/field builders."""
    if node is None or isinstance(node, (ast.Constant, ast.Name)):
        return
    if isinstance(node, ast.Attribute):
        if node.attr in UNSUPPORTED_ATTRIBUTES:
            raise Refusal("dynamic declaration attribute is unsupported: " + node.attr)
        declaration_expression(node.value, external, shadowed, builders=builders)
        return
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        children = node.elts
    elif isinstance(node, ast.Dict):
        if any(key is None for key in node.keys):
            raise Refusal("dynamic declaration dictionary expansion is unsupported")
        children = node.keys + node.values
    elif isinstance(node, ast.Subscript):
        children = [node.value, node.slice]
    elif isinstance(node, ast.Slice):
        children = [node.lower, node.upper, node.step]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        children = [node.left, node.right]
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        try:
            ast.literal_eval(node)
        except (TypeError, ValueError) as error:
            raise Refusal("dynamic declaration unary expression is unsupported") from error
        return
    elif isinstance(node, ast.Call) and builders:
        names = {part.id for part in ast.walk(node.func) if isinstance(part, ast.Name)}
        qualified = qualified_expression(node.func, external) if not names & set(shadowed) else None
        if qualified in {"typing.ForwardRef", "typing_extensions.ForwardRef"}:
            if (len(node.args) != 1 or node.keywords or not isinstance(node.args[0], ast.Constant)
                    or not isinstance(node.args[0].value, str)):
                raise Refusal("declaration ForwardRef must contain exactly one literal annotation")
            return
        if qualified not in DEFINITION_BUILDERS or any(keyword.arg is None for keyword in node.keywords):
            raise Refusal("unsupported definition-time call: " + str(qualified))
        children = node.args + [keyword.value for keyword in node.keywords]
    else:
        raise Refusal("unsupported declaration expression: " + type(node).__name__)
    for child in children:
        declaration_expression(child, external, shadowed, builders=builders)


def method_decorators(function, external, bound, class_bound=(), *, selected_owned=False):
    for decorator in function.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id in METHOD_BUILTINS:
            if decorator.id not in class_bound and (decorator.id not in bound
                    or external.get(decorator.id) == "builtins." + decorator.id):
                continue
        if isinstance(decorator, ast.Call):
            names = {node.id for node in ast.walk(decorator.func) if isinstance(node, ast.Name)}
            qualified = qualified_expression(decorator.func, external) if not names & set(class_bound) else None
            permitted = {"pydantic.model_validator"} if selected_owned else MODEL_DECORATORS
            if qualified in permitted and all(keyword.arg is not None for keyword in decorator.keywords):
                try:
                    for value in decorator.args + [keyword.value for keyword in decorator.keywords]:
                        ast.literal_eval(value)
                except (ValueError, TypeError):
                    pass
                else:
                    continue
        raise Refusal("unsupported or shadowed method declaration decorator")


def generated_declarations(module):
    for declaration in module.tree.body:
        if isinstance(declaration, ast.AnnAssign):
            declaration_expression(declaration.annotation, module.external)
        if isinstance(declaration, (ast.FunctionDef, ast.AsyncFunctionDef)):
            arguments = declaration.args
            for value in ([argument.annotation for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs]
                          + [declaration.returns]
                          + [argument.annotation for argument in (arguments.vararg, arguments.kwarg) if argument]):
                declaration_expression(value, module.external)
        if not isinstance(declaration, ast.ClassDef):
            continue
        if declaration.decorator_list or declaration.keywords:
            raise Refusal("unsupported generated class declaration decorators or keywords")
        for base in declaration.bases:
            if not isinstance(base, (ast.Name, ast.Subscript)):
                raise Refusal("unsupported generated class base expression")
            declaration_expression(base, module.external, builders=True)
        class_bound = set()
        for node in declaration.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("__") and node.name.endswith("__"):
                    raise Refusal("generated declaration contains an unsupported class execution hook")
                method_decorators(node, module.external, module.namespace, class_bound)
                arguments = node.args
                annotations = ([argument.annotation for argument in arguments.posonlyargs + arguments.args + arguments.kwonlyargs]
                               + [node.returns]
                               + [argument.annotation for argument in (arguments.vararg, arguments.kwarg) if argument])
                for value in annotations + arguments.defaults + [value for value in arguments.kw_defaults if value is not None]:
                    declaration_expression(value, module.external, class_bound)
                class_bound.add(node.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(not isinstance(target, ast.Name) for target in targets):
                    raise Refusal("dynamic generated class assignment targets are unsupported")
                if isinstance(node, ast.AnnAssign):
                    declaration_expression(node.annotation, module.external, class_bound, builders=True)
                declaration_expression(node.value, module.external, class_bound, builders=True)
                if node.value is not None:
                    class_bound.update(target.id for target in targets)
            elif isinstance(node, ast.Pass) or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                                               and isinstance(node.value.value, str)):
                continue
            else:
                raise Refusal("unsupported immediate generated class namespace execution")


def owned_signature(function, external, method=False, selected_class=False, bound=(), class_bound=()):
    for value in function.args.defaults + [value for value in function.args.kw_defaults if value is not None]:
        try:
            ast.literal_eval(value)
        except (ValueError, TypeError) as error:
            raise Refusal("owned SDK definition executes a dynamic default") from error
    annotations = [argument.annotation for argument in function.args.posonlyargs + function.args.args + function.args.kwonlyargs]
    annotations += [function.returns]
    for argument in (function.args.vararg, function.args.kwarg):
        if argument:
            annotations.append(argument.annotation)
    for value in annotations:
        if value is not None and any(isinstance(node, (ast.Call, ast.Lambda, ast.NamedExpr, ast.ListComp,
                                                       ast.DictComp, ast.SetComp, ast.GeneratorExp)) for node in ast.walk(value)):
            raise Refusal("owned SDK definition has dynamic annotations")
    if method:
        method_decorators(function, external, bound, class_bound, selected_owned=True)
    elif function.decorator_list:
        raise Refusal("owned SDK definition executes an unsupported decorator")


def violations(baseline, candidate, old_dependencies, new_dependencies, compatibility, sdk_version):
    """Require full class binding and dependency records in exact approvals."""
    problems = []
    for export, before in sorted(baseline["exports"].items()):
        after = candidate["exports"].get(export)
        old = old_dependencies["exports"].get(export)
        new = new_dependencies["exports"].get(export)
        if old == new:
            continue
        accepted = any(
            record.get("export") == export and record.get("before") == before and record.get("after") == after
            and record.get("before_enforcement_dependencies") == old
            and record.get("after_enforcement_dependencies") == new
            and record.get("version_scope") == {"from": baseline["sdk_version"], "to": sdk_version}
            and isinstance(record.get("reason"), str) and bool(record["reason"].strip())
            for record in compatibility.get("enforcement_dependencies_transitions", []) if isinstance(record, dict))
        if not accepted:
            problems.append({"export": export, "before": before, "after": after,
                             "before_enforcement_dependencies": old, "after_enforcement_dependencies": new})
    return problems


def validate_ledger(value, exports):
    """Validate the additional dimension without rewriting class records."""
    if (not isinstance(value, dict) or value.get("format") != FORMAT
            or not isinstance(value.get("exports"), dict) or set(value["exports"]) != set(exports)
            or not isinstance(value.get("graphs_by_contract"), dict)
            or not isinstance(value.get("external_source_provenance"), dict)):
        raise Refusal("invalid or absent protected enforcement dependency ledger")
    budget, checked = Budget(), {}
    for export, record in value["exports"].items():
        if (not isinstance(record, dict) or set(record) != {"contract", "fingerprint"}
                or record["contract"] != exports[export]["contract"]
                or not isinstance(record["fingerprint"], str) or len(record["fingerprint"]) != 64
                or any(char not in "0123456789abcdef" for char in record["fingerprint"])):
            raise Refusal("invalid protected dependency binding: " + export)
        contract = record["contract"]
        if contract not in value["graphs_by_contract"]:
            raise Refusal("missing protected dependency graph: " + contract)
        if contract not in checked:
            checked[contract] = budget.fingerprint(value["graphs_by_contract"][contract])
        if checked[contract] != record["fingerprint"]:
            raise Refusal("protected dependency graph digest disagrees: " + export)
    for path, digest in value["external_source_provenance"].items():
        if (not isinstance(path, str) or not isinstance(digest, str) or len(digest) != 64
                or any(char not in "0123456789abcdef" for char in digest)):
            raise Refusal("invalid owned SDK source provenance")
    return value


def reference_visitor(api, module):
    """Use the generator's lexical-scope rules without importing its module."""
    class References(api.ScopeAwareTransformer):
        def __init__(self, module):
            super().__init__(module)
            self.names, self.local_imports = set(), []

        def visit_ClassDef(self, node):
            node.decorator_list = [self.visit(item) for item in node.decorator_list]
            node.bases = [self.visit(item) for item in node.bases]
            node.keywords = [self.visit(item) for item in node.keywords]
            node.body = self.class_body(node)
            return node

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and not self.is_shadowed(node.id):
                qualified = self.module.external.get(node.id, "")
                if qualified == "sys.modules" or qualified.startswith("importlib."):
                    raise Refusal("runtime module namespace dependency is unsupported: " + qualified)
                self.names.add(node.id)
            return node

        def visit_Attribute(self, node):
            if node.attr in UNSUPPORTED_ATTRIBUTES:
                raise Refusal("dynamic dependency attribute is unsupported: " + node.attr)
            if (isinstance(node.value, ast.Name) and not self.is_shadowed(node.value.id)
                    and self.module.external.get(node.value.id) == "sys" and node.attr == "modules"):
                raise Refusal("runtime module namespace lookup is unsupported")
            if (isinstance(node.value, ast.Name) and node.value.id in self.module.imported
                    and not self.is_shadowed(node.value.id) and node.attr[:1].isupper()):
                self.names.add(node.value.id + "." + node.attr)
                return node
            return self.generic_visit(node)

        def visit_ImportFrom(self, node):
            if any(alias.name == "*" for alias in node.names):
                raise Refusal("wildcard local import is unsupported")
            self.local_imports.append(copy.deepcopy(node))
            return node

        def visit_Import(self, node):
            for alias in node.names:
                if alias.name.split(".")[0] not in TRUSTED_LIBRARIES:
                    raise Refusal("unowned local absolute import: " + alias.name)
            return node

        def visit_Call(self, node):
            qualified = None
            if isinstance(node.func, ast.Name) and not self.is_shadowed(node.func.id):
                qualified = self.module.external.get(node.func.id, node.func.id)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and not self.is_shadowed(node.func.value.id):
                owner = self.module.external.get(node.func.value.id)
                qualified = owner + "." + node.func.attr if owner else None
            if qualified and (qualified in UNSUPPORTED_DYNAMIC or qualified.removeprefix("builtins.") in UNSUPPORTED_DYNAMIC
                              or qualified.startswith("importlib.") or qualified == "pkgutil.resolve_name"):
                raise Refusal("dynamic dependency evaluation is unsupported: " + qualified)
            return super().visit_Call(node)

        def visit_Global(self, node):
            raise Refusal("runtime global namespace mutation is unsupported")

        def visit_Nonlocal(self, node):
            raise Refusal("runtime nonlocal namespace mutation is unsupported")
    return References(module)


class Dependencies:
    def __init__(self, models, *, api, identities=None, sdk_root=None, limits=None, tree=None, budget=None):
        self.api = api
        self.budget = budget or Budget(limits)
        for path in sorted(models.rglob("*.py")):
            self.budget.source(path)
        self.models = tree if tree is not None else api.ApiTree(models, identities, sdk_root=sdk_root)
        for relative, module in self.models.modules.items():
            body, _ = self.budget.source(models / relative)
            if module.source.encode() != body:
                raise Refusal("model source changed during bounded preflight: " + relative)
        self.sdk_root = sdk_root
        self.cache = {}
        self.guard_cache = {}
        self.value_cache, self.projections = {}, {}
        self.provenance = {}
        self.definitions = {}
        for relative, module in self.models.modules.items():
            single_definition_namespace(module.tree, relative, allow_reexports=relative.endswith("__init__.py"))
            definitions = {}
            for node in module.tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name in definitions:
                        raise Refusal("duplicate module helper definition: " + relative + ":" + node.name)
                    definitions[node.name] = node
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                        if isinstance(target, ast.Name) and node.value is not None and not isinstance(node.value, ast.Name):
                            definitions[target.id] = node.value
            self.definitions[relative] = definitions
            generated_declarations(module)
            for node in module.tree.body:
                if isinstance(node, ast.Import):
                    if any(alias.name.split(".")[0] not in TRUSTED_LIBRARIES for alias in node.names):
                        raise Refusal("unowned absolute module import, including unused imports: " + relative)
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    if not trusted_from_import(node):
                        self.owned_guard(relative, node)

    def projection(self, relative, kind, name):
        key = relative, kind, name
        if key not in self.projections:
            module = self.models.modules[relative]
            node = module.classes[name] if kind == "class" else self.definitions[relative].get(name)
            if node is None:
                raise Refusal("enforcement binding has no exact source definition: " + relative + ":" + name)
            self.budget.charge("construction_nodes", sum(1 for _ in ast.walk(node)))
            visitor = reference_visitor(self.api, module)
            visitor.visit(copy.deepcopy(node))
            self.projections[key] = (frozenset(visitor.names), tuple(visitor.local_imports),
                                     self.api.canonical_ast(node) if kind != "class" else None)
        return self.projections[key]

    def nominal(self, binding):
        return self.models.identities.get(binding, binding[0] + ":" + binding[1])

    def owned_guard(self, generated_relative, imported):
        if not imported.level:
            if (imported.module or "").startswith("chio_sdk."):
                path = (imported.module or "").removeprefix("chio_sdk.").replace(".", "/") + ".py"
            elif (imported.module or "").split(".")[0] not in TRUSTED_LIBRARIES:
                raise Refusal("unowned local external library: " + str(imported.module))
            else:
                return {}
        else:
            # Resolve from the actual SDK package directory, including _generated.
            parent = list((Path("_generated") / generated_relative).parent.parts)
            if imported.level - 1 > len(parent):
                raise Refusal("local import escapes declared SDK package")
            if imported.level > 1:
                parent = parent[:-(imported.level - 1)]
            path = "/".join(parent + (imported.module or "").split(".")) + ".py"
        if path.startswith("_generated/"):
            raise Refusal("local generated imports require a supported lexical model binding")
        result = {}
        for alias in imported.names:
            descriptor = OWNED_GUARDS.get((path, alias.name))
            if descriptor is None or self.sdk_root is None:
                raise Refusal("unowned or unavailable external SDK guard: " + path + ":" + alias.name)
            source = self.sdk_root / path
            key = path, alias.name
            if key in self.guard_cache:
                result[descriptor["contract"]] = self.guard_cache[key]
                continue
            body, tree = self.budget.source(source)
            single_definition_namespace(tree, path)
            if descriptor["kind"] == "integer_literal":
                definitions = [node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
                               and any(isinstance(target, ast.Name) and target.id == alias.name
                                       for target in (node.targets if isinstance(node, ast.Assign) else [node.target]))]
            else:
                selected_kind = ast.FunctionDef if descriptor["kind"] in {"function", "module_function"} else ast.ClassDef
                definitions = [node for node in tree.body if isinstance(node, selected_kind) and node.name == alias.name]
            if len(definitions) != 1:
                raise Refusal("owned guard must have exactly one selected definition")
            declaration = definitions[0]
            if descriptor["kind"] == "integer_literal" and not (
                    isinstance(declaration.value, ast.Constant) and type(declaration.value.value) is int):
                raise Refusal("owned integer bound must be a literal integer")
            if isinstance(declaration, ast.FunctionDef) and (
                    declaration.decorator_list or declaration.args.defaults or any(declaration.args.kw_defaults)):
                raise Refusal("owned guard has unsupported definition-time execution")
            # Qualify the selected function, not unrelated SDK declarations.
            globals_bound, external = {}, {}
            for node in tree.body:
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    if isinstance(node, ast.ClassDef):
                        if node.decorator_list or node.keywords or (node is not declaration and node.bases):
                            raise Refusal("owned SDK class has unsupported definition-time execution")
                        if any(not isinstance(base, ast.Name) or base.id not in external for base in node.bases):
                            raise Refusal("owned SDK class has an unqualified declaration-time base")
                        class_bound = set()
                        for child in node.body:
                            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                owned_signature(child, external, method=True, selected_class=node is declaration,
                                                bound=globals_bound, class_bound=class_bound)
                                class_bound.add(child.name)
                            elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                                targets = child.targets if isinstance(child, ast.Assign) else [child.target]
                                if any(not isinstance(target, ast.Name) for target in targets):
                                    raise Refusal("owned SDK class has dynamic assignment targets")
                                if isinstance(child, ast.AnnAssign):
                                    declaration_expression(child.annotation, external, class_bound)
                                if child.value is not None:
                                    try:
                                        ast.literal_eval(child.value)
                                    except (ValueError, TypeError) as error:
                                        raise Refusal("owned SDK class executes a dynamic assignment") from error
                                    class_bound.update(target.id for target in targets)
                            elif not (isinstance(child, ast.Pass) or isinstance(child, ast.Expr)
                                      and isinstance(child.value, ast.Constant) and isinstance(child.value.value, str)):
                                raise Refusal("owned SDK class executes unsupported namespace statements")
                    else:
                        owned_signature(node, external)
                    globals_bound[node.name] = node
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    if isinstance(node, ast.AnnAssign):
                        declaration_expression(node.annotation, external, globals_bound)
                    if node.value is not None:
                        try:
                            ast.literal_eval(node.value)
                        except (ValueError, TypeError):
                            regex = node.value
                            static_regex = (isinstance(regex, ast.Call) and isinstance(regex.func, ast.Attribute)
                                            and isinstance(regex.func.value, ast.Name) and external.get(regex.func.value.id) == "re"
                                            and regex.func.attr == "compile" and not regex.keywords and len(regex.args) in {1, 2}
                                            and isinstance(regex.args[0], ast.Constant) and isinstance(regex.args[0].value, str)
                                            and (len(regex.args) == 1 or isinstance(regex.args[1], ast.Attribute)
                                                 and isinstance(regex.args[1].value, ast.Name)
                                                 and external.get(regex.args[1].value.id) == "re" and regex.args[1].attr == "ASCII"))
                            if not static_regex and not (isinstance(node.value, ast.Name) and node.value.id in globals_bound):
                                raise Refusal("owned SDK module has dynamic assignment expressions")
                    for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                        if not isinstance(target, ast.Name):
                            raise Refusal("owned SDK module has dynamic assignment targets")
                        globals_bound[target.id] = node
                elif isinstance(node, ast.ImportFrom):
                    if node.level or any(item.name == "*" for item in node.names):
                        raise Refusal("owned SDK module has unsupported relative or wildcard imports")
                    if not trusted_from_import(node):
                        raise Refusal("owned SDK module has an unowned absolute import")
                    for item in node.names:
                        name = item.asname or item.name
                        external[name] = (node.module or "") + "." + item.name
                        globals_bound[name] = node
                elif isinstance(node, ast.Import):
                    for item in node.names:
                        if item.name.split(".")[0] not in TRUSTED_LIBRARIES:
                            raise Refusal("owned SDK module has an unowned absolute import")
                        name = item.asname or item.name.split(".")[0]
                        globals_bound[name] = node
                        external[name] = item.name if item.asname else item.name.split(".")[0]
                elif not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                    raise Refusal("owned SDK module has unsupported dynamic top-level statements")
            if globals_bound.get(alias.name) is not declaration:
                raise Refusal("owned guard's import binding is overwritten")
            synthetic = SimpleNamespace(relative=path, references=set(), imported=set(), external=external)
            visitor = reference_visitor(self.api, synthetic)
            visitor.visit(copy.deepcopy(declaration))
            if visitor.local_imports:
                raise Refusal("owned guard has unsupported nested import dependencies")
            builtins = {"str", "int", "len", "ValueError", "classmethod", "isinstance", "dict", "any"}
            for name in visitor.names & builtins:
                if name in globals_bound:
                    raise Refusal("owned guard shadows an assumed builtin: " + name)
            trusted = {name for name, symbol in external.items() if symbol.split(".")[0] in TRUSTED_LIBRARIES
                       and isinstance(globals_bound.get(name), (ast.ImportFrom, ast.Import))}
            globals_used = visitor.names - builtins - trusted
            if globals_used and descriptor["kind"] != "module_function":
                raise Refusal("owned guard has unqualified global dependencies: " + ",".join(sorted(globals_used)))
            if descriptor["kind"] == "module_function":
                # This exact parser root uses its private lexer, number rules and
                # resource constants. Bind the complete preflighted source module,
                # including every import and declaration, without following calls.
                projection = {"source_module_ast": self.api.canonical_ast(tree)}
            else:
                imports_used = {name: external[name] for name in sorted(visitor.names & trusted)}
                projection = {"source_ast": self.api.canonical_ast(declaration), "trusted_import_bindings": imports_used}
            entry = {**descriptor, "fingerprint": self.budget.fingerprint(projection)}
            self.guard_cache[key] = entry
            result[descriptor["contract"]] = entry
            self.provenance[descriptor["source"]] = hashlib.sha256(body).hexdigest()
        return result

    def contract(self, binding, active=()):
        self.budget.charge("graph_steps")
        self.budget.ceiling("model_depth", len(active) + 1)
        nominal = self.nominal(binding)
        if nominal in active:
            return {"recursive_contract": nominal}
        key = binding, active
        if key in self.cache:
            return self.cache[key]
        relative, name = binding
        module = self.models.modules[relative]
        symbols, local_imports, _ = self.projection(relative, "class", name)
        values, guards, models = {}, {}, {}
        for symbol in sorted(symbols):
            self.budget.charge("graph_edges")
            if "." in symbol:
                dependency = self.models.resolve(relative, symbol)
                models[self.nominal(dependency)] = self.contract(dependency, active + (nominal,))
                continue
            item = module.namespace.get(symbol)
            if item is None:
                continue
            owner, actual, kind = item
            if kind in {"class", "import"}:
                dependency = self.models.resolve(relative, symbol)
                if dependency != binding:
                    models[self.nominal(dependency)] = self.contract(dependency, active + (nominal,))
            elif kind in {"value", "function"}:
                values[relative + ":" + kind + ":" + actual] = self.value(relative, actual, ())
            elif kind == "external" and actual.split(".")[0] not in TRUSTED_LIBRARIES:
                package, _, member = actual.rpartition(".")
                imported = ast.ImportFrom(module=package, names=[ast.alias(name=member)], level=0)
                guards.update(self.owned_guard(relative, imported))
        for imported in local_imports:
            guards.update(self.owned_guard(relative, imported))
        result = {"local_bindings": values, "owned_sdk_guards": guards, "model_dependencies": models}
        self.cache[key] = result
        return result

    def value(self, relative, name, active):
        self.budget.charge("graph_steps")
        self.budget.ceiling("value_depth", len(active) + 1)
        identity = relative + ":" + name
        if identity in active:
            return {"recursive_binding": identity}
        key = relative, name, active
        if key in self.value_cache:
            return self.value_cache[key]
        module = self.models.modules[relative]
        symbols, local_imports, source_ast = self.projection(relative, "value", name)
        dependencies, external = {}, {}
        for symbol in sorted(symbols):
            self.budget.charge("graph_edges")
            item = module.namespace.get(symbol)
            if item and item[2] in {"value", "function"}:
                dependencies[relative + ":" + item[1]] = self.value(relative, item[1], active + (identity,))
            elif item and item[2] == "external":
                if item[1].split(".")[0] not in TRUSTED_LIBRARIES:
                    raise Refusal("unowned function/value dependency: " + item[1])
                external[symbol] = item[1]
            elif item and item[2] in {"class", "import"}:
                raise Refusal("function/value model dependencies need an explicit supported context")
        if local_imports:
            raise Refusal("function/value local imports need an explicit owned scope")
        result = {"source_ast": source_ast, "dependencies": dependencies, "trusted_import_bindings": external}
        self.value_cache[key] = result
        return result

    def inventory(self, exports):
        self.budget.ceiling("exports", len(exports))
        result, digests = {}, {}
        for export, record in sorted(exports.items()):
            relative, name = export.rsplit(":", 1)
            binding = self.models.resolve(relative, name)
            graph = self.contract(binding)
            if binding not in digests:
                digests[binding] = self.budget.fingerprint(graph)
            result[export] = {"contract": record["contract"], "fingerprint": digests[binding]}
        return {"format": FORMAT, "exports": result,
                "graphs_by_contract": {self.nominal(binding): graph for (binding, active), graph in self.cache.items() if not active},
                "external_source_provenance": self.provenance,
                "resource_limits": self.budget.limits, "resource_usage": self.budget.usage}
