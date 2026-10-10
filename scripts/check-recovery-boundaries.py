#!/usr/bin/env python3
"""Guard pure recovery sources and the isolated Cargo dependency graph.

These structural checks complement compiler, semantic tests and manual call-graph
review. The existing substrate exposes crypto facilities, so an alloc-only build
alone does not prove purity. This guard does not qualify a live recovery runtime.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
PURE = frozenset({"chio-recovery", "chio-semantic-contracts"})
PORTABLE = PURE | {"chio-core-types", "chio-security-types"}
ALLOWED = frozenset({"chio-core-types", "chio-security-types", "chio-flow", "serde"})
DEV_ALLOWED = frozenset({"chio-semantic-contracts", "serde_json"})
TEST_ONLY_FEATURES = {"chio-semantic-contracts": frozenset({"admission-test-support"})}
CRATE_PATHS = {
    "chio-core-types": "crates/core/chio-core-types",
    "chio-security-types": "crates/security/chio-security-types",
    "chio-flow": "crates/security/chio-flow",
    **{name: "crates/security/" + name for name in PURE},
}
# Reviewed portable substrate closure. New package identities need an explicit
# boundary review even when a manifest or lockfile also changes.
REGISTRY_PACKAGES = frozenset("""
base64ct block-buffer bumpalo cfg-if const-oid cpufeatures crypto-common
curve25519-dalek curve25519-dalek-derive der digest displaydoc ed25519
ed25519-dalek fiat-crypto form_urlencoded generic-array getrandom hex
icu_collections icu_locale_core icu_normalizer icu_normalizer_data icu_properties
icu_properties_data icu_provider idna idna_adapter itoa js-sys libc litemap
memchr once_cell percent-encoding pkcs8 potential_utf proc-macro2 quote
rand_core rustc_version rustversion ryu semver serde serde_core serde_derive
serde_json sha2 signature smallvec spki stable_deref_trait subtle syn synstructure
thiserror thiserror-impl tinystr typenum unicode-ident url utf8_iter version_check
wasi wasm-bindgen wasm-bindgen-macro wasm-bindgen-macro-support
wasm-bindgen-shared writeable yoke yoke-derive zerofrom zerofrom-derive zeroize
zerotrie zerovec zerovec-derive zmij
""".split())
REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
BANNED_IDENTIFIERS = frozenset({
    "std", "tokio", "SystemTime", "Instant", "OsRng", "ThreadRng",
    "SigningBackend", "RecoveryAuthorityPort", "RecoveryProcessReservationPort",
    "include", "include_str", "include_bytes", "env", "option_env",
})
BANNED_FUNCTIONS = frozenset({
    "thread_rng", "random", "generate_keypair", "sign", "sign_with_backend", "sign_payload", "now",
})
IO_MACROS = frozenset({"print", "println", "eprint", "eprintln", "dbg"})
RAW_STRING = re.compile(r'(?:b|c)?r(\#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\r\n])|[^'\\\r\n])'")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def allowed_dependencies(name):
    # Advice reuses the pure bounded contract validator. The reverse edge would
    # collapse the intentional layering and remains outside this contract.
    return ALLOWED | {"chio-semantic-contracts"} if name == "chio-recovery" else ALLOWED


def validate_portable_lock(root):
    path = Path(__file__).resolve().with_name("check-portable-recovery-lock.py")
    spec = importlib.util.spec_from_file_location("portable_lock_contract", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    workspace = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    consumer = tomllib.loads((root / "fixtures/recovery-portable-consumer/Cargo.lock").read_text(encoding="utf-8"))
    findings = module.audit_locks(workspace, consumer)
    require(not findings, f"portable lock contains {len(findings)} unapproved package identities")


def dependency_tables(manifest):
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        dependencies = manifest.get(table, {})
        require(isinstance(dependencies, dict), f"invalid {table}")
        yield table, dependencies
    targets = manifest.get("target", {})
    require(isinstance(targets, dict), "invalid target dependency tables")
    for target, declarations in targets.items():
        require(isinstance(target, str) and isinstance(declarations, dict), "invalid target declaration")
        require(set(declarations) <= {"dependencies", "dev-dependencies", "build-dependencies"},
                f"unreviewed target table: {target}")
        for table, dependencies in dependency_tables({key: value for key, value in declarations.items()}):
            yield f"target.{target}.{table}", dependencies


def dependency_declaration(alias, declaration, workspace_dependencies):
    require(isinstance(declaration, dict), f"uncontrolled dependency declaration: {alias}")
    if not declaration.get("workspace"):
        return declaration
    require(declaration["workspace"] is True and workspace_dependencies is not None,
            f"unreviewed workspace inheritance: {alias}")
    inherited = workspace_dependencies.get(alias)
    require(isinstance(inherited, dict), f"uncontrolled workspace dependency: {alias}")
    require(set(declaration) <= {"workspace", "default-features", "features", "optional"},
            f"workspace dependency overrides identity: {alias}")
    # Cargo inheritance cannot disable defaults enabled by the workspace.
    require(inherited.get("default-features") is False or declaration.get("default-features") is not False,
            f"workspace enables inherited defaults: {alias}")
    merged = {**inherited, **{key: value for key, value in declaration.items() if key != "workspace"}}
    merged["features"] = list(inherited.get("features", [])) + list(declaration.get("features", []))
    return merged


def validate_manifest(name, manifest, workspace_dependencies=None):
    require(manifest["package"]["rust-version"] == "1.93", f"MSRV changed: {name}")
    features = manifest.get("features", {})
    test_features = TEST_ONLY_FEATURES.get(name, frozenset())
    require(isinstance(features, dict) and {"default", "std"} <= set(features)
            <= {"default", "std"} | test_features, f"unreviewed pure feature: {name}")
    for feature in test_features & set(features):
        require(features[feature] == [], f"pure test feature forwards dependencies: {name}/{feature}")
    require(features["default"] == [], f"pure default feature changed: {name}")
    require(isinstance(features["std"], list) and features["std"], f"missing additive std feature: {name}")
    require(manifest["package"].get("build", False) is False, f"pure build script declared: {name}")
    require(not manifest["package"].get("links"), f"native linking declared: {name}")
    require(manifest.get("lib", {}).get("path", "src/lib.rs") == "src/lib.rs",
            f"unreviewed pure library source: {name}")
    require(not manifest.get("lib", {}).get("proc-macro"), f"pure library changed to proc macro: {name}")
    aliases = set()
    for table, dependencies in dependency_tables(manifest):
        require(not table.endswith("build-dependencies") or not dependencies,
                f"pure build dependencies forbidden: {name}/{table}")
        for alias, item in dependencies.items():
            declaration = dependency_declaration(alias, item, workspace_dependencies)
            package = declaration.get("package", alias)
            dev = table.endswith("dev-dependencies")
            require(package in (DEV_ALLOWED if dev else allowed_dependencies(name)),
                    f"effectful/unreviewed dependency: {name}/{alias} -> {package}")
            require(not declaration.get("git") and not declaration.get("registry"),
                    f"unreviewed dependency source: {name}/{alias}")
            if not dev:
                require(declaration.get("default-features") is False,
                        f"dependency defaults enabled: {name}/{alias}")
                require(not declaration.get("optional"), f"unreviewed optional dependency: {name}/{alias}")
                require(f"{alias}/std" in features["std"],
                        f"std feature does not forward to {name}/{alias}")
                require(set(declaration.get("features", [])) <= ({"derive", "alloc"} if package == "serde" else set()),
                        f"unreviewed dependency feature: {name}/{alias}")
                aliases.add(alias)
    require(set(features["std"]) == {f"{alias}/std" for alias in aliases},
            f"unreviewed std feature forwarding: {name}")


def rust_tokens(source, *, with_spans=False):
    """Tokenize names while preserving strings and Rust's nested comments.

    Literal tokens are retained for facade validation, never interpreted as code.
    This is a structural guard rather than a replacement for the Rust parser.
    """
    tokens = []
    position = 0
    length = len(source)
    def append(kind, start, end):
        token = (kind, source[start:end])
        tokens.append((*token, start, end) if with_spans else token)

    while position < length:
        if source[position].isspace():
            position += 1
            continue
        if source.startswith("//", position):
            end = source.find("\n", position + 2)
            position = length if end == -1 else end + 1
            continue
        if source.startswith("/*", position):
            depth = 1
            position += 2
            while depth and position < length:
                if source.startswith("/*", position):
                    depth += 1
                    position += 2
                elif source.startswith("*/", position):
                    depth -= 1
                    position += 2
                else:
                    position += 1
            require(depth == 0, "unterminated Rust block comment")
            continue
        raw = RAW_STRING.match(source, position)
        if raw:
            end = source.find('"' + raw[1], raw.end())
            require(end != -1, "unterminated Rust raw string")
            end += 1 + len(raw[1])
            append("literal", position, end)
            position = end
            continue
        if source[position] == '"':
            end = position + 1
            while end < length and source[end] != '"':
                end += 2 if source[end] == "\\" else 1
            require(end < length, "unterminated Rust string")
            append("literal", position, end + 1)
            position = end + 1
            continue
        char = CHAR_LITERAL.match(source, position)
        if char:
            append("literal", position, char.end())
            position = char.end()
            continue
        if source[position].isalpha() or source[position] == "_":
            end = position + 1
            while end < length and (source[end].isalnum() or source[end] == "_"):
                end += 1
            append("identifier", position, end)
            position = end
        else:
            append("punctuation", position, position + 1)
            position += 1
    return tokens


def validate_source(source, path):
    tokens = rust_tokens(source)
    for index, (kind, value) in enumerate(tokens):
        require(kind != "identifier" or value not in BANNED_IDENTIFIERS,
                f"ambient/effectful source needs review: {path}: {value}")
        if kind == "identifier" and value in BANNED_FUNCTIONS:
            before = [token[1] for token in tokens[max(0, index - 2):index]]
            after = tokens[index + 1][1] if index + 1 < len(tokens) else None
            following = [token[1] for token in tokens[index + 1:index + 3]]
            require(after not in {"(", "as"} and following != [":", ":"] and before != [":", ":"],
                    f"ambient/effectful function needs review: {path}: {value}")
        if kind == "identifier" and value in IO_MACROS:
            require(index + 1 == len(tokens) or tokens[index + 1][1] != "!",
                    f"ambient I/O macro needs review: {path}: {value}")
    values = [value for _, value in tokens]
    attribute_depth = 0
    for index, value in enumerate(values):
        if value == "[" and (attribute_depth or (index and values[index - 1] in {"#", "!"})):
            attribute_depth += 1
        elif value == "]" and attribute_depth:
            attribute_depth -= 1
        elif value == "path" and attribute_depth:
            raise ValueError(f"out-of-tree module source needs review: {path}")
    return values


def crate_attributes(values):
    """Read actual leading crate attributes, excluding unused macro token trees."""
    attributes = []
    position = 0
    while values[position:position + 3] == ["#", "!", "["]:
        start = position
        position += 3
        depth = 1
        while position < len(values) and depth:
            if values[position] == "[":
                depth += 1
            elif values[position] == "]":
                depth -= 1
            position += 1
        require(depth == 0, "unterminated crate attribute")
        attributes.append(values[start:position])
    return attributes


def validate_crate_sources(root, name):
    crate = root / CRATE_PATHS[name]
    require(not (crate / "build.rs").exists(), f"implicit pure build script: {name}")
    require(crate.resolve(strict=True) == crate, f"aliased pure crate source: {name}")
    source = crate / "src"
    require(source.resolve(strict=True) == source, f"aliased pure source directory: {name}")
    for path in source.rglob("*"):
        require(not path.is_symlink(), f"aliased pure source input: {path}")
    reviewed = []
    for path in sorted(source.rglob("*.rs")):
        values = validate_source(path.read_text(encoding="utf-8"), path.relative_to(root))
        if path == source / "lib.rs":
            attributes = crate_attributes(values)
            require(["#", "!", "[", "cfg_attr", "(", "not", "(", "feature", "=", '"std"', ")", ",", "no_std", ")", "]"] in attributes,
                    f"missing alloc-only facade: {name}")
            require(["#", "!", "[", "forbid", "(", "unsafe_code", ")", "]"] in attributes,
                    f"unsafe baseline relaxed: {name}")
        reviewed.append(str(path.relative_to(root)))
    require(str((source / "lib.rs").relative_to(root)) in reviewed, f"missing pure facade: {name}")
    return reviewed


def validate_resolved_graph(metadata, root, lock):
    require(metadata.get("version") == 1, "unreviewed Cargo metadata version")
    packages = {package["id"]: package for package in metadata["packages"]}
    require(len(packages) == len(metadata["packages"]), "duplicate Cargo package identity")
    resolution = metadata.get("resolve")
    require(isinstance(resolution, dict), "Cargo dependency resolution missing")
    nodes = {node["id"]: node for node in resolution["nodes"]}
    require(len(nodes) == len(resolution["nodes"]), "duplicate Cargo graph node")
    locked = {(package["name"], package["version"], package.get("source")) for package in lock["package"]}
    roots = {package["name"]: identity for identity, package in packages.items() if package["name"] in PURE}
    require(set(roots) == PURE and len([package for package in packages.values() if package["name"] in PURE]) == len(PURE),
            "pure Cargo graph roots missing or ambiguous")
    pending = list(roots.values())
    visited = set()
    edges = []
    while pending:
        identity = pending.pop()
        if identity in visited:
            continue
        require(identity in packages and identity in nodes, "unresolved Cargo graph identity")
        package = packages[identity]
        name = package["name"]
        if name in CRATE_PATHS:
            require(package.get("source") is None and Path(package["manifest_path"]).resolve() == root / CRATE_PATHS[name] / "Cargo.toml",
                    f"unreviewed local package identity: {name}")
        else:
            require(name in REGISTRY_PACKAGES and package.get("source") == REGISTRY_SOURCE,
                    f"effectful/unreviewed transitive dependency: {name}")
            require((name, package["version"], package["source"]) in locked,
                    f"unlocked dependency identity: {name}")
        if name in CRATE_PATHS:
            for target in package["targets"]:
                require("custom-build" not in target["kind"], f"pure build target: {name}")
                require(target["kind"] in [["lib"], ["rlib"], ["test"], ["example"], ["bench"]],
                        f"unreviewed pure target kind: {name}")
                path = Path(target["src_path"]).resolve()
                require(path.is_relative_to(root / CRATE_PATHS[name]), f"unreviewed pure target source: {name}")
                if any(kind in {"lib", "rlib", "dylib", "staticlib", "cdylib", "proc-macro"} for kind in target["kind"]):
                    require(target["kind"] in [["lib"], ["rlib"]] and path == root / CRATE_PATHS[name] / "src/lib.rs",
                            f"unreviewed pure library target: {name}")
        node = nodes[identity]
        require(isinstance(node.get("deps"), list), f"Cargo dependency kinds missing: {name}")
        require(set(node["dependencies"]) == {edge["pkg"] for edge in node["deps"]},
                f"Cargo dependency representations disagree: {name}")
        for edge in node["deps"]:
            require(edge["pkg"] in packages and edge["pkg"] in nodes, f"Cargo dependency unresolved: {name}")
            require(isinstance(edge.get("dep_kinds"), list) and edge["dep_kinds"],
                    f"Cargo dependency kinds missing: {name}/{edge['name']}")
            for declaration in edge["dep_kinds"]:
                kind = declaration.get("kind")
                require(kind in {None, "dev", "build"} and "kind" in declaration,
                        f"unreviewed Cargo dependency kind: {name}/{edge['name']}")
                require(declaration.get("target") is None or isinstance(declaration["target"], str),
                        f"unreviewed Cargo target predicate: {name}/{edge['name']}")
                if kind == "dev":
                    continue
                dependency = packages[edge["pkg"]]["name"]
                require(name not in PURE or (kind is None and dependency in allowed_dependencies(name)),
                        f"effectful/unreviewed resolved pure dependency: {name}/{dependency}")
                edges.append({"from": identity, "to": edge["pkg"], "alias": edge["name"],
                              "kind": kind, "target": declaration.get("target")})
                pending.append(edge["pkg"])
        visited.add(identity)
    return {"packages": [{key: packages[identity].get(key) for key in ("id", "name", "version", "source")}
                         for identity in sorted(visited)], "edges": edges}


def resolved_contract(std, offline, root=ROOT):
    command = ["cargo", "metadata", "--format-version", "1", "--locked",
               "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml",
               "--no-default-features"]
    if offline:
        command += ["--offline"]
    if std:
        command += ["--features", "std"]
    metadata = json.loads(subprocess.check_output(command, cwd=root))
    lock = tomllib.loads((root / "fixtures/recovery-portable-consumer/Cargo.lock").read_text())
    graph = validate_resolved_graph(metadata, root, lock)
    return validate_resolved_features(metadata, graph, std), graph


def validate_resolved_features(metadata, graph, std):
    """Audit features by package identity, retaining every reachable version."""
    packages = {package["id"]: package for package in metadata["packages"]}
    features = {node["id"]: node["features"] for node in metadata["resolve"]["nodes"]}
    for identity, enabled in features.items():
        require(identity in packages and isinstance(enabled, list)
                and all(isinstance(feature, str) for feature in enabled),
                "unreviewed Cargo feature representation")
    portable = {}
    for name in PORTABLE:
        identities = [identity for identity, package in packages.items() if package["name"] == name]
        require(len(identities) == 1 and identities[0] in features,
                f"isolated consumer does not include one unambiguous {name}")
        portable[name] = features[identities[0]]
        require(("std" in portable[name]) == std, f"isolated feature drift: {name}")
        require(not set(portable[name]) & TEST_ONLY_FEATURES.get(name, frozenset()),
                f"isolated consumer enabled test feature: {name}")
    if not std:
        for package in graph["packages"]:
            if package["name"] in {"serde", "serde_json", "sha2"}:
                require(package["id"] in features, "resolved package features missing")
                require("std" not in features[package["id"]],
                        f"alloc dependency enabled std: {package['name']} {package['version']}")
    return {name: portable[name] for name in sorted(PORTABLE)}


def resolved_features(std, offline):
    return resolved_contract(std, offline)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    validate_portable_lock(ROOT)
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text())
    workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
    reviewed_sources = []
    for name in sorted(PURE):
        manifest = tomllib.loads((ROOT / CRATE_PATHS[name] / "Cargo.toml").read_text())
        validate_manifest(name, manifest, workspace_dependencies)
        reviewed_sources.extend(validate_crate_sources(ROOT, name))
    for name in ("chio-core-types", "chio-security-types"):
        manifest = tomllib.loads((ROOT / CRATE_PATHS[name] / "Cargo.toml").read_text())
        require(manifest["package"]["rust-version"] == "1.93", f"substrate MSRV changed: {name}")
    fixture = tomllib.loads((ROOT / "fixtures/recovery-portable-consumer/Cargo.toml").read_text())
    require(set(fixture["dependencies"]) == PORTABLE, "isolated consumer inventory drift")
    require(all(item.get("default-features") is False for item in fixture["dependencies"].values()),
            "isolated consumer enabled dependency defaults")
    alloc_features, alloc_graph = resolved_contract(False, args.offline)
    std_features, std_graph = resolved_contract(True, args.offline)
    print(json.dumps({"status": "passed", "pure_sources": reviewed_sources,
                      "isolated_alloc_features": alloc_features, "isolated_std_features": std_features,
                      "isolated_alloc_graph": alloc_graph, "isolated_std_graph": std_graph}, indent=2))


if __name__ == "__main__":
    main()
