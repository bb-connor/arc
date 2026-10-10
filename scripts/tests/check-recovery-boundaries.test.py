#!/usr/bin/env python3
"""Mutation controls for the pure-crate guard without changing production crates."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("recovery_boundaries", ROOT / "scripts/check-recovery-boundaries.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
NAME = "chio-recovery"
BASE = tomllib.loads((ROOT / "crates/security" / NAME / "Cargo.toml").read_text())
WORKSPACE = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["dependencies"]


class RecoveryBoundariesTest(unittest.TestCase):
    def test_reviewed_manifest_passes(self):
        GUARD.validate_manifest(NAME, BASE, WORKSPACE)

    def test_semantic_predecessor_fixture_feature_is_empty_and_default_off(self):
        manifest = tomllib.loads((ROOT / "crates/security/chio-semantic-contracts/Cargo.toml").read_text())
        self.assertEqual(manifest["features"]["admission-test-support"], [])
        self.assertEqual(manifest["features"]["default"], [])
        try:
            GUARD.validate_manifest("chio-semantic-contracts", manifest, WORKSPACE)
        except ValueError as error:
            self.fail(f"reviewed default-off fixture feature refused: {error}")

    def test_predecessor_fixture_feature_cannot_forward_or_activate_in_production(self):
        semantic = tomllib.loads((ROOT / "crates/security/chio-semantic-contracts/Cargo.toml").read_text())
        for mutation in ["forward_std", "default_activation", "std_activation", "different_crate", "dependency_activation", "unknown_feature"]:
            with self.subTest(mutation=mutation):
                name = NAME if mutation in {"different_crate", "dependency_activation"} else "chio-semantic-contracts"
                manifest = copy.deepcopy(BASE if name == NAME else semantic)
                if mutation == "forward_std":
                    manifest["features"]["admission-test-support"] = ["serde/std"]
                elif mutation == "default_activation":
                    manifest["features"]["default"].append("admission-test-support")
                elif mutation == "std_activation":
                    manifest["features"]["std"].append("admission-test-support")
                elif mutation == "different_crate":
                    manifest["features"]["admission-test-support"] = []
                elif mutation == "dependency_activation":
                    manifest["dependencies"]["chio-semantic-contracts"]["features"] = ["admission-test-support"]
                else:
                    manifest["features"]["predecessor"] = []
                with self.assertRaises(ValueError):
                    GUARD.validate_manifest(name, manifest, WORKSPACE)

    def test_recovery_may_use_the_pure_contract_validator_without_a_reverse_edge(self):
        manifest = copy.deepcopy(BASE)
        manifest["dependencies"]["chio-semantic-contracts"] = {"path": "../chio-semantic-contracts", "default-features": False}
        if "chio-semantic-contracts/std" not in manifest["features"]["std"]:
            manifest["features"]["std"].append("chio-semantic-contracts/std")
        try:
            GUARD.validate_manifest(NAME, manifest, WORKSPACE)
        except ValueError as error:
            self.fail(f"authorized pure dependency refused: {error}")
        reverse = tomllib.loads((ROOT / "crates/security/chio-semantic-contracts/Cargo.toml").read_text())
        reverse["dependencies"]["chio-recovery"] = {"path": "../chio-recovery", "default-features": False}
        reverse["features"]["std"].append("chio-recovery/std")
        with self.assertRaisesRegex(ValueError, "unreviewed dependency"):
            GUARD.validate_manifest("chio-semantic-contracts", reverse, WORKSPACE)

    def test_unapproved_isolated_lock_is_refused_before_metadata_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "Cargo.toml").write_text((ROOT / "Cargo.toml").read_text())
            for name in sorted(GUARD.PORTABLE):
                crate = root / GUARD.CRATE_PATHS[name]
                (crate / "src").mkdir(parents=True)
                (crate / "Cargo.toml").write_text((ROOT / GUARD.CRATE_PATHS[name] / "Cargo.toml").read_text())
                (crate / "src/lib.rs").write_text('#![cfg_attr(not(feature = "std"), no_std)]\n#![forbid(unsafe_code)]\n')
            fixture = root / "fixtures/recovery-portable-consumer"
            fixture.mkdir(parents=True)
            (fixture / "Cargo.toml").write_text((ROOT / "fixtures/recovery-portable-consumer/Cargo.toml").read_text())
            dependency = '\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + "a" * 64 + '"\n'
            (root / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "serde"\nversion = "1.0.228"' + dependency)
            (fixture / "Cargo.lock").write_text('version = 4\n[[package]]\nname = "chio-recovery-portable-consumer"\nversion = "0.0.0"\n[[package]]\nname = "serde"\nversion = "1.0.229"' + dependency)
            with patch.object(GUARD, "ROOT", root), patch.object(sys, "argv", ["boundary-guard", "--offline"]), patch.object(GUARD, "resolved_contract", return_value=({}, {})) as resolution:
                with self.assertRaisesRegex(ValueError, "portable lock"):
                    GUARD.main()
                resolution.assert_not_called()

    def test_effectful_packages_cannot_hide_in_dependency_tables(self):
        declarations = [
            {"target": {"cfg(unix)": {"dependencies": {"tokio": {"version": "1", "default-features": False}}}}},
            {"build-dependencies": {"serde": {"version": "1", "default-features": False}}},
            {"target": {"cfg(windows)": {"build-dependencies": {"tokio": {"version": "1"}}}}},
            {"target": {"cfg(unix)": {"dev-dependencies": {"tokio": {"version": "1"}}}}},
        ]
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                manifest = copy.deepcopy(BASE)
                manifest.update(declaration)
                with self.assertRaises(ValueError):
                    GUARD.validate_manifest(NAME, manifest, WORKSPACE)

    def test_renamed_effectful_dependency_is_checked_by_package_identity(self):
        manifest = copy.deepcopy(BASE)
        manifest["dependencies"]["serde"]["package"] = "tokio"
        with self.assertRaises(ValueError):
            GUARD.validate_manifest(NAME, manifest, WORKSPACE)

    def test_workspace_defaults_and_unknown_features_fail_closed(self):
        for mutation in ["default_std", "enabled_defaults", "workspace_inheritance", "msrv", "std_forwarding", "effect_feature"]:
            with self.subTest(mutation=mutation):
                manifest = copy.deepcopy(BASE)
                if mutation == "default_std":
                    manifest["features"]["default"] = ["std"]
                elif mutation == "enabled_defaults":
                    manifest["dependencies"]["chio-security-types"]["default-features"] = True
                elif mutation == "workspace_inheritance":
                    manifest["dependencies"]["chio-security-types"]["workspace"] = True
                elif mutation == "msrv":
                    manifest["package"]["rust-version"] = "1.94"
                elif mutation == "std_forwarding":
                    manifest["features"]["std"] = []
                else:
                    manifest["features"]["provider"] = ["serde/unknown-effect-feature"]
                with self.assertRaises(ValueError):
                    GUARD.validate_manifest(NAME, manifest, WORKSPACE)

    def check_effect(self, source):
        with self.assertRaises(ValueError):
            GUARD.validate_source(source, "consumer.rs")

    def test_source_effects_are_detected_in_grouped_aliases_and_after_strings(self):
        for source in [
            "std::fs::read(path)", "tokio::net::TcpStream", "SystemTime::now()", "OsRng",
            "SigningBackend", "report.sign_with_backend(key)", "key.sign_payload(bytes)",
            "RecoveryAuthorityPort", "use std::{fs, net};", "std::process::Command::new(program)",
            "std::io::stdout()", "std::thread::sleep(duration)",
            'let url = "a//b"; std::fs::read(path);',
            "use std as host; host::fs::read(path);", "extern crate std as host;",
            "use std::{os::unix::net::UnixStream};", "include!(concat!(env!(\"OUT_DIR\"), \"/bridge.rs\"));",
            'println!("ambient output");', 'eprintln!("ambient output");', "dbg!(report);",
        ]:
            with self.subTest(source=source):
                self.check_effect(source)

    def test_comments_literals_and_lifetimes_do_not_change_pure_code(self):
        for source in [
            'let value = "std::fs::read(path) // text"; let x = 1;',
            'let value = r###"std::process::Command /* text */"###;',
            "/* outer /* std::io::stdout() */ still prose */ fn pure() {}",
            "// std::thread::sleep(duration)\nfn pure<'a>(v: &'a str) -> &'a str { v }",
            "fn pure() { let value = 'x'; }",
            "fn decide(now: u64, observed: u64) -> bool { observed <= now }",
        ]:
            with self.subTest(source=source):
                try:
                    GUARD.validate_source(source, "consumer.rs")
                except ValueError as error:
                    self.fail(f"pure source refused: {error}")

    def test_conditional_module_paths_cannot_escape_the_reviewed_source_tree(self):
        self.check_effect('#[cfg_attr(feature = "std", path = "../effects.rs")] mod effects;')

    def test_build_scripts_and_symlinked_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "crates/security/chio-recovery/src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text('#![cfg_attr(not(feature = "std"), no_std)]\n#![forbid(unsafe_code)]\n')
            self.assertEqual(len(GUARD.validate_crate_sources(root, NAME)), 1)
            script = source.parent / "build.rs"
            script.write_text("fn main() {}")
            with self.assertRaisesRegex(ValueError, "build script"):
                GUARD.validate_crate_sources(root, NAME)
            script.unlink()
            (source / "effects.rs").symlink_to(source / "lib.rs")
            with self.assertRaisesRegex(ValueError, "aliased"):
                GUARD.validate_crate_sources(root, NAME)

    def test_facade_attributes_must_be_active_crate_attributes(self):
        facade = '#![cfg_attr(not(feature = "std"), no_std)]\n#![forbid(unsafe_code)]\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "crates/security/chio-recovery/src"
            source.mkdir(parents=True)
            for content in [
                'macro_rules! unused { () => { ' + facade + ' }; }\n',
                '#![cfg_attr(not(feature = "std"), no_std)]\nmacro_rules! unused { () => { #![forbid(unsafe_code)] }; }\n',
            ]:
                with self.subTest(content=content):
                    (source / "lib.rs").write_text(content)
                    with self.assertRaisesRegex(ValueError, "facade|baseline"):
                        GUARD.validate_crate_sources(root, NAME)

    def test_renamed_safe_dependencies_forward_their_alias_features(self):
        manifest = copy.deepcopy(BASE)
        declaration = manifest["dependencies"].pop("serde")
        manifest["dependencies"]["wire"] = {**declaration, "package": "serde"}
        forwarding = manifest["features"]["std"].index("serde/std")
        manifest["features"]["std"][forwarding] = "wire/std"
        GUARD.validate_manifest(NAME, manifest, WORKSPACE)
        manifest["features"]["std"][forwarding] = "serde/std"
        with self.assertRaisesRegex(ValueError, "forward"):
            GUARD.validate_manifest(NAME, manifest, WORKSPACE)

    def test_workspace_inheritance_cannot_hide_defaults_or_change_package_identity(self):
        manifest = copy.deepcopy(BASE)
        manifest["dependencies"]["serde"] = {"workspace": True, "default-features": False}
        safe = {**WORKSPACE, "serde": {"version": "1", "default-features": False, "features": ["derive", "alloc"]}}
        GUARD.validate_manifest(NAME, manifest, safe)
        for declaration in [{"version": "1"}, {"package": "tokio", "version": "1", "default-features": False}]:
            with self.subTest(declaration=declaration):
                with self.assertRaises(ValueError):
                    GUARD.validate_manifest(NAME, manifest, {**WORKSPACE, "serde": declaration})

    def isolated_metadata(self):
        packages = []
        nodes = []
        for name in sorted(GUARD.PORTABLE):
            group = "core" if name == "chio-core-types" else "security"
            packages.append({
                "id": name, "name": name, "version": "0.1.0", "source": None,
                "manifest_path": str(ROOT / "crates" / group / name / "Cargo.toml"),
                "targets": [{"kind": ["lib"], "src_path": str(ROOT / "crates" / group / name / "src/lib.rs")}],
                "dependencies": [],
            })
            nodes.append({"id": name, "features": [], "dependencies": [], "deps": []})
        for node in nodes:
            if node["id"] in GUARD.PURE:
                node["dependencies"] = ["chio-core-types"]
                node["deps"] = [{"name": "chio_core_types", "pkg": "chio-core-types", "dep_kinds": [{"kind": None, "target": None}]}]
        return {"version": 1, "packages": packages, "resolve": {"nodes": nodes, "root": None}}

    def test_unknown_transitive_or_renamed_metadata_dependencies_fail_closed(self):
        metadata = self.isolated_metadata()
        packages = metadata["packages"]
        nodes = metadata["resolve"]["nodes"]
        packages += [{
            "id": "hidden-provider", "name": "tokio", "version": "1.0.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "manifest_path": "/registry/tokio/Cargo.toml", "targets": [], "dependencies": [],
        }]
        nodes.append({"id": "hidden-provider", "features": [], "dependencies": [], "deps": []})
        for node in nodes:
            if node["id"] == "chio-core-types":
                node["dependencies"] = ["hidden-provider"]
                node["deps"] = [{"name": "innocent_alias", "pkg": "hidden-provider", "dep_kinds": [{"kind": None, "target": "cfg(unix)"}]}]
        with patch.object(GUARD.subprocess, "check_output", return_value=json.dumps(metadata).encode()):
            with self.assertRaisesRegex(ValueError, "tokio|unreviewed"):
                GUARD.resolved_features(False, True)

    def test_isolated_alloc_and_std_profiles_never_enable_predecessor_fixture_feature(self):
        lock = tomllib.loads((ROOT / "fixtures/recovery-portable-consumer/Cargo.lock").read_text())
        for std in [False, True]:
            with self.subTest(std=std):
                metadata = self.isolated_metadata()
                if std:
                    for node in metadata["resolve"]["nodes"]:
                        node["features"].append("std")
                graph = GUARD.validate_resolved_graph(metadata, ROOT, lock)
                GUARD.validate_resolved_features(metadata, graph, std)
                semantic = next(node for node in metadata["resolve"]["nodes"] if node["id"] == "chio-semantic-contracts")
                semantic["features"].append("admission-test-support")
                with self.assertRaisesRegex(ValueError, "isolated.*test feature"):
                    GUARD.validate_resolved_features(metadata, graph, std)

    def test_resolved_targets_and_dependency_kinds_cannot_hide_effects(self):
        lock = tomllib.loads((ROOT / "fixtures/recovery-portable-consumer/Cargo.lock").read_text())
        GUARD.validate_resolved_graph(self.isolated_metadata(), ROOT, lock)
        for mutation in ["build_target", "binary_target", "unknown_target", "external_library", "renamed_local_package", "unknown_kind", "build_edge", "missing_kinds", "substrate_build", "substrate_proc_macro", "substrate_external_library"]:
            with self.subTest(mutation=mutation):
                metadata = self.isolated_metadata()
                package = next(item for item in metadata["packages"] if item["name"] == NAME)
                node = next(item for item in metadata["resolve"]["nodes"] if item["id"] == NAME)
                if mutation == "build_target":
                    package["targets"][0]["kind"] = ["custom-build"]
                elif mutation == "binary_target":
                    package["targets"][0]["kind"] = ["bin"]
                elif mutation == "unknown_target":
                    package["targets"][0]["kind"] = ["unreviewed"]
                elif mutation == "external_library":
                    package["targets"][0]["src_path"] = str(ROOT / "crates/kernel/chio-kernel/src/lib.rs")
                elif mutation == "renamed_local_package":
                    core = next(item for item in metadata["packages"] if item["name"] == "chio-core-types")
                    core["manifest_path"] = str(ROOT / "crates/kernel/chio-kernel/Cargo.toml")
                elif mutation == "missing_kinds":
                    node["deps"][0]["dep_kinds"] = []
                elif mutation.startswith("substrate_"):
                    substrate = next(item for item in metadata["packages"] if item["name"] == "chio-core-types")
                    if mutation == "substrate_build":
                        substrate["targets"][0]["kind"] = ["custom-build"]
                    elif mutation == "substrate_proc_macro":
                        substrate["targets"][0]["kind"] = ["proc-macro"]
                    else:
                        substrate["targets"][0]["src_path"] = str(ROOT / "crates/kernel/chio-kernel/src/lib.rs")
                else:
                    node["deps"][0]["dep_kinds"][0]["kind"] = "future-kind" if mutation == "unknown_kind" else "build"
                with self.assertRaises(ValueError):
                    GUARD.validate_resolved_graph(metadata, ROOT, lock)

    def test_alloc_features_are_checked_for_every_reachable_package_identity(self):
        approved = [package for package in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
                    if package["name"] == "sha2" and package["version"] in {"0.10.9", "0.11.0"}]
        self.assertEqual(len(approved), 2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            workspace_lock = (ROOT / "Cargo.lock").read_text()
            (root / "Cargo.lock").write_text(workspace_lock)
            fixture = root / "fixtures/recovery-portable-consumer"
            fixture.mkdir(parents=True)
            (fixture / "Cargo.lock").write_text(workspace_lock + '\n[[package]]\nname = "chio-recovery-portable-consumer"\nversion = "0.0.0"\n')
            GUARD.validate_portable_lock(root)
            metadata = self.isolated_metadata()
            for package in metadata["packages"]:
                path = root / GUARD.CRATE_PATHS[package["name"]]
                package["manifest_path"] = str(path / "Cargo.toml")
                package["targets"][0]["src_path"] = str(path / "src/lib.rs")
            for package in approved:
                identity = "sha2-" + package["version"]
                metadata["packages"].append({
                    "id": identity, "name": "sha2", "version": package["version"],
                    "source": package["source"], "manifest_path": "/registry/" + identity + "/Cargo.toml",
                    "targets": [], "dependencies": [],
                })
                metadata["resolve"]["nodes"].append({"id": identity, "features": [], "dependencies": [], "deps": []})
                core = next(node for node in metadata["resolve"]["nodes"] if node["id"] == "chio-core-types")
                core["dependencies"].append(identity)
                core["deps"].append({"name": identity.replace("-", "_"), "pkg": identity,
                                     "dep_kinds": [{"kind": None, "target": None}]})
            with patch.object(GUARD.subprocess, "check_output", return_value=json.dumps(metadata).encode()):
                GUARD.resolved_contract(False, True, root)
            for version in ["0.10.9", "0.11.0"]:
                for ordering in ["forward", "reverse"]:
                    with self.subTest(version=version, ordering=ordering):
                        altered = copy.deepcopy(metadata)
                        selected = next(node for node in altered["resolve"]["nodes"] if node["id"] == "sha2-" + version)
                        selected["features"].append("std")
                        if ordering == "reverse":
                            altered["resolve"]["nodes"].reverse()
                        with patch.object(GUARD.subprocess, "check_output", return_value=json.dumps(altered).encode()):
                            with self.assertRaisesRegex(ValueError, "alloc dependency enabled std"):
                                GUARD.resolved_contract(False, True, root)


if __name__ == "__main__":
    unittest.main()
