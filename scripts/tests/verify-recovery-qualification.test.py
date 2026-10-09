"""Qualification mutations must fail at their actual semantic boundary."""
from copy import deepcopy
from contextlib import ExitStack, redirect_stderr
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import os
import subprocess
import sys
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "scripts/verify-recovery-qualification.py"
FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "primary_compiler_probe_fixture", Path(__file__).with_name("primary_compiler_probe_fixture.py"))
PRIMARY_FIXTURE = importlib.util.module_from_spec(FIXTURE_SPEC)
FIXTURE_SPEC.loader.exec_module(PRIMARY_FIXTURE)


class QualificationAuditTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(TOOL.is_file(), "current qualification has no self-contained auditor")
        spec = importlib.util.spec_from_file_location("qualification_auditor", TOOL)
        self.audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.audit)

    def test_final_qualified_claim_refuses_missing_compiled_profiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            body = TOOL.read_bytes()
            (root/"auditor.py").write_bytes(body)
            (root/"source.tar.gz").write_bytes(b"public isolated final-claim archive stub\n")
            declared = {"path":"auditor.py","sha256":hashlib.sha256(body).hexdigest()}
            sources = [{"path":"Cargo.toml","sha256":"0"*64}]
            record = {"schema":self.audit.SCHEMA,"source_inventory_version":self.audit.INVENTORY_VERSION,
                "base_commit":"1"*40,"sources":sources,"source_binding":self.audit.binding(sources,"1"*40),
                "gates":[],"performance":{},"cohort_declaration":[],"cohort_attempts":[{"qualified":True}],
                "source_archive":{"path":"source.tar.gz","sha256":self.audit.sha(root/"source.tar.gz")},
                "auditor":declared,"artifacts":[declared],"dimension_records":{},"qualified":True}
            seal = hashlib.sha256(self.audit.canonical(record)).hexdigest()
            with patch.object(self.audit,"gate_catalog",return_value={}), \
                 patch.object(self.audit,"audit_performance"), patch.object(self.audit,"audit_attempts"), \
                 patch.object(self.audit,"audit_archive"), \
                 patch.object(self.audit,"audit_dimensions",return_value={name:True for name in
                     ["linux","formal","live_provider","hosted_ci","complete_review"]}):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_required$"):
                    self.audit.audit_record(root,record,expected_seal=seal)

    def test_raw_percentiles_are_recomputed_and_noninteger_samples_refuse(self):
        sample = {"samples":4, "samples_ns":[40,10,30,20], "p50_ns":20,
                  "p95_ns":40, "p99_ns":40, "max_ns":40}
        self.audit.audit_samples(sample)
        for change, reason in [("summary", "performance_recomputation"),
                               ("missing", "performance_raw_samples"),
                               ("boolean", "performance_raw_samples")]:
            mutated = deepcopy(sample)
            if change == "summary":
                mutated["p95_ns"] = 10
            elif change == "missing":
                del mutated["samples_ns"]
            else:
                mutated["samples_ns"][0] = True
            with self.assertRaisesRegex(ValueError, "^qualification\\."+reason+"$"):
                self.audit.audit_samples(mutated)

    def test_current_inventory_excludes_secret_content_and_metadata_cannot_claim_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git","init","--quiet"],cwd=root,check=True)
            path = root/"fixtures/private-key.pem"
            path.parent.mkdir()
            path.write_bytes(b"synthetic excluded content")
            original = self.audit.sha
            def public_only(selected):
                if Path(selected) == path:
                    raise AssertionError("secret-shaped content was hashed")
                return original(selected)
            with patch.object(self.audit,"sha",public_only):
                rows = self.audit.current_source_inventory(root)
            self.assertEqual(rows,[{"path":"fixtures/private-key.pem","state":"file",
                "mode":os.lstat(path).st_mode & 0o7777,"content_coverage":"metadata-only",
                "exclusion_reason":"secret-path-policy"}])
            self.audit.validate_source_rows(rows)
            mutated = deepcopy(rows)
            mutated[0]["sha256"] = "0"*64
            with self.assertRaisesRegex(ValueError,"^qualification.source_inventory$"):
                self.audit.validate_source_rows(mutated)

    def test_cargo_credentials_are_metadata_only_without_opening_or_hashing_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git","init","--quiet"],cwd=root,check=True)
            path = root/"fixtures/credentials.toml"
            path.parent.mkdir()
            path.write_bytes(b"synthetic excluded Cargo credential fixture\n")
            original = os.open
            def public_open(name,flags,*arguments,**keywords):
                if os.fspath(name) == "credentials.toml" and not flags & os.O_DIRECTORY:
                    raise AssertionError("excluded Cargo credential content was opened")
                return original(name,flags,*arguments,**keywords)
            with patch.object(self.audit.os,"open",side_effect=public_open):
                rows = self.audit.current_source_inventory(root)
            self.assertEqual(rows,[{"path":"fixtures/credentials.toml","state":"file",
                "mode":path.stat(follow_symlinks=False).st_mode & 0o7777,
                "content_coverage":"metadata-only","exclusion_reason":"secret-path-policy"}])
            self.audit.validate_source_rows(rows)
            self.assertEqual(self.audit.materialization_exclusion("fixtures/credentials.toml"),"secret-path-policy")

    def test_archive_and_artifact_rows_do_not_open_or_hash_excluded_contents(self):
        suffixes = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz",
                    ".txz", ".tar.zst", ".tzst", ".zip", ".7z")
        prefixes = ("docs/integrations/acceptance", *(
            f"docs/architecture/recoverable-agent-runtime/implementation/p{number}/evidence"
            for number in range(7)), "sdks/python/chio-hermes/evidence", "audits/evidence",
            "docs/integrations/session-credentials/evidence", "docs/evidence",
            "docs/research/openappa-2026-10-01/evidence", "labs/openappa-recovery/evidence",
            "formal/mutation/evidence")
        names = ["fixtures/retained/archive" + suffix for suffix in suffixes]
        names += [prefix + "/retained-source.rs" for prefix in prefixes]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"synthetic excluded content\n")
            original = os.open
            leaves = {Path(name).name for name in names}
            def public_open(name, flags, *args, **kwargs):
                if not flags & os.O_DIRECTORY and os.fsdecode(name) in leaves:
                    raise AssertionError("excluded synthetic source body was opened")
                return original(name, flags, *args, **kwargs)
            with patch.object(os, "open", side_effect=public_open), \
                    patch.object(self.audit, "sha", side_effect=AssertionError("excluded content was hashed")):
                rows = self.audit.current_source_inventory(root)
            expected = [{"path": name, "state": "file", "mode": (root/name).stat(follow_symlinks=False).st_mode & 0o7777,
                "content_coverage": "metadata-only", "exclusion_reason":
                "archive-file-policy" if index < len(suffixes) else "artifact-tree-policy"}
                for index, name in enumerate(names)]
            self.assertEqual(rows, sorted(expected, key=lambda row: row["path"]))
            self.audit.validate_source_rows(rows)
            self.assertEqual(self.audit.INVENTORY_VERSION, "chio.source-inventory.v4")
            self.assertEqual(set(self.audit.ARTIFACT_PREFIXES), set(prefixes))
            for row in rows:
                with self.subTest(path=row["path"]), self.assertRaisesRegex(ValueError, "^qualification.source_inventory$"):
                    self.audit.validate_source_rows([{"path": row["path"], "sha256": "0"*64}])

    def test_excluded_source_links_never_read_target_text(self):
        names = ["fixtures/retained.TAR.GZ", "fixtures/credentials.toml",
                 "docs/integrations/acceptance/retained-source.rs"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to("/never-read/synthetic-public-referent")
            with patch.object(os, "readlink", side_effect=AssertionError("excluded link text was read")):
                rows = self.audit.current_source_inventory(root)
            self.assertTrue(all(row["state"] == "symlink" and row["content_coverage"] == "metadata-only"
                                and "target" not in row and "sha256" not in row for row in rows))
            self.assertEqual({row["path"] for row in rows}, set(names))
            self.audit.validate_source_rows(rows)

    def test_source_projection_preserves_maintained_acceptance_and_qualification_inputs(self):
        names = ["scripts/acceptance/source.py", "fixtures/qualification/source.py",
                 "crates/platform/chio-control-plane/src/recovery/tests/knowledge/qualification.rs",
                 "crates/platform/chio-control-plane/src/recovery/tests/knowledge/qualification/proof.rs",
                 "docs/integrations/acceptance-current/source.rs", "formal/mutation/source.rs",
                 "sdks/python/chio-hermes/src/example.py", "fixtures/archive.tar.rs", "fixtures/source.gz"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            body = b"synthetic public source\n"
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
            self.assertEqual(self.audit.current_source_inventory(root), [
                {"path": name, "sha256": hashlib.sha256(body).hexdigest()} for name in sorted(names)])

    def test_archive_suffix_directories_preserve_live_and_captured_source_bytes(self):
        names = [f"crates/public{suffix}/src/lib.rs" for suffix in [".zip", ".TAR.GZ", ".7z"]]
        body = b"synthetic public source\n"
        digest = hashlib.sha256(body).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
            sources = [{"path": name, "sha256": digest} for name in sorted(names)]
            self.assertEqual(self.audit.current_source_inventory(root), sources)
            entries = {row["path"]: {"state": "file", "membership": "nonignored-untracked",
                       "content_coverage": "sha256-bytes", "sha256": digest} for row in sources}
            self.audit.audit_snapshot_sources({"entries": entries}, sources, root)
            for name in names:
                parent = str(Path(name).parents[1])
                entries[parent] = {"state": "directory"}
            self.audit.audit_snapshot_sources({"entries": entries}, sources, root)

    def test_public_alias_refuses_excluded_intermediates_before_link_reads(self):
        for name in ["fixtures/retained.zip", "docs/integrations/acceptance/retained-source.rs"]:
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
                public = root / "fixtures/input.rs"
                public.parent.mkdir(parents=True)
                public.write_bytes(b"synthetic public source\n")
                excluded = root / name
                excluded.parent.mkdir(parents=True, exist_ok=True)
                excluded.symlink_to(public)
                (root / "fixtures/input-alias.rs").symlink_to(excluded)
                original = os.readlink
                def public_link(path, *args, **kwargs):
                    if Path(path) == excluded:
                        raise AssertionError("excluded intermediate target was read")
                    return original(path, *args, **kwargs)
                with patch.object(os, "readlink", side_effect=public_link):
                    with self.assertRaisesRegex(ValueError, "^qualification.source_alias_boundary$"):
                        self.audit.current_source_inventory(root)

    def test_materialization_exclusions_bind_exact_metadata_without_link_text(self):
        for name, reason in [("fixtures/credentials.toml", "secret-path-policy"),
                             ("fixtures/retained.zip", "archive-file-policy"),
                             ("docs/integrations/acceptance/retained-source.rs", "artifact-tree-policy")]:
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                excluded = {"path": name, "content_coverage": "metadata-only", "exclusion_reason": reason,
                            "state": "symlink", "mode": 0o777}
                fixture = self.source_origin_bundle(root, extra_inputs=[excluded])
                self.assertEqual(self.check_source_origin(root, fixture), fixture["receipt"])
                excluded["link_text"] = "synthetic-omitted-target"
                fixture = self.source_origin_bundle(root, extra_inputs=[excluded])
                with self.assertRaisesRegex(ValueError, "^qualification.materialization_source_inventory$"):
                    self.check_source_origin(root, fixture)

    def test_historical_transfer_policy_cannot_acquire_current_source_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = self.source_origin_bundle(root, policy_changes={"schema": "chio.confined-return-source-inventory.v1"})
            with self.assertRaisesRegex(ValueError, "^qualification.materialization_policy$"):
                self.check_source_origin(root, fixture)

    def test_linux_reader_joins_the_complete_policy_and_closed_metadata_row(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            fixture = self.source_origin_bundle(root)
            policy = deepcopy(fixture["manifest"]["policy"])
            source = {"path": "fixtures/retained.zip", "state": "file", "mode": 0o644,
                      "content_coverage": "metadata-only", "exclusion_reason": "archive-file-policy"}
            def ref(name, value):
                raw = value.encode() if type(value) is str else json.dumps(value, sort_keys=True).encode()
                (root/name).write_bytes(raw)
                return {"path": name, "sha256": hashlib.sha256(raw).hexdigest()}
            command = ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib",
                       self.audit.LINUX_CASE_PREFIX, "--"]
            count = len(self.audit.LINUX_CASES)
            logs = [("recovery-list.log", command+["--list"], "".join(name+": test\n" for name in self.audit.LINUX_CASES)),
                ("recovery-run.log", command+["--test-threads=1"], f"running {count} tests\n"+
                 "".join("test "+name+" ... ok\n" for name in self.audit.LINUX_CASES)+
                 f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"),
                ("cage-enforcement.log", ["bash", "crates/security/chio-cage/scripts/check-linux-enforcement.sh"],
                 "CHIO_CAGE_REAL_LINUX_EVIDENCE challenge="+"1"*64+" all_targets=72 probes=27 mutations=10\n")]
            commands = []
            for name, argv, text in logs:
                reference = ref(name, text)
                commands.append({"command": argv, "exit_code": 0, "cwd": ".", "log": name,
                                 "log_sha256": reference["sha256"]})
            images = [{"path": "public-mode-"+mode, "sha256": "2"*64, "mode": mode} for mode in [
                "error", "log", "progress", "stream", "file", "callback", "wrong-predicate", "overflow", "hang"]]
            images += [{"path": "public-positive-"+str(index), "sha256": "2"*64} for index in range(2)]
            executable = {"path": "public-native-tests", "sha256": "2"*64}
            primary = {"schema": "chio.confined-return-linux-acceptance.v1", "status": "passed", "exit_code": 0,
                "expected_tests": list(self.audit.LINUX_CASES), "host": {"system": "Linux", "machine": "x86_64"},
                "commands": commands, "cage_challenge": "1"*64, "measured_images": images,
                "native_test_executable": executable}
            evidence = {"schema": "chio.recovery-linux-evidence.v1", "executables": {
                image["path"]: {"path": "retained-"+image["path"], "sha256": image["sha256"]}
                for image in images+[executable]}, "store_gate": {"id": "store"}}
            def observe(changed_policy, input_row):
                actual = {**primary, "source_inventory_policy": changed_policy}
                inputs = [] if input_row is None else [input_row]
                digest = self.audit.materialization_binding(changed_policy, inputs)
                actual.update(source_binding=digest, source_binding_after=digest)
                envelope = {**evidence, "acceptance": ref("native-parser-acceptance.json", actual),
                            "source_inputs": ref("native-parser-inputs.json", inputs)}
                with patch.object(self.audit, "checked_executable"), patch.object(self.audit, "audit_gate"), \
                        patch.object(self.audit, "audit_execution_provenance"):
                    return self.audit.audit_linux(root, envelope, "3"*64, [source], "4"*40)
            self.assertTrue(observe(policy, source))
            with self.assertRaisesRegex(ValueError, "^qualification.linux_candidate_metadata$"):
                observe(policy, None)
            for mutation in [{"excluded_archive_suffixes": []}, {"excluded_artifact_prefixes": ["crates"]},
                             {"coverage": "Self-declared arbitrary coverage"}]:
                with self.subTest(policy=mutation), self.assertRaisesRegex(ValueError, "^qualification.materialization_policy$"):
                    observe({**policy, **mutation}, source)
            for mutation in [{"mode": 0o777}, {"mode": 420.0}, {"mode": False}, {"mode": True},
                             {"sha256": "0"*64}, {"link_text": "unjoined-public-target"}]:
                with self.subTest(metadata=mutation), self.assertRaisesRegex(ValueError, "^qualification.linux_candidate_metadata$"):
                    observe(policy, {**source, **mutation})

    def test_secret_metadata_bracket_requires_truthful_coverage_without_captured_contents(self):
        source = {"path":"fixtures/private-key.pem","state":"file","mode":420,
                  "content_coverage":"metadata-only","exclusion_reason":"secret-path-policy"}
        entry = {**source,"membership":"tracked"}
        snapshot = {"entries":{source["path"]:entry}}
        self.audit.audit_snapshot_sources(snapshot,[source],Path("/candidate"))
        mutations = [{"content_coverage":"uncaptured"},{"exclusion_reason":"ignored-but-tracked"},
                     {"target":"private"},{"target_sha256":"0"*64},{"link_text":"private"},
                     {"size_bytes":1024}]
        for change in mutations:
            with self.subTest(change=change):
                mutated = deepcopy(snapshot)
                mutated["entries"][source["path"]].update(change)
                with self.assertRaisesRegex(ValueError,"^qualification.gate_source_bracket$"):
                    self.audit.audit_snapshot_sources(mutated,[source],Path("/candidate"))
        for state in ["missing","unreachable"]:
            absent = {key:value for key,value in source.items() if key != "mode"}
            absent["state"] = state
            missing = {"state":state,"membership":"tracked"}
            if state == "unreachable":
                missing["reason"] = absent["reason"] = "missing-or-nondirectory-parent"
            self.audit.audit_snapshot_sources({"entries":{source["path"]:missing}},[absent],Path("/candidate"))

    def test_directory_alias_preserves_a_contained_file_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git","init","--quiet"],cwd=root,check=True)
            payload = b"pub struct Input;\n"
            source = root/"fixtures/public/input.rs"
            source.parent.mkdir(parents=True)
            source.write_bytes(payload)
            alias = root/"fixtures/inputs/link.rs"
            alias.parent.mkdir()
            alias.symlink_to("../public/input.rs")
            (root/"fixtures/alias").symlink_to("inputs",target_is_directory=True)
            self.assertEqual(self.audit.current_source_inventory(root),[
                {"path":name,"sha256":hashlib.sha256(payload).hexdigest()} for name in [
                    "fixtures/alias/link.rs","fixtures/inputs/link.rs","fixtures/public/input.rs"]])

    def test_generated_byte_alias_cannot_collide_with_secret_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git","init","--quiet"],cwd=root,check=True)
            source = root/"fixtures/public/input.rs"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"public input\n")
            (root/"fixtures/credential\u017f").symlink_to("public",target_is_directory=True)
            blob = subprocess.check_output(["git","hash-object","-w","fixtures/public/input.rs"],cwd=root).decode().strip()
            subprocess.run(["git","update-index","--add","--cacheinfo",
                            f"100644,{blob},fixtures/credentials/input.rs"],cwd=root,check=True)
            with self.assertRaisesRegex(ValueError,"^qualification.source_case_collision$"):
                self.audit.current_source_inventory(root)

    def test_secret_metadata_refuses_a_retargeted_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            leaf = root/"fixtures/vault/credentials.json"
            leaf.parent.mkdir(parents=True)
            leaf.write_bytes(b"synthetic excluded content")
            parent = leaf.parent
            original = os.open
            swapped = False
            def retarget(name,flags,*args,**kwargs):
                nonlocal swapped
                descriptor = original(name,flags,*args,**kwargs)
                if name == "vault" and flags & os.O_DIRECTORY and not swapped:
                    parent.rename(root/"retired")
                    parent.mkdir()
                    (parent/"credentials.json").mkdir()
                    swapped = True
                return descriptor
            with patch.object(os,"open",retarget):
                with self.assertRaisesRegex(ValueError,"^qualification.source_changed_during_read$"):
                    self.audit.source_metadata(root,Path("fixtures/vault/credentials.json"))
            self.assertTrue(swapped)

    def test_public_alias_never_follows_an_excluded_intermediate_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git","init","--quiet"],cwd=root,check=True)
            source = root/"fixtures/public.rs"
            source.parent.mkdir()
            source.write_bytes(b"public input\n")
            secret = root/"fixtures/private-key.pem"
            secret.symlink_to("public.rs")
            (root/"fixtures/alias.rs").symlink_to("private-key.pem")
            original = os.readlink
            observed = []
            def readlink(path,*args,**kwargs):
                observed.append(str(path))
                return original(path,*args,**kwargs)
            with patch.object(os,"readlink",readlink):
                with self.assertRaisesRegex(ValueError,"^qualification.source_alias_boundary$"):
                    self.audit.current_source_inventory(root)
            self.assertNotIn(str(secret),observed)

    def test_captured_nested_directory_aliases_project_the_same_materialized_rows(self):
        digest = hashlib.sha256(b"public input\n").hexdigest()
        def link(target):
            return {"state":"symlink","membership":"nonignored-untracked","content_coverage":"link-text-only",
                    "target":target,"target_sha256":hashlib.sha256(target.encode()).hexdigest()}
        entries = {"fixtures/copy":link("dataset"),"fixtures/dataset/nested":link("../shared"),
                   "fixtures/shared/input.rs":{"state":"file","membership":"nonignored-untracked",
                     "content_coverage":"sha256-bytes","sha256":digest}}
        sources = [{"path":name,"sha256":digest} for name in ["fixtures/copy/nested/input.rs",
                    "fixtures/dataset/nested/input.rs","fixtures/shared/input.rs"]]
        self.audit.audit_snapshot_sources({"entries":entries},sources,Path("/candidate"))

    def test_link_syntax_preserves_required_directory_components(self):
        digest = hashlib.sha256(b"public input\n").hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git","init","--quiet"],cwd=root,check=True)
            source = root/"fixtures/public.rs"
            source.parent.mkdir()
            source.write_bytes(b"public input\n")
            (root/"fixtures/notdir").write_bytes(b"ordinary file\n")
            alias = root/"fixtures/alias.rs"
            for target in ["notdir/../public.rs","public.rs/","public.rs/."]:
                with self.subTest(target=target):
                    alias.symlink_to(target)
                    try:
                        with self.assertRaisesRegex(ValueError,"^qualification.source_alias_boundary$"):
                            self.audit.current_source_inventory(root)
                    finally:
                        alias.unlink()
                    entries = {"fixtures/alias.rs":{"state":"symlink","target":target,
                        "content_coverage":"link-text-only","target_sha256":hashlib.sha256(target.encode()).hexdigest()},
                        "fixtures/notdir":{"state":"file"},"fixtures/public.rs":{"state":"file","sha256":digest}}
                    with self.assertRaisesRegex(ValueError,"^qualification.source_alias_boundary$"):
                        self.audit.snapshot_target("fixtures/alias.rs",entries,Path("/candidate"))

    def test_deleted_public_parent_is_absent_from_runtime_source_projection(self):
        digest = hashlib.sha256(b"public input\n").hexdigest()
        sources = [{"path":"fixtures/public.py","sha256":digest}]
        entries = {"fixtures/public.py":{"state":"file","membership":"tracked",
                   "content_coverage":"sha256-bytes","sha256":digest},
                   "fixtures/removed/input.py":{"state":"unreachable","membership":"tracked",
                       "reason":"missing-or-nondirectory-parent"}}
        self.audit.audit_snapshot_sources({"entries":entries},sources,Path("/candidate"))

    def test_auditor_reference_must_match_its_retained_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            placeholder = b"unrelated archived placeholder\n"
            (root/"auditor.py").write_bytes(placeholder)
            declared = {"path":"auditor.py","sha256":hashlib.sha256(TOOL.read_bytes()).hexdigest()}
            actual = {"path":"auditor.py","sha256":hashlib.sha256(placeholder).hexdigest()}
            sources = [{"path":"Cargo.toml","sha256":"0"*64}]
            record = {"schema":self.audit.SCHEMA,"source_inventory_version":self.audit.INVENTORY_VERSION,
                "base_commit":"1"*40,"sources":sources,"source_binding":self.audit.binding(sources,"1"*40),
                "gates":[],"cohort_declaration":[],"cohort_attempts":[],"auditor":declared,
                "artifacts":[actual],"qualified":False}
            with self.assertRaisesRegex(ValueError,"^qualification.auditor_binding$"):
                self.audit.audit_record(root,record)

    def test_failed_materialization_transport_cannot_be_replaced_by_a_late_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def ref(name,value):
                raw = json.dumps(value).encode()
                (root/name).write_bytes(raw)
                return {"path":name,"sha256":hashlib.sha256(raw).hexdigest()}
            transport = ref("transfer.json",{"schema":"chio.confined-source-snapshot.v1",
                "status":"failed","exit_code":1,"actual_transport_exit":None,"timeout_seconds":900})
            origin = {"schema":"chio.rust-profile-source-origin.v1","base_commit":"1"*40,
                "source_binding":"candidate","original_repository":"/original","stages":[{"transport":transport,
                    "receipt":ref("late.json",{"schema":"chio.confined-source-snapshot.v1",
                        "status":"received","exit_code":0})}]}
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_transport_exit$"):
                self.audit.audit_source_origin(root,origin,[],"1"*40,"candidate")

    def source_origin_bundle(self, root, profile="rust-confined-return-linux", *,
                             extra_inputs=(), extra_data=None, guest_changes=None,
                             tools_data=None, archive_order="manifest-first", delivery="transport",
                             sender_location=None, receiver_location=None, source_head="1"*40,
                             policy_changes=None):
        def ref(name,value):
            raw = value if isinstance(value,bytes) else json.dumps(value,sort_keys=True).encode()
            (root/name).write_bytes(raw)
            return {"path":name,"sha256":hashlib.sha256(raw).hexdigest()}
        runner_path = "scripts/run-confined-return-linux-acceptance.py"
        data = {"fixtures/input.rs":b"public input\n", "unselected-config.txt":b"SETTING=original\n",
                runner_path:b"# synthetic retained runner, never executed\n", **(extra_data or {})}
        inputs = [{"path":name,"sha256":hashlib.sha256(raw).hexdigest()} for name,raw in data.items()]
        inputs = sorted(inputs+list(extra_inputs),key=lambda item:item["path"])
        sources = sorted([dict(item) for item in inputs if "sha256" in item
            and self.audit.source_selected(item["path"])],key=lambda item:item["path"])
        for item in extra_inputs:
            if self.audit.source_exclusion(item["path"]) is not None:
                sources.append(dict(item))
            elif "target" in item and self.audit.source_selected(item["path"]):
                target = next((row for row in inputs if row["path"] == item["target"] and "sha256" in row),None)
                if target is not None:
                    sources.append({"path":item["path"],"sha256":target["sha256"]})
        sources.sort(key=lambda item:item["path"])
        policy = {"schema":"chio.confined-return-source-inventory.v2","profile":profile,
            "coverage":"Overinclusive Git-visible candidate inputs with declared metadata-only secret, archive and artifact exclusions; not a resolved dependency graph or Python/TypeScript SDK dependency qualification.",
            "discovery":"Cached and nonignored untracked Git paths; ignored untracked inputs are not discovered.",
            "excluded_cache_parts":[".cache",".git",".ignored-cache",".mypy_cache",".next",".pytest_cache",
                ".ruff_cache",".turbo",".venv","__pycache__","node_modules","venv"],
            "excluded_secret_names":sorted(self.audit.SECRET_NAMES),
            "excluded_secret_suffixes":sorted(self.audit.SECRET_SUFFIXES),
            "excluded_secret_patterns":[".env",".env.*","secrets","secrets.*","private-key*"],
            "excluded_archive_suffixes":sorted(self.audit.ARCHIVE_SUFFIXES),
            "excluded_artifact_prefixes":sorted(self.audit.ARTIFACT_PREFIXES),
            "excluded_target_parts":["target"],"excluded_ignored_tracked_inputs":"metadata-only",
            "excluded_link_coverage":"Secret, archive and artifact exclusions have metadata-only coverage without link text or referent reads. Other excluded nonsecret links retain text only; referents are never traversed or hashed.",
            "source_link_coverage":"Relative internal links only, with exact text and independently hashed Git-visible target files."}
        policy.update(policy_changes or {})
        source_digest = self.audit.materialization_binding(policy,inputs)
        tool_data = {"runner":data[runner_path],"utility":b"# synthetic transfer utility, never executed\n",
                     **(tools_data or {})}
        tools = {name:ref(name+".py",raw) for name,raw in tool_data.items()}
        details = {item["path"]:{"mode":0o644,"size":len(data.get(item["path"],b"reserved input"))}
                   for item in inputs if "sha256" in item}
        source_location = sender_location or {"schema":"chio.source-location.v1","repository":"/original",
            "host":{"system":"Darwin","machine":"arm64","node":"synthetic-original"},
            "root":{"device":1,"inode":10,"uid":501,"mode":0o755}}
        guest_location = receiver_location or {"schema":"chio.source-location.v1","repository":"/guest",
            "host":{"system":"Linux" if delivery == "transport" else "Darwin",
                    "machine":"x86_64" if delivery == "transport" else "arm64","node":"synthetic-guest"},
            "root":{"device":2,"inode":20,"uid":501,"mode":0o700}}
        manifest = {"schema":"chio.confined-source-snapshot.v2","policy":policy,"inputs":inputs,
            "file_details":details,"host_binding":source_digest,"snapshot_id":"synthetic-snapshot",
            "runner_sha256":tools["runner"]["sha256"],"utility_sha256":tools["utility"]["sha256"],
            "host_platform":{key:source_location["host"][key] for key in ["system","machine"]},
            "source_location":source_location}
        manifest_ref = ref("manifest.json",manifest)
        archive = root/"source.tar"
        members = []
        raw_manifest = json.dumps(manifest).encode()
        header = tarfile.TarInfo("__declared_source_snapshot__.json")
        header.size,header.mode = len(raw_manifest),0o444
        members.append((header,raw_manifest))
        for item in inputs:
            name = item["path"]
            if name == "__declared_source_snapshot__.json":
                continue
            header = tarfile.TarInfo(name)
            if "sha256" in item:
                raw = data[name]
                header.size,header.mode = len(raw),details[name]["mode"]
                members.append((header,raw))
            elif "target" in item and "link_text" in item:
                header.type,header.linkname = tarfile.SYMTYPE,item["link_text"]
                members.append((header,None))
        if archive_order == "manifest-last":
            members = members[1:]+members[:1]
        with tarfile.open(archive,"w") as stored:
            for header,raw in members:
                stored.addfile(header,None if raw is None else io.BytesIO(raw))
        archive_ref = {"path":"source.tar","sha256":hashlib.sha256(archive.read_bytes()).hexdigest()}
        before = {"inputs":inputs,"policy":policy,"file_details":details,"source_binding":source_digest,
                  "git_identity":{"head":source_head},"memberships":{item["path"]:"tracked" for item in inputs},
                  "source_location":source_location}
        guest = deepcopy(inputs)
        for item in guest:
            item.update((guest_changes or {}).get(item["path"],{}))
        adjustments = [{"path":item["path"],"field":"mode","host":0o755,"guest":0o777,
            "reason":"Darwin/Linux metadata-only cache symlink mode"} for item in inputs
            if item["path"] in (guest_changes or {}) and (guest_changes or {})[item["path"]].get("mode") == 0o777]
        receipt = {"schema":"chio.confined-source-snapshot.v2","status":"received","exit_code":0,
            "candidate":guest_location["repository"],"host_binding":source_digest,
            "guest_binding":self.audit.materialization_binding(policy,guest),
            "normalized_guest_binding":source_digest,"input_paths":len(guest),"mode_adjustments":adjustments,
            "snapshot_id":manifest["snapshot_id"],"runner_sha256":manifest["runner_sha256"],
            "utility_sha256":manifest["utility_sha256"],"archive_sha256":archive_ref["sha256"],
            "archive_bytes":archive.stat().st_size,"host":{key:guest_location["host"][key] for key in ["system","machine"]},
            "location":guest_location,"uid":501,"native_profile_checked":delivery == "transport"}
        snapshot = {"schema":manifest["schema"],"status":"snapshotted","exit_code":0,
            "host_binding":source_digest,"snapshot_id":manifest["snapshot_id"],
            "payload_manifest_sha256":manifest_ref["sha256"],"archive_sha256":archive_ref["sha256"],
            "archive_bytes":archive.stat().st_size}
        stage = {"host_before":ref("before.json",before),"host_after":ref("after.json",before),
            "manifest":manifest_ref,"snapshot_result":ref("snapshot.json",snapshot),"archive":archive_ref,
            "receipt":ref("receipt.json",receipt),"guest_inventory":ref("guest.json",guest),"tools":tools,
            "delivery":delivery}
        transport = {"schema":"chio.confined-source-snapshot.v2","status":"transferred","exit_code":0,
            "actual_transport_exit":0,"host_before_captured":True,"host_after_captured":True,
            "archive_sha256":archive_ref["sha256"],"snapshot_id":manifest["snapshot_id"],
            "host_binding":source_digest,"candidate":receipt["candidate"],"source_location":source_location}
        if delivery == "transport":
            stage.update(transport=ref("transfer.json",transport),
                send_host_before=ref("send-before.json",before),send_host_after=ref("send-after.json",before),
                transport_stdout=ref("transport.stdout.log",receipt))
        candidate = self.audit.binding(sources,"1"*40)
        origin = {"schema":"chio.rust-profile-source-origin.v2","source_binding":candidate,
                  "base_commit":"1"*40,"original_repository":"/original","stages":[stage]}
        return {"ref":ref,"sources":sources,"before":before,"manifest":manifest,"snapshot":snapshot,
                "receipt":receipt,"stage":stage,"origin":origin,"candidate":candidate,
                "guest":guest,"transport":transport}

    def check_source_origin(self, root, fixture):
        return self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],"1"*40,fixture["candidate"])

    def guest_execution_bundle(self, root, fixture):
        # Parser controls only: each artifact describes a synthetic command that was never run.
        entries = self.audit.materialized_entries(fixture["guest"],
            {item["path"]:"tracked" for item in fixture["guest"]})
        for name,detail in fixture["manifest"]["file_details"].items():
            entries[name].update(mode=detail["mode"],size_bytes=detail["size"])
        for name,entry in entries.items():
            if entry["state"] == "symlink":
                entry["mode"] = 0o777
            entry["index"] = [{"mode":"100644","object":"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391","stage":0}]
            if entry.get("content_coverage") == "metadata-only":
                entry["index"][0].pop("object")
                entry["index_object_coverage"] = "redacted-by-content-policy"
        before = {"format":"chio.local-command-provenance.v1","git":{"head":None},
            "entries":entries,"explicit_file_pins":[]}
        self.reseal_full_capture(before)
        ref = fixture["ref"]
        inventory = {"source_inventory_version":self.audit.INVENTORY_VERSION,"base_commit":None,
            "sources":fixture["sources"],"source_binding":self.audit.binding(fixture["sources"],None)}
        log = ref("output.log",b"synthetic command record, never executed\n")
        result = {"format":"chio.local-command-provenance.v1","actual_command_exit":0,"runner_exit":0,
            "inventories_complete":True,"output_pipe_completed":True,"provenance_error":None,
            "source_drift":{"detected":False},"before_manifest_sha256":before["content_manifest_sha256"],
            "after_manifest_sha256":before["content_manifest_sha256"],"log":{"sha256":log["sha256"]}}
        proof = {"start":ref("start.json",{"repository":"/guest","cwd":"/guest","command":["true"],
                "environment":{}}),"before":ref("full-before.json",before),"after":ref("full-after.json",before),
            "result":ref("result.json",result),"runtime_sources_before":ref("runtime-before.json",inventory),
            "runtime_sources_after":ref("runtime-after.json",inventory),"source_origin":ref("origin.json",fixture["origin"])}
        return {"row":{"command":["true"],"cwd":".","log":log,"provenance":proof},
            "expected":{"command":["true"],"cwd":".","environment":{}},"before":before,"result":result}

    def reseal_full_capture(self, snapshot):
        manifest = {key:snapshot[key] for key in ["git","entries","explicit_file_pins"]}
        snapshot["content_manifest_sha256"] = hashlib.sha256(json.dumps(manifest,sort_keys=True,
            ensure_ascii=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()

    def test_materialization_receipt_joins_original_identity_archive_and_guest_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            self.assertEqual(self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],
                             "1"*40,fixture["candidate"]),fixture["receipt"])
            changed = deepcopy(fixture["before"])
            changed["git_identity"]["head"] = "2"*40
            fixture["stage"]["host_before"] = fixture["ref"]("wrong-before.json",changed)
            fixture["stage"]["host_after"] = fixture["ref"]("wrong-after.json",changed)
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_base_commit$"):
                self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],"1"*40,fixture["candidate"])

    def test_materialization_archive_size_is_measured_not_a_matching_false_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            for key in ["snapshot","receipt"]:
                mutated = deepcopy(fixture[key])
                mutated["archive_bytes"] -= 512
                name = "snapshot_result" if key == "snapshot" else key
                fixture["stage"][name] = fixture["ref"]("wrong-"+key+".json",mutated)
                if key == "receipt":
                    fixture["stage"]["transport_stdout"] = fixture["ref"]("wrong-stdout.log",mutated)
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_archive_bytes$"):
                self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],"1"*40,fixture["candidate"])

    def test_cross_platform_materialization_requires_the_original_transfer_outcome(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            fixture["stage"].pop("transport")
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_delivery$"):
                self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],"1"*40,fixture["candidate"])

    def test_materialization_boolean_exits_cannot_supply_an_actual_zero_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            for key in ["snapshot","receipt"]:
                mutated = deepcopy(fixture[key])
                mutated["exit_code"] = False
                name = "snapshot_result" if key == "snapshot" else key
                fixture["stage"][name] = fixture["ref"]("bool-"+key+".json",mutated)
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_exit$"):
                self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],"1"*40,fixture["candidate"])

    def test_materialization_original_repository_cannot_be_relative(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            fixture["origin"]["original_repository"] = "original"
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_origin$"):
                self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],"1"*40,fixture["candidate"])

    def test_materialization_profile_cannot_be_changed_by_resealing_consistent_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root,profile="unrelated-and-unqualified-profile")
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_policy$"):
                self.audit.audit_source_origin(root,fixture["origin"],fixture["sources"],"1"*40,fixture["candidate"])

    def test_successful_transport_must_join_the_specific_stage_and_send_bracket(self):
        mutations = [({"archive_sha256":"2"*64},"materialization_transport_binding"),
            ({"snapshot_id":"unrelated"},"materialization_transport_binding"),
            ({"host_binding":"3"*64},"materialization_transport_binding"),
            ({"candidate":"/unrelated"},"materialization_transport_binding"),
            ({"host_before_captured":False},"materialization_transport_bracket"),
            ({"host_after_captured":False},"materialization_transport_bracket")]
        for changes,reason in mutations:
            with self.subTest(changes=changes),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture = self.source_origin_bundle(root)
                transport = {**fixture["transport"],**changes}
                fixture["stage"]["transport"] = fixture["ref"]("mutated-transfer.json",transport)
                with self.assertRaisesRegex(ValueError,r"^qualification\."+reason+"$"):
                    self.check_source_origin(root,fixture)

    def test_transport_send_captures_and_stdout_receipt_are_required_and_bound(self):
        for field in ["send_host_before","send_host_after","transport_stdout"]:
            with self.subTest(missing=field),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture = self.source_origin_bundle(root)
                fixture["stage"].pop(field)
                with self.assertRaisesRegex(ValueError,"^qualification.materialization_transport_bracket$"):
                    self.check_source_origin(root,fixture)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            wrong = deepcopy(fixture["before"])
            wrong["source_binding"] = "2"*64
            fixture["stage"]["send_host_before"] = fixture["ref"]("unrelated-send.json",wrong)
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_transport_bracket$"):
                self.check_source_origin(root,fixture)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            wrong = {**fixture["receipt"],"candidate":"/unrelated"}
            fixture["stage"]["transport_stdout"] = fixture["ref"]("unrelated-stdout.log",wrong)
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_transport_receipt$"):
                self.check_source_origin(root,fixture)

    def test_full_command_capture_must_match_all_materialized_inputs_and_attributes(self):
        for change in ["unselected-bytes","unselected-missing","unselected-extra","mode","size"]:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture = self.source_origin_bundle(root)
                execution = self.guest_execution_bundle(root,fixture)
                changed = deepcopy(execution["before"])
                if change == "unselected-bytes":
                    changed["entries"]["unselected-config.txt"]["sha256"] = "2"*64
                elif change == "unselected-missing":
                    changed["entries"].pop("unselected-config.txt")
                elif change == "unselected-extra":
                    changed["entries"]["extra-root-input.txt"] = dict(changed["entries"]["unselected-config.txt"])
                elif change == "mode":
                    changed["entries"]["fixtures/input.rs"]["mode"] = 0o600
                else:
                    changed["entries"]["fixtures/input.rs"]["size_bytes"] += 1
                self.reseal_full_capture(changed)
                proof = execution["row"]["provenance"]
                proof["before"] = fixture["ref"]("changed-full-before.json",changed)
                proof["after"] = fixture["ref"]("changed-full-after.json",changed)
                result = {**execution["result"],"before_manifest_sha256":changed["content_manifest_sha256"],
                    "after_manifest_sha256":changed["content_manifest_sha256"]}
                proof["result"] = fixture["ref"]("changed-result.json",result)
                with self.assertRaisesRegex(ValueError,"^qualification.gate_materialized_sources$"):
                    self.audit.audit_execution_provenance(root,execution["row"],fixture["sources"],"1"*40,execution["expected"])

    def test_materialization_runner_tool_cannot_differ_from_the_captured_runner_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root,tools_data={"runner":b"# unrelated runner B, never executed\n"})
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_tool_binding$"):
                self.check_source_origin(root,fixture)

    def test_reserved_manifest_and_original_git_metadata_cannot_be_public_source_inputs(self):
        for name,reason in [("__declared_source_snapshot__.json","materialization_source_path"),
                            (".git/HEAD","materialization_source_path")]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture = self.source_origin_bundle(root,extra_data={name:b"synthetic excluded original metadata\n"})
                with self.assertRaisesRegex(ValueError,r"^qualification\."+reason+"$"):
                    self.check_source_origin(root,fixture)

    def test_materialization_manifest_must_be_the_first_bounded_regular_archive_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root,archive_order="manifest-last")
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_archive_manifest$"):
                self.check_source_origin(root,fixture)

    def test_materialization_source_alias_requires_exact_relative_independently_covered_target(self):
        for text,target in [("/original/fixtures/input.rs","fixtures/input.rs"),
                            ("input.rs","unselected-config.txt"),
                            ("../../outside.rs","fixtures/input.rs")]:
            with self.subTest(text=text,target=target),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture = self.source_origin_bundle(root,extra_inputs=[
                    {"path":"fixtures/link.rs","target":target,"link_text":text}])
                with self.assertRaisesRegex(ValueError,"^qualification.materialization_source_alias$"):
                    self.check_source_origin(root,fixture)

    def test_materialization_unsupported_excluded_shapes_refuse_without_inspecting_contents(self):
        for state in ["special","unreachable"]:
            with self.subTest(state=state),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                excluded = {"path":".env","content_coverage":"metadata-only",
                    "exclusion_reason":"secret-path-policy","state":state,"mode":0o600}
                fixture = self.source_origin_bundle(root,extra_inputs=[excluded])
                with self.assertRaisesRegex(ValueError,"^qualification.materialization_source_inventory$"):
                    self.check_source_origin(root,fixture)

    def test_transport_receiver_identity_is_complete_and_native(self):
        changes = [{"uid":None},{"uid":0},{"uid":True},{"native_profile_checked":False},
            {"host":None},{"host":{"system":"Darwin","machine":"arm64"}}]
        for change in changes:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                fixture = self.source_origin_bundle(root)
                receipt = {**fixture["receipt"],**change}
                fixture["stage"]["receipt"] = fixture["ref"]("wrong-receipt.json",receipt)
                with self.assertRaisesRegex(ValueError,"^qualification.materialization_receiver_identity$"):
                    self.check_source_origin(root,fixture)

    def test_materialization_source_location_binds_the_actual_original_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            fixture["origin"]["original_repository"] = "/unrelated-original"
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_source_location$"):
                self.check_source_origin(root,fixture)

    def test_cache_mode_adjustment_requires_an_actual_policy_classified_cache_path(self):
        for name,allowed in [("node_modules/cache-link",True),("unselected/public-link",False)]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                cache = {"path":name,"content_coverage":"metadata-only","exclusion_reason":"cache-tree-policy",
                    "state":"symlink","mode":0o755,"link_text":"ignored-target"}
                fixture = self.source_origin_bundle(root,extra_inputs=[cache],guest_changes={name:{"mode":0o777}})
                if allowed:
                    self.assertEqual(self.check_source_origin(root,fixture),fixture["receipt"])
                else:
                    with self.assertRaisesRegex(ValueError,"^qualification.materialization_source_policy$"):
                        self.check_source_origin(root,fixture)

    def test_relative_source_alias_preserves_complete_no_head_guest_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root,extra_inputs=[
                {"path":"fixtures/link.rs","target":"fixtures/input.rs","link_text":"input.rs"}])
            execution = self.guest_execution_bundle(root,fixture)
            self.audit.audit_execution_provenance(root,execution["row"],fixture["sources"],"1"*40,execution["expected"])

    def test_local_receive_retains_real_platform_owner_without_claiming_native_linux(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root,delivery="local")
            self.assertFalse(fixture["receipt"]["native_profile_checked"])
            self.assertEqual(self.check_source_origin(root,fixture),fixture["receipt"])
            manifest = {**fixture["manifest"],"host_platform":None}
            receipt = {**fixture["receipt"],"host":None}
            fixture["stage"]["manifest"] = fixture["ref"]("null-manifest.json",manifest)
            fixture["stage"]["receipt"] = fixture["ref"]("null-receipt.json",receipt)
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_receiver_identity$"):
                self.check_source_origin(root,fixture)

    def test_second_stage_sender_must_be_the_previous_physical_receiver(self):
        for change in [None,"repository","host","inode"]:
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                first = self.source_origin_bundle(root)
                sender = deepcopy(first["receipt"]["location"])
                if change == "repository":
                    sender["repository"] = "/unrelated-sender"
                elif change == "host":
                    sender["host"]["node"] = "unrelated-machine"
                elif change == "inode":
                    sender["root"]["inode"] += 1
                receiver = deepcopy(first["receipt"]["location"])
                receiver["repository"],receiver["root"]["inode"] = "/second-guest",30
                second_root = root/"second"
                second_root.mkdir()
                second = self.source_origin_bundle(second_root,sender_location=sender,
                    receiver_location=receiver,source_head=None,delivery="local")
                def rebase(value):
                    if isinstance(value,dict):
                        if set(value) == {"path","sha256"}:
                            return {**value,"path":"second/"+value["path"]}
                        return {key:rebase(item) for key,item in value.items()}
                    return value
                first["origin"]["stages"].append(rebase(second["stage"]))
                if change is None:
                    self.assertEqual(self.check_source_origin(root,first),second["receipt"])
                else:
                    with self.assertRaisesRegex(ValueError,"^qualification.materialization_source_location$"):
                        self.check_source_origin(root,first)

    def test_resealing_an_expanded_cache_policy_does_not_change_auditor_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root,policy_changes={"excluded_cache_parts":["unselected"]})
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_policy$"):
                self.check_source_origin(root,fixture)

    def test_ignored_tracked_cache_link_preserves_the_helper_mode_adjustment(self):
        for name,allowed in [("node_modules/cache-link",True),("unselected/public-link",False)]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                excluded = {"path":name,"content_coverage":"metadata-only","exclusion_reason":"ignored-but-tracked",
                    "state":"symlink","mode":0o755,"link_text":"ignored-target"}
                fixture = self.source_origin_bundle(root,extra_inputs=[excluded],guest_changes={name:{"mode":0o777}})
                if allowed:
                    self.assertEqual(self.check_source_origin(root,fixture),fixture["receipt"])
                else:
                    with self.assertRaisesRegex(ValueError,"^qualification.materialization_mode_adjustments$"):
                        self.check_source_origin(root,fixture)

    def test_historical_success_records_cannot_acquire_current_physical_origin_by_envelope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            fixture["origin"]["schema"] = "chio.rust-profile-source-origin.v1"
            with self.assertRaisesRegex(ValueError,"^qualification.materialization_origin$"):
                self.check_source_origin(root,fixture)

    def compiler_unit_graph_bundle(self):
        image = lambda path,digest,role:{"path":path,"sha256":digest*64,"size":7,"role":role,"artifact":"artifacts/"+digest*64}
        first = {"invocation_id":"a"*32,"kind":"compilation","status":"success","compiler_exit":0,
            "semantics":{"source":"/candidate/dependency.rs"},
            "inputs":[image("/candidate/dependency.rs","1","source")],
            "outputs":[image("/candidate/target/libdependency.rlib","2","unit")]}
        second = {"invocation_id":"b"*32,"kind":"compilation","status":"success","compiler_exit":0,
            "semantics":{"source":"/candidate/consumer.rs"},
            "inputs":[image("/candidate/consumer.rs","3","source"),image("/candidate/target/libdependency.rlib","2","extern")],
            "outputs":[image("/candidate/target/consumer","4","unit")]}
        sources = [{"path":"/candidate/dependency.rs","sha256":"1"*64,"size":7,"role":"candidate"},
                   {"path":"/candidate/consumer.rs","sha256":"3"*64,"size":7,"role":"candidate"}]
        roots = [{"path":"/candidate/target/consumer","sha256":"4"*64,"size":7}]
        return [first,second],sources,roots

    def test_source_bound_unit_and_extern_edges_do_not_claim_native_closure(self):
        rows,sources,roots = self.compiler_unit_graph_bundle()
        report = self.audit.audit_compiler_unit_graph(rows,sources,roots)
        self.assertEqual(report["verified_roots"],1)
        self.assertEqual(report["reachable_units"],2)
        self.assertEqual(report["extern_edges"],1)
        self.assertEqual(report["compiled_closure_status"],"not-established")

    def test_duplicate_root_requests_do_not_inflate_distinct_image_coverage(self):
        rows,sources,roots = self.compiler_unit_graph_bundle()
        report = self.audit.audit_compiler_unit_graph(rows,sources,[*roots,*deepcopy(roots)])
        self.assertEqual(report["verified_roots"],1)
        self.assertEqual(report["root_declarations"],2)

    def test_missing_or_failed_producers_and_wrong_root_images_refuse(self):
        for change,reason in [("missing","compiler_extern_producer"),("failed","compiler_extern_producer"),
                              ("root_hash","compiler_root_producer")]:
            with self.subTest(change=change):
                rows,sources,roots = self.compiler_unit_graph_bundle()
                if change == "missing": rows=rows[1:]
                elif change == "failed": rows[0].update(status="compiler_failed",compiler_exit=1)
                else: roots[0]["sha256"]="5"*64
                with self.assertRaisesRegex(ValueError,"^qualification."+reason+"$"):
                    self.audit.audit_compiler_unit_graph(rows,sources,roots)

    def compiler_profile_request_bundle(self, root, include_auditor=False):
        """Synthetic original parser namespace, never a compiled program."""
        subprocess.run(["git","init","--quiet"],cwd=root,check=True)
        source = root/"crates/public/src/lib.rs"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"pub struct PublicParserFixture;\n")
        if include_auditor:
            inspector = root/"scripts/verify-recovery-qualification.py"
            inspector.parent.mkdir()
            inspector.write_bytes(TOOL.read_bytes())
            (root/"scripts/record-rust-compilation.py").write_bytes((ROOT/"scripts/record-rust-compilation.py").read_bytes())
        fixture = self.compiler_publication_bundle(root/"target")
        namespace = fixture["namespace"]
        output = root/"target/output/parser-image"
        output.parent.mkdir()
        output.write_bytes(b"synthetic output, never executed\n")
        def image(path, role):
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            (namespace/"artifacts"/digest).write_bytes(raw)
            return {"path":str(path),"sha256":digest,"size":len(raw),
                    "role":role,"artifact":"artifacts/"+digest}
        sources = self.audit.current_source_inventory(root)
        runtime = {"source_inventory_version":self.audit.INVENTORY_VERSION,"base_commit":None,
                   "sources":sources,"source_binding":self.audit.binding(sources,None)}
        inventory_path = root/"target/runtime.json"
        inventory_path.write_bytes(self.audit.compilation_canonical(runtime)+b"\n")
        row = fixture["row"]
        row.update(source_binding=runtime["source_binding"],
                   inputs=[image(source,"source")],outputs=[image(output,"unit")],
                   semantics={"source":str(source),"cwd":str(root)})
        raw = self.audit.compilation_canonical(row)+b"\n"
        fixture["record"].write_bytes(raw)
        completion = json.loads(fixture["marker"].read_bytes())
        completion.update(source_binding=runtime["source_binding"],size=len(raw),
                          record_sha256=hashlib.sha256(raw).hexdigest())
        fixture["marker"].write_bytes(self.audit.compilation_canonical(completion)+b"\n")
        request = {"schema":"chio.compiler-profile-custody-request.v1","namespace":str(namespace),
            "repository":str(root),"runtime_inventory":{"path":str(inventory_path),
                "sha256":self.audit.sha(inventory_path)},"source_binding":runtime["source_binding"],
            "roots":[{key:row["outputs"][0][key] for key in ["path","sha256","size"]}],
            "additional_inputs":[],"selected_invocation_ids":[row["invocation_id"]],
            "mode":"host-trusted-fresh","linux":None}
        request_path = root/"target/request.json"
        request_path.write_bytes(self.audit.compilation_canonical(request)+b"\n")
        return {**fixture,"request":request,"request_path":request_path,"runtime":runtime,
                "source":source,"output":output}

    def test_original_host_profile_observation_is_unqualified_and_source_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.compiler_profile_request_bundle(Path(temporary).resolve())
            report = self.audit.inspect_compiler_profile_request(fixture["request_path"])
            self.assertFalse(report["qualified"])
            self.assertEqual(report["profile"]["unit_graph"]["verified_roots"],1)
            self.assertEqual(report["profile"]["compiled_closure_status"],"not-established")
            fixture["source"].write_bytes(b"changed current source\n")
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_source$"):
                self.audit.inspect_compiler_profile_request(fixture["request_path"])

    def test_original_host_profile_refuses_changed_root_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.compiler_profile_request_bundle(Path(temporary).resolve())
            fixture["output"].write_bytes(b"stale output from a different producer\n")
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_roots$"):
                self.audit.inspect_compiler_profile_request(fixture["request_path"])

    def test_original_host_profile_does_not_open_secret_named_additional_inputs(self):
        with tempfile.TemporaryDirectory() as temporary,tempfile.TemporaryDirectory() as excluded:
            root = Path(temporary).resolve()
            fixture = self.compiler_profile_request_bundle(root)
            secret = Path(excluded).resolve()/"credentials.toml"
            secret.write_bytes(b"synthetic policy control\n")
            request = fixture["request"]
            request["additional_inputs"] = [{"path":str(secret),"sha256":self.audit.sha(secret),
                "size":secret.stat().st_size,"role":"toolchain"}]
            fixture["request_path"].write_bytes(self.audit.compilation_canonical(request)+b"\n")
            original = self.audit.regular_input
            def public_only(path):
                if Path(path) == secret:
                    raise AssertionError("excluded original was opened")
                return original(path)
            with patch.object(self.audit,"regular_input",side_effect=public_only):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_input_policy$"):
                    self.audit.inspect_compiler_profile_request(fixture["request_path"])

    def test_rust_format_has_no_fabricated_compilation_subject(self):
        record = {"gates":[{"id":"format","command":["cargo","fmt","--all","--","--check"]},
                           {"id":"contracts","command":["cargo","test"],"executables":[]}],
                  "performance":None,"dimension_records":{}}
        self.assertEqual(self.audit.compiled_subjects(Path("/unused"),record),{"gate/contracts":[]})

    def test_compiled_subject_binding_checks_the_entire_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root/"profile.json").write_text("{}")
            reference = {"path":"profile.json","sha256":self.audit.sha(root/"profile.json")}
            report = {"subjects":{"gate/contracts":[{"path":"/candidate/target/test",
                "sha256":"1"*64,"size":9}]},"roots":{("/candidate/target/test","1"*64,9)}}
            record = {"compiled_profiles":[reference],"gates":[{"id":"contracts","command":["cargo","test"],
                "executables":[{"path":"retained/test","sha256":"1"*64,"size":10}]}]}
            with patch.object(self.audit,"audit_compiled_profile",return_value=report):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_roots$"):
                    self.audit.audit_compiled_profiles(root,record,"2"*64,[],"3"*40)

    def test_original_profile_cannot_claim_linux_protection_on_this_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.compiler_profile_request_bundle(Path(temporary).resolve())
            fixture["request"].update(mode="linux-enforced",linux={"qualified":True})
            fixture["request_path"].write_bytes(self.audit.compilation_canonical(fixture["request"])+b"\n")
            with patch.object(self.audit.platform,"system",return_value="Darwin"):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_mode$"):
                    self.audit.inspect_compiler_profile_request(fixture["request_path"])

    def test_linux_profile_refuses_missing_scope_and_primary_execution(self):
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_linux_required$"):
            self.audit.audit_linux_compiled_profile(Path("/unused"),None,None,None,"1"*64,[],"2"*40,[])

    def test_named_immutable_extern_cannot_replace_a_real_producer(self):
        rows,sources,_roots = self.compiler_unit_graph_bundle()
        old = {key:rows[1]["inputs"][1][key] for key in ["path","sha256","size"]}
        old.update(path="/outside-cache/old.rlib",role="toolchain")
        rows[1]["inputs"][1].update(path=old["path"])
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_immutable_producer$"):
            self.audit.compiler_immutable_externs(rows[1:],[old])

    def test_recorded_toolchain_images_and_declared_native_scope_are_distinct_inputs(self):
        rows,_sources,_roots = self.compiler_unit_graph_bundle()
        image = {key:rows[1]["inputs"][1][key] for key in ["path","sha256","size"]}
        image.update(path="/toolchain/lib/std.rlib",role="toolchain")
        rows[1]["inputs"][1].update(path=image["path"])
        rows[1]["inputs"].append({**image,"role":"toolchain","coverage":"conservative-toolchain-scope"})
        self.assertEqual(self.audit.compiler_immutable_externs(rows[1:],[image]),[image])
        rows[1]["inputs"].pop()
        rows[1]["semantics"]["native_scope"] = {"scope_id":"5"*64}
        rows[1]["inputs"][1].update(origin="declared-immutable-scope",immutable_scope={
            "scope_id":"5"*64,"path":image["path"],"sha256":image["sha256"]})
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_immutable_producer$"):
            self.audit.compiler_immutable_externs(rows[1:],[image])
        # This synthetic map models the private result of native scope joins.
        # It does not establish actual Linux execution or confinement.
        verified = {"5"*64:{self.audit.compiler_graph_image(image)}}
        self.assertEqual(self.audit.compiler_immutable_externs(rows[1:],[image],verified),[image])
        rows[1]["inputs"][1]["immutable_scope"]["scope_id"] = "6"*64
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_immutable_producer$"):
            self.audit.compiler_immutable_externs(rows[1:],[image],verified)

    def compiled_profile_archive_bundle(self, root):
        """Decoded archive controls with synthetic rows and no compiler run."""
        repository = root/"original"
        repository.mkdir()
        fixture = self.compiler_profile_request_bundle(repository,include_auditor=True)
        def reference(name, value):
            path = root/name
            path.write_bytes(self.audit.compilation_canonical(value)+b"\n")
            return {"path":name,"sha256":self.audit.sha(path)}
        runtime = fixture["runtime"]
        runtime_ref = reference("runtime.json",runtime)
        request_ref = reference("request.json",fixture["request"])
        report = self.audit.inspect_compiler_profile_request(fixture["request_path"])
        self.assertEqual(report["request_sha256"],request_ref["sha256"])
        report_ref = reference("report.json",report)
        inspector = root/"inspector.py"
        inspector.write_bytes(TOOL.read_bytes())
        tool = {"path":"inspector.py","sha256":self.audit.sha(inspector)}
        pins = [{"purpose":"compiler-profile-request","path":str(fixture["request_path"]),
                 "observed":{"sha256":request_ref["sha256"]}},
                {"purpose":"compiler-profile-inspector","path":str(repository/"scripts/verify-recovery-qualification.py"),
                 "observed":{"sha256":tool["sha256"]}}]
        start = reference("start.json",{"repository":str(repository),"environment":{
            "RUSTC_WRAPPER":str(repository/"scripts/record-rust-compilation.py"),
            "CHIO_COMPILATION_RECORDS":str(fixture["namespace"]),
            "CHIO_COMPILATION_SOURCE_ROOT":str(repository),"CHIO_COMPILATION_SOURCE_BINDING":runtime["source_binding"]}})
        snapshot = reference("pins.json",{"explicit_file_pins":pins})
        log = root/"custody.log"
        log.write_text("COMPILER_PROFILE_CUSTODY "+json.dumps(report,sort_keys=True)+"\n")
        execution = {"log":{"path":"custody.log","sha256":self.audit.sha(log)},
            "provenance":{"start":start,"before":snapshot,"after":snapshot}}
        producer = {"id":"contracts","command":self.audit.gate_catalog()["contracts"]["command"],
                    "provenance":{"start":start,"before":snapshot,"after":snapshot}}
        images = []
        for image in [*fixture["row"]["inputs"],*fixture["row"]["outputs"],fixture["row"]["compiler"]]:
            name = "image-"+image["sha256"]
            if (root/name).exists():
                continue
            (root/name).write_bytes((fixture["namespace"]/image["artifact"]).read_bytes())
            images.append({"path":name,"sha256":image["sha256"],"size":image["size"]})
        roots = fixture["request"]["roots"]
        profile = {"schema":"chio.compiled-profile-evidence.v1","source_binding":runtime["source_binding"],
            "mode":"host-trusted-fresh","subjects":{"gate/contracts":roots},"producer":producer,
            "runtime_inventory":runtime_ref,"custody_request":request_ref,"custody_report":report_ref,
            "custody_execution":execution,"custody_tool":tool,"rows":reference("rows.json",[fixture["row"]]),
            "inputs":[{key:image[key] for key in ["path","sha256","size"]}|{"role":"candidate"}
                      for image in fixture["row"]["inputs"]],"roots":roots,"images":images,"linux":None}
        return {"fixture":fixture,"profile":profile,"reference":reference,"report":report}

    def test_legacy_compiled_archive_cannot_replace_current_publication_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = self.compiled_profile_archive_bundle(root)
            runtime = bundle["fixture"]["runtime"]
            # Process checks are isolated here; actual process evidence is a separate gate.
            with patch.object(self.audit,"audit_gate"),patch.object(self.audit,"audit_execution_provenance"):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_current_publication$"):
                    self.audit.audit_compiled_profile(root,bundle["profile"],runtime["source_binding"],runtime["sources"],None)
            # The historical decoded graph remains inspectable as a primitive.
            # It cannot substitute for the current physical and process proof.
            result = self.audit.audit_compiler_unit_graph([bundle["fixture"]["row"]],
                bundle["profile"]["inputs"],bundle["profile"]["roots"])
            self.assertEqual(result["verified_roots"],1)
            self.assertEqual(result["compiled_closure_status"],"not-established")
            self.assertNotIn("qualified",result)

    def test_compiled_archive_refuses_stale_source_custody_and_image_changes(self):
        for mutation,reason in [("runtime","compiled_profile_source"),("host","compiled_profile_custody"),
                ("source","compiled_profile_source"),("image","compiled_profile_image"),("request","compiled_profile_source")]:
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                bundle = self.compiled_profile_archive_bundle(root)
                profile, fixture, reference = (bundle[key] for key in ["profile","fixture","reference"])
                runtime = fixture["runtime"]
                if mutation == "runtime":
                    changed = deepcopy(runtime);changed["sources"][0]["sha256"] = "0"*64
                    profile["runtime_inventory"] = reference("changed-runtime.json",changed)
                elif mutation == "host":
                    changed = deepcopy(bundle["report"]);changed["host"] = {"system":"Darwin","qualified":True}
                    profile["custody_report"] = reference("changed-report.json",changed)
                elif mutation == "source": profile["inputs"][0]["path"] = str(root/"original/crates/obsolete/lib.rs")
                elif mutation == "image": (root/profile["images"][0]["path"]).write_bytes(b"substituted\n")
                else:
                    changed = deepcopy(fixture["request"]);changed["runtime_inventory"]["sha256"] = "0"*64
                    profile["custody_request"] = reference("changed-request.json",changed)
                    report = deepcopy(bundle["report"]);report["request_sha256"] = profile["custody_request"]["sha256"]
                    profile["custody_report"] = reference("changed-report.json",report)
                with patch.object(self.audit,"audit_gate"),patch.object(self.audit,"audit_execution_provenance"):
                    with self.assertRaisesRegex(ValueError,"^qualification."+reason+"$"):
                        self.audit.audit_compiled_profile(root,profile,runtime["source_binding"],runtime["sources"],None)

    def test_compiled_archive_cannot_attach_a_namespace_to_an_uninstrumented_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = self.compiled_profile_archive_bundle(root)
            profile, runtime = bundle["profile"],bundle["fixture"]["runtime"]
            start = bundle["reference"]("uninstrumented-start.json",{"repository":str(root/"original"),"environment":{}})
            profile["producer"]["provenance"]["start"] = start
            with patch.object(self.audit,"audit_gate"),patch.object(self.audit,"audit_execution_provenance"):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_compiler_context$"):
                    self.audit.audit_compiled_profile(root,profile,runtime["source_binding"],runtime["sources"],None)

    def test_compiled_gate_subject_requires_its_own_cargo_producer(self):
        for names in [["gate/kernel"], ["gate/"+name for name,item in self.audit.gate_catalog().items()
                if item["command"][0] in {"cargo","target/debug/xtask"} and name != "format"]]:
            with self.subTest(subjects=names),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                bundle = self.compiled_profile_archive_bundle(root)
                runtime,profile = bundle["fixture"]["runtime"],bundle["profile"]
                profile["subjects"] = {name:profile["roots"] for name in names}
                reference = bundle["reference"]("profile.json",profile)
                record = {"compiled_profiles":[reference],"gates":[
                    {"id":name.removeprefix("gate/"),"command":self.audit.gate_catalog()[name.removeprefix("gate/")]["command"]}
                    for name in names]}
                # Synthetic rows isolate gate and enclosing-process verification.
                with patch.object(self.audit,"audit_gate"),patch.object(self.audit,"audit_execution_provenance"):
                    with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_producer_subject$"):
                        self.audit.audit_compiled_profiles(root,record,runtime["source_binding"],runtime["sources"],None)

    def test_compiled_dimension_subject_cannot_borrow_an_unrelated_cargo_producer(self):
        for name in ["dimension/linux/native","dimension/formal/solver","dimension/live_provider/host"]:
            with self.subTest(subject=name),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                bundle = self.compiled_profile_archive_bundle(root)
                runtime,profile = bundle["fixture"]["runtime"],bundle["profile"]
                profile["subjects"] = {name:profile["roots"]}
                with patch.object(self.audit,"audit_gate"),patch.object(self.audit,"audit_execution_provenance"), \
                        patch.object(self.audit,"audit_current_compiled_publication"):
                    with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_producer_subject$"):
                        self.audit.audit_compiled_profile(root,profile,runtime["source_binding"],runtime["sources"],None)

    def test_host_cached_extern_refuses_self_declared_native_scope(self):
        rows,_sources,_roots = self.compiler_unit_graph_bundle()
        image = {key:rows[1]["inputs"][1][key] for key in ["path","sha256","size"]}
        image.update(path="/outside-cache/project.rlib",role="toolchain")
        rows[1]["semantics"]["native_scope"] = {"scope_id":"5"*64}
        rows[1]["inputs"][1].update(path=image["path"],origin="declared-immutable-scope",
            immutable_scope={"scope_id":"5"*64,"path":image["path"],"sha256":image["sha256"]})
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_immutable_producer$"):
            self.audit.compiler_immutable_externs(rows[1:],[image])

    def test_compiled_images_remain_bound_until_the_aggregate_returns(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = self.compiled_profile_archive_bundle(root)
            runtime,profile = bundle["fixture"]["runtime"],bundle["profile"]
            selected = next(image for image in profile["images"] if image["sha256"] == profile["roots"][0]["sha256"])
            original,checked = self.audit.checked_compiled_blob,[]
            def change_after_the_last_individual_check(evidence_root,image):
                original(evidence_root,image)
                checked.append(image["sha256"])
                if len(checked) == len(profile["images"]):
                    (root/selected["path"]).write_bytes(b"X"*selected["size"])
            reference = bundle["reference"]("profile.json",profile)
            record = {"compiled_profiles":[reference],"gates":[profile["producer"]]}
            # Isolate aggregate image custody; current publication/process proof
            # is verified by separate controls and cannot come from this legacy fixture.
            with patch.object(self.audit,"checked_compiled_blob",side_effect=change_after_the_last_individual_check), \
                    patch.object(self.audit,"audit_current_compiled_publication"), \
                    patch.object(self.audit,"audit_gate"),patch.object(self.audit,"audit_execution_provenance"):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_image$"):
                    self.audit.audit_compiled_profiles(root,record,runtime["source_binding"],runtime["sources"],None)

    def test_compiled_image_custody_bounds_the_complete_retained_pool(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            images = []
            for name,payload in [("first",b"12345678"),("second",b"abcdefgh")]:
                (root/name).write_bytes(payload)
                images.append({"path":name,"sha256":hashlib.sha256(payload).hexdigest(),"size":len(payload)})
            with patch.object(self.audit,"COMPILED_IMAGE_POOL_MAX_BYTES",15):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_image_budget$"):
                    with self.audit.compiled_image_custody(root) as hold:
                        hold(images[0])
                        hold(images[0])
                        hold(images[1])
            with patch.object(self.audit,"COMPILED_IMAGE_POOL_MAX_BYTES",16):
                with self.audit.compiled_image_custody(root) as hold:
                    for image in [images[0],images[0],images[1]]:
                        hold(image)

    def test_actual_large_retention_pool_requires_declared_descriptor_capacity(self):
        """Actual publisher/physical-reader resource composition, no Rust run."""
        code = r'''
import contextlib,hashlib,importlib.util,json,os,pathlib,resource,sys,tempfile
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
audit=load('large_pool_auditor',sys.argv[1]);recorder=load('large_pool_recorder',sys.argv[2])
with tempfile.TemporaryDirectory() as temporary:
 root=pathlib.Path(temporary).resolve();namespace=root/'target/records';namespace.mkdir(parents=True)
 with contextlib.redirect_stderr(open(os.devnull,'w')):
  campaign=recorder.Campaign(namespace,'a'*64)
  try:
   with campaign.retention_batch():
    for index in range(1637):campaign.retain(('PUBLIC-DESCRIPTOR-CUSTODY-'+str(index)).encode())
  finally:campaign.close()
 observed={'artifacts':len(list((namespace/'artifacts').iterdir())),'controls':{},'compiler_executed':False}
 hard=resource.getrlimit(resource.RLIMIT_NOFILE)[1]
 original=audit.regular_input;reads=0;pool_entries=0
 @contextlib.contextmanager
 def counted(path):
  global reads
  reads+=1
  with original(path) as stream:yield stream
 audit.regular_input=counted
 original_pool=audit.compiler_input_custody
 @contextlib.contextmanager
 def counted_pool():
  global pool_entries
  pool_entries+=1
  with original_pool() as regular:yield regular
 audit.compiler_input_custody=counted_pool
 resource.setrlimit(resource.RLIMIT_NOFILE,(1024,hard))
 try:audit.audit_compiler_publications(namespace,'a'*64);observed['low']='accepted'
 except Exception as error:observed['low']={'type':type(error).__name__,'reason':str(error),'regular_reads':reads,'pool_entries':pool_entries}
 resource.setrlimit(resource.RLIMIT_NOFILE,(32768,hard))
 before_limit=resource.getrlimit(resource.RLIMIT_NOFILE)
 capacity=audit.original_compiler_descriptor_capacity(namespace)
 report=audit.audit_compiler_publications(namespace,'a'*64)
 observed['capacity']={'required':capacity['required_descriptors'],'leaves':capacity['regular_namespace_leaves'],
  'budget':capacity['descriptor_budget'],'limit_changed':capacity['limit_changed'],
  'process_limits_unchanged':before_limit==resource.getrlimit(resource.RLIMIT_NOFILE)}
 observed['positive']={'records':report['verified_records'],'artifacts':report['verified_artifacts'],'closure':report['compiled_closure_status']}
 victim=next((namespace/'artifacts').iterdir());saved=victim.read_bytes();victim.write_bytes(b'PUBLIC-MUTATED-CUSTODY')
 try:audit.audit_compiler_publications(namespace,'a'*64);observed['controls']['changed']='accepted'
 except (ValueError,OSError):observed['controls']['changed']='refused'
 victim.write_bytes(saved);victim.unlink()
 try:audit.audit_compiler_publications(namespace,'a'*64);observed['controls']['missing']='accepted'
 except (ValueError,OSError):observed['controls']['missing']='refused'
 print(json.dumps(observed))
'''
        command = [sys.executable,"-I","-B",*(["-O"] if sys.flags.optimize else []),"-c",code,
                   str(TOOL),str(ROOT/"scripts/record-rust-compilation.py")]
        result = subprocess.run(command,cwd=ROOT,capture_output=True,timeout=90)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        observed = json.loads(result.stdout)
        self.assertEqual(observed["artifacts"],1637)
        self.assertEqual(observed["low"],{"type":"ValueError",
            "reason":"qualification.compiler_descriptor_capacity","regular_reads":0,"pool_entries":0})
        self.assertEqual(observed["positive"],{"records":0,"artifacts":1637,"closure":"not-established"})
        self.assertGreater(observed["capacity"]["required"],1637)
        self.assertLessEqual(observed["capacity"]["required"],32768)
        self.assertEqual(observed["capacity"]["leaves"],1639)
        self.assertEqual(observed["capacity"]["budget"],32768)
        self.assertFalse(observed["capacity"]["limit_changed"])
        self.assertTrue(observed["capacity"]["process_limits_unchanged"])
        self.assertEqual(observed["controls"],{"changed":"refused","missing":"refused"})
        self.assertFalse(observed["compiler_executed"])

    def test_compiler_input_custody_holds_shared_ancestry_and_each_original_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            directory = root/"public"
            directory.mkdir()
            first, second = directory/"first", directory/"second"
            first.write_bytes(b"PUBLIC-FIRST")
            second.write_bytes(b"PUBLIC-SECOND")
            from contextlib import ExitStack
            with self.audit.compiler_input_custody() as regular:
                with ExitStack() as held:
                    left = held.enter_context(regular(first))
                    right = held.enter_context(regular(second))
                    self.assertEqual(left.read(),b"PUBLIC-FIRST")
                    self.assertEqual(right.read(),b"PUBLIC-SECOND")
                    self.assertEqual(os.fstat(left.fileno()).st_ino,first.stat().st_ino)
                    self.assertNotEqual(left.fileno(),right.fileno())
            with self.assertRaisesRegex(ValueError,"^qualification.compiler_namespace_changed$"):
                with self.audit.compiler_input_custody() as regular:
                    with ExitStack() as held:
                        left = held.enter_context(regular(first))
                        right = held.enter_context(regular(second))
                        directory.rename(root/"displaced-public")
                        directory.mkdir()
                        (directory/"first").write_bytes(b"PUBLIC-FIRST")
                        (directory/"second").write_bytes(b"PUBLIC-SECOND")
                        self.assertEqual(left.read(),b"PUBLIC-FIRST")
                        self.assertEqual(right.read(),b"PUBLIC-SECOND")

    def test_descriptor_capacity_without_resource_api_has_a_typed_refusal(self):
        import builtins
        original = builtins.__import__
        def unsupported(name,*args,**kwargs):
            if name == "resource":
                raise ModuleNotFoundError("resource API unavailable in this control")
            return original(name,*args,**kwargs)
        with patch.object(builtins,"__import__",side_effect=unsupported):
            self.assertIn("workspace-msrv",self.audit.gate_catalog())
            with self.assertRaisesRegex(ValueError,"^qualification.compiler_descriptor_capacity$"):
                self.audit.original_compiler_descriptor_capacity(Path("/unused-original-namespace"))

    def test_workspace_msrv_gate_uses_the_supported_workspace_toolchain(self):
        catalog = self.audit.gate_catalog()
        expected = ["cargo","+1.95.0","check","--offline","--locked","--workspace","--all-targets"]
        self.assertEqual(catalog.get("workspace-msrv",{}).get("command"),expected)
        # The portable crates retain their separately declared minimum version.
        for name in ["allocator-msrv","standard-msrv"]:
            self.assertEqual(catalog[name]["command"][1],"+1.93.0")

    def test_explicit_read_directory_metadata_cannot_expand_the_approved_file_scope(self):
        selected = ["bin/python","lib/python3.12/codecs.py","lib/python3.12/encodings/__init__.py"]
        configured = {"role":"native-runtime","root":"/usr","selection":"explicit-members","members":selected}
        names = ["bin","lib/python3.12","lib/python3.12/encodings"]
        inventory = {"schema":"chio.compilation-read-scope.v2",**{key:configured[key] for key in ["role","root","selection"]},
            "members":[{"path":name,"kind":"regular"} for name in selected],"directories":names,
            "directory_metadata":[{"path":name,"identity":[1,index+1,0o40755]} for index,name in enumerate(names)]}
        self.audit.audit_compilation_directory_inventory(configured,inventory)
        mutations = ["parent","missing","metadata","mode","boolean","version","selected","payload"]
        for change in mutations:
            value = deepcopy(inventory)
            if change == "parent":
                value["directories"].insert(0,".")
                value["directory_metadata"].insert(0,{"path":".","identity":[1,10,0o40755]})
            elif change == "missing":value["directories"].pop();value["directory_metadata"].pop()
            elif change == "metadata":value["directory_metadata"][0]["path"] = "lib"
            elif change == "mode":value["directory_metadata"][0]["identity"][2] = 0o100644
            elif change == "boolean":value["directory_metadata"][0]["identity"][0] = True
            elif change == "version":value["schema"] = []
            elif change == "selected":value["members"].pop()
            else:value["directory_metadata"][0]["contents"] = "SYNTHETIC-UNLISTED-CONTENT"
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError,"^qualification.compilation_scope_directories$"):
                    self.audit.audit_compilation_directory_inventory(configured,value)

    def test_explicit_read_directory_metadata_rejoins_original_no_follow_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            child = root/"encodings"
            child.mkdir()
            (child/"credentials.toml").write_bytes(b"SYNTHETIC-UNLISTED-CONTENT")
            info = child.stat()
            metadata = {"path":"encodings","identity":[info.st_dev,info.st_ino,info.st_mode]}
            inventory = {"schema":"chio.compilation-read-scope.v2","root":str(root),"directory_metadata":[metadata]}
            with patch.object(self.audit,"regular_input",side_effect=AssertionError("directory metadata opened file contents")):
                with ExitStack() as held:
                    self.audit.hold_compilation_directory_metadata([inventory],held,{})
                changed = deepcopy(inventory)
                changed["directory_metadata"][0]["identity"][1] += 1
                with self.assertRaisesRegex(ValueError,"^qualification.compilation_scope_directories_physical$"):
                    with ExitStack() as held:
                        self.audit.hold_compilation_directory_metadata([changed],held,{})
                with self.assertRaisesRegex(ValueError,"^qualification.compiler_namespace_changed$"):
                    with ExitStack() as held:
                        self.audit.hold_compilation_directory_metadata([inventory],held,{})
                        child.chmod(0o700)

    def test_required_executable_belongs_to_its_particular_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root/"profile.json").write_text("{}")
            first = {"path":"/candidate/target/A","sha256":"1"*64,"size":9}
            second = {"path":"/candidate/target/B","sha256":"2"*64,"size":10}
            report = {"subjects":{"gate/contracts":[first]},"roots":{
                self.audit.compiler_graph_image(first),self.audit.compiler_graph_image(second)}}
            record = {"compiled_profiles":[{"path":"profile.json","sha256":self.audit.sha(root/"profile.json")}],
                "gates":[{"id":"contracts","command":self.audit.gate_catalog()["contracts"]["command"],
                    "executables":[{"path":"retained/B","sha256":second["sha256"],"size":second["size"]}]}]}
            with patch.object(self.audit,"audit_compiled_profile",return_value=report):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_roots$"):
                    self.audit.audit_compiled_profiles(root,record,"3"*64,[],None)

    def test_compiled_custody_tools_and_envelopes_stay_bound_through_return(self):
        for changed in ["inspector","envelope"]:
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                bundle = self.compiled_profile_archive_bundle(root)
                runtime,profile = bundle["fixture"]["runtime"],bundle["profile"]
                reference = bundle["reference"]("profile.json",profile)
                record = {"compiled_profiles":[reference],"gates":[profile["producer"]]}
                target = root/(profile["custody_tool"]["path"] if changed == "inspector" else reference["path"])
                original,checked = self.audit.checked_compiled_blob,[]
                def change_after_the_last_image(evidence_root,image):
                    original(evidence_root,image)
                    checked.append(image["sha256"])
                    if len(checked) == len(profile["images"]):
                        target.write_bytes(b"X"*target.stat().st_size)
                # Isolate envelope custody from this historical fixture's unavailable current publication proof.
                with patch.object(self.audit,"checked_compiled_blob",side_effect=change_after_the_last_image), \
                        patch.object(self.audit,"audit_current_compiled_publication"), \
                        patch.object(self.audit,"audit_gate"),patch.object(self.audit,"audit_execution_provenance"):
                    with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_image$"):
                        self.audit.audit_compiled_profiles(root,record,runtime["source_binding"],runtime["sources"],None)

    def test_secret_shaped_original_output_is_refused_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.compiler_profile_request_bundle(root)
            secret = root/"target/output/credentials.toml"
            fixture["output"].rename(secret)
            row,request = fixture["row"],fixture["request"]
            row["outputs"][0]["path"] = request["roots"][0]["path"] = str(secret)
            sources = self.audit.current_source_inventory(root)
            runtime = {**fixture["runtime"],"sources":sources,"source_binding":self.audit.binding(sources,None)}
            row["source_binding"] = request["source_binding"] = runtime["source_binding"]
            inventory = Path(request["runtime_inventory"]["path"])
            inventory.write_bytes(self.audit.compilation_canonical(runtime)+b"\n")
            request["runtime_inventory"]["sha256"] = self.audit.sha(inventory)
            raw = self.audit.compilation_canonical(row)+b"\n"
            fixture["record"].write_bytes(raw)
            marker = json.loads(fixture["marker"].read_bytes())
            marker.update(source_binding=runtime["source_binding"],record_sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))
            fixture["marker"].write_bytes(self.audit.compilation_canonical(marker)+b"\n")
            fixture["request_path"].write_bytes(self.audit.compilation_canonical(request)+b"\n")
            original,attempts = self.audit.regular_input,[]
            def guard_original(path):
                if Path(path) == secret:
                    attempts.append(str(path))
                    raise AssertionError("secret-shaped original output must not be opened")
                return original(path)
            with patch.object(self.audit,"regular_input",side_effect=guard_original):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_input_policy$"):
                    self.audit.inspect_compiler_profile_request(fixture["request_path"])
            self.assertEqual(attempts,[])

    def test_instrumented_compiler_launch_preserves_exact_inner_cargo_command(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repository = Path("/candidate")
            def ref(name, value):
                (root/name).write_bytes(self.audit.compilation_canonical(value)+b"\n")
                return {"path":name,"sha256":self.audit.sha(root/name)}
            config = {"schema":"chio.linux-compilation-launch.v1","candidate":str(repository),"source_binding":"2"*64,
                "images":{"recorder":{"path":"/candidate/scripts/record-rust-compilation.py","sha256":"1"*64},
                          "python":{"path":"/runtime/python"},"cargo":{"path":"/toolchain/cargo"}}}
            launch = {"schema":"chio.compiler-command-launch.v1","source_binding":"2"*64,
                "launcher":config["images"]["recorder"],"configuration":ref("configuration.json",config),
                "configuration_path":"/candidate/target/metadata/launch.json",
                "command":["/toolchain/cargo","test","--offline","--locked"]}
            expected = {"command":["cargo","test","--offline","--locked"],"cwd":".","environment":{}}
            argv = ["/runtime/python","-B",launch["launcher"]["path"],"--launch-scope",
                    launch["configuration_path"],"--",*launch["command"]]
            sources = [{"path":"scripts/record-rust-compilation.py","sha256":"1"*64}]
            result = self.audit.audit_compiler_launch(root,ref("launch.json",launch),argv,repository,
                                                       expected,sources,"2"*64)
            self.assertEqual(result["command"],expected["command"])
            with self.assertRaisesRegex(ValueError,"^qualification.compiler_launch_command$"):
                self.audit.audit_compiler_launch(root,ref("launch.json",launch),argv[:5]+["--probe"]+argv[5:],
                                                repository,expected,sources,"2"*64)
            launch["launcher"]["sha256"] = "3"*64
            with self.assertRaisesRegex(ValueError,"^qualification.compiler_launch_source$"):
                self.audit.audit_compiler_launch(root,ref("changed-launch.json",launch),argv,repository,
                                                expected,sources,"2"*64)

    def test_primary_probe_tools_are_reviewed_images_and_not_arbitrary_reports(self):
        candidate = "/public-candidate"
        tools = {"consumer/verify_public_compilation_probes.py":"c2c218095e11f6abbd862a08a2e9a0f493fd9704fec0079f2d8c5abc09c4707b",
            "consumer/scope-record-functions.py":"fba31e53940e6d37f0170e89fce687a58f7b4fb4a5adf40b8f8b2f06743f3e38",
            "inventory-collector.py":"6004b9a4aa2b2acbb7aaee8c5cbfb56e597b54c94e9e2c6716baf11b26601359",
            "run-public-compiler-campaign-current.py":"bf4b1085c5c5f246fff3130d66b8b26f2417c3b30376ac4ef2b93ca928b0374b"}
        plan = {"candidate":candidate,"tools":[{"path":candidate+"/target/metadata/"+path,"sha256":digest}
                for path,digest in tools.items()]}
        accepted = self.audit.audit_primary_compiler_tools(plan)
        self.assertEqual(len(accepted),4)
        for mutation in ["changed","missing","duplicate"]:
            with self.subTest(mutation=mutation):
                changed = deepcopy(plan)
                if mutation == "changed": changed["tools"][0]["sha256"] = "0"*64
                if mutation == "missing": changed["tools"].pop()
                if mutation == "duplicate": changed["tools"].append(deepcopy(changed["tools"][0]))
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_tool$"):
                    self.audit.audit_primary_compiler_tools(changed)

    def test_current_probe_roster_requires_all_six_pinned_images(self):
        candidate = "/var/tmp/public-primary-contract"
        tools = {
            "consumer/verify_public_compilation_probes.py":"21f92a7d36cf5a4709addda7e3394c8e4cd0a1f919c8895a7fd8e43b42acc60e",
            "consumer/scope-record-functions.py":"f92309385f1eba536d88cd9adbd4eb02943a02a1be84efc808e8d0e29b724471",
            "consumer/physical_publication_functions.py":"35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564",
            "consumer/probe-observation-functions.py":"8ac9b9822c09e629c81d458207cf8f1b0af8a3161bf81dd045dc9b098172403e",
            "inventory-collector.py":"1f35d0a4c6462d30fecc995e68b55e8a7ef4db10dac44ced9023974d4b3c279d",
            "run-public-compiler-campaign-current.py":"35735f7d03fa1030155b076cad5fe5e0d66ac653a2458708750aaf09a3a4d26a",
        }
        plan = {"schema":"chio.public-linux-primary-plan.v2","candidate":candidate,
                "tools":[{"path":candidate+"/target/metadata/"+path,"sha256":digest}
                         for path,digest in tools.items()]}
        self.assertEqual(self.audit.audit_primary_compiler_tools(plan),
                         {row["path"]:row["sha256"] for row in plan["tools"]})
        for mutation in ["changed","missing","duplicate","legacy"]:
            with self.subTest(mutation=mutation):
                changed = deepcopy(plan)
                if mutation == "changed": changed["tools"][0]["sha256"] = "0"*64
                elif mutation == "missing": changed["tools"].pop()
                elif mutation == "duplicate": changed["tools"].append(deepcopy(changed["tools"][0]))
                else:
                    changed["tools"] = [{"path":candidate+"/target/metadata/"+path,"sha256":digest}
                                         for path,digest in self.audit.PRIMARY_COMPILER_TOOLS.items()]
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_tool$"):
                    self.audit.audit_primary_compiler_tools(changed)

    def test_directory_probe_roster_requires_its_complete_matching_successor(self):
        candidate = "/var/tmp/public-primary-directory-contract"
        tools = self.audit.DIRECTORY_PRIMARY_COMPILER_TOOLS
        plan = {"schema":"chio.public-linux-primary-plan.v2","candidate":candidate,
                "tools":[{"path":candidate+"/target/metadata/"+path,"sha256":digest}
                         for path,digest in tools.items()]}
        self.assertEqual(self.audit.audit_primary_compiler_tools(plan),
                         {row["path"]:row["sha256"] for row in plan["tools"]})
        for mutation in ["changed","mixed","missing","duplicate"]:
            changed = deepcopy(plan)
            if mutation == "changed":changed["tools"][0]["sha256"] = "0"*64
            elif mutation == "mixed":changed["tools"][0]["sha256"] = self.audit.CURRENT_PRIMARY_COMPILER_TOOLS["consumer/verify_public_compilation_probes.py"]
            elif mutation == "missing":changed["tools"].pop()
            else:changed["tools"].append(deepcopy(changed["tools"][0]))
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_tool$"):
                    self.audit.audit_primary_compiler_tools(changed)

    def test_descriptor_custody_probe_requires_the_complete_source_pinned_roster(self):
        candidate = "/var/tmp/public-primary-descriptor-custody-contract"
        tools = {
            "consumer/verify_public_compilation_probes.py":"1733d055922b83c4228646b1e7bc4426d89e425f663c3ea5e0fb3279b88696da",
            "consumer/scope-record-functions.py":"39f6e1477b63751a5730305d75035aa97ba3a8cf8c7f8fcb7c2cfa888afeb94b",
            "consumer/physical_publication_functions.py":"35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564",
            "consumer/probe-observation-functions.py":"8ac9b9822c09e629c81d458207cf8f1b0af8a3161bf81dd045dc9b098172403e",
            "inventory-collector.py":"e5cfc57485dcc268d45fba83e588e66c40b6f1386020204106b2a0df9bb9610c",
            "run-public-compiler-campaign-current.py":"35735f7d03fa1030155b076cad5fe5e0d66ac653a2458708750aaf09a3a4d26a",
        }
        plan = {"schema":"chio.public-linux-primary-plan.v2","candidate":candidate,
            "tools":[{"path":candidate+"/target/metadata/"+path,"sha256":digest} for path,digest in tools.items()]}
        self.assertEqual(self.audit.audit_primary_compiler_tools(plan),
                         {row["path"]:row["sha256"] for row in plan["tools"]})
        for mutation in ["mixed","missing","extra","unhashable_path","invalid_hash"]:
            changed = deepcopy(plan)
            if mutation == "mixed":changed["tools"][0]["sha256"] = self.audit.DIRECTORY_PRIMARY_COMPILER_TOOLS["consumer/verify_public_compilation_probes.py"]
            elif mutation == "missing":changed["tools"].pop()
            elif mutation == "extra":changed["tools"].append(deepcopy(changed["tools"][0]))
            elif mutation == "unhashable_path":changed["tools"][0]["path"] = {}
            else:changed["tools"][0]["sha256"] = []
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_tool$"):
                    self.audit.audit_primary_compiler_tools(changed)

    def test_primary_tool_roster_refuses_untyped_paths_before_a_hash_join(self):
        candidate = "/var/tmp/public-primary-typed-tool-contract"
        plan = {"schema":"chio.public-linux-primary-plan.v2","candidate":candidate,
                "tools":[{"path":candidate+"/target/metadata/"+path,"sha256":digest}
                         for path,digest in self.audit.DIRECTORY_PRIMARY_COMPILER_TOOLS.items()]}
        plan["tools"][0]["path"] = {}
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_tool$"):
            self.audit.audit_primary_compiler_tools(plan)

    def test_scope_dependency_probe_roster_accepts_only_its_complete_reviewed_six_images(self):
        candidate = "/var/tmp/public-primary-scope-dependency-contract"
        tools = dict(self.audit.DESCRIPTOR_CUSTODY_PRIMARY_COMPILER_TOOLS)
        tools["consumer/verify_public_compilation_probes.py"] = "4cfecc814d8077069efac6e052005ba506d43c9ce2f47fce4f930dcbd1bf5122"
        tools["consumer/scope-record-functions.py"] = "cd1da76e46982c7f8846cb5e3f5526e4dbc2a54afb486a7361a485676f25b1e6"
        plan = {"schema":"chio.public-linux-primary-plan.v2","candidate":candidate,
            "tools":[{"path":candidate+"/target/metadata/"+name,"sha256":digest} for name,digest in tools.items()]}
        self.assertEqual(self.audit.audit_primary_compiler_tools(plan),
                         {row["path"]:row["sha256"] for row in plan["tools"]})
        for mutation in ["mixed","missing","extra","path_type","hash_type","unknown"]:
            changed = deepcopy(plan)
            if mutation == "mixed":changed["tools"][0]["sha256"] = self.audit.DESCRIPTOR_CUSTODY_PRIMARY_COMPILER_TOOLS["consumer/verify_public_compilation_probes.py"]
            elif mutation == "missing":changed["tools"].pop()
            elif mutation == "extra":changed["tools"].append(deepcopy(changed["tools"][0]))
            elif mutation == "path_type":changed["tools"][0]["path"] = []
            elif mutation == "hash_type":changed["tools"][0]["sha256"] = {}
            else:changed["tools"][0]["sha256"] = "e"*64
            with self.subTest(mutation=mutation),self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_tool$"):
                self.audit.audit_primary_compiler_tools(changed)

    def test_completed_unit_sync_projection_requires_legal_typed_outcomes(self):
        identifier,source_binding = "1"*32,"2"*64
        reference = {"path":"records/"+identifier+".json","sha256":"3"*64,"size":100,
                     "identity":{"device":1,"inode":2}}
        value = {"schema":"chio.rust-unit-publication-outcome.v1","source_binding":source_binding,
            "invocation_id":identifier,"kind":"compilation","record_status":"success","compiler_exit":0,
            "record":reference,"completion":{**reference,"path":"completions/"+identifier+".json"},
            "unit_images_sha256":"4"*64,"physical_status":"complete",
            "durability":{"status":"confirmed","phase":"completion-directory-fsync","errno":None}}
        def observe(outcome):
            payload = b"compilation_recorder.unit_publication_outcome="+self.audit.compilation_canonical(outcome)+b"\n"
            return self.audit.current_primary_sync(payload,source_binding,1)
        for status,exit_code in [("success",0),("compiler_failed",1),("refused",None),("instrumentation_failed",0)]:
            with self.subTest(positive_status=status):
                outcome = {**value,"record_status":status,"compiler_exit":exit_code}
                self.assertEqual(observe(outcome)["unit_outcomes"],{identifier:outcome})
        for field,change in [("kind",[]),("record_status",[]),("compiler_exit",False)]:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_sync$"):
                    observe({**value,field:change})
        for status,exit_code in [("success",None),("success",1),("compiler_failed",0),("compiler_failed",None)]:
            with self.subTest(negative_status=status,exit_code=exit_code):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_sync$"):
                    observe({**value,"record_status":status,"compiler_exit":exit_code})

    def test_native_compiler_output_joins_actual_published_pipe_bytes(self):
        """Actual Python output/publisher/reader composition, not Rust proof."""
        recorder_path=ROOT/"scripts/record-rust-compilation.py"
        spec=importlib.util.spec_from_file_location("diagnostic_output_recorder",recorder_path)
        recorder=importlib.util.module_from_spec(spec);spec.loader.exec_module(recorder)
        with tempfile.TemporaryDirectory() as temporary:
            namespace=Path(temporary).resolve();campaign=recorder.Campaign(namespace,"a"*64)
            def cleanup(process,deadline):
                process.kill();process.wait(timeout=max(0,deadline-recorder.time.monotonic()))
                return {"status":"REAPED","scope":"direct-child-output-control"}
            try:
                result=recorder.bounded_compiler_output([sys.executable,"-c",
                    'import sys;print("PUBLIC-PIPE-OUT");print("PUBLIC-PIPE-ERROR",file=sys.stderr);sys.exit(1)'],
                    {"PATH":"/usr/bin:/bin"},str(namespace),None,cleanup)
                output={"schema":"chio.native-compiler-output.v1",**result.output_observation,
                    "stdout":campaign.retain(result.stdout),"stderr":campaign.retain(result.stderr)}
                def raw(reference):
                    with self.audit.regular_input(namespace/reference["artifact"]) as stream:
                        return stream.read(16*1024**2+1)
                self.audit.audit_native_compiler_output(output,raw)
                self.assertEqual(result.returncode,1)
                self.assertEqual(result.stderr,b"PUBLIC-PIPE-ERROR\n")
                for field in ["status","refusal","cleanup","eof","count","count_type","elapsed","elapsed_type",
                              "policy_cap","policy_timeout","forwarded","reference_path","reference_type","size"]:
                    changed=deepcopy(output)
                    if field=="status":changed["status"]="refused"
                    elif field=="refusal":changed["refusal"]="compiler_output_limit"
                    elif field=="cleanup":changed["cleanup"]={"status":"REAPED"}
                    elif field=="eof":changed["eof"]["stderr"]=False
                    elif field=="count":changed["observed_bytes"]["stderr"]+=1
                    elif field=="count_type":changed["observed_bytes"]["stderr"]=True
                    elif field=="elapsed":changed["elapsed_seconds"]=float("nan")
                    elif field=="elapsed_type":changed["elapsed_seconds"]=False
                    elif field=="policy_cap":changed["policy"]["maximum_bytes_per_stream"]*=2
                    elif field=="policy_timeout":changed["policy"]["execution_and_cleanup_seconds"]=True
                    elif field=="forwarded":changed["policy"]["raw_diagnostics_forwarded"]=True
                    elif field=="reference_path":changed["stderr"]["artifact"]="credentials.toml"
                    elif field=="reference_type":changed["stderr"]["size"]=True
                    else:
                        changed["stderr"]["size"]+=1;changed["observed_bytes"]["stderr"]+=1
                    with self.subTest(field=field),self.assertRaisesRegex(ValueError,"^qualification.micro_compiler_output"):
                        self.audit.audit_native_compiler_output(changed,raw)
                (namespace/output["stderr"]["artifact"]).write_bytes(b"X"*len(result.stderr))
                with self.assertRaisesRegex(ValueError,"^qualification.micro_compiler_output_bytes$"):
                    self.audit.audit_native_compiler_output(output,raw)
            finally:campaign.close()

    def test_native_compiler_dispatch_output_version_is_closed(self):
        base={"schema":"chio.compilation-supervisor-events.v1","events":[]}
        configuration={"candidate":"/candidate","aliases":[],"records":"/candidate/target/records",
                       "evidence":"/candidate/target/evidence"}
        for version in ["chio.compilation-supervisor-events.v1","chio.compilation-supervisor-events.v2"]:
            self.assertEqual(self.audit.audit_compilation_dispatches(Path(configuration["records"]),configuration,{},
                {**base,"schema":version},{"records":[]},None,None),0)
        for version in [None,[],"chio.compilation-supervisor-events.v3"]:
            with self.subTest(version=version),self.assertRaisesRegex(ValueError,"^qualification.micro_supervisor_events$"):
                self.audit.audit_compilation_dispatches(Path(configuration["records"]),configuration,{},
                    {**base,"schema":version},{"records":[]},None,None)
        dispatch={"kind":"compiler-unit","invocation_sha256":"1"*64,"environment_sha256":"2"*64,
                  "cwd":"/candidate","compiler_exit":1}
        event={"request_sha256":"3"*64,"id":"4"*32,"exit":1,"recorder_exit":1,"response":"encoded",
               "refusal":None,"dispatches":[dispatch],"records":[]}
        for version,changed in [("chio.compilation-supervisor-events.v1",{
                **dispatch,"schema":"chio.native-compiler-dispatch.v2","output":{}}),
                ("chio.compilation-supervisor-events.v2",dispatch)]:
            with self.subTest(mixed_version=version),self.assertRaisesRegex(ValueError,"^qualification.micro_dispatch$"):
                self.audit.audit_compilation_dispatches(Path(configuration["records"]),configuration,{},
                    {"schema":version,"events":[{**event,"dispatches":[changed]}]},
                    {"records":[]},None,None)

    def test_actual_recorder_publications_join_the_current_archive_decoder(self):
        """Real public publisher/parser composition; no compiler was executed."""
        recorder_path = ROOT/"scripts/record-rust-compilation.py"
        spec = importlib.util.spec_from_file_location("qualification_recorder_composition",recorder_path)
        recorder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recorder)
        with tempfile.TemporaryDirectory() as temporary:
            namespace = Path(temporary).resolve()
            binding = "a"*64
            outside = io.StringIO()
            campaign = recorder.Campaign(namespace,binding)
            try:
                with redirect_stderr(outside):
                    for kind,status,exit_code in [("compilation","success",0),("compilation","success",0),
                            ("probe","success",0),("compilation","compiler_failed",1),("compilation","refused",None)]:
                        row = recorder.row_for([],{},binding)
                        row.update(kind=kind,status=status,compiler_exit=exit_code)
                        campaign.publish(row)
            finally:
                campaign.close()
            publication = self.audit.audit_compiler_publications(namespace,binding)
            physical = self.audit.current_required_sync_observations(publication,outside.getvalue().encode())
            decoded = self.audit.current_primary_sync(outside.getvalue().encode(),binding,publication["verified_records"])
            self.assertEqual(decoded,physical)
            self.assertEqual(self.audit.checked_public_compilation_count(publication,"gnu-native"),2)
            self.assertEqual(self.audit.checked_public_compilation_count(publication,"musl-static-pie"),2)
            self.assertEqual(publication["compiled_closure_status"],"not-established")
            for replacement in ["probe","compiler_failed"]:
                changed = deepcopy(publication)
                for row in changed["records"]:
                    if row["kind"] == "compilation" and row["status"] == "success":
                        unit = changed["unit_publications"][row["invocation_id"]]
                        if replacement == "probe":row["kind"] = unit["kind"] = "probe"
                        else:
                            row["status"] = unit["record_status"] = "compiler_failed"
                            unit["compiler_exit"] = 1
                with self.subTest(replacement=replacement):
                    with self.assertRaisesRegex(ValueError,"^qualification.micro_primary_compilations$"):
                        self.audit.checked_public_compilation_count(changed,"gnu-native")

    def test_current_source_hash_and_cycles_are_independently_checked(self):
        rows,sources,roots = self.compiler_unit_graph_bundle()
        sources[0]["sha256"]="5"*64
        with self.assertRaisesRegex(ValueError,"^qualification.compiler_unit_source$"):
            self.audit.audit_compiler_unit_graph(rows,sources,roots)
        rows,sources,roots = self.compiler_unit_graph_bundle()
        rows[0]["inputs"].append({**rows[1]["outputs"][0],"role":"extern"})
        with self.assertRaisesRegex(ValueError,"^qualification.compiler_unit_cycle$"):
            self.audit.audit_compiler_unit_graph(rows,sources,roots)

    def test_immutable_externs_need_an_exact_independent_image_declaration(self):
        rows,sources,roots = self.compiler_unit_graph_bundle()
        rows=rows[1:]
        declared={key:rows[0]["inputs"][1][key] for key in ["path","sha256","size"]}
        report=self.audit.audit_compiler_unit_graph(rows,sources,roots,immutable_images=[declared])
        self.assertEqual(report["immutable_extern_edges"],1)
        declared["sha256"]="5"*64
        with self.assertRaisesRegex(ValueError,"^qualification.compiler_extern_producer$"):
            self.audit.audit_compiler_unit_graph(rows,sources,roots,immutable_images=[declared])

    def compiler_publication_bundle(self, root):
        # The image is a synthetic parser artifact, never an executed compiler.
        namespace = root/"compiler"
        for name in ["records","completions","artifacts"]:
            (namespace/name).mkdir(parents=True,exist_ok=True)
        payload = b"synthetic retained image\n"
        digest = hashlib.sha256(payload).hexdigest()
        (namespace/"artifacts"/digest).write_bytes(payload)
        image = {"path":"/synthetic/image","artifact":"artifacts/"+digest,
                 "sha256":digest,"size":len(payload)}
        identifier = "a"*32
        record = namespace/"records"/(identifier+".json")
        marker = namespace/"completions"/(identifier+".json")
        record.touch()
        marker.touch()
        file_identity = lambda path:{"device":path.stat().st_dev,"inode":path.stat().st_ino}
        row = {"schema":"chio.rust-compilation.v3","source_binding":"1"*64,
            "invocation_id":identifier,"kind":"compilation","status":"success","compiler_exit":0,
            "compiler":image,"inputs":[{**image,"role":"source"}],"outputs":[{**image,"role":"unit"}],
            "depfiles":[],"refusal":None,"publication":{"completion":"completions/"+identifier+".json",
                "marker_identity":file_identity(marker)}}
        raw = json.dumps(row,sort_keys=True).encode()+b"\n"
        record.write_bytes(raw)
        completion = {"schema":"chio.rust-compilation-completion.v2","invocation_id":identifier,
            "source_binding":row["source_binding"],"record_sha256":hashlib.sha256(raw).hexdigest(),
            "size":len(raw),"record_identity":file_identity(record)}
        marker.write_text(json.dumps(completion))
        return {"namespace":namespace,"record":record,"marker":marker,"row":row,
                "artifact":namespace/"artifacts"/digest,"binding":row["source_binding"]}

    def test_original_compiler_namespace_publication_verification_is_not_native_qualification(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.compiler_publication_bundle(Path(temporary).resolve())
            result = self.audit.audit_compiler_publications(fixture["namespace"],fixture["binding"])
            self.assertEqual(result["verified_records"],1)
            self.assertEqual(result["status_counts"],{"success":1})
            self.assertEqual(result["compiled_closure_status"],"not-established")

    def test_compiler_publication_cli_requires_an_independent_binding_and_one_mode(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.compiler_publication_bundle(Path(temporary).resolve())
            command = [sys.executable,"-I","-B",str(TOOL),"--compiler-publications",str(fixture["namespace"])]
            accepted = subprocess.run([*command,"--source-binding",fixture["binding"]],
                                      capture_output=True,text=True,check=False)
            self.assertEqual(accepted.returncode,0,accepted.stderr)
            report = json.loads(accepted.stdout)
            self.assertEqual(report["verified_records"],1)
            self.assertEqual(report["compiled_closure_status"],"not-established")
            for options in [[],["--source-binding","2"*64],
                            ["--source-binding",fixture["binding"],"--catalog"]]:
                with self.subTest(options=options):
                    refused = subprocess.run([*command,*options],capture_output=True,text=True,check=False)
                    self.assertNotEqual(refused.returncode,0)
                    self.assertEqual(refused.stdout,"")

    def test_copied_compiler_record_or_marker_cannot_preserve_original_physical_publication(self):
        for name in ["record","marker"]:
            with self.subTest(name=name),tempfile.TemporaryDirectory() as temporary:
                fixture = self.compiler_publication_bundle(Path(temporary).resolve())
                original = fixture[name]
                replacement = original.with_suffix(".replacement")
                replacement.write_bytes(original.read_bytes())
                replacement.replace(original)
                with self.assertRaisesRegex(ValueError,"^qualification.compiler_publication_identity$"):
                    self.audit.audit_compiler_publications(fixture["namespace"],fixture["binding"])

    def test_retained_compiler_artifact_hash_is_checked_independently(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.compiler_publication_bundle(Path(temporary).resolve())
            fixture["artifact"].write_bytes(b"unrelated image\n")
            with self.assertRaisesRegex(ValueError,"^qualification.compiler_artifact_binding$"):
                self.audit.audit_compiler_publications(fixture["namespace"],fixture["binding"])

    def test_compiler_artifact_change_after_validation_refuses_the_namespace_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self.compiler_publication_bundle(Path(temporary).resolve())
            listdir = os.listdir
            artifacts_inode = (fixture["namespace"]/"artifacts").stat().st_ino
            checks = 0
            def observed_listdir(descriptor):
                nonlocal checks
                if isinstance(descriptor,int) and os.fstat(descriptor).st_ino == artifacts_inode:
                    checks += 1
                    if checks == 2:
                        fixture["artifact"].write_bytes(b"changed after original verification\n")
                return listdir(descriptor)
            with patch.object(self.audit.os,"listdir",side_effect=observed_listdir):
                with self.assertRaisesRegex(ValueError,"^qualification.compiler_namespace_changed$"):
                    self.audit.audit_compiler_publications(fixture["namespace"],fixture["binding"])

    def test_guest_execution_joins_original_origin_without_manufacturing_discovery_head(self):
        # These are parser controls with a captured synthetic receipt, never a live guest execution.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self.source_origin_bundle(root)
            ref = fixture["ref"]
            execution = self.guest_execution_bundle(root,fixture)
            before,row,expected = (execution[key] for key in ["before","row","expected"])
            proof = row["provenance"]
            self.audit.audit_execution_provenance(root,row,fixture["sources"],"1"*40,expected)
            mutated = deepcopy(before)
            mutated["git"]["head"] = "1"*40
            mutated_manifest = {key:mutated[key] for key in ["git","entries","explicit_file_pins"]}
            mutated["content_manifest_sha256"] = hashlib.sha256(json.dumps(mutated_manifest,sort_keys=True,
                ensure_ascii=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
            proof["before"] = ref("manufactured-head-before.json",mutated)
            proof["after"] = ref("manufactured-head-after.json",mutated)
            with self.assertRaisesRegex(ValueError,"^qualification.gate_base_commit$"):
                self.audit.audit_execution_provenance(root,row,fixture["sources"],"1"*40,expected)

    def test_inventory_observes_absent_guest_head_without_manufacturing_a_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git","init","--quiet"],cwd=root,check=True)
            (root/"Cargo.toml").write_bytes(b"[workspace]\n")
            result = subprocess.run([sys.executable,"-B",str(TOOL),"--inventory","--source-root",str(root)],
                                    capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            inventory = json.loads(result.stdout)
            self.assertIsNone(inventory["base_commit"])
            self.assertEqual(inventory["source_binding"],self.audit.binding(inventory["sources"],None))

    def test_top_level_rust_counts_do_not_count_a_nested_child_invocation(self):
        log = "running 3 tests\ntest result: ok. 1 passed; 0 failed; 0 ignored; 2 filtered out\n" \
              "test result: ok. 3 passed; 0 failed; 0 ignored; 0 filtered out\n"
        self.assertEqual(self.audit.top_level_rust_counts(log), {"passed":3,"failed":0,"ignored":0})

    def test_model_decoy_markers_do_not_prove_the_required_mutation_campaign(self):
        prefix = "docs/architecture/recoverable-agent-runtime/model/"
        sources = [{"path":prefix+name,"sha256":"0"*64}
                   for name in ["recovery.rs","review.rs","third.rs","run.py"]]
        commands = [{"name":"format","command":["rustfmt","+1.94.1"],"cwd":"/captured/inputs"},
                    {"name":"compiler","command":["rustc","+1.94.1","-Vv"],"cwd":"/captured"}]
        runs = []
        for name, entry in [("ownership","recovery.rs"),("review","review.rs"),("third","third.rs")]:
            commands += [{"name":"compile-"+name,"command":["rustc","+1.94.1","--edition","2021",
                         "-D","warnings",entry,"-o","/captured/"+name],"cwd":"/captured/inputs"},
                         {"name":"execute-"+name,"command":["/captured/"+name],"cwd":"/model"}]
            runs.append({"name":name,"entry":entry,"executable_sha256":"0"*64,
                         "output":name+".txt","output_sha256":"0"*64})
        for row in commands:
            row.update({"exit_code":0,"log":row["name"]+".log","log_sha256":"0"*64})
        architecture = {"schema":"chio.recovery-architecture-model-evidence.v1","toolchain":"+1.94.1",
            "edition":"2021","sources":[{"path":row["path"][len(prefix):],"sha256":row["sha256"]}
                                             for row in sources],
            "runs":runs,"commands":commands,"input_snapshot":"inputs"}
        evidence = {"schema":"chio.recovery-formal-evidence.v1","full_system_proof":False,
            "architecture":{"path":"model/evidence.json","sha256":"0"*64},
            "executables":{name:{"path":name,"sha256":"0"*64} for name in ["ownership","review","third"]},
            "tools":[]}
        # Isolate the output grammar from the independently tested artifact readers.
        # These are deliberately synthetic declarations, never executed evidence.
        with patch.object(self.audit,"artifact_json",return_value=architecture), \
             patch.object(self.audit,"checked_log",return_value="BASELINE PASS\nMUTATION REJECTED Decoy\n"), \
             patch.object(self.audit,"checked_executable"),patch.object(self.audit,"sha",return_value="0"*64):
            with self.assertRaisesRegex(ValueError,"^qualification.formal_model_mutation_inventory$"):
                self.audit.audit_formal(ROOT,evidence,"candidate",sources,"1"*40)

    def test_individual_formal_successes_cannot_replace_the_maintained_lanes(self):
        prefix = "docs/architecture/recoverable-agent-runtime/model/"
        names = ["recovery.rs","review.rs","third.rs","run.py"]
        commands = [{"name":"format","command":["rustfmt","+1.94.1"],"cwd":"/captured/inputs"},
                    {"name":"compiler","command":["rustc","+1.94.1","-Vv"],"cwd":"/captured"}]
        runs = []
        for name, entry in [("ownership","recovery.rs"),("review","review.rs"),("third","third.rs")]:
            commands += [{"name":"compile-"+name,"command":["rustc","+1.94.1","--edition","2021",
                         "-D","warnings",entry,"-o","/captured/"+name],"cwd":"/captured/inputs"},
                         {"name":"execute-"+name,"command":["/captured/"+name],"cwd":"/model"}]
            runs.append({"name":name,"entry":entry,"executable_sha256":"0"*64,
                         "output":name+".txt","output_sha256":"0"*64})
        for row in commands:
            row.update({"exit_code":0,"log":row["name"]+".log","log_sha256":"0"*64})
        architecture = {"schema":"chio.recovery-architecture-model-evidence.v1","toolchain":"+1.94.1",
            "edition":"2021","sources":[{"path":name,"sha256":"0"*64} for name in names],
            "runs":runs,"commands":commands,"input_snapshot":"inputs"}
        sources = [{"path":prefix+name,"sha256":"0"*64} for name in names]
        sources += [{"path":".kani/harnesses.toml","sha256":"0"*64},
                    {"path":"formal/lean4/Chio/lean-toolchain","sha256":"0"*64}]
        tools = [{"tool":"kani","primary":{"path":"kani.json","sha256":"0"*64}},
                 {"tool":"lean","primary":{"path":"lean.json","sha256":"0"*64}}]
        records = {"model/evidence.json":architecture}
        for tool, command, source in [
            ("kani",["cargo","kani","--harness","selected_only"],sources[-2]),
            ("lean",["lake","build"],sources[-1]),
        ]:
            records[tool+".json"] = {"schema":"chio.formal-tool-execution.v1","tool":tool,
                "source_binding":"candidate","source_inputs":[source],"executables":[],
                "execution":{"command":command,"cwd":".","exit_code":0,
                             "log":{"path":tool+".log","sha256":"0"*64}}}
        evidence = {"schema":"chio.recovery-formal-evidence.v1","full_system_proof":False,
            "architecture":{"path":"model/evidence.json","sha256":"0"*64},"tools":tools,
            "executables":{run["name"]:{"path":run["name"],"sha256":run["executable_sha256"]}
                           for run in architecture["runs"]}}
        def log(_root, reference):
            if reference["path"] == "kani.log":
                return "Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n"
            if reference["path"] == "lean.log":
                return "Build completed successfully\n"
            return "synthetic isolated model output\n"
        # Isolate the lane command validation from separately tested artifact,
        # model grammar and provenance readers. These synthetic declarations
        # never establish that the maintained lanes actually executed.
        with patch.object(self.audit,"artifact_json",side_effect=lambda root,ref:records[ref["path"]]), \
             patch.object(self.audit,"checked_log",side_effect=log), \
             patch.object(self.audit,"checked_executable"),patch.object(self.audit,"sha",return_value="0"*64), \
             patch.object(self.audit,"audit_execution_provenance"),patch.object(self.audit,"audit_model_output"):
            with self.assertRaisesRegex(ValueError,"^qualification.formal_tool_command$"):
                self.audit.audit_formal(ROOT,evidence,"candidate",sources,"1"*40)

    def test_formal_lane_verdicts_require_each_enrolled_harness_and_script_stage(self):
        contract = b'''schema = "chio.kani.multi-crate.v1"
[[harness]]
crate = "example"
harness = "first"
lane = "pr"
default_unwind = 8
timeout_secs = 30
[[harness]]
crate = "example"
harness = "second"
lane = "pr"
default_unwind = 16
timeout_secs = 60
'''
        groups = ["::group::cargo kani example::kani_public_harnesses::first (unwind=8 timeout=30s)\n",
                  "::group::cargo kani example::kani_public_harnesses::second (unwind=16 timeout=60s)\n"]
        footer = "Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n::endgroup::\n"
        text = "".join(group+footer for group in groups)+"run-kani-manifest.sh: 2 harnesses passed (lane=pr)\n"
        self.audit.audit_formal_lane_verdict("kani",text,contract)
        for mutant in [text.replace(groups[1],groups[0]),text.replace("unwind=16","unwind=8"),
                       text.replace(groups[1]+footer,"")]:
            with self.assertRaisesRegex(ValueError,"^qualification.formal_harness_inventory$"):
                self.audit.audit_formal_lane_verdict("kani",mutant,contract)
        with self.assertRaisesRegex(ValueError,"^qualification.formal_tool_verdict$"):
            self.audit.audit_formal_lane_verdict("kani",text.replace("0 failures","1 failures",1),contract)
        lean = "\n".join([
            "==> Canonical JSON Lean fixture drift","==> Lean 4 proof build","Build completed successfully",
            "==> Lean 4 placeholder scan","==> Elaborated Lean assumption audit regressions",
            "PASS: elaborated Lean assumptions include public, private, and generated declarations",
            "==> Proof manifest and theorem inventory sanity","formal proof check passed",""])
        self.audit.audit_formal_lane_verdict("lean",lean,b"leanprover/lean4:v4.28.0\n")
        with self.assertRaisesRegex(ValueError,"^qualification.formal_tool_verdict$"):
            self.audit.audit_formal_lane_verdict("lean",lean.replace("==> Lean 4 placeholder scan\n",""),
                                                b"leanprover/lean4:v4.28.0\n")

    def test_semantic_gate_refusal_precedes_generic_artifact_hash(self):
        expected = self.audit.gate_catalog()["format"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "format.log").write_text("formatted\n")
            row = {"id":"format", **expected, "exit_code":0, "source_stable":True,
                   "source_binding":"candidate", "log":{"path":"format.log", "sha256":"0"*64}}
            row["command"] = ["true"]
            with self.assertRaisesRegex(ValueError, "^qualification.gate_command$"):
                self.audit.audit_gate(root, row, "candidate")

    def test_python_gate_requires_exact_environment_and_in_tree_module_origin(self):
        expected = self.audit.gate_catalog()["python-sdk"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "sdk.log").write_text("1 passed\n")
            row = {"id":"python-sdk", **deepcopy(expected), "exit_code":0, "source_stable":True,
                   "source_binding":"candidate", "log":{"path":"sdk.log", "sha256":"0"*64}}
            row["environment"] = {}
            with self.assertRaisesRegex(ValueError, "^qualification.gate_environment$"):
                self.audit.audit_gate(root, row, "candidate")

    def test_missing_or_replaced_declared_cohort_cannot_be_censored(self):
        declaration = [{"id":"first", "planned_trials":96}, {"id":"second", "planned_trials":96}]
        attempts = [{"id":"first", "planned_trials":96, "measured_trials":95,
                     "unknown_trials":1, "qualified":False, "positive_strata_passed":0,
                     "positive_strata":1},
                    {"id":"second", "planned_trials":96, "measured_trials":95,
                     "unknown_trials":1, "qualified":False, "positive_strata_passed":1,
                     "positive_strata":1}]
        self.audit.audit_attempts(declaration, attempts)
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_inventory$"):
            self.audit.audit_attempts(declaration, attempts[1:])
        attempts[0]["qualified"] = True
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_qualification$"):
            self.audit.audit_attempts(declaration, attempts)

    def test_one_trial_and_success_counters_do_not_prove_a_live_cohort(self):
        attempt = {"id":"one", "planned_trials":1, "measured_trials":1, "unknown_trials":0,
                   "positive_strata":1, "positive_strata_passed":1, "qualified":True}
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_denominator$"):
            self.audit.audit_attempts([{"id":"one", "planned_trials":1}], [attempt])
        attempt.update({"planned_trials":96, "measured_trials":96})
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_primary_evidence$"):
            self.audit.audit_attempts([{"id":"one", "planned_trials":96}], [attempt])

    def test_live_corpus_refuses_unsupported_host_or_model_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "rows.jsonl").write_bytes(b"")
            sources = [{"path":"fixtures/source.py", "sha256":"0"*64}]
            base = "1"*40
            candidate = self.audit.binding(sources, base)
            manifest = {"schema":"chio.recovery-live-corpus.v2", "source_inventory_version":self.audit.INVENTORY_VERSION,
                "provider_endpoint":self.audit.PROVIDER_ENDPOINT, "sources":sources, "base_commit":base,
                "source_binding":candidate,
                "model":"gpt-5.4-2026-03-05", "hosts":{"crewai":"0.203.2", "langgraph":"1.2.12", "openai":"3.3.0", "httpx":"0.28.1"},
                "authority_policy":"2"*64,
                "trials":[{"id":f"{host}-{workflow}-{arm}-{case}-r{repeat}", "host":host, "workflow":workflow,
                    "arm":arm, "case":case, "repetition":repeat}
                    for host in ["langgraph","crewai"] for workflow in ["support","artifact"]
                    for arm in ["baseline","product"] for case in ["authorized","lost_ack_restart","wrong_authority","conflicting_basis"]
                    for repeat in range(1,4)],
                "budgets":{"model_calls":4, "tool_actions":8, "prompt_bytes":16384, "output_tokens":512,
                    "output_bytes":8192, "provider_seconds":45, "native_http_seconds":120,
                    "native_preparation_seconds":240, "native_shutdown_seconds":120,
                    "host_start_deadline_seconds":240, "trial_seconds":720, "concurrent_trials":2, "transport_retries":0}}
            measured = {"planned_trials":96, "measured_trials":0, "unknown_trials":96, "native_unknown_trials":0,
                        "unknown_token_usage_attempts":0, "positive_strata":16, "positive_strata_passed":0, "qualified":False}
            evidence = {"schema":"chio.recovery-live-cohort-evidence.v1", "source_binding":candidate,
                        "manifest":{"path":"manifest.json", "sha256":"3"*64},
                        "rows":{"path":"rows.jsonl", "sha256":hashlib.sha256(b"").hexdigest()},
                        "trials":{}, "recomputed":measured}
            def observe(declared):
                with patch.object(self.audit, "artifact_json", side_effect=[evidence, declared]):
                    return self.audit.audit_live_cohort(root, {}, candidate)
            self.assertEqual(observe(manifest), measured)
            for field, value in [("model","gpt-5.4-mini-2026-03-17"),
                                 ("hosts", {**manifest["hosts"], "crewai":"1.15.23"}),
                                 ("hosts", {**manifest["hosts"], "openai":"2.36.0"}),
                                 ("hosts", {key:value for key,value in manifest["hosts"].items() if key != "httpx"})]:
                with self.subTest(field=field, value=value):
                    mutated = {**manifest, field:value}
                    with self.assertRaisesRegex(ValueError, "^qualification.cohort_profile$"):
                        observe(mutated)

    def test_python_gate_requires_the_supported_preimport_environment(self):
        expected = {"OTEL_SDK_DISABLED":"true", "CREWAI_DISABLE_TELEMETRY":"true",
                    "CREWAI_TELEMETRY_DISABLED":"true", "LITELLM_LOCAL_MODEL_COST_MAP":"True"}
        for name in ["python-sdk", "python-fixtures"]:
            environment = self.audit.gate_catalog()[name]["environment"]
            for key, value in expected.items():
                with self.subTest(gate=name, key=key):
                    self.assertEqual(environment.get(key), value)

    def test_content_manifests_are_recomputed_and_runtime_pins_are_linked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def reference(name, value):
                raw = json.dumps(value).encode()
                (root / name).write_bytes(raw)
                return {"path":name, "sha256":hashlib.sha256(raw).hexdigest()}
            base = "1"*40
            sources = [{"path":"fixtures/source.py", "sha256":"0"*64}]
            snapshot = {"format":"chio.local-command-provenance.v1", "git":{"head":base,"branch":"candidate"},
                "entries":{"fixtures/source.py":{"membership":"nonignored-untracked", "state":"file",
                    "content_coverage":"sha256-bytes", "mode":420, "size_bytes":1, "sha256":"0"*64}},
                "explicit_file_pins":[]}
            snapshot["content_manifest_sha256"] = hashlib.sha256(json.dumps(
                {key:snapshot[key] for key in ["git","entries","explicit_file_pins"]},
                sort_keys=True, ensure_ascii=True, separators=(",",":")).encode()).hexdigest()
            start = {"repository":"/candidate", "cwd":"/candidate", "command":["cargo","fmt","--all","--","--check"], "environment":{}}
            result = {"format":"chio.local-command-provenance.v1", "actual_command_exit":0, "runner_exit":0,
                "inventories_complete":True, "output_pipe_completed":True, "provenance_error":None,
                "source_drift":{"detected":False}, "before_manifest_sha256":snapshot["content_manifest_sha256"],
                "after_manifest_sha256":snapshot["content_manifest_sha256"], "log":{"sha256":"2"*64}}
            runtime = {"source_inventory_version":self.audit.INVENTORY_VERSION, "base_commit":base,
                       "sources":sources, "source_binding":self.audit.binding(sources,base)}
            row = {"id":"format", "command":start["command"], "cwd":".", "log":result["log"], "provenance":{}}
            def proofs(before, after):
                row["provenance"] = {key:reference(key+".json", value) for key,value in {
                    "before":before,"after":after,"start":start,"result":result,
                    "runtime_sources_before":runtime,"runtime_sources_after":runtime}.items()}
            proofs(snapshot, snapshot)
            self.audit.audit_execution_provenance(root,row,sources,base)
            changed = deepcopy(snapshot)
            changed["entries"]["fixtures/source.py"]["sha256"] = "3"*64
            proofs(snapshot,changed)
            with self.assertRaisesRegex(ValueError,"^qualification.gate_source_manifest$"):
                self.audit.audit_execution_provenance(root,row,sources,base)
            changed["content_manifest_sha256"] = hashlib.sha256(json.dumps(
                {key:changed[key] for key in ["git","entries","explicit_file_pins"]},
                sort_keys=True, ensure_ascii=True, separators=(",",":")).encode()).hexdigest()
            result["before_manifest_sha256"] = result["after_manifest_sha256"] = changed["content_manifest_sha256"]
            proofs(changed,changed)
            with self.assertRaisesRegex(ValueError,"^qualification.gate_source_bracket$"):
                self.audit.audit_execution_provenance(root,row,sources,base)

    def test_unrelated_runs_and_self_declared_dimensions_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "text").write_bytes(b"unrelated ordinary text")
            text_ref = {"path":"text", "sha256":hashlib.sha256(b"unrelated ordinary text").hexdigest()}
            raw = json.dumps({"schema":"chio.recovery-dimension-evidence.v1", "dimension":"linux",
                "source_binding":"candidate", "actual_exit_code":0, "source_stable":True,
                "host":{"system":"Linux", "machine":"x86_64"}, "profile":"NativeMinimalV1",
                "confined_return_tests":10, "linux_only_store_tests_passed":True,
                "runs":[{"actual_exit_code":0,"executables":[text_ref],"log":text_ref}]}).encode()
            (root / "linux.json").write_bytes(raw)
            reference = {"path":"linux.json", "sha256":hashlib.sha256(raw).hexdigest()}
            with self.assertRaisesRegex(ValueError, "^qualification.linux_record$"):
                self.audit.audit_dimensions(root,{"linux":reference},"candidate")


    def public_primary_contract_fixture(self):
        # Exact B2 published payload bytes and plan/summary header fields. This
        # is a source guard fixture, not a native campaign or qualification.
        raw = b'{\n  "allowed_substitutions": [\n    "candidate",\n    "configuration"\n  ],\n  "campaign_budget_seconds": 900,\n  "cases": [\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "allowed-read",\n        "--path",\n        "{candidate}/public-probes/allowed-input.txt"\n      ],\n      "configuration_relative_path": "target/metadata/public-allowed-read.launch.json",\n      "expected_command_exit": 0,\n      "name": "allowed-read",\n      "timeout_seconds": 120\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "outside-read",\n        "--path",\n        "{candidate}/target/outside-public/allowed-input.txt"\n      ],\n      "configuration_relative_path": "target/metadata/public-outside-read.launch.json",\n      "expected_command_exit": 0,\n      "name": "outside-read",\n      "timeout_seconds": 120\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "outside-write",\n        "--path",\n        "{candidate}/target/outside-public/fresh-output"\n      ],\n      "configuration_relative_path": "target/metadata/public-outside-write.launch.json",\n      "expected_command_exit": 0,\n      "name": "outside-write",\n      "timeout_seconds": 120\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "evidence-read"\n      ],\n      "configuration_relative_path": "target/metadata/public-evidence-read.launch.json",\n      "expected_command_exit": 0,\n      "name": "evidence-read",\n      "timeout_seconds": 120\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "evidence-write"\n      ],\n      "configuration_relative_path": "target/metadata/public-evidence-write.launch.json",\n      "expected_command_exit": 0,\n      "name": "evidence-write",\n      "timeout_seconds": 120\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "network"\n      ],\n      "configuration_relative_path": "target/metadata/public-network.launch.json",\n      "expected_command_exit": 0,\n      "name": "network",\n      "timeout_seconds": 120\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "forged-ipc"\n      ],\n      "configuration_relative_path": "target/metadata/public-forged-ipc.launch.json",\n      "expected_command_exit": 0,\n      "name": "forged-ipc",\n      "timeout_seconds": 120\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "gnu-native",\n        "--fixture-root",\n        "{candidate}/public-probes",\n        "--output-root",\n        "{candidate}/target/write/gnu-native/outputs/gnu-probe",\n        "--linker",\n        "/usr/bin/x86_64-linux-gnu-gcc-13",\n        "--implicit-linker"\n      ],\n      "configuration_relative_path": "target/metadata/public-gnu-native.launch.json",\n      "expected_command_exit": 0,\n      "name": "gnu-native",\n      "timeout_seconds": 180\n    },\n    {\n      "command_template": [\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/scripts/record-rust-compilation.py",\n        "--launch-scope",\n        "{configuration}",\n        "--probe",\n        "--",\n        "/usr/bin/python3.12",\n        "-B",\n        "{candidate}/public-probes/native-scope-probe.py",\n        "musl-static-pie",\n        "--fixture-root",\n        "{candidate}/public-probes",\n        "--output-root",\n        "{candidate}/target/write/musl-static-pie/outputs/musl-probe",\n        "--linker",\n        "/usr/bin/x86_64-linux-musl-gcc",\n        "--implicit-linker"\n      ],\n      "configuration_relative_path": "target/metadata/public-musl-static-pie.launch.json",\n      "expected_command_exit": 0,\n      "name": "musl-static-pie",\n      "timeout_seconds": 180\n    }\n  ],\n  "native_case_seconds": 180,\n  "ordinary_case_seconds": 120,\n  "payloads": [\n    {\n      "path": "public-probes/allowed-input.txt",\n      "sha256": "a6951fcb41290f05a4cb68504f187fb0fff9d9041a1ec4c210ffd13f4a43f265",\n      "size": 20\n    },\n    {\n      "path": "public-probes/native-scope-probe.py",\n      "sha256": "2772799b09e5948a57afac5d2be66973b723dcde19aaf24a6dd290c4d0db2cb4",\n      "size": 9251\n    },\n    {\n      "path": "public-probes/public-input.txt",\n      "sha256": "9282c9b1536f651a561231c358efe0f9bceae45a90e011854701220ec12a50ae",\n      "size": 15\n    },\n    {\n      "path": "public-probes/src/gnu-main.rs",\n      "sha256": "182be7b42ac5c46a230f97cc46d97411ec666377675444e5fd3a6062c82694ec",\n      "size": 354\n    },\n    {\n      "path": "public-probes/src/musl-main.rs",\n      "sha256": "236f93e8055681f0443d8d85a1538f30ac101c23185ad98b884440079ea2f844",\n      "size": 43\n    },\n    {\n      "path": "public-probes/src/public-macro.rs",\n      "sha256": "a28a24503e66ae419fae27545039d4ff867dc27c140a8894c42a09a3331b7ef5",\n      "size": 1173\n    }\n  ],\n  "profile": "public-linux-x86_64-gnu-musl-explicit-instrumented-compiler",\n  "schema": "chio.public-linux-primary-authorization.v1",\n  "scope": "Six fixed public fixture images and nine fixed command templates. Approval of this exact table is separately required; no native results or current main qualification."\n}\n'
        plan = {'schema': 'chio.public-linux-primary-plan.v2', 'candidate': '/var/tmp/chio-public-directory.b2b7534cfd08', 'authorization_sha256': '0658e3dfa7e8a5ecd58a11ccc4842e76275fd055bd57052e063bf238f6908f21', 'tools': [{'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/consumer/physical_publication_functions.py', 'sha256': '35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564'}, {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/consumer/probe-observation-functions.py', 'sha256': '6137af233bdbbedc245eb5105a8fe381a6981576a81b582c5c5ae8ce73aaa027'}, {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/consumer/scope-record-functions.py', 'sha256': 'cd1da76e46982c7f8846cb5e3f5526e4dbc2a54afb486a7361a485676f25b1e6'}, {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/consumer/verify_public_compilation_probes.py', 'sha256': '47deea10c5be41a12dd2b4528677623c01999f4a81ae8a50c80d1f25099c0f31'}, {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/inventory-collector.py', 'sha256': '0ec77f139132a449270a96baf188a49efad057d3d8be3214e118efcb7d34f410'}, {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/run-public-compiler-campaign-current.py', 'sha256': 'e3b2cca44d42b0487ca604061a30486fdf35402d4bf6bf8f47802c90079fb5cf'}]}
        summary = {'schema': 'chio.public-linux-primary-result.v2', 'authorization_sha256': '0658e3dfa7e8a5ecd58a11ccc4842e76275fd055bd57052e063bf238f6908f21'}
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            "0658e3dfa7e8a5ecd58a11ccc4842e76275fd055bd57052e063bf238f6908f21")
        return raw,plan,summary

    def test_public_primary_payload_is_bound_to_its_reviewed_tool_roster(self):
        raw,plan,summary = self.public_primary_contract_fixture()
        authorization,tools,digest = self.audit.checked_primary_compiler_contract(plan,summary,raw)
        self.assertEqual(authorization,json.loads(raw))
        self.assertEqual(tools,{row["path"]:row["sha256"] for row in plan["tools"]})
        self.assertEqual(digest,plan["authorization_sha256"])

    def test_public_primary_contract_refuses_crossed_payload_rosters_and_summaries(self):
        raw,plan,summary = self.public_primary_contract_fixture()
        old_authority = deepcopy(plan)
        old_authority["authorization_sha256"] = self.audit.PRIMARY_AUTHORIZATION_SHA
        old_tools = deepcopy(plan)
        old_tools["tools"] = [{"path":str(Path(plan["candidate"])/"target/metadata"/name),"sha256":digest}
            for name,digest in self.audit.SCOPE_DEPENDENCY_PRIMARY_COMPILER_TOOLS.items()]
        old_summary = deepcopy(summary)
        old_summary["authorization_sha256"] = self.audit.PRIMARY_AUTHORIZATION_SHA
        for changed,observed in [(old_authority,summary),(old_tools,summary),(plan,old_summary)]:
            with self.subTest(authorization=changed["authorization_sha256"]):
                with self.assertRaises(ValueError):
                    self.audit.checked_primary_compiler_contract(changed,observed,raw)
        for changed in [old_authority,old_tools]:
            with self.assertRaises(ValueError):self.audit.audit_primary_compiler_tools(changed)

    def test_public_primary_contract_checks_every_tool_and_untyped_authority(self):
        raw,plan,summary = self.public_primary_contract_fixture()
        for index in range(6):
            for field,value in [("path","/usr/forged-tool"),("sha256","0"*64),("path",None),("sha256",True)]:
                with self.subTest(index=index,field=field):
                    changed = deepcopy(plan)
                    changed["tools"][index][field] = value
                    with self.assertRaises(ValueError):
                        self.audit.checked_primary_compiler_contract(changed,summary,raw)
        for value in [None,True,1,"0"*64]:
            with self.subTest(value=value):
                changed = deepcopy(plan)
                changed["authorization_sha256"] = value
                with self.assertRaises(ValueError):self.audit.audit_primary_compiler_tools(changed)
        for changed in [raw+b"\n",bytearray(raw),b"{}",None]:
            with self.assertRaises(ValueError):self.audit.checked_public_authorization(changed)


    def primary_authorization_join_clauses(self):
        import ast
        tree = ast.parse(TOOL.read_bytes())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == "audit_current_primary_compiler_probes")
        nodes = list(ast.walk(function))
        def assigned(name):
            return next(node for node in nodes if isinstance(node, ast.Assign)
                        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
        def requires(reason):
            return [node for node in nodes if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                    and isinstance(node.value.func, ast.Name) and node.value.func.id == "require"
                    and len(node.value.args) == 2 and isinstance(node.value.args[1], ast.Constant)
                    and node.value.args[1].value == reason]
        pin_checks = requires("compiled_profile_primary_tool")
        report_checks = [node for node in requires("compiled_profile_primary_custody")
                         if any(isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute)
                                and isinstance(value.func.value, ast.Name) and value.func.value.id == "original"
                                and value.func.attr == "get" and value.args
                                and isinstance(value.args[0], ast.Constant)
                                and value.args[0].value == "authorization_sha256" for value in ast.walk(node))]
        self.assertEqual(len(pin_checks), 1)
        self.assertEqual(len(report_checks), 1)
        return assigned("expected_pins"), pin_checks[0], assigned("report_fields"), report_checks[0]


    def invoke_original_primary_join_clause(self, node, context):
        import ast
        scope = dict(self.audit.__dict__)
        scope.update(context)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),
                     str(TOOL),"exec"),scope)
        return scope


    def test_public_primary_payload_threads_through_execution_file_pins(self):
        raw,plan,summary = self.public_primary_contract_fixture()
        _,tools,digest = self.audit.checked_primary_compiler_contract(plan,summary,raw)
        assignment,check,_,_ = self.primary_authorization_join_clauses()
        candidate = Path(plan["candidate"])
        controller = candidate/"target/metadata/run-public-compiler-campaign-current.py"
        original_plan = candidate/"target/metadata/primary-campaign-plan.json"
        authorization = candidate/"target/metadata/public-probe-authorization.json"
        plan_digest = "9ef129a977e7066e86e12cacfc525bc0a2287fd197d2dd382e5171f1c2acd13b"
        context = {"candidate":candidate,"tools":tools,"authorization_sha":digest,
            "original_controller":controller,"original_plan":original_plan,
            "original_authorization":authorization,"controller":{"sha256":tools[str(controller)]},
            "evidence":{"plan":{"sha256":plan_digest}}}
        expected = self.invoke_original_primary_join_clause(assignment,context)
        actual_images = {**tools,str(original_plan):plan_digest,str(authorization):digest}
        # A guard fixture from actual B2 Source41 digests; no new provenance.
        pins = [{"purpose":purpose,"path":path,"observed":{"sha256":actual_images[path]}}
                for purpose,path,_ in expected["expected_pins"]]
        self.invoke_original_primary_join_clause(check,{**expected,"pins":pins})
        changed = deepcopy(pins)
        next(row for row in changed if row["purpose"]=="compiler-primary-authorization")["observed"]["sha256"] = self.audit.PRIMARY_AUTHORIZATION_SHA
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_tool$"):
            self.invoke_original_primary_join_clause(check,{**expected,"pins":changed})

    def test_public_primary_payload_threads_through_original_audit_report(self):
        raw,plan,summary = self.public_primary_contract_fixture()
        _,_,digest = self.audit.checked_primary_compiler_contract(plan,summary,raw)
        _,_,assignment,check = self.primary_authorization_join_clauses()
        report_fields = self.invoke_original_primary_join_clause(assignment,{})["report_fields"]
        # Exact original allowed-read report, independently joined in B2.
        original = {'authorization_sha256': '0658e3dfa7e8a5ecd58a11ccc4842e76275fd055bd57052e063bf238f6908f21', 'compiled_closure_status': 'not-established', 'coverage': 'original-namespace-public-microprobe-record-joins-only', 'launcher_capture': {'stderr': {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/primary-observations/allowed-read/launcher.stderr.log', 'sha256': 'c94acb7595e5946c51efabd4ab08721b040ef0cf5aee413633b3ab69fbf41149', 'size': 781}, 'stdout': {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/primary-observations/allowed-read/launcher.stdout.log', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'size': 0}}, 'launcher_observation': {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/metadata/primary-observations/allowed-read/launcher-observation.json', 'sha256': 'd3532dd0ce072351e0ca2182f2454b48ad345ee867256d91a9735a5aad7c938d', 'size': 1438}, 'original_namespace': '/var/tmp/chio-public-directory.b2b7534cfd08/target/records/allowed-read', 'primary_probe_result_coverage': 'separate actual whole controller execution required', 'probe_observation': {'mode': 'allowed-read', 'result': {'public_bytes': 20}, 'schema': 'chio.public-linux-compilation-probe.v1'}, 'qualified': False, 'required_sync_observation_sha256': '7e9bb7f41ca5c4a4672b6f3e96023c02e537a20836ff69453ec4301e5a56226d', 'schema': 'chio.original-public-compilation-probe-verification.v2', 'scope_id': 'b610e8602a2d1a51f7560aa4d53efca2879aa82b5edce05786952e3f5fc8b498', 'scope_path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/evidence/allowed-read/d209cb8da63546cab3dd7bb4ad396df5/scope.json', 'scope_stderr_capture': {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/evidence/allowed-read/d209cb8da63546cab3dd7bb4ad396df5/stderr.log', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'size': 0}, 'scope_stdout_capture': {'path': '/var/tmp/chio-public-directory.b2b7534cfd08/target/evidence/allowed-read/d209cb8da63546cab3dd7bb4ad396df5/stdout.log', 'sha256': 'b37667547968f46a90a4e58ed80984392d2a85619b08ea0ef9bc7ee47db0313d', 'size': 109}, 'source_binding': '078f14932b59d6d1cd487a9e36da6811e238a6c85b82ddc5a4b56184250b0eb9', 'verified_compilations': 0, 'verified_dispatches': 0, 'verified_inventory_images': 1624, 'verified_publications': 0}
        context = {"original":original,"report_fields":report_fields,
            "micro_binding":"078f14932b59d6d1cd487a9e36da6811e238a6c85b82ddc5a4b56184250b0eb9",
            "scope_path":Path(original["scope_path"]),"candidate":Path(plan["candidate"]),
            "case":{"name":"allowed-read"},"observed":{"launcher_capture":original["launcher_capture"]},
            "ref":original["launcher_observation"],"authorization_sha":digest}
        self.invoke_original_primary_join_clause(check,context)
        changed = deepcopy(context)
        changed["original"]["authorization_sha256"] = self.audit.PRIMARY_AUTHORIZATION_SHA
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_custody$"):
            self.invoke_original_primary_join_clause(check,changed)

    def test_formal_kani_version_requires_the_current_released_toolchain(self):
        supported = "Kani Rust Verifier 0.68.0 (cargo plugin)\nCBMC 6.11.0\n"
        self.audit.audit_kani_tool_version(supported)
        for mutant in [supported.replace("0.68.0","0.67.0"), supported.replace("6.11.0","6.10.0"),
                       supported.replace(" (cargo plugin)"," (standalone)"),
                       "cargo-kani 0.68.0\n", supported + "unexpected trailer\n",
                       supported.replace("CBMC 6.11.0\n","")]:
            with self.subTest(version=mutant), self.assertRaisesRegex(ValueError,"^qualification.formal_tool_version$"):
                self.audit.audit_kani_tool_version(mutant)



class PublicLauncherObservationTest(unittest.TestCase):
    """Exercise maintained command and capture checks with fixed public inputs."""

    setUp = QualificationAuditTest.setUp

    def fixture(self, name="allowed-read"):
        candidate = "/var/tmp/chio-public-fixture"
        authorization = self.audit.checked_public_authorization(PRIMARY_FIXTURE.AUTHORIZATION_BYTES)
        approved = next(row for row in authorization["cases"] if row["name"] == name)
        configuration = candidate + "/" + approved["configuration_relative_path"]
        command = [value.format(candidate=candidate, configuration=configuration)
                   for value in approved["command_template"]]
        logs, captures = {}, {}
        for stream, body in [("stdout", b""), ("stderr", b"PUBLIC-OUTSIDE-SYNC-OBSERVATION\n")]:
            path = candidate + "/target/metadata/primary-observations/" + name + "/launcher." + stream + ".log"
            logs[path] = body
            captures[stream] = {"path": path, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
        observation = {"schema": "chio.public-linux-launcher-observation.v1", "candidate": candidate,
            "source_binding": "a" * 64, "name": name, "command": command, "actual_exit": 0,
            "command_timeout_seconds": approved["timeout_seconds"], "elapsed_seconds": 1.0,
            "pid": 123, "process_group": 123, "launcher_capture": captures}
        return observation, {"candidate": candidate, "source_binding": "a" * 64}, command[command.index("--")+1:], logs

    def consume(self, parts):
        observation, configuration, command, logs = parts
        authorization = self.audit.checked_public_authorization(PRIMARY_FIXTURE.AUTHORIZATION_BYTES)
        return self.audit.checked_public_launcher_observation(
            observation, authorization, configuration, command, lambda path: logs[str(path)])

    def test_exact_approved_commands_and_original_outer_captures_are_accepted(self):
        self.assertEqual(hashlib.sha256(PRIMARY_FIXTURE.AUTHORIZATION_BYTES).hexdigest(),
                         PRIMARY_FIXTURE.AUTHORIZATION_SHA256)
        self.assertEqual(hashlib.sha256(PRIMARY_FIXTURE.CONTROLLER_BYTES).hexdigest(),
                         PRIMARY_FIXTURE.CONTROLLER_SHA256)
        for name in self.audit.PRIMARY_COMPILER_PROBES:
            with self.subTest(name=name):
                self.assertEqual(self.consume(self.fixture(name)),
                                 {"stdout": b"", "stderr": b"PUBLIC-OUTSIDE-SYNC-OBSERVATION\n"})

    def test_missing_replaced_and_resealed_outer_capture_references_refuse(self):
        for change in ["missing", "changed-digest", "changed-size", "changed-body", "alternate-path", "float-size"]:
            with self.subTest(change=change):
                parts = self.fixture()
                observation, _, _, logs = parts
                capture = observation["launcher_capture"]["stderr"]
                reason = "micro_primary_capture"
                if change == "missing":
                    del observation["launcher_capture"]
                    reason = "micro_primary_observation"
                elif change == "changed-body":
                    logs[capture["path"]] = b"REPLACED-PUBLIC-BODY"
                elif change == "alternate-path":
                    capture["path"] += ".replacement"
                    logs[capture["path"]] = b"PUBLIC-OUTSIDE-SYNC-OBSERVATION\n"
                elif change == "changed-digest":
                    capture["sha256"] = "0" * 64
                elif change == "float-size":
                    capture["size"] = float(capture["size"])
                else:
                    capture["size"] += 1
                with self.assertRaisesRegex(ValueError, "^qualification\\." + reason + "$"):
                    self.consume(parts)

    def test_unsupported_argv_or_configuration_cannot_self_reseal(self):
        for change in ["argv", "config", "inner", "source", "false-exit", "false-pid", "extra-ready"]:
            with self.subTest(change=change):
                parts = self.fixture()
                observation, _, command, _ = parts
                reason = "micro_primary_command" if change in {"argv", "config", "inner"} else "micro_primary_observation"
                if change == "argv":
                    observation["command"][-1] += ".altered"
                elif change == "config":
                    observation["command"][4] += ".samebytes"
                elif change == "inner":
                    command[-1] += ".altered"
                elif change == "source":
                    observation["source_binding"] = "b" * 64
                elif change == "false-exit":
                    observation["actual_exit"] = False
                elif change == "false-pid":
                    observation["pid"] = observation["process_group"] = True
                else:
                    observation["qualified"] = True
                with self.assertRaisesRegex(ValueError, "^qualification\\." + reason + "$"):
                    self.consume(parts)

    def test_fixed_authorization_rejects_a_self_approved_payload(self):
        authorization = json.loads(PRIMARY_FIXTURE.AUTHORIZATION_BYTES)
        authorization["payloads"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "^qualification.micro_primary_authorization$"):
            self.audit.checked_public_authorization((json.dumps(authorization, indent=2, sort_keys=True)+"\n").encode())

    def test_inner_probe_observation_is_distinct_from_outer_launcher_bytes(self):
        sample = {"schema": "chio.public-linux-compilation-probe.v1", "mode": "allowed-read",
                  "result": {"public_bytes": 20}}
        raw = json.dumps(sample).encode() + b"\n"
        self.assertEqual(self.audit.checked_public_probe_observation(raw, "allowed-read", 0), sample)
        for raw in self.consume(self.fixture()).values():
            with self.subTest(outer_stream=raw), self.assertRaisesRegex(ValueError, "^qualification.micro_primary_probe$"):
                self.audit.checked_public_probe_observation(raw, "allowed-read", 0)
        for value in [20.0, False]:
            sample["result"]["public_bytes"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "^qualification.micro_primary_probe$"):
                self.audit.checked_public_probe_observation(json.dumps(sample).encode()+b"\n", "allowed-read", 0)


class CurrentPrimaryPackageTest(unittest.TestCase):
    """Finite synthetic parser controls, without native campaign execution."""

    setUp = QualificationAuditTest.setUp

    def package(self, root):
        return PRIMARY_FIXTURE.PrimaryProbePackage(self.audit, root, ROOT)

    def refuse(self,change,reason,*,bundle_change=None):
        with tempfile.TemporaryDirectory() as temporary:
            package = self.package(Path(temporary))
            change(package)
            package.bundle()
            if bundle_change is not None:
                bundle_change(package)
            reference = package.ref("final-evidence.json",package.evidence)
            with self.assertRaisesRegex(ValueError,"^qualification\\."+reason+"$"):
                self.audit.audit_primary_compiler_probes(package.root,reference,package.sources)

    def test_current_decoder_joins_separate_inner_and_outer_streams(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = self.package(Path(temporary)); reference = package.bundle()
            result = self.audit.audit_primary_compiler_probes(package.root,reference,package.sources)
            self.assertEqual(result["case_count"],9)
            self.assertNotIn("qualified",result)

    def test_current_decoder_does_not_accept_legacy_evidence_as_current(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = self.package(Path(temporary)); package.bundle()
            package.evidence["schema"] = "chio.linux-compiler-primary-probes.v1"
            reference = package.ref("legacy.json",package.evidence)
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_primary_record$"):
                self.audit.audit_primary_compiler_probes(package.root,reference,package.sources)

    def test_missing_inner_capture_refuses_at_the_case_boundary(self):
        self.refuse(lambda package:package.cases[0].pop("scope_stdout"),"compiled_profile_primary_case")

    def test_missing_or_reordered_case_cannot_change_the_fixed_denominator(self):
        for change in [lambda package:package.cases.pop(),lambda package:package.cases.reverse(),
                       lambda package:package.cases.__setitem__(0,False)]:
            with self.subTest(change=change):
                self.refuse(change,"compiled_profile_primary_denominator")

    def test_literal_authorization_cannot_be_replaced_by_a_self_consistent_table(self):
        for field in ["timeout", "payload"]:
            def change(package):
                value = package.read(package.authorization_ref)
                if field == "timeout":
                    value["cases"][0]["timeout_seconds"] += 1
                else:
                    value["payloads"][0]["sha256"] = "0" * 64
                package.replace(package.authorization_ref,value)
            with self.subTest(field=field):
                self.refuse(change,"micro_primary_authorization")

    def test_resealed_result_and_plan_cannot_approve_altered_argv_or_configuration(self):
        for argument in [-1, 4]:
            def change(package):
                def alter_command(row):
                    row["command"][argument] += ".altered"
                package.change_observation(0, alter_command)
                command = package.results[0]["command"]
                package.configs[0]["command"] = command
                package.replace(package.cases[0]["command"], command[command.index("--")+1:])
            with self.subTest(argument=argument):
                self.refuse(change, "micro_primary_command")

    def test_boolean_deadline_does_not_equal_a_numeric_deadline(self):
        for field,value in [("ordinary_seconds",120.0),("retry",0)]:
            def change(package,field=field,value=value):
                for key in ["plan","summary","dispatch_start"]:
                    ref=package.evidence[key];data=package.read(ref);data["caps"][field]=value;package.replace(ref,data)
            with self.subTest(field=field):
                self.refuse(lambda _:None,"compiled_profile_primary_execution",bundle_change=change)

    def test_runtime_output_must_come_from_the_case_path_and_pinned_collector(self):
        for field in ["path","command","actual_exit"]:
            def change(package,field=field):
                def mutate(row):
                    if field=="path":row["runtime_before"][field] += ".copied"
                    elif field=="command":row["runtime_before"][field][3] += ".copied"
                    else:row["runtime_before"][field] = False
                package.change_result(0,mutate)
            with self.subTest(field=field):
                self.refuse(change,"compiled_profile_primary_source")

    def test_same_byte_outer_capture_cannot_claim_another_original_path(self):
        self.refuse(lambda package:package.cases[0]["launcher_stdout"].update(original_path="/var/tmp/copied-stdout.log"),
                    "compiled_profile_primary_capture")

    def test_boolean_capture_size_cannot_replace_an_empty_stream_size(self):
        self.refuse(lambda package:package.cases[0]["launcher_stdout"].update(size=False),"compiled_profile_primary_capture")

    def test_current_capture_references_require_their_measured_size_and_original_path(self):
        for name in ["launcher_stdout","launcher_stderr","scope_stdout","scope_stderr","launcher_observation"]:
            for field in ["size","original_path"]:
                with self.subTest(name=name,field=field):
                    self.refuse(lambda package,name=name,field=field:package.cases[0][name].pop(field),
                                "compiled_profile_primary_capture")

    def test_native_metadata_probes_cannot_satisfy_compilation_minimum(self):
        for index in [7,8]:
            with self.subTest(index=index):
                self.refuse(lambda package,index=index:package.change_original(index,lambda row:row.update(verified_compilations=0)),
                            "compiled_profile_primary_observation")

    def test_original_report_counts_are_typed_and_cannot_promote_qualification(self):
        for field,value,reason in [("verified_publications",True,"compiled_profile_primary_observation"),
                                   ("verified_compilations",1.0,"compiled_profile_primary_observation"),
                                   ("qualified",True,"compiled_profile_primary_custody")]:
            with self.subTest(field=field):
                self.refuse(lambda package,field=field,value=value:package.change_original(0,lambda row:row.update({field:value})),reason)

    def test_original_namespace_and_scope_identity_are_checked(self):
        for field,value in [("original_namespace","/var/tmp/copied-namespace"),("scope_id","not-a-scope-id")]:
            with self.subTest(field=field):
                self.refuse(lambda package,field=field,value=value:package.change_original(0,lambda row:row.update({field:value})),
                            "compiled_profile_primary_custody")

    def test_boolean_launcher_exit_does_not_equal_success(self):
        self.refuse(lambda package:package.change_result(0,lambda row:row.update(actual_exit=False)),"compiled_profile_primary_case")

    def test_campaign_range_checks_precede_numeric_conversion(self):
        for value in [10**400, 1e308, 0, -1, True]:
            with self.subTest(field="summary",value=value):
                def change_summary(package,value=value):
                    reference=package.evidence["summary"]
                    summary=package.read(reference)
                    summary["elapsed_from_first_dispatch_seconds"]=value
                    package.replace(reference,summary)
                self.refuse(lambda _:None,"compiled_profile_primary_execution",bundle_change=change_summary)
            with self.subTest(field="case",value=value):
                self.refuse(lambda package,value=value:package.change_observation(0,
                    lambda row:row.update(elapsed_seconds=value)),"compiled_profile_primary_execution")
            with self.subTest(field="timeout",value=value):
                self.refuse(lambda package,value=value:package.change_observation(0,
                    lambda row:row.update(command_timeout_seconds=value)),"compiled_profile_primary_execution")

    def test_wrong_public_inner_bytes_refuse_even_when_report_and_hashes_match(self):
        def change(package):
            sample = package.sample("allowed-read");sample["result"]["public_bytes"] = 21
            ref = package.cases[0]["scope_stdout"]
            package.replace(ref,self.audit.compilation_canonical(sample)+b"\n")
            package.change_original(0,lambda row:row.update(probe_observation=sample,
                scope_stdout_capture={"path":ref["original_path"],"sha256":ref["sha256"],"size":ref["size"]}))
        self.refuse(change,"micro_primary_probe")

    def test_duplicate_inner_observation_is_not_a_single_success(self):
        def change(package):
            ref=package.cases[0]["scope_stdout"];raw=(package.root/ref["path"]).read_bytes()*2
            package.replace(ref,raw)
            package.change_original(0,lambda row:row.update(scope_stdout_capture={
                "path":ref["original_path"],"sha256":ref["sha256"],"size":ref["size"]}))
        self.refuse(change,"micro_primary_probe")

    def test_resealed_outer_success_cannot_replace_the_missing_inner_observation(self):
        def change(package):
            inner = package.cases[0]["scope_stdout"]
            outer = package.cases[0]["launcher_stdout"]
            package.replace(outer, (package.root/inner["path"]).read_bytes())
            package.change_observation(0, lambda row: row["launcher_capture"].update(stdout={
                "path": outer["original_path"], "sha256": outer["sha256"], "size": outer["size"]}))
            package.replace(inner, b"")
            package.change_original(0, lambda row: row.update(scope_stdout_capture={
                "path": inner["original_path"], "sha256": inner["sha256"], "size": inner["size"]}))
        self.refuse(change, "micro_primary_probe")

    def test_changed_required_sync_digest_refuses(self):
        self.refuse(lambda package:package.change_original(7,lambda row:row.update(required_sync_observation_sha256="0"*64)),
                    "compiled_profile_primary_sync")

    def test_durability_unknown_refuses_despite_complete_physical_outcomes(self):
        def change(package):
            ref=package.cases[7]["launcher_stderr"]
            raw=(package.root/ref["path"]).read_bytes().replace(b'"status":"confirmed"',b'"status":"unconfirmed"')
            package.replace(ref,raw)
            package.change_observation(7,lambda row:row["launcher_capture"].update(stderr={
                "path":ref["original_path"],"sha256":ref["sha256"],"size":ref["size"]}))
        self.refuse(change,"compiler_required_sync_observation")

    def test_missing_outside_unit_outcomes_cannot_be_inferred_from_the_report(self):
        def change(package):
            ref=package.cases[7]["launcher_stderr"];package.replace(ref,b"")
            package.change_observation(7,lambda row:row["launcher_capture"].update(stderr={
                "path":ref["original_path"],"sha256":ref["sha256"],"size":ref["size"]}))
        self.refuse(change,"compiled_profile_primary_sync")

    def test_resealed_inner_stderr_cannot_supply_outer_publication_outcomes(self):
        def change(package):
            outer = package.cases[7]["launcher_stderr"]
            inner = package.cases[7]["scope_stderr"]
            package.replace(inner, (package.root/outer["path"]).read_bytes())
            package.change_original(7, lambda row: row.update(scope_stderr_capture={
                "path": inner["original_path"], "sha256": inner["sha256"], "size": inner["size"]}))
            package.replace(outer, b"")
            package.change_observation(7, lambda row: row["launcher_capture"].update(stderr={
                "path": outer["original_path"], "sha256": outer["sha256"], "size": outer["size"]}))
        self.refuse(change, "compiled_profile_primary_sync")

    def test_actual_enclosing_process_exit_is_required(self):
        def change(package):
            ref=package.evidence["execution"]["provenance"]["result"]
            value=package.read(ref);value["actual_command_exit"] = 1;package.replace(ref,value)
        self.refuse(lambda _:None,"gate_execution_provenance",bundle_change=change)

    def test_actual_tool_pins_need_the_owning_purpose_in_both_brackets(self):
        def change(package):
            proof=package.evidence["execution"]["provenance"]
            for key in ["before","after"]:
                value=package.read(proof[key]);value["explicit_file_pins"][2]["purpose"]="unrelated-pin"
                value["content_manifest_sha256"]=hashlib.sha256(json.dumps({name:value[name] for name in ["git","entries","explicit_file_pins"]},
                    sort_keys=True,ensure_ascii=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
                package.replace(proof[key],value)
            result=package.read(proof["result"])
            result["before_manifest_sha256"]=result["after_manifest_sha256"]=value["content_manifest_sha256"]
            package.replace(proof["result"],result)
        self.refuse(lambda _:None,"compiled_profile_primary_tool",bundle_change=change)


class RetainedCohortOutcomeTest(unittest.TestCase):
    """Retained model/native facts must support the outcome counted by the auditor."""

    def setUp(self):
        QualificationAuditTest.setUp(self)

    def cohort_package(self, root, mutation=None, *, qualified=True, selected=96, manifest_mutation=None):
        def retain(name, value, *, raw=False):
            body = value if raw else json.dumps(value, allow_nan=False).encode()
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            return {"path":name, "sha256":hashlib.sha256(body).hexdigest()}
        sources = [{"path":"fixtures/source.py", "sha256":"0" * 64}]
        base = "1" * 40
        candidate = self.audit.binding(sources, base)
        planned = [{"id":f"{host}-{workflow}-{arm}-{case}-r{repeat}",
                    "host":host, "workflow":workflow, "arm":arm, "case":case, "repetition":repeat}
                   for host in ("langgraph", "crewai") for workflow in ("support", "artifact")
                   for arm in ("baseline", "product")
                   for case in ("authorized", "lost_ack_restart", "wrong_authority", "conflicting_basis")
                   for repeat in range(1, 4)]
        manifest = {"schema":"chio.recovery-live-corpus.v2",
            "source_inventory_version":self.audit.INVENTORY_VERSION,
            "provider_endpoint":self.audit.PROVIDER_ENDPOINT, "sources":sources, "base_commit":base,
            "source_binding":candidate, "model":self.audit.COHORT_MODEL,
            "hosts":dict(self.audit.COHORT_HOSTS), "authority_policy":"2" * 64,
            "trials":planned,
            "budgets":{"model_calls":4, "tool_actions":8, "prompt_bytes":16384,
                       "output_tokens":512, "output_bytes":8192, "provider_seconds":45,
                       "native_http_seconds":120, "native_preparation_seconds":240,
                       "native_shutdown_seconds":120, "host_start_deadline_seconds":240,
                       "trial_seconds":720, "concurrent_trials":2, "transport_retries":0}}
        if manifest_mutation is not None:
            manifest_mutation(manifest)
        # These retained bytes exercise the parser's executable-format check.
        # They are a synthetic fixture and are never executed or called native proof.
        image = retain("executable.fixture", b"\x7fELF" + b"\0" * 60, raw=True)
        image["size"] = 64
        log = retain("native.log", b"test live_comparative_native_host ... ok\n"
            b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", raw=True)
        rows = []
        trials = {}
        positives = {(h, w, a, c):0 for h in ("langgraph", "crewai")
                     for w in ("support", "artifact") for a in ("baseline", "product")
                     for c in ("authorized", "lost_ack_restart")}
        unknown_native = 0
        unknown_tokens = 0
        for index, plan in enumerate(planned[:selected]):
            positive = plan["case"] in ("authorized", "lost_ack_restart")
            messages = [{"role":"user", "content":"public synthetic request"}]
            prompt = json.dumps(messages, ensure_ascii=False, separators=(",", ":")).encode()
            attempt = {"provider_endpoint":self.audit.PROVIDER_ENDPOINT, "model":self.audit.COHORT_MODEL,
                       "request_id":"synthetic-provider-response", "error":None,
                       "messages":messages, "prompt_bytes":len(prompt),
                       "prompt_sha256":hashlib.sha256(prompt).hexdigest(),
                       "input_tokens":7, "output_tokens":3, "seconds":0.01,
                       "completion":"public synthetic completion"}
            native = {"effects":int(positive), "charges":int(positive),
                      "unauthorized_effects":0, "duplicate_effects":0, "unresolved":0,
                      "unresolved_age_ms":0, "extra_approvals":0,
                      "source_label_retained":True, "useful_completion":positive}
            row = {**plan, "source_binding":candidate, "base_commit":base,
                   "provider_endpoint":manifest["provider_endpoint"],
                   "source_inventory_version":manifest["source_inventory_version"],
                   "authority_policy":manifest["authority_policy"], "requested_model":manifest["model"],
                   "hidden_retries":0, "tool_actions":int(positive), "model_attempts":[attempt],
                   "native":native, "native_observation":"observed", "native_exit_code":0,
                   "native_executable":dict(image), "elapsed_seconds":10,
                   "outcome":"complete" if positive else "refused"}
            if mutation is not None:
                mutation(row, index)
            rows.append(row)
            unknown_tokens += sum(a.get("input_tokens") is None or a.get("output_tokens") is None
                                  for a in row["model_attempts"])
            current_native = row["native"]
            unknown_native += current_native is None
            key = tuple(row[k] for k in ("host", "workflow", "arm", "case"))
            if key in positives and row["outcome"] == "complete" and current_native is not None and current_native["useful_completion"]:
                positives[key] += 1
            refs = {"result":retain("trials/" + row["id"] + ".json", row),
                    "native_log":log, "native_executable":image}
            if current_native is not None:
                refs["native"] = retain("native/" + row["id"] + ".json", current_native)
            trials[row["id"]] = refs
        raw_rows = b"\n".join(json.dumps(r, allow_nan=False).encode() for r in rows) + b"\n"
        evidence = {"schema":"chio.recovery-live-cohort-evidence.v1", "source_binding":candidate,
                    "manifest":retain("manifest.json", manifest), "rows":retain("rows.jsonl", raw_rows, raw=True),
                    "trials":trials,
                    "recomputed":{"planned_trials":96, "measured_trials":selected,
                        "unknown_trials":96 - selected, "native_unknown_trials":unknown_native,
                        "unknown_token_usage_attempts":unknown_tokens, "positive_strata":16,
                        "positive_strata_passed":sum(v >= 1 for v in positives.values()), "qualified":qualified}}
        return retain("evidence.json", evidence), candidate

    def observe(self, mutation=None, *, qualified=True, selected=96, manifest_mutation=None):
        retained = getattr(self, "retained_case_directory", None)
        if retained is not None:
            retained.mkdir(parents=True, exist_ok=False)
            reference, candidate = self.cohort_package(retained, mutation, qualified=qualified, selected=selected,
                                                      manifest_mutation=manifest_mutation)
            try:
                result = self.audit.audit_live_cohort(retained, reference, candidate)
            except ValueError as error:
                (retained / "reader-observation.json").write_text(json.dumps({
                    "scope":"synthetic retained-file parser control, no native or provider execution",
                    "exception_category":str(error), "whole_qualification":False}) + "\n")
                raise
            (retained / "reader-observation.json").write_text(json.dumps({
                "scope":"synthetic retained-file parser control, no native or provider execution",
                "reader_return":result, "whole_qualification":False}) + "\n")
            return result
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            reference, candidate = self.cohort_package(root, mutation, qualified=qualified, selected=selected,
                                                      manifest_mutation=manifest_mutation)
            return self.audit.audit_live_cohort(root, reference, candidate)

    def test_supported_cohort_parser_retains_all_ninety_six_rows_and_sixteen_strata(self):
        observed = self.observe()
        self.assertTrue(observed["qualified"])
        self.assertEqual((observed["measured_trials"], observed["positive_strata_passed"]), (96, 16))

    def test_complete_cohort_cannot_be_supported_only_by_failed_provider_attempts(self):
        def replace(row, _):
            for attempt in row["model_attempts"]:
                attempt.update(model=None, error="provider_unavailable", input_tokens=None, output_tokens=None)
                attempt.pop("completion")
                attempt.pop("request_id")
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_trial_completion$"):
            self.observe(replace)

    def test_success_log_cannot_hide_a_failed_native_process_exit(self):
        def replace(row, index):
            if index == 0:
                row["native_exit_code"] = 101
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_native_execution$"):
            self.observe(replace)

    def test_native_process_exit_requires_an_integer_not_boolean_success(self):
        def replace(row, index):
            if index == 0:
                row["native_exit_code"] = False
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_native_execution$"):
            self.observe(replace)

    def test_successful_provider_attempt_requires_its_retained_completion(self):
        def replace(row, index):
            if index == 0:
                row["model_attempts"][0].pop("completion")
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_provider_completion$"):
            self.observe(replace)

    def test_successful_provider_tokens_cannot_exceed_the_declared_output_bound(self):
        def replace(row, index):
            if index == 0:
                row["model_attempts"][0]["output_tokens"] = 513
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_provider_completion$"):
            self.observe(replace)

    def test_successful_provider_utf8_completion_cannot_exceed_the_declared_byte_bound(self):
        def replace(row, index):
            if index == 0:
                row["model_attempts"][0]["completion"] = "\u00e9" * 4097
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_provider_completion$"):
            self.observe(replace)

    def test_serial_provider_elapsed_cannot_exceed_the_entire_recorded_trial(self):
        def replace(row, index):
            if index == 0:
                row["model_attempts"][0]["seconds"] = 1000
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_latency$"):
            self.observe(replace)

    def test_failed_native_process_is_retained_as_a_failed_cohort_observation(self):
        def replace(row, index):
            if index == 0:
                row["native_exit_code"] = 101
                row["native_execution_error"] = True
        self.assertFalse(self.observe(replace, qualified=False)["qualified"])

    def test_partial_trial_inventory_retains_unknown_slots_without_qualification(self):
        observed = self.observe(qualified=False, selected=48)
        self.assertEqual(observed["unknown_trials"], 48)
        self.assertFalse(observed["qualified"])

    def test_failed_provider_rows_remain_retained_without_useful_completion(self):
        def replace(row, _):
            row["outcome"] = "provider_error"
            row["native"]["useful_completion"] = False
            for attempt in row["model_attempts"]:
                attempt.update(model=None, error="provider_unavailable", input_tokens=None, output_tokens=None)
                attempt.pop("completion")
                attempt.pop("request_id")
        observed = self.observe(replace, qualified=False)
        self.assertFalse(observed["qualified"])
        self.assertEqual(observed["unknown_token_usage_attempts"], 96)

    def test_empty_provider_response_remains_retained_without_a_completion_claim(self):
        def replace(row, _):
            row["outcome"] = "skipped_tool"
            row["native"]["useful_completion"] = False
            row["model_attempts"][0]["completion"] = ""
        observed = self.observe(replace, qualified=False)
        self.assertFalse(observed["qualified"])
        self.assertEqual(observed["unknown_token_usage_attempts"], 0)

    def test_useful_native_completion_requires_a_recorded_tool_action(self):
        def replace(row, _):
            row["tool_actions"] = 0
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_completion_without_action$"):
            self.observe(replace)

    def test_live_version_outcomes_cannot_borrow_a_legacy_pending_value(self):
        def replace(row, _):
            if row["case"] in ("wrong_authority", "conflicting_basis"):
                row["outcome"] = "pending"
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_outcome$"):
            self.observe(replace)

    def test_manifest_and_trial_literals_cannot_substitute_the_computed_source_binding(self):
        def replace(row, _):
            row["source_binding"] = "f" * 64
        def replace_manifest(manifest):
            manifest["source_binding"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_manifest$"):
            self.observe(replace, manifest_mutation=replace_manifest)

    def test_present_native_facts_require_the_observed_presence_label(self):
        def replace(row, _):
            row["native_observation"] = "unknown"
        with self.assertRaisesRegex(ValueError, "^qualification.cohort_native_observation$"):
            self.observe(replace)

    def test_absent_native_facts_are_retained_as_unknown_without_qualification(self):
        def replace(row, _):
            row["native"] = None
            row["native_observation"] = "unknown"
            row["outcome"] = "native_error"
            row["native_exit_code"] = None
            row["model_attempts"] = []
        observed = self.observe(replace, qualified=False)
        self.assertEqual(observed["native_unknown_trials"], 96)
        self.assertEqual(observed["positive_strata_passed"], 0)
        self.assertFalse(observed["qualified"])


if __name__ == "__main__":
    unittest.main()
