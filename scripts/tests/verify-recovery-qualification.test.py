"""Qualification mutations must fail at their actual semantic boundary."""
from copy import deepcopy
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


if __name__ == "__main__":
    unittest.main()
