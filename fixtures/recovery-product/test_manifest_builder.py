import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from manifest_builder import SOURCE_INVENTORY_VERSION, source_binding, source_inventory, source_metadata, write_source_archive
import manifest_builder


class SupportedCampaignProfileTest(unittest.TestCase):
    def test_sealed_profile_matches_supported_hosts_without_changing_tasks_or_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = root / "authority.json"
            authority.write_text('{"public_fixture":true}\n')
            destination = root / "corpus"
            sources = [{"path":"fixtures/public-profile.py", "sha256":hashlib.sha256(b"PUBLIC = True\n").hexdigest()}]
            with patch.object(sys, "argv", ["manifest_builder.py", "--authority-contract", str(authority),
                                            "--destination", str(destination)]), \
                 patch.object(manifest_builder.subprocess, "check_output", return_value=b"1" * 40), \
                 patch.object(manifest_builder, "source_inventory", return_value=sources), \
                 patch.object(manifest_builder, "write_source_archive"):
                manifest_builder.main()
            body = (destination / "manifest.json").read_bytes()
            self.assertEqual((destination / "manifest.sha256").read_text().strip(), hashlib.sha256(body).hexdigest())
            manifest = json.loads(body)
        self.assertEqual(manifest["model"], "gpt-5.4-2026-03-05")
        self.assertEqual(manifest["hosts"], {"crewai":"0.203.2", "langgraph":"1.2.12", "openai":"3.3.0", "httpx":"0.28.1"})
        self.assertEqual(len(manifest["trials"]), 96)
        self.assertEqual(len({row["id"] for row in manifest["trials"]}), 96)
        self.assertEqual({row["case"] for row in manifest["trials"]},
                         {"authorized", "lost_ack_restart", "wrong_authority", "conflicting_basis"})
        self.assertEqual(manifest["budgets"], {
            "model_calls":4, "tool_actions":8, "prompt_bytes":16384, "output_tokens":512,
            "output_bytes":8192, "provider_seconds":45, "native_http_seconds":120,
            "native_preparation_seconds":240, "native_shutdown_seconds":120,
            "host_start_deadline_seconds":240, "trial_seconds":720,
            "concurrent_trials":2, "transport_retries":0})


class SourceInventoryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.git("init", "--quiet")

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], cwd=self.root)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_tracked_and_new_inputs_are_bound_without_a_baseline_document(self):
        tracked = self.write("crates/example/src/lib.rs", b"pub struct Original;\n")
        self.git("add", str(tracked.relative_to(self.root)))
        tracked.write_bytes(b"pub struct Current;\n")
        added = self.write("fixtures/example.py", b"VALUE = 1\n")
        rows = source_inventory(self.root)
        self.assertEqual(rows, [
            {"path": str(path.relative_to(self.root)),
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in [tracked, added]
        ])

    def test_cargo_credentials_are_metadata_only_without_opening_or_hashing_them(self):
        path = self.write("fixtures/credentials.toml",b"synthetic excluded Cargo credential fixture\n")
        original = os.open
        def public_open(name,flags,*arguments,**keywords):
            if os.fspath(name) == "credentials.toml" and not flags & os.O_DIRECTORY:
                raise AssertionError("excluded Cargo credential content was opened")
            return original(name,flags,*arguments,**keywords)
        with patch.object(os,"open",side_effect=public_open):
            rows = source_inventory(self.root)
            self.assertEqual(rows,[{"path":"fixtures/credentials.toml","state":"file",
                "mode":path.stat(follow_symlinks=False).st_mode & 0o7777,
                "content_coverage":"metadata-only","exclusion_reason":"secret-path-policy"}])
            archive = self.root/"sources.tar.gz"
            write_source_archive(self.root,rows,archive)
        with tarfile.open(archive) as stored:
            self.assertEqual(stored.getnames(),[])

    def test_directory_alias_preserves_a_contained_file_alias(self):
        payload = b"pub struct Input;\n"
        self.write("fixtures/public/input.rs",payload)
        alias = self.root/"fixtures/inputs/link.rs"
        alias.parent.mkdir()
        alias.symlink_to("../public/input.rs")
        (self.root/"fixtures/alias").symlink_to("inputs",target_is_directory=True)
        rows = source_inventory(self.root)
        self.assertEqual(rows,[{"path":name,"sha256":hashlib.sha256(payload).hexdigest()} for name in [
            "fixtures/alias/link.rs","fixtures/inputs/link.rs","fixtures/public/input.rs"]])
        archive = self.root/"sources.tar.gz"
        write_source_archive(self.root,rows,archive)
        with tarfile.open(archive) as stored:
            self.assertEqual(stored.getnames(),[row["path"] for row in rows])
            for row in rows:
                self.assertEqual(stored.extractfile(row["path"]).read(),payload)

    def test_generated_byte_alias_cannot_collide_with_secret_metadata(self):
        self.write("fixtures/public/input.rs",b"public input\n")
        (self.root/"fixtures/credential\u017f").symlink_to("public",target_is_directory=True)
        blob = self.git("hash-object","-w","fixtures/public/input.rs").decode().strip()
        self.git("update-index","--add","--cacheinfo",f"100644,{blob},fixtures/credentials/input.rs")
        with self.assertRaisesRegex(ValueError,"^campaign.case_collision$"):
            source_inventory(self.root)

    def test_secret_metadata_refuses_a_retargeted_parent(self):
        self.write("fixtures/vault/credentials.json",b"synthetic excluded content")
        parent = self.root/"fixtures/vault"
        original = os.open
        swapped = False
        def retarget(name,flags,*args,**kwargs):
            nonlocal swapped
            descriptor = original(name,flags,*args,**kwargs)
            if name == "vault" and flags & os.O_DIRECTORY and not swapped:
                parent.rename(self.root/"retired")
                parent.mkdir()
                (parent/"credentials.json").mkdir()
                swapped = True
            return descriptor
        with patch.object(os,"open",retarget):
            with self.assertRaisesRegex(ValueError,"^campaign.changed_source$"):
                source_metadata(self.root,Path("fixtures/vault/credentials.json"))
        self.assertTrue(swapped)

    def test_public_alias_never_follows_an_excluded_intermediate_link(self):
        self.write("fixtures/public.rs",b"public input\n")
        secret = self.root/"fixtures/private-key.pem"
        secret.symlink_to("public.rs")
        (self.root/"fixtures/alias.rs").symlink_to("private-key.pem")
        original = os.readlink
        observed = []
        def readlink(path,*args,**kwargs):
            observed.append(str(path))
            return original(path,*args,**kwargs)
        with patch.object(os,"readlink",readlink):
            with self.assertRaisesRegex(ValueError,"^campaign.symbolic_source$"):
                source_inventory(self.root)
        self.assertNotIn(str(secret),observed)

    def test_file_alias_rejects_directory_requirements_in_raw_link_syntax(self):
        self.write("fixtures/public.rs",b"public input\n")
        self.write("fixtures/notdir",b"ordinary file\n")
        alias = self.root/"fixtures/alias.rs"
        for target in ["notdir/../public.rs","public.rs/","public.rs/."]:
            with self.subTest(target=target):
                alias.symlink_to(target)
                try:
                    with self.assertRaisesRegex(ValueError,"^campaign.symbolic_source$"):
                        source_inventory(self.root)
                finally:
                    alias.unlink()

    def test_clean_tracked_source_is_included_and_deleted_source_is_absent(self):
        retained = self.write("Cargo.toml", b"[workspace]\n")
        deleted = self.write("crates/example/removed.rs", b"pub struct Removed;\n")
        self.git("add", ".")
        deleted.unlink()
        self.assertEqual(source_inventory(self.root), [{
            "path": "Cargo.toml", "sha256": hashlib.sha256(retained.read_bytes()).hexdigest(),
        }])

    def test_workspace_members_and_recovery_models_are_source_inputs(self):
        names = ["Makefile", "playwright.config.ts", "bench/native/src/lib.rs", "formal/diff-tests/src/lib.rs",
                 "integrations/host/src/lib.rs",
                 ".clusterfuzzlite/Dockerfile", ".config/nextest.toml", ".dst/harnesses.toml",
                 ".kani/harnesses.toml", ".loom/harnesses.toml", "arena/scenarios/example.toml",
                 "ci-gates/runtime.toml", "config/example.json", "contracts/src/Contract.sol",
                 "deploy/Dockerfile.sidecar", "labs/example/src/lib.rs", "packaging/example.rb.tmpl",
                 "supply-chain/config.toml", "wit/guards/world.wit",
                 "docs/architecture/recoverable-agent-runtime/model/state.rs",
                 "third_party/patched/src/lib.rs", "docs/standards/input.json",
                 "docs/architecture/CHIO_RUNTIME_BOUNDARIES.md"]
        for name in names:
            self.write(name, b"pub struct Source;\n")
        self.assertEqual([row["path"] for row in source_inventory(self.root)], sorted(names))

    def test_build_outputs_and_planning_documents_are_not_source_inputs(self):
        for name in ["docs/plans/notes.md", "fixtures/example/target/output",
                     "sdks/example/node_modules/package/index.js", "fixtures/example/.venv/config"]:
            self.write(name, b"excluded\n")
        self.write(".gitignore", b"fixtures/ignored.py\n")
        self.write("fixtures/ignored.py", b"ignored\n")
        self.git("add", ".")
        self.assertEqual(source_inventory(self.root), [{"path":".gitignore",
            "sha256":hashlib.sha256((self.root/".gitignore").read_bytes()).hexdigest()}])

    def test_symbolic_sources_cannot_escape_the_archive(self):
        secret = self.write("private.txt", b"outside source boundary\n")
        symbolic = self.root / "fixtures" / "linked.py"
        symbolic.parent.mkdir()
        symbolic.symlink_to(secret)
        with self.assertRaisesRegex(ValueError, "campaign.symbolic_source"):
            source_inventory(self.root)

    def test_secret_shaped_inputs_are_metadata_only_and_never_read_or_archived(self):
        import manifest_builder
        secret = self.write("fixtures/private-key.pem",b"synthetic excluded fixture\n")
        public = self.write("fixtures/public.rs",b"pub struct Public;\n")
        original = manifest_builder.read_source
        def public_only(root, relative, **options):
            if Path(relative) == secret.relative_to(self.root):
                raise AssertionError("secret-shaped input was opened for content")
            return original(root,relative,**options)
        with patch.object(manifest_builder,"read_source",public_only):
            rows = source_inventory(self.root)
            metadata = next(row for row in rows if row["path"] == "fixtures/private-key.pem")
            self.assertEqual(metadata,{"path":"fixtures/private-key.pem","content_coverage":"metadata-only",
                "exclusion_reason":"secret-path-policy","state":"file","mode":secret.stat().st_mode & 0o7777})
            destination = self.root/"sources.tar.gz"
            write_source_archive(self.root,rows,destination)
        with tarfile.open(destination) as archive:
            self.assertEqual([row.name for row in archive],[str(public.relative_to(self.root))])

    def test_secret_shaped_links_retain_metadata_without_following_the_target(self):
        target = self.write("undeclared.txt",b"synthetic excluded target\n")
        alias = self.root/"fixtures/credentials.pem"
        alias.parent.mkdir()
        alias.symlink_to(target)
        original = Path.resolve
        def no_secret_target(path,*arguments,**options):
            if path == alias:
                raise AssertionError("secret-shaped link was followed")
            return original(path,*arguments,**options)
        with patch.object(Path,"resolve",no_secret_target):
            rows = source_inventory(self.root)
        self.assertEqual(rows,[{"path":"fixtures/credentials.pem","content_coverage":"metadata-only",
            "exclusion_reason":"secret-path-policy","state":"symlink","mode":os.lstat(alias).st_mode & 0o7777}])

    def test_alias_swap_cannot_read_or_archive_an_undeclared_target(self):
        import manifest_builder
        public = self.write("fixtures/public.py", b"PUBLIC = 1\n")
        private = self.write("private.txt", b"synthetic undeclared bytes\n")
        alias = self.root / "fixtures/alias.py"
        alias.symlink_to(public)
        original_read = manifest_builder.read_source
        def swap(root, relative, **options):
            if relative == Path("fixtures/alias.py"):
                alias.unlink()
                alias.symlink_to(private)
            return original_read(root, relative, **options)
        with patch.object(manifest_builder, "read_source", swap):
            with self.assertRaisesRegex(ValueError, "campaign.(changed_source|symbolic_source)"):
                source_inventory(self.root)
        source = {"path":"fixtures/alias.py", "sha256":hashlib.sha256(private.read_bytes()).hexdigest()}
        with self.assertRaisesRegex(ValueError, "campaign.symbolic_source"):
            write_source_archive(self.root, [source], self.root / "sources.tar.gz")

    def test_directory_aliases_bind_declared_files_and_archive_regular_bytes(self):
        target = self.write("tests/fixtures/input.json", b'{"value":1}\n')
        alias = self.root / "crates" / "example" / "fixtures"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(target.parent, target_is_directory=True)
        self.write("tests/fixtures/.gitignore", b"ignored.json\n")
        self.write("tests/fixtures/ignored.json", b'{"private":true}\n')
        sources = source_inventory(self.root)
        names = {row["path"] for row in sources}
        self.assertIn("crates/example/fixtures/input.json", names)
        self.assertIn("tests/fixtures/input.json", names)
        self.assertNotIn("crates/example/fixtures/ignored.json", names)
        destination = self.root / "sources.tar.gz"
        write_source_archive(self.root, sources, destination)
        with tarfile.open(destination) as archive:
            self.assertEqual({member.name for member in archive}, names)
            self.assertTrue(all(member.isfile() for member in archive))
            self.assertEqual(archive.extractfile("crates/example/fixtures/input.json").read(), target.read_bytes())

    def test_directory_alias_swap_cannot_mix_member_names_and_referent_bytes(self):
        first = self.write("fixtures/first/one.py", b"FIRST = 1\n").parent
        second = self.write("fixtures/second/one.py", b"SECOND = 2\n").parent
        self.write("fixtures/second/two.py", b"EXTRA = 3\n")
        alias = self.root / "fixtures/linked"
        alias.symlink_to(first,target_is_directory=True)
        original = Path.is_symlink
        swapped = False
        def swap(path):
            nonlocal swapped
            if path == alias and not swapped:
                alias.unlink()
                alias.symlink_to(second,target_is_directory=True)
                swapped = True
            return original(path)
        with patch.object(Path,"is_symlink",swap):
            with self.assertRaisesRegex(ValueError,"campaign.changed_source"):
                source_inventory(self.root)

    def test_outside_aliases_and_source_cycles_fail_closed(self):
        alias = self.root / "fixtures" / "linked"
        alias.parent.mkdir()
        with tempfile.TemporaryDirectory() as outside:
            alias.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "campaign.symbolic_source"):
                source_inventory(self.root)
        alias.unlink()
        self.write("fixtures/input.py", b"VALUE = 1\n")
        alias.symlink_to(alias.parent, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "campaign.cyclic_source"):
            source_inventory(self.root)

    def test_archive_refuses_sources_changed_after_inventory(self):
        source = self.write("crates/example/src/lib.rs", b"pub struct Original;\n")
        sources = source_inventory(self.root)
        source.write_bytes(b"pub struct Changed;\n")
        with self.assertRaisesRegex(ValueError, "campaign.changed_source"):
            write_source_archive(self.root, sources, self.root / "sources.tar.gz")

    def test_case_aliases_in_the_git_index_refuse(self):
        source = self.write("fixtures/Case.py", b"VALUE = 1\n")
        self.git("add", "fixtures/Case.py")
        digest = self.git("hash-object", str(source)).decode().strip()
        self.git("update-index", "--add", "--cacheinfo", f"100644,{digest},fixtures/case.py")
        with self.assertRaisesRegex(ValueError, "campaign.case_collision"):
            source_inventory(self.root)

    def test_unicode_normalization_aliases_in_an_imported_git_index_refuse(self):
        source = self.write("fixtures/café.py", b"VALUE = 1\n")
        self.git("config", "core.precomposeunicode", "false")
        digest = self.git("hash-object", str(source)).decode().strip()
        for name in ["fixtures/café.py", "fixtures/cafe\u0301.py"]:
            self.git("update-index", "--add", "--cacheinfo", f"100644,{digest},{name}")
        with self.assertRaisesRegex(ValueError, "campaign.case_collision"):
            source_inventory(self.root)

    def test_inventory_binding_uses_the_declared_utf8_bytes(self):
        sources = [{"path":"fixtures/café.py", "sha256":"0"*64}]
        wire = ('{"base_commit":"'+'1'*40+'","source_inventory_version":"'+SOURCE_INVENTORY_VERSION+'",'
                '"sources":[{"path":"fixtures/café.py","sha256":"'+'0'*64+'"}]}').encode("utf-8")
        self.assertEqual(source_binding(sources, "1"*40), hashlib.sha256(wire).hexdigest())

    def test_failed_archive_does_not_publish_partial_bytes(self):
        source = self.write("fixtures/example.py", b"VALUE = 1\n")
        sources = source_inventory(self.root)
        source.write_bytes(b"VALUE = 2\n")
        destination = self.root / "sources.tar.gz"
        with self.assertRaisesRegex(ValueError, "campaign.changed_source"):
            write_source_archive(self.root, sources, destination)
        self.assertFalse(destination.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO source replacement requires Unix")
    def test_replaced_source_fifo_refuses_without_blocking_open(self):
        import sys
        source = self.write("fixtures/example.py", b"VALUE = 1\n")
        self.git("add", "fixtures/example.py")
        source.unlink()
        os.mkfifo(source)
        code = "from pathlib import Path; from manifest_builder import write_source_archive; import sys; " \
               "root=Path(sys.argv[1]); write_source_archive(root, " \
               "[{'path':'fixtures/example.py','sha256':'0'*64}], root/'sources.tar.gz')"
        result = subprocess.run([sys.executable, "-B", "-c", code, str(self.root)],
                                cwd=Path(__file__).parent, capture_output=True, text=True, timeout=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("campaign.unsupported_source", result.stderr)
        self.assertFalse((self.root / "sources.tar.gz").exists())

    def test_authority_contract_hash_and_parse_share_one_read(self):
        import json
        import manifest_builder
        import os
        import sys
        authority = self.write("authority.json", b'{"authority":"original"}')
        self.git("-c", "user.name=Qualification Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "--allow-empty", "--quiet", "-m", "fixture")
        original = authority.read_bytes()
        destination = self.root / "sealed"
        original_read = Path.read_bytes
        reads = []
        def read(path):
            data = original_read(path)
            if path == authority:
                reads.append(data)
                authority.write_bytes(b'{"authority":"changed"}')
            return data
        previous = Path.cwd()
        try:
            os.chdir(self.root)
            with patch.object(sys, "argv", ["manifest_builder", "--authority-contract", str(authority),
                                          "--destination", str(destination)]), patch.object(Path, "read_bytes", read):
                manifest_builder.main()
        finally:
            os.chdir(previous)
        manifest = json.loads((destination / "manifest.json").read_bytes())
        self.assertEqual(manifest["authority_contract"], {"authority":"original"})
        self.assertEqual(manifest["authority_policy"], hashlib.sha256(original).hexdigest())
        self.assertEqual(len(reads), 1)


if __name__ == "__main__":
    unittest.main()
