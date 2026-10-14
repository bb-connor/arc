"""Subprocess regression controls and actual standalone rustc recorder evidence."""
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import struct
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).absolute().parents[2]
TOOL = ROOT / "scripts/record-rust-compilation.py"
EVIDENCE = ROOT / "target/recovery-safety-remediation/all-findings/qualification/compiler-recorder"
FAKE = '''#!/usr/bin/env python3
import json, os, pathlib, sys
here=pathlib.Path(__file__).parent
if sys.argv[1:]==['-vV']:
 print('rustc 1.94.1 (mock parser control)\\nhost: mock-target'); sys.exit(0)
if sys.argv[1:]==['--print','sysroot']:
 print(here/'sysroot'); sys.exit(0)
if any(a.startswith('--print=') for a in sys.argv[1:]):
 print('public probe'); sys.exit(0)
cfg=json.loads((here/'control.json').read_text())
if cfg.get('echo_values'):
 print(os.environ.get('PUBLIC_ENVIRONMENT','')); print(' '.join(sys.argv[1:]), file=sys.stderr)
with (here/'observer/dispatches').open('a') as f: f.write('dispatch\\n')
if cfg.get('failure'): sys.exit(cfg['failure'])
args=sys.argv[1:]
source=next(x for x in args if x.endswith('.rs'))
out=pathlib.Path(args[args.index('-o')+1])
out.write_bytes(b'mock image')
dep=out.with_suffix('.d')
if cfg.get('missing_depfile'): sys.exit(0)
if cfg.get('fifo_depfile'): os.mkfifo(dep); sys.exit(0)
if cfg.get('replace_source'):
 p=pathlib.Path(source); p.unlink(); p.write_text('pub fn changed() {}')
dep.write_text(cfg.get('depfile',str(out)+': '+source+'\\n\\n'+source+':\\n'))
sys.exit(0)
'''


FAKE_EXPLICIT = '''#!/usr/bin/env python3
import json, pathlib, sys
here=pathlib.Path(__file__).parent
cfg=json.loads((here/'control.json').read_text())
if sys.argv[1:]==['-vV']:
 print('rustc 1.94.1 (mock explicit-metadata control)\\nhost: '+cfg['host_triple']); sys.exit(0)
if sys.argv[1:]==['--print','sysroot']:
 print(here/'sysroot'); sys.exit(0)
if any(a.startswith('--print=') for a in sys.argv[1:]):
 print('public probe'); sys.exit(0)
emit=next(a for a in sys.argv[1:] if a.startswith('--emit='))
items={piece.split('=',1)[0]:piece.split('=',1)[1] for piece in emit[len('--emit='):].split(',') if '=' in piece}
out=pathlib.Path(items['metadata']); dep=pathlib.Path(items['dep-info'])
with (here/'observer/dispatches').open('a') as f: f.write('dispatch\\n')
if cfg.get('failure_without_output'): sys.exit(cfg['failure_without_output'])
out.write_bytes(cfg.get('metadata_text','mock metadata image').encode())
if cfg.get('failure'): sys.exit(cfg['failure'])
if cfg.get('missing_depfile'): sys.exit(0)
deps=cfg.get('depfile')
if deps is None:
 dep.write_text(str(out)+':\\n\\n'+str(dep)+':\\n')
else:
 dep.write_text(str(out)+': '+deps+'\\n\\n'+deps+':\\n')
sys.exit(0)
'''


class RecorderSubprocessTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(TOOL.is_file(), "actual compiler recorder is missing")
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="controls-", dir=EVIDENCE)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source_root = self.base / "candidate"
        self.source_root.mkdir()
        self.records = self.source_root / "target/campaign"
        self.records.mkdir(parents=True)
        self.source = self.source_root / "input.rs"
        self.source.write_text("pub fn input() -> u8 { 1 }\n")
        (self.base / "observer").mkdir()
        self.compiler = self.base / "compiler"
        self.compiler.write_text(FAKE)
        self.compiler.chmod(0o755)
        (self.base / "sysroot/lib/rustlib/mock-target/lib").mkdir(parents=True)
        (self.base / "sysroot/lib/rustlib/mock-target/lib/libstd.rlib").write_bytes(b"mock std")
        (self.base / "control.json").write_text("{}")
        self.out = self.source_root / "target/libunit.rlib"
        self.env = dict(os.environ)
        for key in list(self.env):
            if key in {"LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "RUSTC_CODEGEN_BACKEND", "RUST_TARGET_PATH"} or any(term in key.lower() for term in ["token", "password", "secret", "credential", "api_key"]):
                del self.env[key]
        self.env.update(CHIO_COMPILATION_SOURCE_ROOT=str(self.source_root),
                        CHIO_COMPILATION_RECORDS=str(self.records),
                        CHIO_COMPILATION_SOURCE_BINDING="a" * 64)

    def run_wrapper(self, args=None, env=None, optimize=False):
        cmd = [sys.executable] + (["-O"] if optimize else []) + [str(TOOL), str(self.compiler)]
        cmd += args or [str(self.source), "--crate-name", "unit", "--crate-type", "rlib",
                        "--emit", "dep-info,link", "-o", str(self.out)]
        return subprocess.run(cmd, cwd=self.source_root, env=env or self.env,
                              capture_output=True, timeout=30)

    def rows(self):
        return [json.loads(p.read_text()) for p in sorted((self.records / "records").glob("*.json"))]

    def control(self, **kwargs):
        (self.base / "control.json").write_text(json.dumps(kwargs))

    def test_valid_compilation_retains_inputs_and_outputs(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(r for r in self.rows() if r["kind"] == "compilation")
        self.assertEqual(row["status"], "success")
        self.assertEqual(row["schema"], "chio.rust-compilation.v4")
        record_path = self.records / "records" / (row["invocation_id"] + ".json")
        completion = json.loads((self.records / row["publication"]["completion"]).read_text())
        record_metadata = record_path.stat()
        marker_metadata = (self.records / row["publication"]["completion"]).stat()
        self.assertEqual(row["publication"]["marker_identity"], {"device": marker_metadata.st_dev, "inode": marker_metadata.st_ino})
        self.assertEqual(completion, {"schema": "chio.rust-compilation-completion.v3", "invocation_id": row["invocation_id"],
                                      "source_binding": row["source_binding"], "record_sha256": hashlib.sha256(record_path.read_bytes()).hexdigest(),
                                      "size": record_metadata.st_size,
                                      "record_identity": {"device": record_metadata.st_dev, "inode": record_metadata.st_ino}})
        self.assertEqual((self.base / "observer/dispatches").read_text(), "dispatch\n")
        for item in row["inputs"] + row["outputs"] + [row["compiler"]]:
            payload = (self.records / item["artifact"]).read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), item["sha256"])
        self.assertTrue(any(i["role"] == "source" for i in row["inputs"]))
        self.assertTrue(any(i["role"] == "unit" for i in row["outputs"]))

    def test_compiler_failure_keeps_actual_code_and_separate_record(self):
        self.control(failure=23)
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 23, result.stderr)
        row = next(r for r in self.rows() if r["kind"] == "compilation")
        self.assertEqual((row["status"], row["compiler_exit"]), ("compiler_failed", 23))

    def test_missing_configuration_refuses_before_dispatch(self):
        env = dict(self.env)
        del env["CHIO_COMPILATION_SOURCE_BINDING"]
        self.assertNotEqual(self.run_wrapper(env=env).returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_original_secret_arguments_and_environment_are_not_disclosed(self):
        sentinel = "SYNTHETIC-CREDENTIAL-SENTINEL"
        variants = [(None, {**self.env, "PROVIDER_API_TOKEN": sentinel}),
                    ([str(self.source), "--cfg", 'api_token="'+sentinel+'"'], self.env)]
        for args, env in variants:
            result = self.run_wrapper(args=args, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(sentinel.encode(), result.stdout + result.stderr)
            for path in self.records.rglob("*.json"):
                self.assertNotIn(sentinel, path.read_text())
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_secret_path_and_intermediate_symlink_refuse_before_dispatch(self):
        secret = self.source_root / "credentials/input.rs"
        secret.parent.mkdir()
        secret.write_text("synthetic excluded input")
        alias = self.source_root / "alias"
        alias.symlink_to(secret.parent, target_is_directory=True)
        for source in [secret, alias / "input.rs"]:
            result = self.run_wrapper(args=[str(source), "-o", str(self.out), "--emit", "dep-info,link"])
            self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())
        for path in self.records.rglob("artifacts/*"):
            if path.is_file():
                self.assertNotEqual(path.read_bytes(), b"synthetic excluded input")

    def test_response_file_refuses_without_read(self):
        response = self.source_root / "credentials.rsp"
        response.write_text("synthetic excluded response input")
        result = self.run_wrapper(args=["@" + str(response)])
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_malformed_and_ambiguous_depfiles_refuse_after_zero(self):
        for index in range(3):
            directory = self.source_root / ("target/depfile-case-" + str(index))
            directory.mkdir()
            self.out = directory / "libunit.rlib"
            depfile = ["not a depfile\n", f"{self.out}: {self.source}\n{self.out}: other.rs\n",
                       f"{self.out}: {self.source} | hidden\n"][index]
            self.control(depfile=depfile)
            result = self.run_wrapper()
            self.assertNotEqual(result.returncode, 0)
            row = [r for r in self.rows() if r["kind"] == "compilation"][-1]
            self.assertEqual(row["status"], "instrumentation_failed")
            self.assertEqual(row["compiler_exit"], 0)

    def test_secret_depfile_dependency_refuses_without_retention(self):
        secret = self.source_root / "private-key.pem"
        secret.write_text("synthetic excluded dependency")
        self.control(depfile=f"{self.out}: {self.source} {secret}\n")
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(all(r["status"] != "success" for r in self.rows() if r["kind"] == "compilation"))
        digest = hashlib.sha256(b"synthetic excluded dependency").hexdigest()
        self.assertFalse((self.records / "artifacts" / digest).exists())

    def test_opaque_depfile_environment_value_is_never_retained(self):
        sentinel = "SYNTHETIC-OPAQUE-SENTINEL"
        self.control(depfile=f"{self.out}: {self.source}\n# env-dep:PUBLIC_ENVIRONMENT={sentinel}\n")
        result = self.run_wrapper(env={**self.env, "PUBLIC_ENVIRONMENT": sentinel})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(sentinel.encode(), result.stdout + result.stderr)
        for path in self.records.rglob("*"):
            if path.is_file():
                self.assertNotIn(sentinel.encode(), path.read_bytes())

    def test_fifo_source_refuses_without_blocking(self):
        self.source.unlink()
        os.mkfifo(self.source)
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_fifo_depfile_refuses_after_compiler_zero(self):
        self.control(fifo_depfile=True)
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(next(r for r in self.rows() if r["kind"] == "compilation")["status"], "instrumentation_failed")

    def test_replaced_source_refuses_after_compiler_zero(self):
        self.control(replace_source=True)
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(next(r for r in self.rows() if r["kind"] == "compilation")["status"], "instrumentation_failed")

    def test_missing_depfile_cannot_claim_success(self):
        self.control(missing_depfile=True)
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        row = next(r for r in self.rows() if r["kind"] == "compilation")
        self.assertEqual((row["status"], row["compiler_exit"]), ("instrumentation_failed", 0))

    def test_optimized_validation_still_refuses(self):
        result = self.run_wrapper(args=["@never-read.rsp"], optimize=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_concurrent_publications_are_unique(self):
        commands = []
        for index in range(4):
            out = self.out.with_name(f"libunit{index}.rlib")
            cmd = [sys.executable, str(TOOL), str(self.compiler), str(self.source),
                   "--crate-name", f"unit{index}", "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(out)]
            commands.append(subprocess.Popen(cmd, cwd=self.source_root, env=self.env,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        for process in commands:
            stdout, stderr = process.communicate(timeout=30)
            self.assertEqual(process.returncode, 0, stderr)
        rows = [r for r in self.rows() if r["kind"] == "compilation"]
        self.assertEqual(len(rows), 4)
        self.assertEqual(len({r["invocation_id"] for r in rows}), 4)
        self.assertTrue(all(r["status"] == "success" for r in rows))

    def test_nonfresh_namespace_refuses(self):
        (self.records / "foreign").write_text("unowned evidence")
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_compiler_diagnostics_cannot_echo_original_opaque_values(self):
        self.control(echo_values=True)
        sentinel = "SYNTHETIC-OPAQUE-SENTINEL"
        result = self.run_wrapper(env={**self.env, "PUBLIC_ENVIRONMENT": sentinel})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(sentinel.encode(), result.stdout + result.stderr)
        for path in self.records.rglob("*.json"):
            self.assertNotIn(sentinel, path.read_text())

    def test_default_binary_and_dynamic_extern_refuse_hidden_runtime(self):
        args = [str(self.source), "--emit", "dep-info,link", "-o", str(self.out)]
        result = self.run_wrapper(args=args)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())
        dynamic = self.source_root / "macro.dylib"
        dynamic.write_bytes(b"mock executable macro")
        args += ["--crate-type", "rlib", "--extern", "macro=" + str(dynamic)]
        result = self.run_wrapper(args=args)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_rmeta_extern_requires_the_supported_metadata_format(self):
        # rustc standalone metadata framing: 8-byte magic ending in the pinned
        # metadata version, u64 little-endian root position reserved for the
        # crate root, varint length prefixed rustc version banner (no newline).
        banner = b"rustc 1.95.0 (synthetic pinned banner)"
        header = (b"rust\x00\x00\x00\x0a" + struct.pack("<Q", 16 + 1 + len(banner))
                  + bytes([len(banner)]) + banner)
        supported = header + b"synthetic metadata payload"
        extern = self.source_root / "target/libdependency.rmeta"
        extern.write_bytes(supported)
        fresh = self.source_root / "target/metadata-extern"
        fresh.mkdir()
        self.out = fresh / "libunit.rlib"
        result = self.run_wrapper(args=[str(self.source), "--crate-name", "unit", "--crate-type", "rlib",
                                        "--emit", "dep-info,link", "-o", str(self.out),
                                        "--extern", "dependency=" + str(extern)])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.base / "observer/dispatches").read_text(), "dispatch\n")
        row = next(r for r in self.rows() if r["kind"] == "compilation")
        captured = next(i for i in row["inputs"] if i["role"] == "extern")
        self.assertEqual(captured["path"], str(extern))
        self.assertEqual(captured["extern_name"], "dependency")
        self.assertNotIn("extern_kind", captured)
        self.assertNotIn("proc-macro-or-dynamic-image", json.dumps(row))
        # The old layout put a literal '#rustc ' banner at offset 8 where the
        # actual encoder reserves the u64 little-endian root position.
        old_layout = (b"rust\x00\x00\x00\x0a#rustc 1.95.0 (synthetic pinned banner)\n"
                      + b"synthetic metadata payload")
        truncated = header[:16]
        out_of_bounds = (b"rust\x00\x00\x00\x0a" + struct.pack("<Q", len(supported) + 1)
                         + bytes([len(banner)]) + banner)
        for label, payload in [("old-layout", old_layout),
                               ("arbitrary", b"synthetic arbitrary image"),
                               ("truncated", truncated),
                               ("root-out-of-bounds", out_of_bounds),
                               ("root-at-end", supported[:8] + struct.pack("<Q", len(supported)) + supported[16:]),
                               ("root-in-header", supported[:8] + struct.pack("<Q", 16) + supported[16:]),
                               ("truncated-length", supported[:16] + b"\x80"),
                               ("link-masquerade", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)]:
            directory = self.source_root / ("target/metadata-extern-refusal-" + label)
            directory.mkdir()
            extern.write_bytes(payload)
            result = self.run_wrapper(args=[str(self.source), "--crate-name", "unit", "--crate-type", "rlib",
                                            "--emit", "dep-info,link", "-o", str(directory / "libunit.rlib"),
                                            "--extern", "dependency=" + str(extern)])
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"extern_image_format", result.stderr)
        self.assertEqual((self.base / "observer/dispatches").read_text(), "dispatch\n")

    def ordinary_host_module(self):
        spec = importlib.util.spec_from_file_location("ordinary_host_recorder", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_stdin_source_is_host_only_and_requires_nonlink_outputs(self):
        module = self.ordinary_host_module()
        host = {"target": "mock-target"}
        args = ["--crate-name", "autocfg_check", "--crate-type=lib", "--out-dir", str(self.out.parent),
                "--emit=llvm-ir", "-"]
        parsed = module.parse(args, self.source_root, host=host)
        self.assertTrue(parsed["stdin"] and parsed["stdin_instrumentation"])
        self.assertIsNone(parsed["source"])
        self.assertEqual(parsed["emit"], {"llvm-ir": None, "dep-info": None})
        self.assertFalse(module.parse(args+["--emit=dep-info"], self.source_root, host=host)["stdin_instrumentation"])
        for context, selected in [({}, args), ({"host": host, "executor": object()}, args),
                                  ({"host": host}, args+["-"]), ({"host": host}, args+[str(self.source)]),
                                  ({"host": host}, args+["-o", str(self.out)]),
                                  ({"host": host}, args+["--emit=link"]),
                                  ({"host": host}, [x for x in args if x != "--emit=llvm-ir"])]:
            with self.subTest(context=context, args=selected), self.assertRaises(module.Refusal):
                module.parse(selected, self.source_root, **context)

    def test_stdin_bytes_are_bounded_before_retention(self):
        module = self.ordinary_host_module()
        with mock.patch.object(module.os, "fstat", return_value=type("Metadata", (), {"st_mode": stat.S_IFIFO})()):
            for payload, reason in [(b"pub fn probe() {}", None), (b"\xff", "stdin_encoding"),
                                    (b"const API_KEY: &str = \"synthetic\";", "unsafe_stdin_source"),
                                    (b"x"*65, "input_limit")]:
                with mock.patch.object(module, "MAX_JSON", 64), mock.patch.object(module.os, "read", side_effect=[payload, b""]):
                    if reason is None:
                        self.assertEqual(module.read_stdin_source(), payload)
                    else:
                        with self.assertRaisesRegex(module.Refusal, reason):
                            module.read_stdin_source()
        with mock.patch.object(module.os, "fstat", return_value=type("Metadata", (), {"st_mode": stat.S_IFCHR})()), \
                self.assertRaisesRegex(module.Refusal, "stdin_input_kind"):
            module.read_stdin_source()

    def test_anonymous_depfile_rules_require_exact_declared_output_set(self):
        module = self.ordinary_host_module()
        host = {"repository": str(self.source_root), "vendor_roots": [], "target_directory": str(self.out.parent)}
        outputs = {str(self.out.with_suffix(".d")), str(self.out.with_suffix(".ll"))}
        for path in outputs:
            Path(path).write_bytes(b"observed output")
        payload = "".join(path+":\n\n" for path in sorted(outputs)).encode()
        parsed = module.parse_depfile(payload, self.source_root, {}, host=host, anonymous_targets=outputs)
        self.assertEqual(parsed["dependencies"], [])
        self.assertEqual(set(parsed["targets"]), outputs)
        for declared in [None, outputs|{str(self.out)}, outputs-{str(self.out.with_suffix(".ll"))}]:
            with self.assertRaises(module.Refusal):
                module.parse_depfile(payload, self.source_root, {}, host=host, anonymous_targets=declared)
        included = "".join(path+": "+str(self.source)+"\n\n" for path in sorted(outputs)) + str(self.source)+":\n"
        self.assertEqual(module.parse_depfile(included.encode(), self.source_root, {}, host=host,
                                             anonymous_targets=outputs)["dependencies"], [str(self.source)])
        with self.assertRaisesRegex(module.Refusal, "depfile_environment_not_public"):
            module.parse_depfile(payload+b"# env-dep:HOME=/public/home\n", self.source_root,
                                 {"HOME": "/public/home"}, host=host, anonymous_targets=outputs)

    def test_partial_output_lease_refuses_extra_paths_and_changed_baseline(self):
        module = self.ordinary_host_module()
        baseline = self.out.parent / "earlier.ll"
        baseline.write_bytes(b"prior output")
        emissions = {"llvm-ir": str(self.out.with_suffix(".ll")), "dep-info": str(self.out.with_suffix(".d"))}
        lease = module.OutputLease(self.out.parent, emissions)
        self.addCleanup(lease.close)
        Path(emissions["dep-info"]).write_bytes(b"observed sidecar")
        self.assertEqual(set(lease.produced(complete=False)), {Path(emissions["dep-info"]).name})
        extra = self.out.parent / "unexpected.ll"
        extra.write_bytes(b"undeclared output")
        with self.assertRaisesRegex(module.Refusal, "unexpected_compiler_output"):
            lease.produced(complete=False)
        extra.unlink()
        baseline.write_bytes(b"changed prior output")
        with self.assertRaisesRegex(module.Refusal, "preexisting_output_changed"):
            lease.produced(complete=False)

    def test_name_only_proc_macro_extern_is_host_only_and_single(self):
        module = self.ordinary_host_module()
        host = {"target": "mock-target", "toolchain": str(self.base / "sysroot"), "features": set(),
                "build_cfg": set(), "build_check_cfg": set(), "linker": "/public/clang"}
        args = [str(self.source), "--crate-name", "unit", "--crate-type", "rlib",
                "--emit", "dep-info,link", "--out-dir", str(self.source_root / "target")]
        parsed = module.parse(args + ["--extern", "proc_macro"], self.source_root, host=host)
        self.assertEqual(parsed["externs"], [{"name": "proc_macro", "path": None, "kind": "sysroot-implicit"}])
        # Arbitrary implicit names are never authorized, in any context.
        for extra in [["--extern", "core"], ["--extern", "proc_macro2"], ["--extern", "private"]]:
            with self.assertRaisesRegex(module.Refusal, "implicit_extern"):
                module.parse(args + extra, self.source_root, host=host)
        # Standalone and duplicate compiler-owned names keep refusing.
        for context in [{}]:
            with self.assertRaisesRegex(module.Refusal, "implicit_extern"):
                module.parse(args + ["--extern", "proc_macro"], self.source_root, **context)
        with self.assertRaisesRegex(module.Refusal, "implicit_extern"):
            module.parse(args + ["--extern", "proc_macro"] * 2, self.source_root, host=host)
        explicit = self.source_root / "target/libdependency.rlib"
        explicit.write_bytes(b"!<arch>\nsynthetic explicit extern image")
        parsed = module.parse(args + ["--extern", "dependency=" + str(explicit), "--extern", "proc_macro"],
                              self.source_root, host=host)
        self.assertEqual([(e["name"], e["path"]) for e in parsed["externs"]],
                         [("dependency", str(explicit)), ("proc_macro", None)])

        explicit_proc_macro = ["--extern", "proc_macro=" + str(explicit)]
        self.assertEqual(module.parse(args + explicit_proc_macro, self.source_root, host=host)
                         ["externs"][0]["path"], str(explicit))
        for options in [explicit_proc_macro + ["--extern", "proc_macro"],
                        ["--extern", "proc_macro"] + explicit_proc_macro]:
            with self.assertRaisesRegex(module.Refusal, "implicit_extern"):
                module.parse(args + options, self.source_root, host=host)

    def test_completed_producer_cannot_shadow_compiler_owned_crate(self):
        # Exercise the actual recorder publication with the existing fake
        # compiler, then the ordinary lookup against its completed record.
        output = self.source_root / "target/libproc_macro.rlib"
        result = self.run_wrapper(args=[str(self.source), "--crate-name", "proc_macro",
                                        "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(output)])
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(row for row in self.rows() if row["kind"] == "compilation")
        image = next(item for item in row["outputs"] if item["role"] == "unit")
        module = self.ordinary_host_module()
        campaign = module.Campaign(self.records, "a" * 64)
        try:
            self.assertEqual(module.producing_unit(campaign, image, required_crate="proc_macro")
                             ["invocation_id"], row["invocation_id"])
            with self.assertRaisesRegex(module.Refusal, "sysroot_extern_shadowed"):
                module.producing_unit(campaign, image, excluded_crate="proc_macro")
        finally:
            campaign.close()

    def test_numeric_aliases_cannot_complete_a_producing_unit(self):
        # The fake compiler publishes one real completed unit first; every
        # mutation below changes exactly one numeric layer of that projection.
        output = self.source_root / "target/libproc_macro.rlib"
        result = self.run_wrapper(args=[str(self.source), "--crate-name", "proc_macro",
                                        "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(output)])
        self.assertEqual(result.returncode, 0, result.stderr)
        row = next(row for row in self.rows() if row["kind"] == "compilation")
        image = next(item for item in row["outputs"] if item["role"] == "unit")
        name = row["invocation_id"] + ".json"
        record_path = self.records / "records" / name
        marker_path = self.records / "completions" / name
        module = self.ordinary_host_module()
        original_record = json.loads(record_path.read_bytes())
        original_marker = json.loads(marker_path.read_bytes())
        campaign = module.Campaign(self.records, "a" * 64)
        try:
            self.assertEqual(module.producing_unit(campaign, image, required_crate="proc_macro")
                             ["invocation_id"], row["invocation_id"])

            def reseal(record_change=lambda record: None, marker_change=lambda marker: None):
                # Rewrite both objects in place, so the record digest and byte
                # length stay joined and both inodes keep binding.
                record = json.loads(json.dumps(original_record))
                record_change(record)
                payload = module.canonical(record) + b"\n"
                record_path.write_bytes(payload)
                marker = json.loads(json.dumps(original_marker))
                marker.update(record_sha256=hashlib.sha256(payload).hexdigest(), size=len(payload))
                marker_change(marker)
                marker_path.write_bytes(module.canonical(marker) + b"\n")

            reseal()
            self.assertEqual(module.producing_unit(campaign, image, required_crate="proc_macro")
                             ["invocation_id"], row["invocation_id"])

            def float_output_size(record):
                for item in record["outputs"]:
                    if item["role"] == "unit":
                        item["size"] = float(item["size"])

            def float_publication_identity(record):
                identity = record["publication"]["marker_identity"]
                identity.update(device=float(identity["device"]), inode=float(identity["inode"]))

            def float_record_identity(marker):
                identity = marker["record_identity"]
                identity.update(device=float(identity["device"]), inode=float(identity["inode"]))

            for change, reason in [("false-exit", "extern_producing_unit_not_completed"),
                                   ("float-output-size", "extern_producing_unit_not_completed"),
                                   ("float-marker-size", "producer_completion_binding"),
                                   ("float-publication-identity", "producer_completion_binding"),
                                   ("float-record-identity", "producer_completion_binding")]:
                with self.subTest(change=change):
                    if change == "false-exit":
                        reseal(lambda record: record.update(compiler_exit=False))
                    elif change == "float-output-size":
                        reseal(float_output_size)
                    elif change == "float-marker-size":
                        reseal(marker_change=lambda marker: marker.update(size=float(marker["size"])))
                    elif change == "float-publication-identity":
                        reseal(float_publication_identity)
                    else:
                        reseal(marker_change=float_record_identity)
                    with self.assertRaisesRegex(module.Refusal, reason):
                        module.producing_unit(campaign, image, required_crate="proc_macro")
        finally:
            campaign.close()

    def test_sysroot_candidates_bind_captured_images_and_refuse_alternatives(self):
        module = self.ordinary_host_module()
        library = self.base / "sysroot/lib/rustlib/mock-target/lib"
        library.mkdir(parents=True, exist_ok=True)
        banner = b"rustc 1.95.0 (synthetic pinned banner)"
        rmeta_header = b"rust\x00\x00\x00\x0a" + struct.pack("<Q", 16 + 1 + len(banner)) + bytes([len(banner)]) + banner
        records = self.source_root / "target/sysroot-candidate-campaign"
        records.mkdir()
        campaign = module.Campaign(records, "a" * 64)
        host = {"target": "mock-target", "toolchain": str(self.base / "sysroot")}

        def captured(names):
            items = []
            for name, body in names.items():
                (library / name).write_bytes(body)
                item, _ = module.capture(library / name, "toolchain", campaign)
                items.append(item)
            return items

        try:
            items = captured({"libproc_macro-01234567.rlib": b"!<arch>\nsynthetic pinned rlib",
                              "libproc_macro-01234567.rmeta": rmeta_header + b"synthetic pinned metadata"})
            module.bind_sysroot_proc_macro(items, host)
            externs = items
            # Both captured candidates bind conservatively; no consumed-image
            # selection is claimed.
            self.assertEqual(sorted(e["sysroot_binding"]["candidate_kind"] for e in externs), ["rlib", "rmeta"])
            for extern in externs:
                self.assertEqual(extern["role"], "toolchain")
                self.assertEqual(extern["sysroot_binding"]["extern_name"], "proc_macro")
                self.assertEqual(extern["sysroot_binding"]["coverage"], "conservative-candidates")
                self.assertEqual(extern["sysroot_binding"]["sysroot"], str(self.base / "sysroot"))
                self.assertEqual((records / extern["artifact"]).read_bytes(),
                                 (library / Path(extern["path"]).name).read_bytes())
            # Unowned toolchain, missing rlib, ambiguous stems, and unsupported
            # image bytes refuse.
            with self.assertRaisesRegex(module.Refusal, "sysroot_extern_unowned"):
                module.bind_sysroot_proc_macro(items, {**host, "toolchain": str(self.base / "unowned")})
            with self.assertRaisesRegex(module.Refusal, "sysroot_extern_missing"):
                module.bind_sysroot_proc_macro([items[1]], host)
            (library / "libproc_macro-aaaabbbb.rlib").write_bytes(b"!<arch>\nsynthetic second stem")
            with self.assertRaisesRegex(module.Refusal, "sysroot_extern_ambiguous"):
                module.bind_sysroot_proc_macro(items + captured(
                    {"libproc_macro-aaaabbbb.rlib": b"!<arch>\nsynthetic second stem"}), host)
            (library / "libproc_macro-aaaabbbb.rlib").unlink()
            (library / "libproc_macro-mixed.rlib").write_bytes(b"!<arch>\nsynthetic odd stem")
            with self.assertRaisesRegex(module.Refusal, "sysroot_extern_ambiguous"):
                module.bind_sysroot_proc_macro(captured(
                    {"libproc_macro-mixed.rlib": b"!<arch>\nsynthetic odd stem"}), host)
            (library / "libproc_macro-mixed.rlib").unlink()
            (library / "libproc_macro-01234567.rlib").write_bytes(b"synthetic not an archive")
            with self.assertRaisesRegex(module.Refusal, "extern_image_format"):
                module.bind_sysroot_proc_macro(captured(
                    {"libproc_macro-01234567.rlib": b"synthetic not an archive"}), host)
            (library / "libproc_macro-01234567.rmeta").write_bytes(b"synthetic unsupported metadata")
            with self.assertRaisesRegex(module.Refusal, "extern_image_format"):
                module.bind_sysroot_proc_macro(captured(
                    {"libproc_macro-01234567.rlib": b"!<arch>\nsynthetic pinned rlib",
                     "libproc_macro-01234567.rmeta": b"synthetic unsupported metadata"}), host)
        finally:
            campaign.close()

    def test_artifact_cache_corruption_refuses_current_binding(self):
        self.assertEqual(self.run_wrapper().returncode, 0)
        row = next(r for r in self.rows() if r["kind"] == "compilation")
        retained = self.records / row["compiler"]["artifact"]
        retained.write_bytes(b"corrupt retained compiler image")
        before = (self.base / "observer/dispatches").read_text()
        fresh = self.source_root / "target/cache-check"
        fresh.mkdir()
        self.out = fresh / "libunit.rlib"
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"artifact_changed", result.stderr)
        self.assertEqual((self.base / "observer/dispatches").read_text(), before)

    def test_ordinary_host_declared_features_and_darwin_outputs(self):
        spec = importlib.util.spec_from_file_location("ordinary_host_recorder", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        host = {"target": "aarch64-apple-darwin", "features": {"default", "proc-macro"},
                "build_cfg": set(), "build_check_cfg": set(), "linker": "/public/clang"}
        for kind, expected in [("bin", "unit"), ("proc-macro", "libunit.dylib")]:
            args = [str(self.source), "--crate-name", "unit", "--crate-type", kind,
                    "--emit", "dep-info,link", "--out-dir", str(self.source_root / "target"),
                    "--cfg", 'feature="proc-macro"', "--check-cfg", 'cfg(feature, values("default", "proc-macro"))',
                    "-Clinker=/public/clang"]
            try:
                parsed = module.parse(args, self.source_root, host=host)
            except (TypeError, module.Refusal) as error:
                self.fail("declared ordinary host compilation refused: " + str(error))
            self.assertEqual(Path(module.output_paths(parsed)[1]["link"]).name, expected)

    def test_ordinary_host_never_accepts_undeclared_cfg_values(self):
        spec = importlib.util.spec_from_file_location("ordinary_host_recorder", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        host = {"target": "aarch64-apple-darwin", "features": {"default"},
                "build_cfg": set(), "build_check_cfg": set(), "linker": "/public/clang"}
        args = [str(self.source), "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(self.out)]
        for extra in [["--cfg", 'feature="undeclared"'], ["--cfg", 'opaque="private-value"'],
                      ["--check-cfg", 'cfg(opaque,values("private-value"))']]:
            try:
                with self.assertRaisesRegex(module.Refusal, "opaque_cfg_value"):
                    module.parse(args + extra, self.source_root, host=host)
            except TypeError as error:
                self.fail("ordinary host context unavailable: " + str(error))

    def test_ordinary_host_binds_exact_manifest_check_cfg_declarations(self):
        module = self.ordinary_host_module()
        declaration = 'cfg(getrandom_backend, values("custom", "efi_rng", "rdrand", "rndr", "linux_getrandom", "linux_raw", "wasm_js", "windows_legacy", "unsupported"))'
        declared = module.manifest_check_cfg({"lints": {"rust": {
            "unexpected_cfgs": {"level": "warn", "check-cfg": [declaration]}}}})
        host = {"target": "aarch64-apple-darwin", "features": set(), "build_cfg": set(),
                "build_check_cfg": set(), "manifest_check_cfg": declared, "linker": "/public/clang"}
        args = [str(self.source), "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(self.out)]
        self.assertIn({"name": "--check-cfg", "value_sha256": module.digest(declaration)},
                      module.parse(args + ["--check-cfg", declaration], self.source_root, host=host)["flags"])
        for value in ['cfg(getrandom_backend, values("custom"))', declaration.replace('"custom"', '"other"')]:
            with self.subTest(value=value), self.assertRaisesRegex(module.Refusal, "opaque_cfg_value"):
                module.parse(args + ["--check-cfg", value], self.source_root, host=host)
        with self.assertRaisesRegex(module.Refusal, "opaque_cfg_value"):
            module.parse(args + ["--check-cfg", declaration], self.source_root)
        with self.assertRaisesRegex(module.Refusal, "opaque_cfg_value"):
            module.parse(args + ["--cfg", 'getrandom_backend="custom"'], self.source_root, host=host)

    def test_manifest_check_cfg_keeps_level_only_lints_and_refuses_invalid_tables(self):
        module = self.ordinary_host_module()
        for lints in [{}, {"workspace": True}, {"rust": {"unexpected_cfgs": "warn"}},
                      {"rust": {"unexpected_cfgs": {"level": "warn"}}}]:
            self.assertEqual(module.manifest_check_cfg({"lints": lints}), set())
        for entries in [None, "cfg(loom)", [7], [""], ["x" * 4097], ['cfg(auth_token)']]:
            with self.subTest(entries=entries), self.assertRaisesRegex(module.Refusal, "host_manifest_check_cfg"):
                module.manifest_check_cfg({"lints": {"rust": {"unexpected_cfgs": {"check-cfg": entries}}}})
        with self.assertRaisesRegex(module.Refusal, "host_manifest_check_cfg"):
            module.manifest_check_cfg({"lints": {"workspace": True, "rust": {"unexpected_cfgs": "warn"}}})

    def test_ordinary_host_retains_cargo_long_lint_arguments(self):
        spec = importlib.util.spec_from_file_location("ordinary_host_recorder", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        host = {"target": "aarch64-apple-darwin", "features": set(),
                "build_cfg": set(), "build_check_cfg": set(), "linker": "/public/clang"}
        args = [str(self.source), "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(self.out)]
        for flag in ["--allow", "--warn", "--deny", "--forbid", "--force-warn"]:
            for selector in ["unused_qualifications", "clippy::unnecessary_semicolon", "dead-code"]:
                for extra in [[flag, selector], [flag + "=" + selector]]:
                    with self.subTest(extra=extra):
                        parsed = module.parse(args + extra, self.source_root, host=host)
                        self.assertIn({"name": flag, "value_sha256": module.digest(selector)}, parsed["flags"])
            with self.assertRaisesRegex(module.Refusal, "unsupported_option"):
                module.parse(args + [flag, "warnings"], self.source_root)
            for selector in ["clippy::", "file/path", "opaque value", "warnings,unused"]:
                with self.subTest(flag=flag, selector=selector):
                    with self.assertRaisesRegex(module.Refusal, "unsupported_lint_selector"):
                        module.parse(args + [flag, selector], self.source_root, host=host)

    def test_bounded_quota_controls_use_real_subprocess(self):
        for name, limit in [("MAX_INPUT", 4), ("MAX_CONTENT", 4), ("MAX_JSON", 100), ("MAX_RECORDS", 0)]:
            campaign = self.source_root / ("target/quota-" + name)
            campaign.mkdir()
            output = self.source_root / ("target/quota-output-" + name)
            output.mkdir()
            self.out = output / "libunit.rlib"
            env = {**self.env, "CHIO_COMPILATION_RECORDS": str(campaign)}
            code = ("import importlib.util,sys; spec=importlib.util.spec_from_file_location('recorder',sys.argv[1]); "
                    "module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); "
                    "setattr(module,sys.argv[2],int(sys.argv[3])); sys.exit(module.main(sys.argv[4:]))")
            args = [str(self.compiler), str(self.source), "--crate-type", "rlib", "--crate-name", "unit", "--emit", "dep-info,link", "-o", str(self.out)]
            result = subprocess.run([sys.executable, "-O", "-c", code, str(TOOL), name, str(limit), *args],
                                    env=env, cwd=self.source_root, capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0, name)
            expected = {"MAX_INPUT": b"input_limit", "MAX_CONTENT": b"content_limit",
                        "MAX_JSON": b"record_json_limit", "MAX_RECORDS": b"record_limit"}[name]
            self.assertIn(expected, result.stderr)
            rows = [json.loads(p.read_text()) for p in (campaign / "records").glob("*.json")]
            self.assertFalse(any(r["kind"] == "compilation" and r["status"] == "success" for r in rows))
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_depfile_escape_and_environment_parser_controls(self):
        spec = importlib.util.spec_from_file_location("recorder", TOOL)
        recorder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recorder)
        dep = recorder.parse_depfile(b"out\\ file: source\\ file.rs\nsource\\ file.rs:\n# env-dep:CARGO_PKG_VERSION=1.2.3\n",
                                    self.source_root, {"CARGO_PKG_VERSION": "1.2.3"})
        self.assertEqual(dep["dependencies"], [str(self.source_root / "source file.rs")])
        self.assertEqual(dep["environment_requirements"][0]["name"], "CARGO_PKG_VERSION")
        self.assertNotIn("synthetic public value", json.dumps(dep))
        for payload in [b"out: source.rs $BAD\n", b"out: source.rs\n# env-dep:PUBLIC_VALUE=changed\n",
                        b"out: source.rs\nother: different.rs\n", b"out: source.rs\n# env-dep:API_TOKEN=hidden\n"]:
            with self.assertRaises(recorder.Refusal):
                recorder.parse_depfile(payload, self.source_root, {"PUBLIC_VALUE": "synthetic public value"})

    def test_reused_output_paths_refuse_without_a_second_dispatch(self):
        self.assertEqual(self.run_wrapper().returncode, 0)
        before = (self.base / "observer/dispatches").read_text()
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"preexisting_output", result.stderr)
        self.assertEqual((self.base / "observer/dispatches").read_text(), before)

    def test_same_output_concurrent_invocations_have_one_owner(self):
        command = [sys.executable, str(TOOL), str(self.compiler), str(self.source), "--crate-name", "unit",
                   "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(self.out)]
        processes = [subprocess.Popen(command, cwd=self.source_root, env=self.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE) for _ in range(2)]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            results.append(process.returncode)
        self.assertEqual(sorted(results), [0, 86])
        self.assertEqual((self.base / "observer/dispatches").read_text(), "dispatch\n")
        rows = [row for row in self.rows() if row["kind"] == "compilation"]
        self.assertEqual(sorted(row["status"] for row in rows), ["refused", "success"])

    def test_state_failure_after_zero_is_a_failed_wrapper_record(self):
        control = """import importlib.util,sys
spec=importlib.util.spec_from_file_location('recorder',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
original=m.Campaign.publish

def controlled(self,row):
    if row['kind']=='compilation' and row['status']=='success':
        restore=self.save_state
        def fail_once():
            self.save_state=restore
            raise OSError('synthetic post-zero state persistence failure')
        self.save_state=fail_once
    return original(self,row)
m.Campaign.publish=controlled
sys.exit(m.main(sys.argv[2:]))
"""
        command = [sys.executable, "-O", "-c", control, str(TOOL), str(self.compiler), str(self.source),
                   "--crate-name", "unit", "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(self.out)]
        result = subprocess.run(command, cwd=self.source_root, env=self.env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 86)
        self.assertEqual((self.base / "observer/dispatches").read_text(), "dispatch\n")
        rows = [row for row in self.rows() if row["kind"] == "compilation"]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["status"], rows[0]["compiler_exit"]), ("instrumentation_failed", 0))

    def test_parent_traversal_refuses_for_all_declared_path_roles(self):
        ordinary = [str(self.source), "--crate-name", "unit", "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(self.out)]
        variants = [ordinary + ["--extern", "dependency=" + str(self.source_root) + "/sub/../libdependency.rlib"],
                    ordinary + ["-L", "dependency=" + str(self.source_root) + "/sub/../target"],
                    [str(self.source_root) + "/sub/../input.rs", *ordinary[1:]],
                    ordinary[:-1] + [str(self.source_root) + "/target/sub/../libunit.rlib"]]
        for args in variants:
            result = self.run_wrapper(args=args, optimize=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"parent_traversal", result.stderr)
        command = [sys.executable, str(TOOL), str(self.base) + "/observer/../compiler", *ordinary]
        result = subprocess.run(command, cwd=self.source_root, env=self.env, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"parent_traversal", result.stderr)
        self.assertFalse((self.base / "observer/dispatches").exists())
        spec = importlib.util.spec_from_file_location("recorder", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaisesRegex(module.Refusal, "parent_traversal"):
            module.parse_depfile(b"out: hop/../source.rs\n", self.source_root, {})

    def test_cargo_stdin_print_probe_is_typed_without_unit_coverage(self):
        args = ["-", "--crate-name", "___", "--print=file-names", "--crate-type", "bin", "--crate-type", "rlib",
                "--print=sysroot", "--print=split-debuginfo", "--print=crate-name", "--print=cfg"]
        result = self.run_wrapper(args=args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.rows())
        self.assertTrue(all(r["kind"] == "probe" and not r["outputs"] for r in self.rows()))
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_probe_never_claims_compilation(self):
        result = self.run_wrapper(args=["-vV"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.rows())
        self.assertTrue(all(r["kind"] == "probe" for r in self.rows()))
        self.assertTrue(all(not r["outputs"] for r in self.rows()))

    def test_version_probe_refuses_extra_arguments_before_dispatch(self):
        result = self.run_wrapper(args=["--version", "--verbose", "--edition", "2021"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.unsupported_option", result.stderr)
        self.assertFalse(any(r["kind"] == "probe" for r in self.rows()))
        self.assertFalse((self.base / "observer/dispatches").exists())


@unittest.skipUnless(platform.system() == "Darwin", "ordinary host execution is Darwin only")
class ExplicitMetadataStdinTest(unittest.TestCase):
    """Closed v2 explicit-metadata stdin lane through actual recorder custody.

    The mock control uses the exact reconstructed argument shape of the
    retained Rustix 1.1.4 can_compile caller. The actual compiler selector
    below exercises the same argument shape under the single build owner. Fake compiler
    fixtures never qualify the original CP-F01 producer.
    """

    rows = RecorderSubprocessTest.rows
    ordinary_host_module = RecorderSubprocessTest.ordinary_host_module

    def setUp(self):
        RecorderSubprocessTest.setUp(self)
        self.triple = {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}[platform.machine()]
        self.compiler.write_text(FAKE_EXPLICIT)
        (self.base / ("sysroot/lib/rustlib/%s/lib" % self.triple)).mkdir(parents=True)
        (self.base / ("sysroot/lib/rustlib/%s/lib/libstd.rlib" % self.triple)).write_bytes(b"mock std")
        self.target_directory = self.source_root / "target/probe"
        self.target_directory.mkdir(parents=True)
        self.primary = self.target_directory / "rustix_test_can_compile"
        manifest = self.source_root / "Cargo.toml"
        manifest.write_text('[package]\nname = "probe"\nversion = "0.1.0"\n')
        included = self.source_root / "included.txt"
        included.write_text("actual included input")
        sources = [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                   for path in [manifest, included]]
        inventory = {"source_inventory_version": "chio.source-inventory.v4", "base_commit": None, "sources": sources}
        self.binding = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":"),
                                                 ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        runtime_path = self.base / "runtime.json"
        runtime_path.write_text(json.dumps({**inventory, "source_binding": self.binding},
                                          sort_keys=True, separators=(",", ":")) + "\n")
        cargo, linker = self.base / "cargo", self.base / "linker"
        cargo.write_bytes(b"mock cargo image")
        linker.write_bytes(b"mock linker image")
        sdk = self.base / "sdk"
        (sdk / "unused").mkdir(parents=True)
        sdk_image = sdk / "tool"
        sdk_image.write_bytes(b"mock sdk image")
        dyld = Path("/usr/lib/dyld")
        images = [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "size": path.stat().st_size, "purpose": purpose}
                  for path, purpose in [(cargo, "cargo"), (linker, "linker"), (dyld, "loader"), (sdk_image, "sdk")]]
        declaration = {"schema": "chio.ordinary-host-execution.v1", "repository": str(self.source_root),
                       "namespace": str(self.records), "source_binding": self.binding,
                       "target_directory": str(self.target_directory), "target": self.triple,
                       "machine": platform.machine(), "compiler": str(self.compiler), "cargo": str(cargo),
                       "linker": str(linker), "sdk": str(sdk), "toolchain": str(self.base / "sysroot"),
                       "images": images, "aliases": [],
                       "runtime_metadata": {"coverage": "ordinary-host-observation-no-retained-os-image-coverage",
                                            "system": "Darwin", "release": "mock", "version": "mock",
                                            "macos_version": "mock", "shared_cache_file_metadata": []},
                       "vendor_roots": [str(self.base / "vendor")],
                       "runtime_inventory": {"path": str(runtime_path),
                                             "sha256": hashlib.sha256(runtime_path.read_bytes()).hexdigest(),
                                             "size": runtime_path.stat().st_size}}
        declaration_path = self.base / "host.json"
        declaration_path.write_text(json.dumps(declaration, sort_keys=True) + "\n")
        self.explicit_env = dict(self.env)
        for key in list(self.explicit_env):
            if key.startswith(("LD_", "DYLD_")) or key in {"CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH",
                    "OBJC_INCLUDE_PATH", "LIBRARY_PATH", "COMPILER_PATH", "GCC_EXEC_PREFIX",
                    "RUSTC_CODEGEN_BACKEND", "RUST_TARGET_PATH", "RUSTC_OVERRIDE_VERSION_STRING",
                    "CARGO_MANIFEST_PATH", "CARGO_MANIFEST_DIR", "CARGO_PKG_NAME", "SDKROOT", "CARGO_TARGET_DIR"}:
                del self.explicit_env[key]
        self.explicit_env.update(CHIO_COMPILATION_SOURCE_BINDING=self.binding,
                                 CHIO_COMPILATION_HOST_EXECUTION=str(declaration_path), RUSTC=str(self.compiler),
                                 CARGO=str(cargo), SDKROOT=str(sdk), CARGO_TARGET_DIR=str(self.target_directory),
                                 CARGO_MANIFEST_PATH=str(manifest), CARGO_MANIFEST_DIR=str(self.source_root),
                                 CARGO_PKG_NAME="probe")
        self.explicit_control()

    def explicit_control(self, **kwargs):
        kwargs.setdefault("host_triple", self.triple)
        (self.base / "control.json").write_text(json.dumps(kwargs))

    def rustix_arguments(self, *, include_target=True, crate_name=None):
        # Exact reconstructed Rustix 1.1.4 can_compile shape: unnamed stdin,
        # one rlib crate type, one bare metadata emission, the actual host
        # target, one explicit extensionless -o and the split debuginfo and
        # linker flags. The single build owner reruns this exact shape.
        arguments = [str(self.compiler)]
        if crate_name is not None:
            arguments.append("--crate-name=" + crate_name)
        arguments += ["--crate-type=rlib", "--emit=metadata"]
        if include_target:
            arguments += ["--target", self.triple]
        arguments += ["-o", str(self.primary), "-Csplit-debuginfo=off", "-Clinker=" + str(self.base / "linker"), "-"]
        return arguments

    def run_explicit(self, source, *, include_target=True, crate_name=None, env=None):
        return subprocess.run([sys.executable, *(["-O"] if sys.flags.optimize else []), str(TOOL), *self.rustix_arguments(
            include_target=include_target, crate_name=crate_name)], cwd=self.source_root,
            env=env or self.explicit_env, input=source, capture_output=True, timeout=120)

    def compilation_rows(self):
        return [row for row in self.rows() if row["kind"] == "compilation"]

    def auditor_module(self):
        spec = importlib.util.spec_from_file_location("explicit_metadata_auditor",
                                                      ROOT / "scripts/verify-recovery-qualification.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def audit_namespace(self, auditor):
        publication = auditor.audit_compiler_publications(self.records, self.binding)
        rows = self.rows()
        auditor.audit_compiler_stdin_inputs(rows, self.records,
                                            lambda image: (self.records / image["artifact"]).read_bytes(),
                                            publication["unit_publications"])
        return publication, rows

    def assert_chained(self, rows):
        fresh = [row for row in rows if row["semantics"]["output_ownership"]["predecessor"] is None]
        self.assertEqual(len(fresh), 1)
        order = []
        predecessors = {row["semantics"]["output_ownership"]["predecessor"]["invocation_id"]
                        for row in rows if row["semantics"]["output_ownership"]["predecessor"] is not None}
        latest = [row for row in rows if row["invocation_id"] not in predecessors]
        self.assertEqual(len(latest), 1)
        current = latest[0]
        remaining = {row["invocation_id"]: row for row in rows}
        while True:
            order.append(current)
            edge = current["semantics"]["output_ownership"]["predecessor"]
            if edge is None:
                break
            self.assertEqual(current["semantics"]["output_ownership"]["policy"],
                             "explicit-metadata-predecessor-retirement")
            predecessor = remaining[edge["invocation_id"]]
            self.assertEqual(edge["record"]["path"], "records/" + edge["invocation_id"] + ".json")
            self.assertEqual(edge["completion"]["path"], "completions/" + edge["invocation_id"] + ".json")
            sealed = predecessor["semantics"]["output_ownership"]["produced"][self.primary.name]
            self.assertEqual(edge["physical"], sealed)
            image = edge["output"]
            self.assertTrue(any(item.get("role") == "unit" and item["path"] == image["path"]
                                 and item["sha256"] == image["sha256"] and item["size"] == image["size"]
                                 for item in predecessor["outputs"]))
            current = predecessor
        self.assertEqual(len(order), len(rows))
        return list(reversed(order))

    def test_explicit_metadata_success_records_closed_v2_instrumentation(self):
        result = self.run_explicit(b"pub fn probe() -> u32 { 17 }")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.compilation_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row["status"], row["compiler_exit"]), ("success", 0))
        semantics = row["semantics"]
        self.assertIsNone(semantics["source"])
        self.assertIsNone(semantics["crate_name"])
        self.assertEqual(semantics["crate_types"], ["rlib"])
        self.assertEqual(semantics["target"], self.triple)
        instrumentation = semantics["dep_info_instrumentation"]
        self.assertEqual(set(instrumentation), {"schema", "mode", "original_argv", "effective_argv",
                                                "effective_invocation_sha256", "primary_output", "depfile_output"})
        self.assertEqual(instrumentation["schema"], "chio.rust-compilation-dep-info-instrumentation.v2")
        self.assertEqual(instrumentation["mode"], "explicit-metadata-output")
        self.assertEqual(instrumentation["primary_output"], str(self.primary))
        depfile = str(self.primary.parent / (self.primary.name + ".chio-" + row["invocation_id"] + ".d"))
        self.assertEqual(instrumentation["depfile_output"], depfile)
        original = json.loads((self.records / instrumentation["original_argv"]["artifact"]).read_bytes())
        effective = json.loads((self.records / instrumentation["effective_argv"]["artifact"]).read_bytes())
        arguments = self.rustix_arguments()
        self.assertEqual(original, arguments)
        self.assertEqual(effective, ["--emit=metadata=%s,dep-info=%s" % (self.primary, depfile)
                                      if argument == "--emit=metadata" else argument for argument in arguments])
        self.assertEqual(instrumentation["effective_invocation_sha256"], hashlib.sha256(
            json.dumps(effective, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest())
        ownership = semantics["output_ownership"]
        self.assertEqual(ownership, {"policy": "explicit-metadata-fresh-lease",
                                     "directory": str(self.target_directory),
                                     "directory_binding": ownership["directory_binding"],
                                     "predecessor": None, "produced": {
            self.primary.name: {"device": self.primary.stat().st_dev, "inode": self.primary.stat().st_ino,
                                "size": self.primary.stat().st_size},
            Path(depfile).name: {"device": Path(depfile).stat().st_dev, "inode": Path(depfile).stat().st_ino,
                                 "size": Path(depfile).stat().st_size}}})
        self.assertEqual(self.primary.read_bytes(), b"mock metadata image")
        unit = next(item for item in row["outputs"] if item["role"] == "unit")
        self.assertEqual(unit["path"], str(self.primary))
        self.assertNotIn("partial", unit)
        retained_depfile = next(item for item in row["outputs"] if item["role"] == "depfile")
        self.assertEqual(retained_depfile["path"], depfile)
        self.assertEqual((self.records / retained_depfile["artifact"]).read_bytes().decode(),
                         "%s:\n\n%s:\n" % (self.primary, depfile))
        self.assertEqual(row["depfiles"][0]["targets"], sorted([str(self.primary), depfile]))
        auditor = self.auditor_module()
        publication, audited = self.audit_namespace(auditor)
        self.assertTrue(any(entry["invocation_id"] == row["invocation_id"]
                            and entry["status"] == "success" for entry in publication["records"]))
        module = self.ordinary_host_module()
        campaign = module.Campaign(self.records, self.binding)
        try:
            with self.assertRaisesRegex(module.Refusal, "extern_producing_unit_not_completed"):
                module.producing_unit(campaign, unit)
        finally:
            campaign.close()

    def test_explicit_metadata_positive_include_dependency_is_retained(self):
        included = self.source_root / "included.txt"
        self.explicit_control(depfile=str(included))
        result = self.run_explicit(('pub const TEXT: &str = include_str!("included.txt");').encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        row = self.compilation_rows()[0]
        self.assertEqual(row["depfiles"][0]["dependencies"], [str(included)])
        self.assertTrue(any(item["role"] == "source" and item["path"] == str(included)
                            for item in row["inputs"]))
        auditor = self.auditor_module()
        self.audit_namespace(auditor)

    def test_explicit_metadata_three_sequential_same_output_calls_retire_chain(self):
        source = b"pub fn probe() -> u32 { 17 }"
        for _ in range(3):
            result = self.run_explicit(source)
            self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.compilation_rows()
        self.assertEqual(len(rows), 3)
        order = self.assert_chained(rows)
        first, latest, _final = order[0], order[1], order[2]
        self.assertEqual(first["semantics"]["output_ownership"]["policy"], "explicit-metadata-fresh-lease")
        identities = [row["semantics"]["output_ownership"]["produced"][self.primary.name]["inode"]
                      for row in rows]
        self.assertEqual(len(set(identities)), 3)
        self.assertEqual(self.primary.read_bytes(), b"mock metadata image")
        self.assertEqual(sorted(path.name for path in self.target_directory.iterdir()),
                         sorted([self.primary.name] + [row["semantics"]["dep_info_instrumentation"]["depfile_output"]
                                .rsplit("/", 1)[-1] for row in rows]))
        auditor = self.auditor_module()
        publication, audited = self.audit_namespace(auditor)
        self.assertEqual(sorted(entry["invocation_id"] for entry in publication["records"]
                                if entry["status"] == "success" and entry["kind"] == "compilation"),
                         sorted(row["invocation_id"] for row in rows))
        self.assertEqual(latest["semantics"]["output_ownership"]["predecessor"]["invocation_id"],
                         first["invocation_id"])

    def test_explicit_metadata_absent_failure_keeps_authenticated_lineage(self):
        source = b"pub fn probe() {}"
        self.assertEqual(self.run_explicit(source).returncode, 0)
        first = self.compilation_rows()[0]
        self.explicit_control(failure_without_output=23)
        failure = self.run_explicit(b"broken")
        self.assertEqual(failure.returncode, 23, failure.stderr)
        self.assertFalse(self.primary.exists())
        second = next(row for row in self.compilation_rows() if row["status"] == "compiler_failed")
        self.assertEqual(second["semantics"]["output_ownership"]["predecessor"]["invocation_id"], first["invocation_id"])
        self.assertNotIn(self.primary.name, second["semantics"]["output_ownership"]["produced"])
        self.explicit_control()
        third_run = self.run_explicit(source)
        self.assertEqual(third_run.returncode, 0, third_run.stderr)
        third = next(row for row in self.compilation_rows() if row["invocation_id"] not in
                     {first["invocation_id"], second["invocation_id"]})
        ownership = third["semantics"]["output_ownership"]
        self.assertEqual(ownership["policy"], "explicit-metadata-predecessor-absence")
        self.assertEqual(ownership["predecessor"]["invocation_id"], second["invocation_id"])
        self.assertEqual(ownership["predecessor"]["output"], {"path": str(self.primary), "state": "absent"})
        self.assertIsNone(ownership["predecessor"]["physical"])
        auditor = self.auditor_module()
        self.audit_namespace(auditor)

    def test_explicit_metadata_missing_success_output_does_not_reset_history(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        self.primary.unlink()
        before = (self.base / "observer/dispatches").read_bytes()
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"predecessor_output_missing", result.stderr)
        self.assertEqual((self.base / "observer/dispatches").read_bytes(), before)

    def test_explicit_metadata_directory_replacement_cannot_retire_same_leaf(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        before = self.primary.stat()
        original = self.target_directory.with_name("held-old-directory")
        self.target_directory.rename(original)
        self.target_directory.mkdir()
        (original / self.primary.name).rename(self.primary)
        dispatches = (self.base / "observer/dispatches").read_bytes()
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"predecessor_directory_binding", result.stderr)
        self.assertEqual((self.primary.stat().st_dev, self.primary.stat().st_ino), (before.st_dev, before.st_ino))
        self.assertEqual((self.base / "observer/dispatches").read_bytes(), dispatches)

    def test_explicit_metadata_absence_cannot_cross_replaced_directory(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        self.explicit_control(failure_without_output=23)
        self.assertEqual(self.run_explicit(b"broken").returncode, 23)
        self.assertFalse(self.primary.exists())
        self.target_directory.rename(self.target_directory.with_name("old-absent-directory"))
        self.target_directory.mkdir()
        dispatches = (self.base / "observer/dispatches").read_bytes()
        self.explicit_control()
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"predecessor_directory_binding", result.stderr)
        self.assertFalse(self.primary.exists())
        self.assertEqual((self.base / "observer/dispatches").read_bytes(), dispatches)

    def test_explicit_metadata_directory_membership_can_change_between_calls(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        (self.target_directory / "unrelated").write_bytes(b"retained")
        (self.target_directory / "child").mkdir()
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.target_directory / "unrelated").read_bytes(), b"retained")
        self.audit_namespace(self.auditor_module())

    def test_explicit_metadata_compile_failure_retains_partial_custody(self):
        self.explicit_control(failure=23)
        result = self.run_explicit(b"pub fn probe() { missing_function(); }")
        self.assertEqual(result.returncode, 23, result.stderr)
        rows = self.compilation_rows()
        self.assertEqual(len(rows), 1)
        failed = rows[0]
        self.assertEqual((failed["status"], failed["compiler_exit"]), ("compiler_failed", 23))
        partial = next(item for item in failed["outputs"] if item["role"] == "unit")
        self.assertEqual(partial["path"], str(self.primary))
        self.assertIs(partial["partial"], True)
        self.assertEqual(set(failed["semantics"]["output_ownership"]["produced"]), {self.primary.name})
        self.assertFalse(any(item["role"] == "depfile" for item in failed["outputs"]))
        auditor = self.auditor_module()
        self.audit_namespace(auditor)
        # A later completed row may retire exactly the sealed partial output.
        self.explicit_control()
        result = self.run_explicit(b"pub fn probe() -> u32 { 17 }")
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = self.compilation_rows()
        self.assertEqual(len(rows), 2)
        order = self.assert_chained(rows)
        self.assertEqual(order[0]["invocation_id"], failed["invocation_id"])
        self.assertEqual(order[0]["status"], "compiler_failed")
        self.audit_namespace(auditor)

    def test_explicit_metadata_unauthenticated_preexisting_primary_refuses(self):
        # Unowned file: no sealed predecessor exists, nothing is unlinked.
        self.primary.write_bytes(b"unrelated leaf")
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.predecessor_not_sealed", result.stderr)
        self.assertEqual(self.primary.read_bytes(), b"unrelated leaf")
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_explicit_metadata_aliased_primary_refuses(self):
        self.primary.symlink_to(self.source / "input.rs")
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.output_namespace_alias", result.stderr)
        self.assertTrue(self.primary.is_symlink())
        self.assertFalse((self.base / "observer/dispatches").exists())

    def test_explicit_metadata_hardlinked_primary_refuses(self):
        self.primary.write_bytes(b"hardlinked leaf")
        os.link(self.primary, self.base / "extra link")
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.hardlink_alias", result.stderr)
        self.assertEqual(self.primary.stat().st_nlink, 2)
        self.assertEqual(self.primary.read_bytes(), b"hardlinked leaf")

    def test_explicit_metadata_substituted_same_byte_inode_refuses(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        substitute = self.target_directory / "substitute"
        substitute.write_bytes(b"mock metadata image")
        os.replace(substitute, self.primary)
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.predecessor_not_sealed", result.stderr)
        # The substituted leaf is preserved; nothing was unlinked.
        self.assertEqual(self.primary.read_bytes(), b"mock metadata image")
        auditor = self.auditor_module()
        publication = auditor.audit_compiler_publications(self.records, self.binding)
        self.assertEqual(publication["status_counts"]["refused"], 1)
        with self.assertRaisesRegex(ValueError, "compiler_stdin_binding"):
            self.audit_namespace(auditor)

    def test_explicit_metadata_changed_primary_bytes_refuse(self):
        self.explicit_control(metadata_text="x" * 32)
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        self.primary.write_bytes(b"y" * 32)
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.predecessor_bytes_changed", result.stderr)
        self.assertEqual(self.primary.read_bytes(), b"y" * 32)
        self.primary.write_bytes(b"z")
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.predecessor_not_sealed", result.stderr)
        self.assertEqual(self.primary.read_bytes(), b"z")

    def test_explicit_metadata_cross_target_predecessor_refuses(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        result = self.run_explicit(b"pub fn probe() {}", include_target=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.predecessor_not_sealed", result.stderr)
        self.assertEqual(self.primary.read_bytes(), b"mock metadata image")

    def test_explicit_metadata_unconfirmed_completion_marker_refuses(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        row = self.compilation_rows()[0]
        marker = self.records / "completions" / (row["invocation_id"] + ".json")
        marker.write_text(json.dumps({"schema": "chio.rust-compilation-completion.v3",
                                      "invocation_id": row["invocation_id"],
                                      "source_binding": self.binding,
                                      "record_sha256": "0" * 64, "size": 1,
                                      "record_identity": {"device": 0, "inode": 0}}) + "\n")
        result = self.run_explicit(b"pub fn probe() {}")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.predecessor_completion_binding", result.stderr)
        self.assertEqual(self.primary.read_bytes(), b"mock metadata image")

    def test_explicit_metadata_other_namespace_cannot_retire_primary(self):
        self.assertEqual(self.run_explicit(b"pub fn probe() {}").returncode, 0)
        other = self.source_root / "target/other-campaign"
        other.mkdir()
        declaration = self.base / "host.json"
        document = json.loads(declaration.read_text())
        document["namespace"] = str(other)
        declaration.write_text(json.dumps(document) + "\n")
        result = self.run_explicit(b"pub fn probe() {}",
                                   env={**self.explicit_env, "CHIO_COMPILATION_RECORDS": str(other)})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"compilation_recorder.predecessor_not_sealed", result.stderr)
        self.assertEqual(self.primary.read_bytes(), b"mock metadata image")

    def test_explicit_metadata_explicit_crate_name_is_preserved_not_invented(self):
        result = self.run_explicit(b"pub fn probe() {}", crate_name="rustix_can_compile_probe")
        self.assertEqual(result.returncode, 0, result.stderr)
        row = self.compilation_rows()[0]
        self.assertEqual(row["semantics"]["crate_name"], "rustix_can_compile_probe")
        # The anonymous lane never derives or injects a name anywhere else.
        self.assertNotIn("crate_name", row["semantics"]["dep_info_instrumentation"])
        original = json.loads((self.records / row["semantics"]["dep_info_instrumentation"]
                               ["original_argv"]["artifact"]).read_bytes())
        self.assertIn("--crate-name=rustix_can_compile_probe", original)
        auditor = self.auditor_module()
        self.audit_namespace(auditor)

    def test_explicit_metadata_parse_lane_and_transformation_controls(self):
        module = self.ordinary_host_module()
        host = {"target": "mock-target"}
        lane = ["--crate-type=rlib", "--emit=metadata", "--target=mock-target", "-o", str(self.out), "-"]
        parsed = module.parse(lane, self.source_root, host=host)
        self.assertTrue(parsed["stdin"] and parsed["stdin_explicit_metadata"])
        self.assertFalse(parsed["stdin_instrumentation"])
        self.assertIsNone(parsed["crate_name"])
        self.assertEqual((parsed["crate_types"], parsed["emit"], parsed["output"], parsed["out_dir"]),
                         (["rlib"], {"metadata": None}, str(self.out), None))
        invocation = "a" * 32
        argv = [str(self.compiler), *lane]
        effective, primary, depfile = module.explicit_metadata_effective_argv(
            argv, parsed, self.source_root, invocation)
        self.assertEqual((primary, depfile),
                         (str(self.out), str(self.out.parent / (self.out.name + ".chio-" + invocation + ".d"))))
        self.assertEqual(effective, [argv[0], "--crate-type=rlib",
                         "--emit=metadata=%s,dep-info=%s" % (primary, depfile), "--target=mock-target",
                         "-o", str(self.out), "-"])
        # Split --emit metadata preserves its exact shape; -o requires two tokens.
        split = ["--crate-type=rlib", "--emit", "metadata", "-o", str(self.out), "-"]
        split_parsed = module.parse(split, self.source_root, host=host)
        split_effective, _, _ = module.explicit_metadata_effective_argv(
            [str(self.compiler), *split], split_parsed, self.source_root, invocation)
        self.assertEqual(split_effective, [str(self.compiler), "--crate-type=rlib", "--emit",
                         "metadata=%s,dep-info=%s" % (primary, depfile), "-o", str(self.out), "-"])
        for output in [["-o=" + str(self.out)], ["-o", "-"], ["-o", str(self.out) + "/"],
                       ["-o", str(self.out.parent) + "/./" + self.out.name],
                       ["-o", str(self.out.parent) + "/unused/../" + self.out.name]]:
            with self.subTest(output=output):
                args = ["--crate-type=rlib", "--emit=metadata", *output, "-"]
                with self.assertRaisesRegex(module.Refusal, "stdin_explicit_output_spelling|parent_traversal"):
                    parsed_output = module.parse(args, self.source_root, host=host)
                    module.explicit_metadata_effective_argv([str(self.compiler), *args], parsed_output,
                                                           self.source_root, invocation)
        for mutation, reason in [
                (["--crate-type=bin", "--emit=metadata", "-o", str(self.out), "-"], "stdin_explicit_crate_type"),
                (["--crate-type=rlib", "--crate-type=rlib", "--emit=metadata", "-o", str(self.out), "-"],
                 "stdin_explicit_crate_type"),
                (["--crate-type=rlib", "--emit=dep-info", "-o", str(self.out), "-"], "stdin_explicit_emission"),
                (["--crate-type=rlib", "--emit=metadata=explicit.rmeta", "-o", str(self.out), "-"],
                 "stdin_explicit_emission"),
                (["--crate-type=rlib", "--emit=metadata", "--emit=metadata", "-o", str(self.out), "-"],
                 "duplicate_emit"),
                (["--crate-type=rlib", "--emit=link", "-o", str(self.out), "-"], "stdin_link_emission"),
                (["--crate-type=rlib", "--emit=metadata", "--out-dir", str(self.out.parent),
                  "-o", str(self.out), "-"], "stdin_output_directory"),
                (["--crate-type=rlib", "--emit=metadata", "-o", str(self.out), "-", "-"],
                 "unsupported_positional")]:
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(module.Refusal, reason):
                    module.parse(mutation, self.source_root, host=host)
        # A duplicate explicit output selector is refused before mutation.
        duplicated = ["--crate-type=rlib", "--emit=metadata", "-o", str(self.out),
                      "-o", str(self.source_root / "target/other"), "-"]
        duplicated_parsed = module.parse(duplicated, self.source_root, host=host)
        with self.assertRaisesRegex(module.Refusal, "ambiguous_output_selector"):
            module.explicit_metadata_effective_argv([str(self.compiler), *duplicated], duplicated_parsed,
                                                    self.source_root, invocation)
        # An explicit crate name keeps its compiler meaning and is never derived.
        named = module.parse(["--crate-name=probe", "--crate-type=rlib", "--emit=metadata",
                              "-o", str(self.out), "-"], self.source_root, host=host)
        self.assertEqual(named["crate_name"], "probe")
        # Executor or native context keeps refusing the stdin positional.
        with self.assertRaises(module.Refusal):
            module.parse(lane, self.source_root, host=host, executor=object())

    def test_explicit_metadata_lease_retires_only_held_authenticated_leaves(self):
        module = self.ordinary_host_module()
        unrelated = self.target_directory / "unrelated.ll"
        unrelated.write_bytes(b"unrelated prior output")
        self.primary.write_bytes(b"sealed predecessor image")
        depfile = self.target_directory / (self.primary.name + ".chio-" + "b" * 32 + ".d")
        emissions = {"metadata": str(self.primary), "dep-info": str(depfile)}
        observed = {}

        def retirement(name, baseline, handle):
            observed[name] = (baseline, handle.read_digest())
            return {"invocation_id": "b" * 32}

        lease = module.OutputLease(self.target_directory, emissions, retirement)
        self.addCleanup(lease.close)
        self.assertEqual(list(lease.retirements), [self.primary.name])
        self.assertFalse(self.primary.exists())
        self.assertEqual(unrelated.read_bytes(), b"unrelated prior output")
        self.assertEqual(set(lease.baseline), {unrelated.name})
        # The dispatch then produces both expected leaves from the fresh lease.
        self.primary.write_bytes(b"fresh metadata image")
        depfile.write_bytes(b"fresh dep-info")
        produced = lease.produced()
        self.assertEqual(set(produced), {self.primary.name, depfile.name})
        self.assertEqual(observed[self.primary.name][1],
                         (hashlib.sha256(b"sealed predecessor image").hexdigest(),
                          len(b"sealed predecessor image")))

    def test_explicit_metadata_lease_refuses_replacement_before_unlink(self):
        module = self.ordinary_host_module()
        self.primary.write_bytes(b"sealed predecessor image")
        depfile = self.target_directory / (self.primary.name + ".chio-" + "c" * 32 + ".d")
        emissions = {"metadata": str(self.primary), "dep-info": str(depfile)}

        def retirement(name, baseline, handle):
            # Deterministic injected race: substitute an identical-byte leaf
            # under the held name after validation, before the unlink.
            substitute = self.target_directory / "substitute"
            substitute.write_bytes(b"sealed predecessor image")
            os.replace(substitute, self.primary)
            return {"invocation_id": "c" * 32}

        with self.assertRaisesRegex(module.Refusal, "file_race|preexisting_output_changed"):
            module.OutputLease(self.target_directory, emissions, retirement)
        # The substituted leaf was not unlinked and the dep-info path is fresh.
        self.assertTrue(self.primary.exists())
        self.assertEqual(self.primary.read_bytes(), b"sealed predecessor image")
        self.assertFalse(depfile.exists())

    def test_explicit_metadata_lease_refusal_leaves_candidate_intact(self):
        module = self.ordinary_host_module()
        self.primary.write_bytes(b"sealed predecessor image")
        emissions = {"metadata": str(self.primary),
                     "dep-info": str(self.target_directory / (self.primary.name + ".chio-" + "d" * 32 + ".d"))}

        def retirement(name, baseline, handle):
            raise module.Refusal("predecessor_not_sealed")

        with self.assertRaisesRegex(module.Refusal, "predecessor_not_sealed"):
            module.OutputLease(self.target_directory, emissions, retirement)
        self.assertEqual(self.primary.read_bytes(), b"sealed predecessor image")

    def test_explicit_metadata_lease_refuses_unrelated_baseline_mutation_before_unlink(self):
        module = self.ordinary_host_module()
        self.primary.write_bytes(b"sealed predecessor image")
        unrelated = self.target_directory / "unrelated"
        unrelated.write_bytes(b"original")
        emissions = {"metadata": str(self.primary),
                     "dep-info": str(self.target_directory / "new.d")}

        def retirement(name, baseline, handle):
            unrelated.write_bytes(b"changed")
            return {"invocation_id": "d" * 32}

        with self.assertRaisesRegex(module.Refusal, "preexisting_output_changed"):
            module.OutputLease(self.target_directory, emissions, retirement)
        self.assertEqual(self.primary.read_bytes(), b"sealed predecessor image")


class RetentionBatchReconciliationTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("batch_reconciliation_recorder", TOOL)
        self.recorder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.recorder)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.namespace = Path(self.temporary.name).resolve()
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        try:
            for _ in range(3):
                with campaign.retention_batch():
                    self.image = campaign.retain(b"public retained compiler image")
        finally:
            campaign.close()

    def reopen(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        campaign.close()

    def test_reopen_checks_shared_artifact_once_across_all_batches(self):
        opened = []
        original = self.recorder.HeldPath

        def observe(path, *args, **kwargs):
            if Path(path).parent == self.namespace / "artifacts":
                opened.append(Path(path).name)
            return original(path, *args, **kwargs)

        with mock.patch.object(self.recorder, "HeldPath", side_effect=observe):
            self.reopen()
        self.assertEqual(opened, [self.image["sha256"]])

    def test_repeated_artifact_does_not_skip_later_batch_validation(self):
        path = sorted((self.namespace / "batches").glob("*.complete.json"))[-1]
        complete = json.loads(path.read_bytes())
        complete["schema"] = "unsupported-batch-format"
        path.write_bytes(self.recorder.canonical(complete) + b"\n")
        with self.assertRaisesRegex(self.recorder.Refusal, "retention_batch_incomplete"):
            self.reopen()

    def test_repeated_artifact_cannot_claim_conflicting_physical_identities(self):
        complete_path = sorted((self.namespace / "batches").glob("*.complete.json"))[-1]
        complete = json.loads(complete_path.read_bytes())
        start_path = self.namespace / complete["start"]["path"]
        start = json.loads(start_path.read_bytes())
        # Change both sides of one internally consistent later declaration.
        # Earlier batches still bind the original physical identity.
        for inventory in [start["before"], complete["after"]]:
            for member in inventory["artifacts"]:
                member["identity"][4] += 1
        for member in complete["retained"]:
            member["identity"][4] += 1
        complete["before_sha256"] = self.recorder.digest(start["before"])
        start_body = self.recorder.canonical(start) + b"\n"
        start_path.write_bytes(start_body)
        complete["start"]["sha256"] = hashlib.sha256(start_body).hexdigest()
        complete["start"]["size"] = len(start_body)
        complete_path.write_bytes(self.recorder.canonical(complete) + b"\n")
        with self.assertRaisesRegex(self.recorder.Refusal, "retention_batch_incomplete"):
            self.reopen()


    def test_streamed_artifact_digests_hash_fresh_bounded_chunks(self):
        root = self.namespace / "streamed-digest"
        root.mkdir()
        payload = b"retained compiler image" * 300000
        name = hashlib.sha256(payload).hexdigest()
        (root / name).write_bytes(payload)
        requested = []
        original_read = self.recorder.os.read

        def observed(descriptor, count, *args, **kwargs):
            requested.append(count)
            return original_read(descriptor, count, *args, **kwargs)

        with mock.patch.object(self.recorder.os, "read", side_effect=observed):
            with self.recorder.HeldPath(root / name) as handle:
                self.assertEqual(handle.read_digest(), (name, len(payload)))
                with self.assertRaisesRegex(self.recorder.Refusal, "input_limit"):
                    handle.read_digest(limit=64)
        self.assertGreater(len(requested), 1)
        self.assertTrue(all(0 < count <= 1024 * 1024 for count in requested))

    def test_streamed_publication_match_compares_exactly_without_a_second_body(self):
        root = self.namespace / "streamed-match"
        root.mkdir()
        payload = b"published unit image" * 300000
        name = hashlib.sha256(payload).hexdigest()
        (root / name).write_bytes(payload)
        with self.recorder.HeldPath(root / name) as handle:
            self.assertEqual(handle.read_matches(payload, "publication_bytes"), name)
            for variant in [payload[:-1] + b"x", payload + b"tail", payload[:-1]]:
                with self.assertRaisesRegex(self.recorder.Refusal, "publication_bytes"):
                    handle.read_matches(variant, "publication_bytes")
            with self.assertRaisesRegex(self.recorder.Refusal, "input_limit"):
                handle.read_matches(payload, "publication_bytes", limit=64)
        (root / name).write_bytes(payload[:-1] + b"y")
        with self.recorder.HeldPath(root / name) as handle:
            with self.assertRaisesRegex(self.recorder.Refusal, "publication_bytes"):
                handle.read_matches(payload, "publication_bytes")

    def test_streamed_inventory_and_retain_recheck_keep_exact_members(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        try:
            members = campaign.artifact_inventory()
            with campaign.retention_batch():
                marker = campaign.retain(b"retained streamed marker")
            after = campaign.artifact_inventory()
        finally:
            campaign.close()
        expected = (self.namespace / "artifacts" / self.image["sha256"]).stat()
        self.assertEqual(members[0]["identity"], list(self.recorder.identity(expected)))
        self.assertEqual(members[0]["size"], expected.st_size)
        self.assertEqual([item["sha256"] for item in after],
                         sorted({self.image["sha256"], marker["sha256"]}))


    def test_unchanged_journal_reuses_parsing_but_rechecks_artifacts(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        self.addCleanup(campaign.close)
        pairs = list(campaign._retention_pairs)
        opened = []
        original = self.recorder.HeldPath

        def observe(path, *args, **kwargs):
            if Path(path).parent == self.namespace / "artifacts":
                opened.append(Path(path).name)
            return original(path, *args, **kwargs)

        with mock.patch.object(self.recorder, "HeldPath", side_effect=observe), \
                mock.patch.object(self.recorder.json, "loads", wraps=json.loads) as parse:
            with campaign.locked():
                pass
        parse.assert_not_called()
        self.assertEqual(opened, [self.image["sha256"]])
        self.assertEqual(campaign._retention_pairs, pairs)

    def test_changed_journal_bytes_refuse_with_the_same_descriptor_identity(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        self.addCleanup(campaign.close)
        path = sorted((self.namespace / "batches").glob("*.complete.json"))[-1]
        prior = self.recorder.identity(os.stat(path))
        before = path.read_bytes()
        after = before.replace(b"retention-batch-complete.v1", b"retention-batch-complete.v0")
        self.assertNotEqual(before, after)
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)
        original = self.recorder.identity

        def stable_identity(value):
            return prior if (value.st_dev, value.st_ino) == prior[:2] else original(value)

        # Model dirty mapped bytes without changing any of the seven metadata
        # fields. A metadata-only journal shortcut must fail this control.
        with mock.patch.object(self.recorder, "identity", side_effect=stable_identity):
            with self.assertRaisesRegex(self.recorder.Refusal, "retention_batch_incomplete"):
                with campaign.locked():
                    pass

    def test_added_batch_parses_only_the_new_pair_and_preserves_prior_union(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        self.addCleanup(campaign.close)
        with campaign.retention_batch():
            marker = campaign.retain(b"retained growth marker")
        prior_union = campaign._validated_journal[1]
        prior_union_snapshot = dict(prior_union)
        opened = []
        original = self.recorder.HeldPath

        def observe(path, *args, **kwargs):
            if Path(path).parent == self.namespace / "artifacts":
                opened.append(Path(path).name)
            return original(path, *args, **kwargs)

        with mock.patch.object(self.recorder, "HeldPath", side_effect=observe), \
                mock.patch.object(self.recorder.json, "loads", wraps=json.loads) as parse:
            with campaign.locked():
                pass
        self.assertEqual(parse.call_count, 2)
        self.assertEqual(opened, [self.image["sha256"], marker["sha256"]])
        self.assertEqual(prior_union, prior_union_snapshot)
        self.assertIsNot(campaign._validated_journal[1], prior_union)
        fresh = self.recorder.Campaign(self.namespace, "a" * 64)
        try:
            self.assertEqual(campaign._retention_pairs, fresh._retention_pairs)
        finally:
            fresh.close()

    def test_changed_old_pair_with_added_batch_reparses_the_whole_journal(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        self.addCleanup(campaign.close)
        earlier = sorted((self.namespace / "batches").glob("*.complete.json"))
        with campaign.retention_batch():
            campaign.retain(b"retained growth marker")
        earlier[0].write_bytes(earlier[0].read_bytes() + b" \n")
        with mock.patch.object(self.recorder.json, "loads", wraps=json.loads) as parse:
            with campaign.locked():
                pass
        self.assertEqual(parse.call_count, 8)
        fresh = self.recorder.Campaign(self.namespace, "a" * 64)
        try:
            self.assertEqual(campaign._retention_pairs, fresh._retention_pairs)
        finally:
            fresh.close()

    def test_stable_metadata_old_pair_change_with_added_batch_still_refuses(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        self.addCleanup(campaign.close)
        earlier = sorted((self.namespace / "batches").glob("*.complete.json"))
        with campaign.retention_batch():
            campaign.retain(b"retained growth marker")
        path = earlier[0]
        prior = self.recorder.identity(os.stat(path))
        before = path.read_bytes()
        after = before.replace(b"retention-batch-complete.v1", b"retention-batch-complete.v0")
        self.assertNotEqual(before, after)
        self.assertEqual(len(before), len(after))
        path.write_bytes(after)
        original = self.recorder.identity

        def stable_identity(value):
            return prior if (value.st_dev, value.st_ino) == prior[:2] else original(value)

        # Model dirty mapped bytes without changing any of the seven metadata
        # fields. Neither a metadata-only shortcut nor pair reuse may accept
        # a changed old pair while a new pair sorts beside it.
        with mock.patch.object(self.recorder, "identity", side_effect=stable_identity):
            with self.assertRaisesRegex(self.recorder.Refusal, "retention_batch_incomplete"):
                with campaign.locked():
                    pass

    def test_removed_old_pair_with_added_batch_reparses_the_remaining_journal(self):
        campaign = self.recorder.Campaign(self.namespace, "a" * 64)
        self.addCleanup(campaign.close)
        earlier = sorted((self.namespace / "batches").glob("*.start.json"))
        with campaign.retention_batch():
            campaign.retain(b"retained growth marker")
        batch_id = earlier[0].name.split(".")[0]
        (earlier[0].parent / (batch_id + ".complete.json")).unlink()
        earlier[0].unlink()
        with mock.patch.object(self.recorder.json, "loads", wraps=json.loads) as parse:
            with campaign.locked():
                pass
        self.assertEqual(parse.call_count, 6)
        fresh = self.recorder.Campaign(self.namespace, "a" * 64)
        try:
            self.assertEqual(campaign._retention_pairs, fresh._retention_pairs)
        finally:
            fresh.close()

    def test_grouped_rechecks_preserve_input_and_parent_refusals(self):
        def individual(originals, mutable_directory=None):
            for path, binding in originals.items():
                self.recorder.verify_unchanged(path, binding, mutable_directory)

        checks = (individual, self.recorder.verify_all_unchanged)
        for mutation in ("sibling", "leaf", "ancestor_mode"):
            with self.subTest(mutation=mutation):
                ancestor = self.namespace / mutation
                parent = ancestor / "inputs"
                parent.mkdir(parents=True)
                paths = [parent / "first.rs", parent / "second.rs"]
                for path in paths:
                    path.write_bytes(b"original source")
                originals = self.recorder.snapshot(paths)
                for check in checks:
                    check(originals)
                if mutation == "sibling":
                    (parent / "new.rs").write_bytes(b"new source")
                elif mutation == "leaf":
                    paths[0].write_bytes(b"changed source bytes")
                else:
                    ancestor.chmod(ancestor.stat().st_mode ^ 0o020)
                reason = ("input_changed_during_compilation" if mutation == "leaf"
                          else "input_parent_changed")
                for check in checks:
                    with self.assertRaisesRegex(self.recorder.Refusal, reason):
                        check(originals)
                    if mutation == "sibling":
                        check(originals, parent)

    def test_grouped_recheck_refuses_parent_substitution_and_closes_handles(self):
        ancestor = self.namespace / "ancestor"
        parent = ancestor / "inputs"
        parent.mkdir(parents=True)
        paths = [parent / "first.rs", parent / "second.rs"]
        for path in paths:
            path.write_bytes(b"original source")
        originals = self.recorder.snapshot(paths)
        original_open, original_close = self.recorder.os.open, self.recorder.os.close
        live = set()
        first = None
        replaced = False

        def opened(path, flags, *args, **kwargs):
            nonlocal first
            descriptor = original_open(path, flags, *args, **kwargs)
            live.add(descriptor)
            if path == "first.rs":
                first = descriptor
            return descriptor

        def closed(descriptor):
            nonlocal replaced
            original_close(descriptor)
            live.remove(descriptor)
            if descriptor == first and not replaced:
                replaced = True
                ancestor.rename(self.namespace / "displaced")
                parent.mkdir(parents=True)
                paths[1].write_bytes(b"replacement source")

        with mock.patch.object(self.recorder.os, "open", side_effect=opened), \
                mock.patch.object(self.recorder.os, "close", side_effect=closed):
            with self.assertRaisesRegex(self.recorder.Refusal, "parent_race"):
                self.recorder.verify_all_unchanged(originals)
        self.assertTrue(replaced)
        self.assertFalse(live, "grouped recheck leaked owned descriptors")

    def test_borrowed_child_lifetime_and_name_substitution(self):
        root = self.namespace / "held"
        root.mkdir()
        payload = b"retained compiler image"
        name = hashlib.sha256(payload).hexdigest()
        (root / name).write_bytes(payload)
        parent = self.recorder.HeldPath(root, directory=True)
        self.addCleanup(parent.close)
        # A borrowed binding must observe current, not parent-open, metadata.
        (root / "peer").write_bytes(b"new directory member")
        with self.recorder.HeldPath(root / name) as absolute:
            expected = absolute.binding()
        snapshot = self.recorder.snapshot({root / name, root / "peer"})
        self.assertEqual(snapshot[str(root / name)], expected)
        self.assertEqual(set(snapshot), {str(root / name), str(root / "peer")})
        with self.recorder.HeldPath(root / name, held_parent=parent) as child:
            self.assertEqual(child.binding(), expected)
            self.assertEqual(child.read(), payload)
            substitute = root / "substitute"
            substitute.write_bytes(b"replacement bytes")
            os.replace(substitute, root / name)
            with self.assertRaisesRegex(self.recorder.Refusal, "file_race"):
                child.read()
        parent.verify(content=False)
        with self.recorder.HeldPath(root / name, held_parent=parent) as child:
            moved = self.namespace / "moved"
            root.rename(moved)
            root.mkdir()
            with self.assertRaisesRegex(self.recorder.Refusal, "parent_race"):
                child.read()
            with self.assertRaisesRegex(self.recorder.Refusal, "file_race"):
                self.recorder.HeldPath(root / name, held_parent=parent)
            root.rmdir()
            moved.rename(root)
        parent.verify(content=False)
        substitute = root / "substitute"
        substitute.write_bytes(b"open race")
        opened = []
        original_open = self.recorder.os.open

        def replace_before_open(path, flags, *args, **kwargs):
            if path == name:
                os.replace(substitute, root / name)
            descriptor = original_open(path, flags, *args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with mock.patch.object(self.recorder.os, "open", side_effect=replace_before_open):
            with self.assertRaisesRegex(self.recorder.Refusal, "file_race"):
                self.recorder.HeldPath(root / name, held_parent=parent)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])
        parent.verify(content=False)
        with self.recorder.HeldPath(root / name, held_parent=parent) as stale:
            parent.close()
            with self.assertRaisesRegex(self.recorder.Refusal, "held_parent_closed"):
                stale.read()


class ActualRustCompilerTest(unittest.TestCase):
    def prepare_ordinary_host(self, candidate, paths):
        self.assertTrue(TOOL.is_file(), "actual compiler recorder is missing")
        recorder_spec = importlib.util.spec_from_file_location("actual_host_recorder", TOOL)
        recorder = importlib.util.module_from_spec(recorder_spec)
        recorder_spec.loader.exec_module(recorder)
        gate_spec = importlib.util.spec_from_file_location("compiled_gate_profiles", ROOT / "scripts/compiled-gate-profiles.py")
        gate = importlib.util.module_from_spec(gate_spec)
        gate_spec.loader.exec_module(gate)
        base_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        sources = [{"path": str(path.relative_to(candidate)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                   for path in sorted(paths)]
        inventory = {"source_inventory_version": "chio.source-inventory.v4", "base_commit": base_commit, "sources": sources}
        binding = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":"),
                                             ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        evidence = candidate / "target/host-evidence"
        evidence.mkdir(parents=True)
        gate.write(evidence / "runtime-preparation.json", {**inventory, "source_binding": binding})
        host, configuration, environment = gate.prepare_host(candidate, evidence, {**inventory, "source_binding": binding},
                                                            recorder)
        return host, configuration, environment

    @unittest.skipUnless(platform.system() == "Darwin", "ordinary host execution is Darwin only")
    def test_pinned_host_explicit_stdin_preserves_semantics_and_retires_outputs(self):
        """Real Rustix behavior, effective-emission byte identity and custody.

        The single build owner runs this control. Its retained observations
        do not repair or replace a failed original qualification namespace.
        """
        base = EVIDENCE / ("actual-explicit-stdin-" + os.urandom(6).hex())
        candidate = base / "candidate"
        candidate.mkdir(parents=True)
        manifest = candidate / "Cargo.toml"
        manifest.write_text('[package]\nname="probe"\nversion="0.1.0"\n')
        named_source = candidate / "root.rs"
        named_source.write_text("pub fn root() -> u32 { 17 }\n")
        included = candidate / "public.txt"
        included.write_text("actual included input")
        host, _configuration, environment = self.prepare_ordinary_host(candidate, [manifest, named_source, included])
        campaign = Path(host["namespace"])
        target = Path(host["target_directory"])
        output = target / "rustix-probe"
        output.mkdir()
        primary = output / "rustix_test_can_compile"
        environment = {**environment, "CARGO_MANIFEST_PATH": str(manifest),
                       "CARGO_MANIFEST_DIR": str(candidate), "CARGO_PKG_NAME": "probe"}
        auditor_spec = importlib.util.spec_from_file_location("actual_explicit_stdin_consumer",
                                                             ROOT / "scripts/verify-recovery-qualification.py")
        auditor = importlib.util.module_from_spec(auditor_spec)
        auditor_spec.loader.exec_module(auditor)
        source = b"pub fn probe() -> u32 { 17 }"
        probes = [source, source, source, b"pub fn probe() { missing_function(); }", source,
                  ('#![crate_name = "declared_stdin"]\npub const TEXT: &str = include_str!("'
                   + str(included) + '");').encode()]
        observations, stderrs, compilation_ids = [], [], []
        for index, stdin in enumerate(probes):
            original = [host["compiler"], "--crate-type=rlib", "--emit=metadata", "--target", host["target"],
                        "-o", str(primary), "-Csplit-debuginfo=off", "-Clinker=" + host["linker"], "-"]
            comparison_dir = target / ("unwrapped-" + str(index))
            comparison_dir.mkdir()
            comparison = comparison_dir / primary.name
            baseline = list(original)
            baseline[baseline.index("-o") + 1] = str(comparison)
            raw = subprocess.run(baseline, cwd=candidate, env=environment, input=stdin,
                                 capture_output=True, timeout=300)
            result = subprocess.run([sys.executable, str(TOOL), *original], cwd=candidate,
                                    env=environment, input=stdin, capture_output=True, timeout=300)
            for label, execution in [("unwrapped", raw), ("recorded", result)]:
                (base / (str(index) + "-" + label + ".stdout")).write_bytes(execution.stdout)
                (base / (str(index) + "-" + label + ".stderr")).write_bytes(execution.stderr)
            expected = 1 if index == 3 else 0
            self.assertEqual(raw.returncode, expected, raw.stderr)
            self.assertEqual(result.returncode, expected, result.stderr[-6000:])
            self.assertEqual(comparison.exists(), expected == 0)
            self.assertEqual(primary.exists(), expected == 0)
            rows = [json.loads(path.read_text()) for path in (campaign / "records").glob("*.json")]
            new = [row for row in rows if row["kind"] == "compilation" and row["invocation_id"] not in compilation_ids]
            self.assertEqual(len(new), 1)
            row = new[0]
            compilation_ids.append(row["invocation_id"])
            self.assertEqual(row["status"], "compiler_failed" if expected else "success")
            self.assertEqual(row["compiler_exit"], expected)
            self.assertIsNone(row["refusal"])
            self.assertIsNone(row["semantics"]["crate_name"])
            input_image = next(image for image in row["inputs"] if image["role"] == "stdin")
            self.assertEqual((campaign / input_image["artifact"]).read_bytes(), stdin)
            instrumentation = row["semantics"]["dep_info_instrumentation"]
            self.assertEqual(json.loads((campaign / instrumentation["original_argv"]["artifact"]).read_bytes()), original)
            transformed = list(original)
            transformed[2] = "--emit=metadata=" + str(primary) + ",dep-info=" + instrumentation["depfile_output"]
            self.assertEqual(json.loads((campaign / instrumentation["effective_argv"]["artifact"]).read_bytes()), transformed)
            # Rust tracks the emission set in its crate hash. Compare full
            # metadata bytes with an independent execution of the same emission,
            # changing only its primary and dep-info output destinations.
            effective_dir = target / ("unwrapped-effective-" + str(index))
            effective_dir.mkdir()
            effective_primary = effective_dir / primary.name
            effective_depfile = effective_dir / Path(instrumentation["depfile_output"]).name
            effective_baseline = list(transformed)
            effective_baseline[2] = ("--emit=metadata=" + str(effective_primary)
                                     + ",dep-info=" + str(effective_depfile))
            effective_baseline[effective_baseline.index("-o") + 1] = str(effective_primary)
            effective = subprocess.run(effective_baseline, cwd=candidate, env=environment, input=stdin,
                                       capture_output=True, timeout=300)
            (base / (str(index) + "-unwrapped-effective.stdout")).write_bytes(effective.stdout)
            (base / (str(index) + "-unwrapped-effective.stderr")).write_bytes(effective.stderr)
            observation = {"invocation_id": row["invocation_id"], "original_argv": original,
                           "baseline_argv": baseline, "effective_argv": transformed,
                           "effective_baseline_argv": effective_baseline,
                           "original_output_substitution": {"from": str(primary), "to": str(comparison)},
                           "effective_output_substitutions": [
                               {"from": str(primary), "to": str(effective_primary)},
                               {"from": instrumentation["depfile_output"], "to": str(effective_depfile)}],
                           "cwd": str(candidate), "stdin_sha256": hashlib.sha256(stdin).hexdigest(),
                           "original_exit": raw.returncode, "compiler_exit": result.returncode,
                           "effective_exit": effective.returncode,
                           "original_primary_present": comparison.exists(), "primary_present": primary.exists(),
                           "effective_primary_present": effective_primary.exists()}
            (base / (str(index) + "-executions.json")).write_text(json.dumps(observation, indent=2) + "\n")
            self.assertEqual(effective.returncode, expected, effective.stderr)
            self.assertEqual(effective_primary.exists(), expected == 0)
            if expected == 0:
                retained_primary = [image for image in row["outputs"]
                                    if image["role"] == "unit" and image["path"] == str(primary)]
                self.assertEqual(len(retained_primary), 1)
                primary_bytes = primary.read_bytes()
                self.assertEqual(effective_primary.read_bytes(), primary_bytes)
                self.assertEqual((campaign / retained_primary[0]["artifact"]).read_bytes(), primary_bytes)
            if index in {1, 2, 3, 4, 5}:
                self.assertEqual(row["semantics"]["output_ownership"]["predecessor"]["invocation_id"],
                                 compilation_ids[index - 1])
            if index == 3:
                self.assertFalse(primary.exists())
                self.assertFalse(any(image["path"] == str(primary) for image in row["outputs"]))
            if index == 4:
                ownership = row["semantics"]["output_ownership"]
                self.assertEqual(ownership["policy"], "explicit-metadata-predecessor-absence")
                self.assertEqual(ownership["predecessor"]["output"], {"path": str(primary), "state": "absent"})
                self.assertIsNone(ownership["predecessor"]["physical"])
            if index == 5:
                self.assertTrue(any(image["role"] == "source" and image["path"] == str(included)
                                    for image in row["inputs"]))
                self.assertIn(str(included), row["depfiles"][0]["dependencies"])
            stderrs.append(result.stderr)
            observations.append(observation)
        named_dir = target / "named"
        named_dir.mkdir()
        named = [host["compiler"], str(named_source), "--crate-name", "root", "--crate-type=rlib",
                 "--emit=dep-info,metadata", "--out-dir", str(named_dir)]
        named_result = subprocess.run([sys.executable, str(TOOL), *named], cwd=candidate,
                                      env=environment, capture_output=True, timeout=300)
        (base / "named.stdout").write_bytes(named_result.stdout)
        (base / "named.stderr").write_bytes(named_result.stderr)
        self.assertEqual(named_result.returncode, 0, named_result.stderr[-6000:])
        stderrs.append(named_result.stderr)
        publication = auditor.audit_compiler_publications(campaign, environment["CHIO_COMPILATION_SOURCE_BINDING"])
        auditor.current_required_sync_observations(publication, b"".join(stderrs))
        rows = [json.loads(path.read_text()) for path in sorted((campaign / "records").glob("*.json"))]
        auditor.audit_compiler_stdin_inputs(rows, campaign, lambda image: (campaign / image["artifact"]).read_bytes(),
                                           publication["unit_publications"])
        declarations = {auditor.compiler_graph_image(image): {**image, "role": "candidate"}
                        for row in rows for image in row.get("inputs", []) if image["role"] == "source"}
        named_row = next(row for row in rows if (row.get("semantics") or {}).get("source") == str(named_source))
        root = next(image for image in named_row["outputs"] if image["role"] == "unit")
        graph = auditor.audit_compiler_unit_graph(rows, list(declarations.values()), [root])
        self.assertEqual(graph["reachable_units"], 1)
        auxiliary = next(image for row in rows if row["invocation_id"] == compilation_ids[0]
                         for image in row["outputs"] if image["role"] == "unit")
        with self.assertRaisesRegex(ValueError, "compiler_root_source"):
            auditor.audit_compiler_unit_graph(rows, list(declarations.values()), [auxiliary])
        named_row["inputs"].append({**auxiliary, "role": "extern"})
        with self.assertRaisesRegex(ValueError, "compiler_extern_source"):
            auditor.audit_compiler_unit_graph(rows, list(declarations.values()), [root])
        (base / "result.json").write_text(json.dumps({"observations": observations,
            "namespace": str(campaign), "compiler": host["compiler"], "publication": publication,
            "unit_graph": graph, "recorder_sha256": hashlib.sha256(TOOL.read_bytes()).hexdigest(),
            "verifier_sha256": hashlib.sha256((ROOT / "scripts/verify-recovery-qualification.py").read_bytes()).hexdigest(),
            "tests_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, indent=2) + "\n")

    def test_pinned_host_stdin_tracks_real_dependencies_and_compiler_failures(self):
        base = EVIDENCE / ("actual-host-stdin-" + os.urandom(6).hex())
        candidate = base / "candidate"
        candidate.mkdir(parents=True)
        manifest = candidate / "Cargo.toml"
        manifest.write_text('[package]\nname="probe"\nversion="0.1.0"\n')
        host, _configuration, environment = self.prepare_ordinary_host(candidate, [manifest])
        campaign = Path(host["namespace"])
        generated = Path(host["target_directory"]) / "generated"
        generated.mkdir(parents=True)
        included = generated / "public.txt"
        included.write_text("actual generated input")
        unknown = base / "unobserved.rs"
        unknown.write_text("pub fn included() {}")
        probes = [
            ("positive", b"pub fn probe() -> u32 { 17 }", 0, "success"),
            ("negative", b"pub fn probe() { missing_function(); }", 1, "compiler_failed"),
            ("included", ('pub const TEXT: &str = include_str!("'+str(included)+'");').encode(), 0, "success"),
            ("relative", b'pub const TEXT: &str = include_str!("public.txt");', 1, "compiler_failed"),
            ("unobserved", ('include!("'+str(unknown)+'"); pub fn fail() { missing_function(); }').encode(), 1, None),
        ]
        audit_spec = importlib.util.spec_from_file_location("stdin_consumer", ROOT / "scripts/verify-recovery-qualification.py")
        auditor = importlib.util.module_from_spec(audit_spec)
        audit_spec.loader.exec_module(auditor)
        for name, source, expected_exit, expected_status in probes:
            output = Path(host["target_directory"]) / name
            output.mkdir()
            arguments = [host["compiler"], "--crate-name", name, "--crate-type=lib", "--out-dir", str(output), "--emit=llvm-ir", "-"]
            result = subprocess.run([sys.executable, str(TOOL), *arguments], cwd=candidate,
                env={**environment, "CARGO_MANIFEST_PATH": str(manifest), "CARGO_MANIFEST_DIR": str(candidate),
                     "CARGO_PKG_NAME": "probe", "OUT_DIR": str(generated)}, input=source, capture_output=True, timeout=300)
            (base / (name+".stdout")).write_bytes(result.stdout)
            (base / (name+".stderr")).write_bytes(result.stderr)
            self.assertEqual(result.returncode, expected_exit, result.stderr[-6000:])
            rows = [json.loads(path.read_text()) for path in (campaign / "records").glob("*.json")]
            if name == "unobserved":
                self.assertIn(b"compilation_recorder.include_outside_declared_scope", result.stderr)
                self.assertFalse(any(row["kind"] == "compilation" and row["semantics"].get("crate_name") == name for row in rows))
                self.assertTrue((output / "unobserved.d").is_file())
                # The failed sidecar was checked before any retained disclosure.
                digest = hashlib.sha256((output / "unobserved.d").read_bytes()).hexdigest()
                self.assertFalse((campaign / "artifacts" / digest).exists())
                with self.assertRaises(ValueError):
                    auditor.audit_compiler_publications(campaign, environment["CHIO_COMPILATION_SOURCE_BINDING"])
                continue
            row = next(row for row in rows if row["kind"] == "compilation" and row["semantics"].get("crate_name") == name)
            self.assertEqual(row["status"], expected_status)
            self.assertEqual(row["compiler_exit"], expected_exit)
            retained = next(image for image in row["inputs"] if image["role"] == "stdin")
            self.assertEqual((campaign / retained["artifact"]).read_bytes(), source)
            invocation = row["semantics"]["dep_info_instrumentation"]
            self.assertEqual(json.loads((campaign / invocation["original_argv"]["artifact"]).read_bytes()), arguments)
            self.assertEqual(json.loads((campaign / invocation["effective_argv"]["artifact"]).read_bytes()), arguments+["--emit=dep-info"])
            auditor.audit_compiler_stdin_inputs([row], campaign, lambda image: (campaign / image["artifact"]).read_bytes())
            if name == "included":
                self.assertEqual(row["depfiles"][0]["dependencies"], [str(included)])
                self.assertTrue(any(image["role"] == "source" and image["path"] == str(included) for image in row["inputs"]))
            if name in {"positive", "negative"}:
                self.assertTrue(any(image["role"] == "depfile" for image in row["outputs"]))
            if name == "positive":
                self.assertEqual(row["depfiles"][0]["dependencies"], [])
                self.assertIn(b"17", (output / "positive.ll").read_bytes())

    def test_pinned_standalone_dependency_and_compiler_failure(self):
        self.assertTrue(TOOL.is_file(), "actual compiler recorder is missing")
        selected = subprocess.run(["rustup", "which", "--toolchain", "1.95.0", "rustc"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        base = EVIDENCE / "actual-standalone"
        if base.exists():
            base = EVIDENCE / ("actual-standalone-" + os.urandom(6).hex())
        candidate = base / "candidate"
        candidate.mkdir(parents=True)
        campaign = candidate / "target/campaign"
        campaign.mkdir(parents=True)
        dependency = candidate / "dependency.rs"
        root = candidate / "consumer.rs"
        broken = candidate / "broken.rs"
        dependency.write_text("pub fn answer() -> u32 { 42 }\n")
        root.write_text("pub fn consume() -> u32 { dependency::answer() }\n")
        broken.write_text("fn invalid(\n")
        ignore = candidate / ".gitignore"
        ignore.write_text("target/\n")
        subprocess.run(["git", "init", "--quiet", str(candidate)], check=True)
        base_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        sources = [{"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                   for path in sorted([dependency, root, broken, ignore])]
        source_vector = {"source_inventory_version": "chio.source-inventory.v3",
                         "base_commit": base_commit, "sources": sources}
        source_binding = hashlib.sha256(json.dumps(source_vector, sort_keys=True, separators=(",", ":"),
                                                   ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        (base / "source-binding.json").write_text(json.dumps({**source_vector, "source_binding": source_binding}, indent=2)+"\n")
        env = dict(os.environ)
        for key in list(env):
            if key in {"LD_PRELOAD", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "RUSTC_CODEGEN_BACKEND", "RUST_TARGET_PATH"} or any(t in key.lower() for t in ["token", "password", "secret", "credential", "api_key"]):
                del env[key]
        env.update(CHIO_COMPILATION_SOURCE_ROOT=str(candidate), CHIO_COMPILATION_RECORDS=str(campaign),
                   CHIO_COMPILATION_SOURCE_BINDING=source_binding)
        metadata_dir = candidate / "target/metadata"
        metadata_dir.mkdir()
        invocations = [
            [str(dependency), "--crate-name", "dependency", "--crate-type", "rlib", "--edition", "2021",
             "--emit", "dep-info,link", "-o", str(candidate / "target/libdependency.rlib")],
            # Real standalone metadata emission: actual rustc writes the true
            # header framing (magic, reserved root position, varint length
            # prefixed version banner) that the recorder validates.
            [str(dependency), "--crate-name", "dependency", "--crate-type", "rlib", "--edition", "2021",
             "--emit", "dep-info,metadata", "-o", str(metadata_dir / "libdependency.rmeta")],
            [str(root), "--crate-name", "consumer", "--crate-type", "rlib", "--edition", "2021",
             "--extern", "dependency="+str(candidate / "target/libdependency.rlib"),
             "--emit", "dep-info,link", "-o", str(candidate / "target/libconsumer.rlib")],
            # Actual rustc consumes the recorded metadata emission as a real
            # extern dependency, so the recorded producer bytes are the exact
            # bytes later compiles load.
            [str(root), "--crate-name", "consumer_metadata", "--crate-type", "rlib", "--edition", "2021",
             "--extern", "dependency="+str(metadata_dir / "libdependency.rmeta"),
             "--emit", "dep-info,metadata", "-o", str(candidate / "target/libconsumer_metadata.rmeta")],
            [str(broken), "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(candidate / "target/libbroken.rlib")]]
        summaries = []
        print_args = ["-", "--crate-name", "___", "--print=file-names", "--crate-type", "bin", "--crate-type", "rlib",
                      "--print=sysroot", "--print=split-debuginfo", "--print=crate-name", "--print=cfg"]
        probe_result = subprocess.run([sys.executable, str(TOOL), selected, *print_args], cwd=candidate,
                                      env=env, capture_output=True, timeout=30)
        (base / "cargo-print-probe.stdout").write_bytes(probe_result.stdout)
        (base / "cargo-print-probe.stderr").write_bytes(probe_result.stderr)
        self.assertEqual(probe_result.returncode, 0, probe_result.stderr)
        for order in (["--verbose", "--version"], ["--version", "--verbose"]):
            version_result = subprocess.run([sys.executable, str(TOOL), selected, *order], cwd=candidate,
                                            env=env, capture_output=True, timeout=30)
            self.assertEqual(version_result.returncode, 0, version_result.stderr)
            self.assertIn(b"rustc 1.95.0", version_result.stdout)
            argv_sha256 = hashlib.sha256(json.dumps([selected, *order], sort_keys=True, separators=(",", ":"),
                                                    ensure_ascii=True).encode()).hexdigest()
            bound = [json.loads(p.read_text()) for p in (campaign / "records").glob("*.json")]
            bound = [r for r in bound if r["invocation_sha256"] == argv_sha256]
            self.assertEqual([(r["kind"], r["status"], r["outputs"]) for r in bound], [("probe", "success", [])])
        for index, args in enumerate(invocations):
            result = subprocess.run([sys.executable, str(TOOL), selected, *args], cwd=candidate,
                                    env=env, capture_output=True, timeout=180)
            (base / f"invocation-{index}.stdout").write_bytes(result.stdout)
            (base / f"invocation-{index}.stderr").write_bytes(result.stderr)
            summaries.append({"index": index, "exit": result.returncode})
            if index < len(invocations) - 1:
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertEqual(result.returncode, 1, result.stderr)
        rows = [json.loads(p.read_text()) for p in (campaign / "records").glob("*.json")]
        units = [r for r in rows if r["kind"] == "compilation"]
        self.assertEqual(sorted(r["status"] for r in units),
                         ["compiler_failed", "success", "success", "success", "success"])
        dep_output = next(i for r in units for i in r["outputs"] if i["path"].endswith("libdependency.rlib"))
        extern = next(i for r in units for i in r["inputs"]
                      if i["role"] == "extern" and i["path"].endswith("libdependency.rlib"))
        self.assertEqual(dep_output["sha256"], extern["sha256"])
        # The recorded standalone metadata emission equals the bytes actual
        # rustc later consumed as its --extern dependency input.
        rmeta_output = next(i for r in units for i in r["outputs"] if i["path"].endswith("libdependency.rmeta"))
        rmeta_extern = next(i for r in units for i in r["inputs"]
                            if i["role"] == "extern" and i["path"].endswith("libdependency.rmeta"))
        self.assertEqual(rmeta_output["sha256"], rmeta_extern["sha256"])
        (base / "summary.json").write_text(json.dumps({"invocations": summaries, "campaign": str(campaign),
            "compiler": selected, "compiler_sha256": hashlib.sha256(Path(selected).read_bytes()).hexdigest(),
            "source_binding": source_binding, "recorder_sha256": hashlib.sha256(TOOL.read_bytes()).hexdigest(),
            "tests_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, indent=2)+"\n")

    def test_pinned_host_proc_macro_sequence_binds_captured_sysroot_candidates(self):
        """Actual rustc proc-macro producing/consuming run through prepare_host.

        The ordinary-host-execution declaration comes from the existing
        compiled-gate-profiles prepare_host helper over a real source
        inventory; the producing invocation uses cargo's real name-only
        --extern proc_macro argument, and the consuming invocation loads the
        recorded producer image plus the same compiler-owned sysroot extern.
        Both rows must bind the captured conservative sysroot candidates.
        """
        base = EVIDENCE / ("actual-host-proc-macro-" + os.urandom(6).hex())
        candidate = base / "candidate"
        candidate.mkdir(parents=True)
        macro = candidate / "proc_macro2"
        (macro / "src").mkdir(parents=True)
        (macro / "Cargo.toml").write_text('[package]\nname = "proc-macro2"\nversion = "0.1.0"\n')
        (macro / "src/lib.rs").write_text('use proc_macro::TokenStream;\n#[proc_macro]\npub fn answer(input: TokenStream) -> TokenStream { input }\n')
        consumer = candidate / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text('[package]\nname = "consumer"\nversion = "0.1.0"\n')
        (consumer / "src/lib.rs").write_text('pub fn consume() -> u32 {\n    let _ = proc_macro2::answer!(7);\n    3\n}\n')
        host, configuration, environment = self.prepare_ordinary_host(candidate, [macro / "Cargo.toml", macro / "src/lib.rs",
                                                                   consumer / "Cargo.toml", consumer / "src/lib.rs"])
        campaign = Path(host["namespace"])
        deps = Path(host["target_directory"]) / "deps"
        deps.mkdir(parents=True)
        invocations = [
            ("proc-macro2", "proc_macro2", macro / "src/lib.rs", macro / "Cargo.toml", [],
             ["--crate-type", "proc-macro", "--extern", "proc_macro"]),
            ("consumer", "consumer", consumer / "src/lib.rs", consumer / "Cargo.toml",
             ["libproc_macro2.dylib"], ["--crate-type", "rlib", "-L", "crate=" + str(deps),
              "--extern", "proc_macro2=" + str(deps / "libproc_macro2.dylib"), "--extern", "proc_macro"]),
        ]
        summaries = []
        for index, (package, crate, source, manifest, outputs, extra) in enumerate(invocations):
            arguments = [str(source), "--crate-name", crate, "--edition=2021", *extra,
                         "--emit", "dep-info,link", "--cap-lints", "allow",
                         "-Clinker=" + host["linker"], "--out-dir", str(deps)]
            result = subprocess.run([sys.executable, str(TOOL), host["compiler"], *arguments], cwd=candidate,
                                    env={**environment, "CARGO_MANIFEST_PATH": str(manifest),
                                         "CARGO_MANIFEST_DIR": str(manifest.parent), "CARGO_PKG_NAME": package},
                                    capture_output=True, timeout=300)
            (base / f"invocation-{index}.stdout").write_bytes(result.stdout)
            (base / f"invocation-{index}.stderr").write_bytes(result.stderr)
            summaries.append({"index": index, "exit": result.returncode, "outputs": outputs})
            self.assertEqual(result.returncode, 0, result.stderr)
            # One batch before dispatch and one after.
            self.assertEqual(len(list((campaign / "batches").glob("*.complete.json"))), 2 * (index + 1))
        rows = [json.loads(p.read_text()) for p in (campaign / "records").glob("*.json")]
        units = [r for r in rows if r["kind"] == "compilation"]
        self.assertEqual(sorted(r["status"] for r in units), ["success", "success"])
        externs = [item for r in units for item in r["inputs"] if item.get("sysroot_binding", {}).get("extern_name") == "proc_macro"]
        # Both rows bind both captured sysroot candidates conservatively.
        self.assertEqual(len(externs), 4)
        for item in externs:
            self.assertEqual(item["role"], "toolchain")
            self.assertEqual(item["coverage"], "conservative-toolchain-scope")
            self.assertEqual(item["sysroot_binding"]["coverage"], "conservative-candidates")
            self.assertEqual(item["sysroot_binding"]["sysroot"], host["toolchain"])
            self.assertTrue(Path(item["path"]).is_relative_to(
                Path(host["toolchain"]) / "lib/rustlib" / host["target"] / "lib"))
        producer = next(r for r in units for item in r["outputs"] if item["path"] == str(deps / "libproc_macro2.dylib"))
        produced = next(item for item in producer["outputs"] if item["path"] == str(deps / "libproc_macro2.dylib"))
        macro_extern = next(item for r in units for item in r["inputs"]
                            if item.get("extern_name") == "proc_macro2")
        # The consumer's macro extern joins the recorded producer provenance.
        self.assertEqual(macro_extern["sha256"], produced["sha256"])
        self.assertEqual(macro_extern["producer"]["invocation_id"], producer["invocation_id"])
        # A real sysroot image copied into the crate-search path has no local
        # producer. Its name alone must not give it compiler-input authority.
        shadow = deps / "libproc_macro-unrecorded.rlib"
        original = next(item for item in externs if item["sysroot_binding"]["candidate_kind"] == "rlib")
        shadow.write_bytes(Path(original["path"]).read_bytes())
        fresh = Path(host["target_directory"]) / "refused"
        fresh.mkdir()
        shadow_args = [str(consumer / "src/lib.rs"), "--crate-name", "consumer_shadow", "--edition=2021",
                       "--crate-type", "rlib", "--extern", "proc_macro", "--emit", "dep-info,link",
                       "-L", "crate=" + str(deps), "--out-dir", str(fresh)]
        refusal = subprocess.run([sys.executable, str(TOOL), host["compiler"], *shadow_args], cwd=candidate,
                                 env={**environment, "CARGO_MANIFEST_PATH": str(consumer / "Cargo.toml"),
                                      "CARGO_MANIFEST_DIR": str(consumer), "CARGO_PKG_NAME": "consumer"},
                                 capture_output=True, timeout=300)
        (base / "shadow-refusal.stderr").write_bytes(refusal.stderr)
        self.assertEqual(refusal.returncode, 86, refusal.stderr)
        self.assertIn(b"extern_producing_unit_not_completed", refusal.stderr)
        self.assertFalse((fresh / "libconsumer_shadow.rlib").exists())
        (base / "summary.json").write_text(json.dumps({"invocations": summaries, "shadow_refusal_exit": refusal.returncode, "campaign": str(campaign),
            "host_execution": str(configuration), "compiler": host["compiler"],
            "toolchain": host["toolchain"], "recorder_sha256": hashlib.sha256(TOOL.read_bytes()).hexdigest(),
            "tests_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}, indent=2)+"\n")


PUBLICATION_CONTROL = r"""
import hashlib, importlib.util, json, os, pathlib, sys
spec = importlib.util.spec_from_file_location('recorder', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
base = pathlib.Path(sys.argv[2]); kind = sys.argv[3]
campaign = m.Campaign(base, 'd'*64)
raised = False; returned = False; stored = None; marker_exists = False
if kind in {'artifact-swap', 'record-swap', 'completion-swap', 'completion-copy'}:
    real_link = m.os.link
    def exchanged(source, dest, **kwargs):
        if str(source).startswith('.pending-') and (kind not in {'completion-swap', 'completion-copy'} or
                os.fstat(kwargs['src_dir_fd']).st_ino == os.fstat(campaign.completions.fd).st_ino):
            fd = kwargs['src_dir_fd']
            replacement = b'substituted public bytes'
            if kind == 'completion-copy':
                observed = os.open(source, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                replacement = os.read(observed, 1024*1024); os.close(observed)
            os.rename(source, 'displaced-' + str(source), src_dir_fd=fd, dst_dir_fd=fd)
            forged = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
            os.write(forged, replacement); os.close(forged)
        return real_link(source, dest, **kwargs)
    m.os.link = exchanged
    try:
        if kind == 'artifact-swap':
            item = campaign.retain(b'expected public bytes')
            returned = True
            stored = hashlib.sha256((base/item['artifact']).read_bytes()).hexdigest() == item['sha256']
        else:
            row = m.row_for([], {}, 'd'*64); row.update(status='success', compiler_exit=0)
            campaign.publish(row); returned = True
            path = base/'records'/(row['invocation_id']+'.json')
            stored = path.read_bytes() == m.canonical(row)+b'\n'
    except (m.Refusal, OSError, ValueError):
        raised = True
else:
    row = m.row_for([], {}, 'd'*64); row.update(status='success', compiler_exit=0)
    def fail_state(): raise OSError('synthetic state persistence failure')
    campaign.save_state = fail_state
    try:
        campaign.publish(row); returned = True
    except (m.Refusal, OSError, ValueError):
        raised = True
    path = base/'records'/(row['invocation_id']+'.json')
    if path.exists(): stored = json.loads(path.read_text())['status']
    marker_exists = (base/'completions'/(row['invocation_id']+'.json')).exists()
if kind in {'record-swap', 'completion-swap', 'completion-copy'}:
    marker_exists = (base/'completions'/(row['invocation_id']+'.json')).exists()
print(json.dumps({'boundary':'publication primitive subprocess control', 'kind':kind, 'raised':raised,
                  'returned':returned, 'stored':stored, 'completion_exists':marker_exists, 'schema':m.SCHEMA}))
campaign.close()
"""


class RecorderReviewRegressionTest(unittest.TestCase):
    """Independent-review regressions; persistent authored fixtures, no original secrets."""
    def fixture(self, name):
        base = EVIDENCE / 'repair-round-one' / (name + '-' + os.urandom(6).hex())
        candidate = base / 'candidate'
        campaign = candidate / 'target/campaign'
        campaign.mkdir(parents=True)
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(('LD_', 'DYLD_')) and not any(
                   word in key.lower() for word in ['token', 'password', 'secret', 'credential', 'api_key'])}
        env.update(CHIO_COMPILATION_SOURCE_ROOT=str(candidate), CHIO_COMPILATION_RECORDS=str(campaign),
                   CHIO_COMPILATION_SOURCE_BINDING='c'*64, PYTHONDONTWRITEBYTECODE='1')
        return base, candidate, campaign, env

    def actual(self, name, source_builder, output_name, optimize=False):
        base, candidate, campaign, env = self.fixture(name)
        target = candidate / 'target'
        source = source_builder(candidate, target)
        rustc = subprocess.check_output(['rustup', 'which', '--toolchain', '1.94.1', 'rustc'], text=True).strip()
        command = [sys.executable] + (['-O'] if optimize else []) + [str(TOOL), rustc, str(source),
                   '--crate-name', 'unit', '--crate-type', 'rlib', '--emit', 'dep-info,link', '-o', str(target/output_name)]
        result = subprocess.run(command, cwd=candidate, env=env, capture_output=True, timeout=120)
        rows = [json.loads(path.read_text()) for path in (campaign/'records').glob('*.json')]
        (base/'stdout.log').write_bytes(result.stdout); (base/'stderr.log').write_bytes(result.stderr)
        (base/'result.json').write_text(json.dumps({'boundary':'actual rustc 1.94.1 subprocess', 'command':command,
            'exit':result.returncode, 'rows':rows, 'script_sha256':hashlib.sha256(TOOL.read_bytes()).hexdigest()}, indent=2)+'\n')
        return result, rows, campaign, target

    def test_actual_rustc_parent_traversal_refuses_before_excluded_source(self):
        def sources(candidate, target):
            (target/'input.rs').write_text('pub fn public_marker() -> u64 { 111 }\n')
            (candidate/'.env/nested').mkdir(parents=True)
            (candidate/'.env/input.rs').write_text('#[no_mangle]\npub static SYNTHETIC_EXCLUDED_MARKER: [u8; 21] = *b"SYNTHETIC-EXCLUDED-42";\n')
            (target/'hop').symlink_to(candidate/'.env/nested', target_is_directory=True)
            return str(target/'hop')+'/../input.rs'
        for optimize in [False, True]:
            with self.subTest(optimize=optimize):
                result, rows, campaign, target = self.actual('parent-traversal', sources, 'libunit.rlib', optimize)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse((target/'libunit.rlib').exists())
                self.assertFalse(any(row['status']=='success' and row['kind']=='compilation' for row in rows))
                self.assertFalse(any(b'SYNTHETIC-EXCLUDED-42' in path.read_bytes() for path in (campaign/'artifacts').glob('*')))

    def test_actual_rustc_stale_nominal_output_cannot_be_a_produced_image(self):
        def sources(candidate, target):
            (target/'input.rs').write_text('pub fn public_marker() -> u64 { 111 }\n')
            (target/'unit.rlib').write_bytes(b'SYNTHETIC-PREEXISTING-IMAGE')
            return target/'input.rs'
        for optimize in [False, True]:
            with self.subTest(optimize=optimize):
                result, rows, campaign, target = self.actual('stale-output', sources, 'unit.rlib', optimize)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual((target/'unit.rlib').read_bytes(), b'SYNTHETIC-PREEXISTING-IMAGE')
                self.assertFalse(any(row['status']=='success' and row['kind']=='compilation' for row in rows))

    def primitive(self, kind, optimize):
        base, candidate, campaign, env = self.fixture(kind)
        control = base/'primitive'
        control.mkdir()
        command = [sys.executable] + (['-O'] if optimize else []) + ['-c', PUBLICATION_CONTROL, str(TOOL), str(control), kind]
        result = subprocess.run(command, env=env, capture_output=True, timeout=30)
        (base/'primitive.stdout').write_bytes(result.stdout); (base/'primitive.stderr').write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        row = json.loads(result.stdout)
        (base/'primitive-result.json').write_text(json.dumps(row, indent=2)+'\n')
        return row

    def test_artifact_and_record_publication_bind_the_verified_inode(self):
        for kind in ['artifact-swap', 'record-swap', 'completion-swap', 'completion-copy']:
            for optimize in [False, True]:
                with self.subTest(kind=kind, optimize=optimize):
                    row = self.primitive(kind, optimize)
                    self.assertFalse(row['returned'], row)
                    self.assertTrue(row['raised'], row)
                    self.assertFalse(row['completion_exists'], row)

    def test_state_failure_cannot_leave_usable_success(self):
        for optimize in [False, True]:
            with self.subTest(optimize=optimize):
                row = self.primitive('record-state-failure', optimize)
                usable = row['stored']=='success' and (row['schema']=='chio.rust-compilation.v1' or row['completion_exists'])
                self.assertFalse(row['raised'] and usable, row)



COMPLETION_ERROR_CONTROL = r"""
import hashlib,importlib.util,json,os,pathlib,stat,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('recorder',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=pathlib.Path(sys.argv[2]);fail_quarantine=sys.argv[3]=='fail';target=sys.argv[4] if len(sys.argv)>4 else 'marker'
campaign=m.Campaign(base,'d'*64)
row=m.row_for([],{},'d'*64);row.update(status='success',compiler_exit=0)
name=row['invocation_id']+'.json';real_unlink=os.unlink;real_rename=os.rename
exchanged=False;raised=None;returned=False

def exchange_after_unlink(path,**kwargs):
    global exchanged
    result=real_unlink(path,**kwargs)
    if kwargs.get('dir_fd')==campaign.completions.fd and str(path).startswith('.pending-') and not exchanged:
        final=base/('records' if target=='record' else 'completions')/name
        payload=final.read_bytes()
        real_rename(final,base.parent/(base.name+'-displaced-'+target))
        final.write_bytes(payload)
        exchanged=True
    return result

def quarantine(source,dest,**kwargs):
    if fail_quarantine and str(dest).startswith('.incomplete-'):
        raise OSError('synthetic quarantine rename failure')
    return real_rename(source,dest,**kwargs)

os.unlink=exchange_after_unlink;os.rename=quarantine
try:
    campaign.publish(row);returned=True
except (m.Refusal,OSError,ValueError) as error:
    raised=str(error)
record=base/'records'/name;completion=base/'completions'/name
usable=False;byte_pair=False;marker_identity_matches=None;record_identity_matches=None
if record.exists() and completion.exists():
    rs=record.lstat();cs=completion.lstat()
    try:
        rb=record.read_bytes();r=json.loads(rb);c=json.loads(completion.read_bytes())
        byte_pair=(stat.S_ISREG(rs.st_mode) and rs.st_nlink==1 and stat.S_ISREG(cs.st_mode) and cs.st_nlink==1 and
                   c['invocation_id']==r['invocation_id'] and c['source_binding']==r['source_binding'] and
                   c['record_sha256']==hashlib.sha256(rb).hexdigest() and c['size']==len(rb))
        if r['schema']=='chio.rust-compilation.v2':
            usable=byte_pair and r['status']=='success' and r['publication']=={'completion':'completions/'+name} and c['schema']=='chio.rust-compilation-completion.v1'
        elif r['schema']=='chio.rust-compilation.v4':
            marker_identity_matches=r['publication']['marker_identity']=={'device':cs.st_dev,'inode':cs.st_ino}
            record_identity_matches=c['record_identity']=={'device':rs.st_dev,'inode':rs.st_ino}
            usable=byte_pair and r['status']=='success' and c['schema']=='chio.rust-compilation-completion.v3' and marker_identity_matches and record_identity_matches
    except (ValueError,KeyError,TypeError):
        pass
print(json.dumps({'boundary':'ordinary local file-I/O publication primitive','target':target,'quarantine_failure':fail_quarantine,
                  'replacement_triggered':exchanged,'returned':returned,'raised':raised,'record_exists':record.exists(),
                  'marker_exists':completion.exists(),'byte_pair_matches':byte_pair,'consumer_usable_success':usable,
                  'marker_identity_matches':marker_identity_matches,'record_identity_matches':record_identity_matches,
                  'recorder_schema':m.SCHEMA}))
campaign.close()
"""


class CompletionPublicationFailureTest(unittest.TestCase):
    """Same-byte final marker substitution cannot rely on successful cleanup."""
    def run_control(self, quarantine_failure, optimize, target="marker"):
        base=EVIDENCE/'repair-round-two'/('publication-'+os.urandom(6).hex())
        namespace=base/'namespace'
        namespace.mkdir(parents=True)
        env={key:value for key,value in os.environ.items() if not key.startswith(('LD_','DYLD_'))
             and not any(term in key.lower() for term in ['token','password','secret','credential','api_key'])}
        env['PYTHONDONTWRITEBYTECODE']='1'
        command=[sys.executable]+(['-O'] if optimize else [])+['-c',COMPLETION_ERROR_CONTROL,str(TOOL),str(namespace),
                                                           'fail' if quarantine_failure else 'ok',target]
        result=subprocess.run(command,cwd=ROOT,env=env,capture_output=True,timeout=30)
        (base/'stdout.log').write_bytes(result.stdout);(base/'stderr.log').write_bytes(result.stderr)
        self.assertEqual(result.returncode,0,result.stderr)
        observed=json.loads(result.stdout)
        (base/'result.json').write_text(json.dumps({'command':command,'observation':observed,
            'script_sha256':hashlib.sha256(TOOL.read_bytes()).hexdigest()},indent=2)+'\n')
        return observed

    def test_post_unlink_replacement_with_failed_quarantine_is_unusable(self):
        for optimize in [False,True]:
            with self.subTest(optimize=optimize):
                observed=self.run_control(True,optimize)
                self.assertTrue(observed['replacement_triggered'],observed)
                self.assertTrue(observed['raised'],observed)
                self.assertFalse(observed['returned'],observed)
                self.assertTrue(observed['marker_exists'] and observed['byte_pair_matches'],observed)
                self.assertFalse(observed['consumer_usable_success'],observed)

    def test_post_completion_record_copy_cannot_match_held_identity(self):
        for optimize in [False,True]:
            with self.subTest(optimize=optimize):
                observed=self.run_control(True,optimize,target="record")
                self.assertTrue(observed['replacement_triggered'],observed)
                self.assertTrue(observed['raised'],observed)
                self.assertFalse(observed['returned'],observed)
                self.assertTrue(observed['marker_exists'] and observed['byte_pair_matches'],observed)
                self.assertFalse(observed['record_identity_matches'],observed)
                self.assertFalse(observed['consumer_usable_success'],observed)

    def test_post_unlink_replacement_with_successful_quarantine_is_unusable(self):
        for optimize in [False,True]:
            with self.subTest(optimize=optimize):
                observed=self.run_control(False,optimize)
                self.assertTrue(observed['replacement_triggered'],observed)
                self.assertTrue(observed['raised'],observed)
                self.assertFalse(observed['consumer_usable_success'],observed)

    def test_directory_content_mutation_allows_open_but_regular_mutation_refuses(self):
        control = r'''
import importlib.util,json,os,pathlib,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('recorder',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=pathlib.Path(sys.argv[2]);base.mkdir(parents=True)
directory=base/'subject';directory.mkdir();regular=base/'regular';regular.write_bytes(b'before')
real_open=os.open;observations={}
for target in [directory,regular]:
    triggered=False
    def changing_open(path,flags,*args,**kwargs):
        global triggered
        if str(path)==target.name and not triggered:
            triggered=True
            if target==directory:
                (directory/'new-member').write_bytes(b'public directory member')
            else:
                regular.write_bytes(b'different regular content and size')
        return real_open(path,flags,*args,**kwargs)
    os.open=changing_open
    try:
        with m.HeldPath(target,directory=target==directory):
            accepted=True;refusal=None
    except m.Refusal as error:
        accepted=False;refusal=str(error)
    finally:
        os.open=real_open
    observations[target.name]={'triggered':triggered,'accepted':accepted,'refusal':refusal}
print(json.dumps(observations))
'''
        for optimize in [False, True]:
            with self.subTest(optimize=optimize):
                base = EVIDENCE/'repair-round-two'/('directory-open-'+os.urandom(6).hex())
                command = [sys.executable]+(['-O'] if optimize else [])+['-c',control,str(TOOL),str(base)]
                result = subprocess.run(command,cwd=ROOT,capture_output=True,timeout=30)
                base.mkdir(exist_ok=True)
                (base/'stdout.log').write_bytes(result.stdout)
                (base/'stderr.log').write_bytes(result.stderr)
                (base/'command.json').write_text(json.dumps({'argv':command,'script_sha256':hashlib.sha256(TOOL.read_bytes()).hexdigest()},indent=2)+'\n')
                self.assertEqual(result.returncode,0,result.stderr)
                observed=json.loads(result.stdout)
                self.assertTrue(observed['subject']['triggered'],observed)
                self.assertTrue(observed['subject']['accepted'],observed)
                self.assertTrue(observed['regular']['triggered'],observed)
                self.assertFalse(observed['regular']['accepted'],observed)
                self.assertEqual(observed['regular']['refusal'],'file_race',observed)



DECLARED_DRIVER_TEST_SETUP = r'''
targets=[]
for triple in ['x86_64-unknown-linux-gnu','x86_64-unknown-linux-musl']:
 library=base/'toolchain/lib/rustlib'/triple/'lib';library.mkdir(parents=True)
 crt=library/'public-crt.o';crt.write_bytes(b'PUBLIC-CRT-'+triple.encode())
 targets.append({'triple':triple,'sysroot':str(base/'toolchain'),'library_root':str(library),'crt_members':[str(crt)]})
config['supported_targets']=targets
musl_driver=base/'native-runtime/musl-driver';musl_driver.write_bytes(b'PUBLIC-MUSL-DRIVER');musl_driver.chmod(0o755)
drivers=[images['linker'],{'path':str(musl_driver),'sha256':hashlib.sha256(musl_driver.read_bytes()).hexdigest()}]
config['linker_selection']={'schema':'chio.compiler-linker-selection.v1','mode':'declared-driver-if-missing',
 'profile':'explicit-instrumented-compiler','targets':[{**target,'driver':driver} for target,driver in zip(targets,drivers)]}
args=[images['rustc']['path'],str(candidate/'main.rs'),'--crate-name','unit','--crate-type','bin','--emit','dep-info,link',
      '--out-dir',str(candidate/'target/work')]
'''



class LinuxScopeContractTest(unittest.TestCase):
    """Local declaration/parser controls, never primary Linux enforcement proof."""
    def child(self, operation):
        base = EVIDENCE/'native-successor'/('structural-'+os.urandom(6).hex())
        base.mkdir(parents=True)
        code = r'''
import copy,hashlib,importlib.util,json,os,pathlib,struct,subprocess,sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('recorder',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base=pathlib.Path(sys.argv[2]);candidate=base/'candidate';candidate.mkdir();(candidate/'target').mkdir()
scopes=[]
for role in ['candidate','vendor','toolchain','native-runtime']:
 root=candidate if role=='candidate' else base/role
 root.mkdir(exist_ok=True);(root/'public').write_bytes(b'public scope member')
 scopes.append({'role':role,'root':str(root),'selection':'complete-tree','members':[]})
images={}
for kind in ['cargo','rustc','linker','python','recorder']:
 path=base/'native-runtime'/kind;path.write_bytes(b'public '+kind.encode());path.chmod(0o755)
 images[kind]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
references={}
for name in ['inventory.json','origin.json']:
 payload=b'{"fixture":"public structural declaration"}\n';(base/name).write_bytes(payload)
 references[name]={'path':name,'sha256':hashlib.sha256(payload).hexdigest()}
config={'schema':'chio.linux-compilation-launch.v1','candidate':str(candidate),'source_binding':'a'*64,
 'profile':{'name':'dev','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0'},
 'package_root':str(base),'runtime_inventory':references['inventory.json'],
 'source_origin':references['origin.json'],'scopes':scopes,'images':images,'aliases':[],
 'write_roots':[str(candidate/'target/work')],'environment_metadata':[],
 'environment':{'PATH':str(base/'native-runtime'),'HOME':str(candidate/'target/work/home'),
 'CARGO_HOME':str(candidate/'target/work/cargo-home'),'TMPDIR':str(candidate/'target/work/tmp'),
 'CARGO_INCREMENTAL':'0','CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','CARGO_TERM_COLOR':'never',
 'CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0'},
 'records':str(candidate/'target/records'),'evidence':str(candidate/'target/scope-evidence')}
(candidate/'target/work').mkdir()
observed={}
OPERATION
print(json.dumps(observed))
'''.replace('OPERATION', operation)
        command = [sys.executable,'-B',*(['-O']*sys.flags.optimize),'-c',code,str(TOOL),str(base)]
        result = subprocess.run(command,cwd=ROOT,capture_output=True,timeout=30)
        (base/'stdout.log').write_bytes(result.stdout);(base/'stderr.log').write_bytes(result.stderr)
        (base/'command.json').write_text(json.dumps({'argv':command,'source_sha256':hashlib.sha256(TOOL.read_bytes()).hexdigest(),'parent_optimization':sys.flags.optimize},indent=2)+'\n')
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)

    def test_native_parser_needs_explicit_declared_contract(self):
        observed=self.child(r'''
args=[str(candidate/'main.rs'),'--crate-name','unit','--crate-type','bin','--emit','dep-info,link','--out-dir',str(candidate/'target'),
      '-C','linker='+images['linker']['path'],'--extern','macro='+str(candidate/'target/libmacro.so')]
native=m.validate_linux_configuration(config,{})
parsed=m.parse(args,candidate,native)
observed={'types':parsed['crate_types'],'externs':parsed['externs'],'linker':parsed['linker']}
''')
        self.assertEqual(observed['types'],['bin'])
        self.assertEqual(observed['externs'][0]['kind'],'dynamic-image')
        self.assertTrue(observed['linker'].endswith('/native-runtime/linker'))

    def test_explicit_file_scope_records_only_approved_leaf_parent_directories(self):
        observed=self.child(r'''
runtime=base/'native-runtime'
(runtime/'lib/python3.12/encodings').mkdir(parents=True)
for name in ['lib/python3.12/codecs.py','lib/python3.12/encodings/__init__.py']:
 (runtime/name).write_bytes(b'public import input')
(runtime/'credentials.toml').write_bytes(b'SYNTHETIC-UNLISTED-CONTENT')
selected=['cargo','rustc','linker','python','recorder','lib/python3.12/codecs.py','lib/python3.12/encodings/__init__.py']
config['scopes'][-1].update(selection='explicit-members',members=selected)
m.validate_linux_configuration(config,{})
campaign_root=candidate/'target/records';campaign_root.mkdir()
campaign=m.Campaign(campaign_root,config['source_binding']);campaign.root=campaign_root
try:
 declaration,originals=m.collect_linux_scope(config,campaign)
 reference=declaration['scopes'][-1]['inventory']
 inventory=json.loads((campaign_root/reference['artifact']).read_bytes())
 observed={'schema':inventory['schema'],'directories':inventory['directories'],
  'directory_metadata':inventory.get('directory_metadata'),
  'members':[row['path'] for row in inventory['members']],
  'original_directory_count':sum(path in originals for path in [str(runtime),str(runtime/'lib/python3.12'),str(runtime/'lib/python3.12/encodings')])}
finally:campaign.close()
''')
        self.assertEqual(observed['schema'],'chio.compilation-read-scope.v2')
        self.assertEqual(observed['directories'],['.','lib/python3.12','lib/python3.12/encodings'])
        self.assertEqual([row['path'] for row in observed['directory_metadata']],observed['directories'])
        self.assertEqual(observed['original_directory_count'],3)
        self.assertNotIn('credentials.toml',observed['members'])
        for row in observed['directory_metadata']:
            self.assertEqual(set(row),{'path','identity'})
            self.assertEqual(len(row['identity']),3)
            self.assertTrue(all(type(value) is int for value in row['identity']))

    def test_explicit_scope_emits_read_dir_only_rules_and_refuses_replaced_directory(self):
        observed=self.child(r'''
runtime=base/'native-runtime'
(runtime/'lib/python3.12/encodings').mkdir(parents=True)
for name in ['lib/python3.12/codecs.py','lib/python3.12/encodings/__init__.py']:
 (runtime/name).write_bytes(b'public import input')
unlisted=runtime/'credentials.toml';unlisted.write_bytes(b'SYNTHETIC-UNLISTED-CONTENT')
selected=['cargo','rustc','linker','python','recorder','lib/python3.12/codecs.py','lib/python3.12/encodings/__init__.py']
config['scopes'][-1].update(selection='explicit-members',members=selected)
campaign_root=candidate/'target/records';campaign_root.mkdir()
campaign=m.Campaign(campaign_root,config['source_binding']);campaign.root=campaign_root
try:
 declaration,originals=m.collect_linux_scope(config,campaign)
 campaign.aliases=m.linux_alias_bindings(config)
 inventory=json.loads((campaign_root/declaration['scopes'][-1]['inventory']['artifact']).read_bytes())
 class Library:
  def __init__(self):self.rules=[]
  def syscall(self,number,*args):
   if number==444:return os.open(os.devnull,os.O_RDONLY)
   if number==445:
    entry=m.ctypes.cast(args[2],m.ctypes.POINTER(m.LinuxPathRule)).contents
    info=os.fstat(entry.parent_fd)
    self.rules.append({'identity':[info.st_dev,info.st_ino,info.st_mode],'allowed':entry.allowed_access})
   return 0
  def prctl(self,*args):return 0
 library=Library();m.linux_abi=lambda:(library,5)
 m.enforce_linux_scope(config,declaration,originals,campaign,'x86_64')
 expected={tuple(row['identity']) for row in inventory['directory_metadata']}
 runtime_rules=[row for row in library.rules if tuple(row['identity']) in expected]
 unlisted_info=unlisted.stat();unlisted_identity=[unlisted_info.st_dev,unlisted_info.st_ino,unlisted_info.st_mode]
 replacement=runtime/'lib/python3.12/encodings'
 replacement.rename(runtime/'lib/python3.12/displaced-encodings');replacement.mkdir()
 try:m.enforce_linux_scope(config,declaration,originals,campaign,'x86_64');refusal=None
 except m.Refusal as error:refusal=str(error)
 observed={'runtime_rules':runtime_rules,'directory_count':len(expected),
  'unlisted_file_rule':any(row['identity']==unlisted_identity for row in library.rules),
  'replacement_refusal':refusal,'native_kernel_executed':False}
finally:campaign.close()
''')
        self.assertEqual(len(observed['runtime_rules']),observed['directory_count'])
        self.assertTrue(all(row['allowed']==1<<3 for row in observed['runtime_rules']))
        self.assertFalse(observed['unlisted_file_rule'])
        self.assertEqual(observed['replacement_refusal'],'linux_scope_changed')
        self.assertFalse(observed['native_kernel_executed'])

    def test_scope_inventory_binds_terminal_root_identity_and_refuses_root_replacement(self):
        observed=self.child(r'''
campaign_root=candidate/'target/records';campaign_root.mkdir()
campaign=m.Campaign(campaign_root,config['source_binding']);campaign.root=campaign_root
try:
 declaration,originals=m.collect_linux_scope(config,campaign)
 campaign.aliases=m.linux_alias_bindings(config)
 vendor_reference=next(ref for ref in declaration['scopes'] if ref['role']=='vendor')
 vendor=json.loads((campaign_root/vendor_reference['inventory']['artifact']).read_bytes())
 info=os.stat(vendor['root'])
 observed={'root_identity':vendor['root_identity'],'root_bound':vendor['root'] in originals,
  'identity_matches_stat':vendor['root_identity']==[info.st_dev,info.st_ino,info.st_mode]}
 class Library:
  def __init__(self):self.rules=[]
  def syscall(self,number,*args):
   if number==444:return os.open(os.devnull,os.O_RDONLY)
   return 0
  def prctl(self,*args):return 0
 library=Library();m.linux_abi=lambda:(library,5)
 m.enforce_linux_scope(config,declaration,originals,campaign,'x86_64')
 observed['accepted_before_replacement']=True
 (base/'vendor').rename(base/'displaced-vendor');(base/'vendor').mkdir()
 try:m.enforce_linux_scope(config,declaration,originals,campaign,'x86_64');observed['root_refusal']=None
 except m.Refusal as error:observed['root_refusal']=str(error)
finally:campaign.close()
''')
        identity=observed['root_identity']
        self.assertEqual(len(identity),3)
        self.assertTrue(all(type(value) is int for value in identity))
        self.assertTrue(identity[2] & 0o170000 == 0o040000, identity)
        self.assertTrue(observed['identity_matches_stat'],observed)
        self.assertTrue(observed['root_bound'],observed)
        self.assertTrue(observed['accepted_before_replacement'],observed)
        self.assertEqual(observed['root_refusal'],'linux_scope_changed')

    def test_scope_collection_refuses_a_late_added_walked_directory_member(self):
        observed=self.child(r'''
vendor=base/'vendor'
(vendor/'public').unlink()
(vendor/'a-walked-child').mkdir()
(vendor/'b-public-sibling').write_bytes(b'public sibling source')
original_capture=m.capture
def wrapped_capture(path, role, campaign):
    if str(path).endswith('b-public-sibling'):
        (vendor/'a-walked-child'/'late-added-source').write_bytes(b'late public addition')
    return original_capture(path, role, campaign)
m.capture=wrapped_capture
campaign_root=candidate/'target/records';campaign_root.mkdir()
campaign=m.Campaign(campaign_root,config['source_binding']);campaign.root=campaign_root
try:
 try:m.collect_linux_scope(config,campaign);observed['late_refusal']=None
 except m.Refusal as error:observed['late_refusal']=str(error)
finally:
 campaign.close()
 m.capture=original_capture
''')
        self.assertEqual(observed['late_refusal'],'linux_scope_directory_changed')

    def test_scope_inventory_binds_an_empty_terminal_root_and_refuses_replacement(self):
        observed=self.child(r'''
(base/'empty-toolchain').mkdir()
config['scopes'].append({'role':'toolchain','root':str(base/'empty-toolchain'),'selection':'complete-tree','members':[]})
campaign_root=candidate/'target/records';campaign_root.mkdir()
campaign=m.Campaign(campaign_root,config['source_binding']);campaign.root=campaign_root
try:
 declaration,originals=m.collect_linux_scope(config,campaign)
 campaign.aliases=m.linux_alias_bindings(config)
 reference=next(ref for ref in declaration['scopes'] if ref['root']==str(base/'empty-toolchain'))
 empty=json.loads((campaign_root/reference['inventory']['artifact']).read_bytes())
 info=(base/'empty-toolchain').stat()
 observed={'members':empty['members'],'directories':empty['directories'],
  'root_identity':empty['root_identity'],
  'identity_matches_stat':empty['root_identity']==[info.st_dev,info.st_ino,info.st_mode]}
 class Library:
  def __init__(self):self.rules=[]
  def syscall(self,number,*args):
   if number==444:return os.open(os.devnull,os.O_RDONLY)
   return 0
  def prctl(self,*args):return 0
 library=Library();m.linux_abi=lambda:(library,5)
 m.enforce_linux_scope(config,declaration,originals,campaign,'x86_64')
 observed['accepted_before_replacement']=True
 (base/'empty-toolchain').rename(base/'displaced-empty');(base/'empty-toolchain').mkdir()
 try:m.enforce_linux_scope(config,declaration,originals,campaign,'x86_64');observed['replacement_refusal']=None
 except m.Refusal as error:observed['replacement_refusal']=str(error)
finally:campaign.close()
''')
        self.assertEqual(observed['members'],[])
        self.assertEqual(observed['directories'],['.'])
        self.assertTrue(observed['identity_matches_stat'],observed)
        identity=observed['root_identity']
        self.assertEqual(len(identity),3)
        self.assertTrue(identity[2] & 0o170000 == 0o040000, identity)
        self.assertTrue(observed['accepted_before_replacement'],observed)
        self.assertEqual(observed['replacement_refusal'],'linux_scope_changed')

    def test_scope_rule_traversal_stays_within_a_bounded_descriptor_budget(self):
        observed=self.child(r'''
import resource
bounded=base/'bounded-toolchain'
bounded.mkdir()
for index in range(40):
 (bounded/('member-%02d.rs'%index)).write_bytes(b'public member %d'%index)
config['scopes'].append({'role':'toolchain','root':str(bounded),'selection':'complete-tree','members':[]})
soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
campaign_root=candidate/'target/records';campaign_root.mkdir()
campaign=m.Campaign(campaign_root,config['source_binding']);campaign.root=campaign_root
try:
 declaration,originals=m.collect_linux_scope(config,campaign)
 campaign.aliases=m.linux_alias_bindings(config)
 class Library:
  def __init__(self):self.rules=[]
  def syscall(self,number,*args):
   if number==444:return os.open(os.devnull,os.O_RDONLY)
   return 0
  def prctl(self,*args):return 0
 library=Library();m.linux_abi=lambda:(library,5)
 # Campaign custody already owns parent chains, whose size depends on
 # checkout depth. Leave a fixed budget above those existing descriptors.
 # Forty leaked leaf descriptors would exceed this additional budget.
 baseline=max(int(name) for name in os.listdir('/dev/fd'))
 limit=baseline+32
 if limit>hard:raise AssertionError('insufficient descriptor headroom for the control')
 resource.setrlimit(resource.RLIMIT_NOFILE,(limit,hard))
 m.enforce_linux_scope(config,declaration,originals,campaign,'x86_64')
 observed['traversed']=True
finally:
 campaign.close()
 resource.setrlimit(resource.RLIMIT_NOFILE,(soft,hard))
''')
        self.assertTrue(observed['traversed'])

    def test_inherited_selectors_and_proxy_inputs_refuse(self):
        observed=self.child(r'''
for name in ['RUSTC','RUSTC_WRAPPER','CARGO_BUILD_RUSTC','RUSTC_BOOTSTRAP','CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER',
             'RUSTDOCFLAGS','LD_LIBRARY_PATH','HTTPS_PROXY','PYTHONPATH','PROVIDER_API_KEY']:
 try:m.validate_linux_configuration(config,{name:'SYNTHETIC-OPAQUE'});observed[name]='accepted'
 except m.Refusal as error:observed[name]=str(error)
''')
        self.assertTrue(all(value=='inherited_linux_input' for value in observed.values()),observed)

    def test_unknown_config_environment_and_escaping_scope_refuse(self):
        observed=self.child(r'''
for key,value in [('environment',{'ARBITRARY_INPUT':'opaque'}),('write_roots',[str(base/'toolchain')]),
                  ('aliases',[{'path':str(base/'alias'),'text':'../outside','target':str(base/'outside')}])]:
 changed=copy.deepcopy(config);changed[key]=value
 try:m.validate_linux_configuration(changed,{});observed[key]='accepted'
 except m.Refusal as error:observed[key]=str(error)
''')
        self.assertNotIn('accepted',observed.values(),observed)

    def test_exact_linux_native_output_names(self):
        observed=self.child(r'''
native=m.validate_linux_configuration(config,{})
for kind in ['bin','proc-macro','cdylib','dylib','rlib']:
 args=[str(candidate/'main.rs'),'--crate-name','unit','--crate-type',kind,'--emit','dep-info,link','--out-dir',str(candidate/'target')]
 parsed=m.parse(args,candidate,native);dep,outputs=m.output_paths(parsed);observed[kind]=pathlib.Path(outputs['link']).name
''')
        self.assertEqual(observed,{'bin':'unit','proc-macro':'libunit.so','cdylib':'libunit.so','dylib':'libunit.so','rlib':'libunit.rlib'})

    def test_native_linker_image_requires_actual_explicit_selection(self):
        observed=self.child(r'''
native=m.validate_linux_configuration(config,{})
args=[str(candidate/'main.rs'),'--crate-name','unit','--crate-type','bin','--emit','dep-info,link',
      '--out-dir',str(candidate/'target/work')]
for label,arguments in [('implicit',args),('explicit',args+['-C','linker='+images['linker']['path']])]:
 parsed=m.parse(arguments,candidate,native)
 try:m.require_native_linker_selection(parsed,native);observed[label]='accepted'
 except m.Refusal as error:observed[label]=str(error)
''')
        self.assertEqual(observed,{'implicit':'native_linker_selection_not_bound','explicit':'accepted'})

    def test_network_filter_rejects_alternate_abis_and_async_socket_paths(self):
        observed=self.child(r'''
for machine in ['x86_64','aarch64']:
 architecture,blocked,program=m.linux_network_filter(machine)
 observed[machine]={'architecture':architecture,'blocked':blocked,'first':program[:3],'last':program[-1]}
''')
        for machine, expected in [('x86_64',[41,53,425,426,427]),('aarch64',[198,199,425,426,427])]:
            self.assertTrue(set(expected)<=set(observed[machine]['blocked']),observed)
            self.assertEqual(observed[machine]['first'][0],[32,0,0,4])
            self.assertEqual(observed[machine]['first'][2],[6,0,0,2147483648])
            self.assertEqual(observed[machine]['last'],[6,0,0,2147418112])

    def test_declared_inventory_retains_public_bytes_and_excludes_secret_metadata(self):
        observed=self.child(r'''
(candidate/'.env').write_bytes(b'SYNTHETIC-EXCLUDED-SENTINEL')
(base/'toolchain/credentials.toml').write_bytes(b'SYNTHETIC-CARGO-CREDENTIAL-SENTINEL')
records=pathlib.Path(config['records']);records.mkdir()
campaign=m.Campaign(records,config['source_binding'])
declaration,originals=m.collect_linux_scope(config,campaign)
inventories=[json.loads((records/ref['inventory']['artifact']).read_bytes()) for ref in declaration['scopes']]
members=[member for inventory in inventories for member in inventory['members']]
observed={'scope_id':declaration['scope_id'],'candidate':declaration['candidate'],
          'excluded':next(member for member in members if member['path']=='.env'),
          'public':next(member for member in members if member['path']=='public'),
          'cargo_auth':next(member for member in members if member['path']=='credentials.toml'),
          'secret_retained':any(path.read_bytes()==b'SYNTHETIC-EXCLUDED-SENTINEL' for path in (records/'artifacts').iterdir()),
          'independent_id':m.digest({'configuration':config,'inventories':inventories})}
campaign.close()
''')
        self.assertEqual(observed['scope_id'],observed['independent_id'])
        self.assertEqual(observed['excluded'],{'path':'.env','kind':'excluded','reason':'secret-shaped-original'})
        self.assertFalse(observed['secret_retained'])
        self.assertEqual(observed['cargo_auth'],{'path':'credentials.toml','kind':'excluded','reason':'secret-shaped-original'})
        self.assertEqual(observed['public']['size'],19)

    def test_raw_linker_and_backend_inputs_still_refuse_with_scope(self):
        observed=self.child(r'''
native=m.validate_linux_configuration(config,{})
baseargs=[str(candidate/'main.rs'),'--crate-name','unit','--crate-type','bin','--emit','dep-info,link','--out-dir',str(candidate/'target')]
for suffix in [['-C','link-arg=@hidden'],['-C','linker=/unknown'],['-C','codegen-backend=/unknown'],['--target','custom.json']]:
 try:m.parse(baseargs+suffix,candidate,native);observed[str(suffix)]='accepted'
 except m.Refusal as error:observed[str(suffix)]=str(error)
''')
        self.assertNotIn('accepted',observed.values(),observed)

    def test_depfile_parent_include_walk_checks_actual_components(self):
        observed=self.child(r'''
native=m.validate_linux_configuration(config,{})
(candidate/'nested').mkdir();(candidate/'input.rs').write_bytes(b'public source');(candidate/'vector.json').write_bytes(b'public include')
raw=str(candidate/'nested')+'/../vector.json'
payload=(str(candidate/'target/libunit.rlib')+': '+str(candidate/'input.rs')+' '+raw+'\n'+raw+':\n').encode()
parsed=m.parse_depfile(payload,candidate,{},native)
observed['include']=parsed['dependencies'];observed['resolution']=parsed['path_resolution']
(candidate/'hop').symlink_to(candidate/'nested',target_is_directory=True)
try:m.parse_depfile(payload.replace(b'nested/../',b'hop/../'),candidate,{},native);observed['hop']='accepted'
except m.Refusal as error:observed['hop']=str(error)
try:m.parse([raw.removesuffix('.json')+'.rs','--emit','dep-info,link','--out-dir',str(candidate/'target')],candidate,native);observed['argv']='accepted'
except m.Refusal as error:observed['argv']=str(error)
''')
        self.assertEqual(len(observed['include']),2)
        self.assertTrue(observed['resolution'])
        self.assertNotEqual(observed['hop'],'accepted')
        self.assertEqual(observed['argv'],'parent_traversal')

    @unittest.skipIf(sys.platform.startswith('linux'), 'Requires a non-Linux host')
    def test_nonlinux_launch_refuses_before_dispatch_or_scope_publication(self):
        observed=self.child(r'''
path=base/'launch.json';path.write_text(json.dumps(config));os.chdir(candidate);os.environ.clear()
code=m.launch_scope([str(path),'--',images['cargo']['path']])
observed={'exit':code,'records_created':pathlib.Path(config['records']).exists(),'evidence_created':pathlib.Path(config['evidence']).exists()}
''')
        self.assertEqual(observed,{'exit':86,'records_created':False,'evidence_created':False})

    def test_owned_output_read_keeps_descriptor_identity(self):
        observed=self.child(r'''
path=base/'output'
with m.HeldPath(path,create=True) as held:
 os.write(held.fd,b'public output');observed['bytes']=m.written_bytes(held).decode()
 os.rename(path,base/'displaced-output');path.write_bytes(b'public output')
 try:m.written_bytes(held);observed['replacement']='accepted'
 except m.Refusal as error:observed['replacement']=str(error)
''')
        self.assertEqual(observed,{'bytes':'public output','replacement':'file_race'})

    def test_cargo_child_loader_paths_need_exact_prior_declaration(self):
        observed=self.child(r'''
config['loader_paths']=[str(candidate/'target/work/deps'),str(base/'toolchain')]
native=m.validate_linux_configuration(config,{})
env={'RUSTC':images['rustc']['path'],'RUSTC_WRAPPER':images['recorder']['path'],'LD_LIBRARY_PATH':os.pathsep.join(config['loader_paths'])}
m.validate_native_child_environment(env,native,{'images':images});observed['declared']='accepted'
for name,value in [('LD_LIBRARY_PATH',str(base/'outside')),('LD_PRELOAD',images['linker']['path']),('HTTPS_PROXY','opaque'),('RUSTC',images['cargo']['path'])]:
 changed={**env,name:value}
 try:m.validate_native_child_environment(changed,native,{'images':images});observed[name]='accepted'
 except m.Refusal as error:observed[name]=str(error)
''')
        self.assertEqual(observed.pop('declared'),'accepted')
        self.assertNotIn('accepted',observed.values(),observed)

    def test_original_musl_target_requires_separate_pinned_declaration(self):
        observed=self.child(r'''
sysroot=base/'toolchain';library=sysroot/'lib/rustlib/x86_64-unknown-linux-musl/lib';library.mkdir(parents=True)
(library/'rcrt1.o').write_bytes(b'public structural CRT');(library/'libstd.rlib').write_bytes(b'public structural target library')
config['supported_targets']=[{'triple':'x86_64-unknown-linux-musl','sysroot':str(sysroot),'library_root':str(library),'crt_members':[str(library/'rcrt1.o')]}]
native=m.validate_linux_configuration(config,{})
args=[str(candidate/'main.rs'),'--crate-name','unit','--crate-type','bin','--emit','dep-info,link','--out-dir',str(candidate/'target'),
 '--target','x86_64-unknown-linux-musl']
observed['target']=m.parse(args,candidate,native)['target']
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,config['source_binding'])
declaration,_=m.collect_linux_scope(config,campaign);observed['declared_target']=declaration['targets'][0];campaign.close()
''')
        self.assertEqual(observed['target'],'x86_64-unknown-linux-musl')
        self.assertEqual(observed['declared_target']['triple'],'x86_64-unknown-linux-musl')
        self.assertTrue(observed['declared_target']['crt_members'])

    def test_public_identifier_exception_is_typed_and_source_pinned(self):
        observed=self.child(r'''
manifest=candidate/'crates/trust/chio-credentials/Cargo.toml';source=manifest.parent/'src/lib.rs';source.parent.mkdir(parents=True)
manifest.write_bytes(b'[package]\nname="chio-credentials"\nversion="0.1.0"\n');source.write_bytes(b'pub fn public_item() {}\n')
entries=[{'path':str(path.relative_to(candidate)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in [manifest,source]]
config['public_arguments']=[{'kind':'crate-name','value':'chio_credentials','source':entries[0]},
 {'kind':'source','value':str(source),'source':entries[1]}]
native=m.validate_linux_configuration(config,{})
members={str(candidate/entry['path']):{'sha256':entry['sha256']} for entry in entries}
native=m.bind_public_arguments(native,{'sources':entries},members)
args=[str(source),'--crate-name','chio_credentials','--crate-type','rlib','--emit','dep-info,link','--out-dir',str(candidate/'target')]
observed['crate']=m.parse(args,candidate,native)['crate_name']
for value in ['api_token="SYNTHETIC-OPAQUE"',str(source)]:
 try:m.parse(args+['--cfg',value],candidate,native);observed[value]='accepted'
 except m.Refusal as error:observed[value]=str(error)
broken=copy.deepcopy(config);broken['public_arguments'][0]['source']['sha256']='0'*64
try:m.bind_public_arguments(broken,{'sources':entries},members);observed['wrong_pin']='accepted'
except m.Refusal as error:observed['wrong_pin']=str(error)
''')
        self.assertEqual(observed.pop('crate'),'chio_credentials')
        self.assertNotIn('accepted',observed.values(),observed)

    def test_public_identifier_cannot_compile_another_public_source(self):
        observed=self.child(r'''
manifest=candidate/'crates/trust/chio-credentials/Cargo.toml';source=manifest.parent/'src/lib.rs';source.parent.mkdir(parents=True)
manifest.write_bytes(b'[package]\nname="chio-credentials"\nversion="0.1.0"\n');source.write_bytes(b'pub fn public_item() {}\n')
entries=[{'path':str(path.relative_to(candidate)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in [manifest,source]]
config['public_arguments']=[{'kind':'crate-name','value':'chio_credentials','source':entries[0]},{'kind':'source','value':str(source),'source':entries[1]}]
native=m.bind_public_arguments(m.validate_linux_configuration(config,{}),{'sources':entries},{str(candidate/e['path']):e for e in entries})
other=candidate/'other.rs';other.write_bytes(b'pub fn other() {}')
args=[str(other),'--crate-name','chio_credentials','--crate-type','rlib','--emit','dep-info,link','--out-dir',str(candidate/'target')]
try:m.parse(args,candidate,native);observed['wrong_source']='accepted'
except m.Refusal as error:observed['wrong_source']=str(error)
''')
        self.assertNotEqual(observed['wrong_source'],'accepted')

    def test_public_extern_producer_needs_source_pin_and_physical_completion(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,config['source_binding'])
banner=b'rustc 1.95.0 (synthetic pinned banner)'
unit=candidate/'target/libchio_credentials.rmeta';unit.write_bytes(b'rust\x00\x00\x00\x0a'+struct.pack('<Q',16+1+len(banner))+bytes([len(banner)])+banner+b'synthetic public primitive metadata image')
image,_=m.capture(unit,'unit',campaign);source=candidate/'wrong.rs';source.write_bytes(b'public wrong source')
source_image,_=m.capture(source,'source',campaign)
row=m.row_for([],{},config['source_binding']);row.update(status='success',compiler_exit=0,semantics={'crate_name':'chio_credentials','source':str(source)},
 inputs=[source_image],outputs=[image]);campaign.publish(row)
try:m.producing_unit(campaign,image,'chio_credentials');observed['unbound']='accepted'
except m.Refusal as error:observed['unbound']=str(error)
campaign.close()
''')
        self.assertNotEqual(observed['unbound'],'accepted')

    def test_existing_writable_secret_bytes_refuse_before_scope_grant(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,config['source_binding'])
(candidate/'target/work/.env').write_bytes(b'SYNTHETIC-EXISTING-WRITE-SCOPE-BYTES')
try:m.generated_inventory(config,campaign,original_inputs=True);observed['existing']='accepted'
except m.Refusal as error:observed['existing']=str(error)
observed['retained']=any(path.read_bytes()==b'SYNTHETIC-EXISTING-WRITE-SCOPE-BYTES' for path in (records/'artifacts').iterdir())
campaign.close()
''')
        self.assertNotEqual(observed['existing'],'accepted')
        self.assertFalse(observed['retained'])

    def test_instrumentation_namespace_has_no_descendant_writable_ancestor(self):
        observed=self.child(r'''
valid=m.validate_linux_configuration(config,{})
observed['valid']=valid['records']
unsafe=copy.deepcopy(config);unsafe['write_roots']=[str(candidate/'target')]
try:m.validate_linux_configuration(unsafe,{});observed['unsafe']='accepted'
except m.Refusal as error:observed['unsafe']=str(error)
''')
        self.assertNotEqual(observed['unsafe'],'accepted')

    def test_read_scope_cannot_start_inside_protected_namespace(self):
        observed=self.child(r'''
config['scopes'][1]['root']=config['records']
try:m.validate_linux_configuration(config,{});observed['scope']='accepted'
except m.Refusal as error:observed['scope']=str(error)
''')
        self.assertNotEqual(observed['scope'],'accepted')

    def test_alias_binding_detects_identical_text_inode_replacement(self):
        observed=self.child(r'''
link=base/'toolchain'/'alias';link.symlink_to('public')
config['aliases']=[{'path':str(link),'text':'public','target':str(base/'toolchain'/'public')}]
before=m.linux_alias_bindings(config)
replacement=base/'toolchain'/'replacement';replacement.symlink_to('public');os.replace(replacement,link)
try:m.verify_linux_aliases(config,before);observed['alias']='accepted'
except m.Refusal as error:observed['alias']=str(error)
''')
        self.assertNotEqual(observed['alias'],'accepted')

    def test_forged_ipc_cannot_supply_success_or_select_another_program(self):
        observed=self.child(r'''
declaration={'images':images,'scope_id':'e'*64}
request={'schema':'chio.rust-compilation-request.v1','id':'f'*32,'argv':[images['rustc']['path'],'-vV'],
 'environment':{},'cwd':str(candidate)}
for label,changed in [('caller-success',{**request,'status':'success','compiler_exit':0}),
                     ('program',{**request,'argv':[images['linker']['path'],'-vV']})]:
 try:m.validate_compilation_request(changed,config,declaration);observed[label]='accepted'
 except m.Refusal as error:observed[label]=str(error)
''')
        self.assertNotIn('accepted',observed.values(),observed)

    def test_filter_preserves_enclosing_process_group(self):
        observed=self.child(r'''
observed['blocked']=m.linux_network_filter('x86_64')[1]
''')
        self.assertTrue({109,112}<=set(observed['blocked']))

    def test_request_cannot_change_declared_profile_environment(self):
        observed=self.child(r'''
declaration={'images':images,'scope_id':'e'*64}
environment={**config['environment'],'RUSTC':images['rustc']['path'],'RUSTC_WRAPPER':images['recorder']['path']}
environment['CARGO_PROFILE_DEV_DEBUG']='2'
request={'schema':'chio.rust-compilation-request.v1','id':'f'*32,'argv':[images['rustc']['path'],'-vV'],
 'environment':environment,'cwd':str(candidate)}
try:m.validate_compilation_request(request,config,declaration);observed['profile']='accepted'
except m.Refusal as error:observed['profile']=str(error)
''')
        self.assertNotEqual(observed['profile'],'accepted')

    def test_protected_namespace_bytes_never_enter_read_inventory(self):
        observed=self.child(r'''
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir()
evidence=pathlib.Path(config['evidence']);evidence.mkdir()
(evidence/'protected.json').write_bytes(b'PROTECTED-PUBLIC-TEST-BYTES')
campaign=m.Campaign(records,'a'*64)
declaration,_=m.collect_linux_scope(config,campaign)
inventory=json.loads((records/declaration['scopes'][0]['inventory']['artifact']).read_bytes())
observed['protected']=[entry for entry in inventory['members'] if entry['kind']=='trusted-recorder-namespace']
observed['retained']=any(path.read_bytes()==b'PROTECTED-PUBLIC-TEST-BYTES' for path in (records/'artifacts').iterdir())
campaign.close()
''')
        self.assertEqual(len(observed['protected']),2)
        self.assertFalse(observed['retained'])

    def test_supervisor_refusal_never_retains_opaque_caller_identifier(self):
        observed=self.child(r'''
declaration={'images':images,'scope_id':'e'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},None,{})
try:
 response=json.loads(supervisor.respond(m.canonical({'id':'SYNTHETIC-CREDENTIAL-VALUE','status':'success'})))
 observed={'response':response,'events':supervisor.events}
finally:supervisor.close()
''')
        self.assertEqual(observed['response']['exit'],86)
        self.assertEqual(observed['events'][0]['id'],'')

    def test_parent_source_authority_refuses_before_unit_dispatch(self):
        observed=self.child(r'''
declaration={'images':images,'scope_id':'e'*64}
fixed={**config['environment'],'RUSTC':images['rustc']['path'],'RUSTC_WRAPPER':images['recorder']['path'],
 'CHIO_COMPILATION_SOURCE_BINDING':'a'*64,'CHIO_COMPILATION_SCOPE_ID':'e'*64}
environment={**fixed,'CHIO_COMPILATION_SOURCE_BINDING':'b'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},None,fixed)
called=[]
m.main=lambda *args:called.append(args) or 0
try:
 request={'schema':'chio.rust-compilation-request.v1','id':'f'*32,'argv':[images['rustc']['path'],'-vV'],
          'environment':environment,'cwd':str(candidate)}
 response=json.loads(supervisor.respond(m.canonical(request)))
 observed={'exit':response['exit'],'called':len(called),'dispatches':supervisor.events[0]['dispatches']}
finally:supervisor.close()
''')
        self.assertEqual(observed,{'exit':86,'called':0,'dispatches':[]})

    def test_pipe_frame_limit_refuses_before_dispatch(self):
        observed=self.child(r'''
declaration={'images':images,'scope_id':'e'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},None,{})
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(1)'])
try:
 m.pipe_write(supervisor.channels[0][0],m.struct.pack('>I',m.MAX_JSON+1))
 try:supervisor.wait(child);observed['frame']='accepted'
 except m.Refusal as error:observed['frame']=str(error)
 observed['events']=len(supervisor.events)
finally:
 child.terminate();child.wait();supervisor.close()
''')
        self.assertEqual(observed,{'frame':'compilation_ipc_limit','events':0})

    def test_supervisor_drains_anonymous_stdout_to_owned_log(self):
        observed=self.child(r'''
declaration={'images':images,'scope_id':'e'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},None,{})
with m.HeldPath(base/'stdout',create=True) as out,m.HeldPath(base/'stderr',create=True) as err:
 child=subprocess.Popen([sys.executable,'-c','import sys;print("PUBLIC-PIPE");print("PUBLIC-ERROR",file=sys.stderr)'],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
 try:
  observed['exit']=supervisor.wait(child,(out,err))
  observed['stdout']=m.written_bytes(out).decode();observed['stderr']=m.written_bytes(err).decode()
 finally:supervisor.close()
''')
        self.assertEqual(observed,{'exit':0,'stdout':'PUBLIC-PIPE\n','stderr':'PUBLIC-ERROR\n'})

    def native_compiler_output_observation(self, probe=False, exit_code=1):
        """Actual Python child I/O through execute; no Rust or Linux proof."""
        return self.child(r'''
from unittest.mock import patch
records=pathlib.Path(config['records']);records.mkdir(mode=0o700)
campaign=m.Campaign(records,'a'*64);declaration={'images':images,'scope_id':'e'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},campaign,{})
supervisor.scope_identity=(1,2,3,4)
argv=[sys.executable,'-c','import sys;print("PUBLIC-COMPILER-OUT");print("PUBLIC-COMPILER-ERROR",file=sys.stderr);sys.exit(EXIT)'.replace('EXIT','EXIT_CODE')]
try:
 with patch.object(m,'native_target_context',return_value=(config,None)),patch.object(m,'verify_linux_aliases'), \
      patch.object(m,'parse',return_value={}),patch.object(m,'output_paths',return_value=(candidate/'target/unit.d',{})), \
      patch.object(m,'enforce_linux_scope'),patch.object(m,'native_scope_owner_identity',return_value=(1,2,3,4),create=True):
  result=supervisor.execute(argv,{'PATH':'/usr/bin:/bin'},str(candidate),PROBE)
 output=supervisor.dispatches[-1].get('output')
 observed={'exit':result.returncode,'stdout':None,'stderr':None,'output':output,
           'raw_diagnostics_forwarded':False,'compiler_executed':False,'linux_enforcement_established':False}
 if output is not None:
  observed['stdout']=(records/output['stdout']['artifact']).read_bytes().decode()
  observed['stderr']=(records/output['stderr']['artifact']).read_bytes().decode()
finally:supervisor.close();campaign.close()
'''.replace('EXIT_CODE',str(exit_code)).replace('PROBE',repr(probe)))

    def test_native_compiler_unit_outputs_remain_in_owned_evidence(self):
        observed=self.native_compiler_output_observation()
        self.assertEqual((observed['exit'],observed['stdout'],observed['stderr']),
            (1,'PUBLIC-COMPILER-OUT\n','PUBLIC-COMPILER-ERROR\n'))
        self.assertEqual(observed['output']['status'],'complete')
        self.assertFalse(observed['raw_diagnostics_forwarded'])

    def test_native_compiler_probe_diagnostics_remain_in_owned_evidence(self):
        observed=self.native_compiler_output_observation(probe=True,exit_code=0)
        self.assertEqual((observed['exit'],observed['stdout'],observed['stderr']),
            (0,'PUBLIC-COMPILER-OUT\n','PUBLIC-COMPILER-ERROR\n'))
        self.assertEqual(observed['output']['status'],'complete')

    def test_native_compiler_output_drains_both_full_pipes_before_retention(self):
        observed=self.child(r'''
from unittest.mock import patch
payload=128*1024
code='import os,sys;os.write(2,b"E"*'+str(payload)+');os.write(1,b"O"*'+str(payload)+');sys.exit(1)'
def cleanup(process,deadline):
 process.kill();process.wait(timeout=max(0,deadline-m.time.monotonic()));return {'status':'REAPED'}
result=m.bounded_compiler_output([sys.executable,'-c',code],{'PATH':'/usr/bin:/bin'},str(candidate),None,cleanup)
observed={'exit':result.returncode,'stdout_size':len(result.stdout),'stderr_size':len(result.stderr),
 'stdout_exact':result.stdout==b'O'*payload,'stderr_exact':result.stderr==b'E'*payload,
 'observation':result.output_observation,'rust_compiler_dispatch':False}
''')
        self.assertEqual((observed['exit'],observed['stdout_size'],observed['stderr_size']),(1,128*1024,128*1024))
        self.assertTrue(observed['stdout_exact'] and observed['stderr_exact'])
        self.assertEqual(observed['observation']['status'],'complete')
        self.assertEqual(observed['observation']['eof'],{'stdout':True,'stderr':True})

    def test_native_compiler_output_limit_refuses_and_reaps_the_owned_child(self):
        observed=self.child(r'''
m.MAX_NATIVE_COMPILER_OUTPUT=1024
calls=[]
def cleanup(process,deadline):
 process.kill();process.wait(timeout=max(0,deadline-m.time.monotonic()));calls.append(process.returncode)
 return {'status':'REAPED','scope':'direct-child-byte-limit-control'}
result=m.bounded_compiler_output([sys.executable,'-c','import os,time;os.write(2,b"E"*2048);time.sleep(30)'],
 {'PATH':'/usr/bin:/bin'},str(candidate),None,cleanup)
observed={'exit':result.returncode,'stderr_size':len(result.stderr),'calls':calls,'observation':result.output_observation}
''')
        self.assertLess(observed['exit'],0)
        self.assertEqual(observed['stderr_size'],1024)
        self.assertEqual(len(observed['calls']),1)
        self.assertEqual(observed['observation']['status'],'refused')
        self.assertEqual(observed['observation']['refusal'],'compiler_output_limit')
        self.assertGreater(observed['observation']['observed_bytes']['stderr'],1024)

    def test_native_compiler_output_timeout_is_inside_the_whole_dispatch_budget(self):
        observed=self.child(r'''
m.NATIVE_COMPILER_DISPATCH_SECONDS=2
def cleanup(process,deadline):
 process.kill();process.wait(timeout=max(0,deadline-m.time.monotonic()))
 return {'status':'REAPED','scope':'direct-child-timeout-control'}
result=m.bounded_compiler_output([sys.executable,'-c','import time;time.sleep(30)'],
 {'PATH':'/usr/bin:/bin'},str(candidate),None,cleanup)
observed={'exit':result.returncode,'observation':result.output_observation}
''')
        self.assertLess(observed['exit'],0)
        self.assertEqual(observed['observation']['refusal'],'compiler_output_timeout')
        self.assertLess(observed['observation']['elapsed_seconds'],2)

    def test_native_compiler_output_publication_failure_cannot_be_a_complete_observation(self):
        observed=self.child(r'''
from unittest.mock import patch
records=pathlib.Path(config['records']);records.mkdir(mode=0o700)
campaign=m.Campaign(records,'a'*64);declaration={'images':images,'scope_id':'e'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},campaign,{})
supervisor.scope_identity=(1,2,3,4);calls=[]
def unavailable(payload):raise OSError(5,'controlled public output I/O failure')
def cleanup(*args):calls.append(True);return {'status':'REAPED','scope':'publication-control-only'}
try:
 with patch.object(m,'native_scope_owner_identity',return_value=(1,2,3,4)), \
      patch.object(m,'native_target_context',return_value=(config,None)),patch.object(m,'verify_linux_aliases'), \
      patch.object(m,'parse',return_value={}),patch.object(m,'output_paths',return_value=(candidate/'target/unit.d',{})), \
      patch.object(m,'enforce_linux_scope'),patch.object(m,'stop_owned_scope_children',side_effect=cleanup), \
      patch.object(campaign,'retain',side_effect=unavailable):
  try:supervisor.execute([sys.executable,'-c','print("PUBLIC-OUTPUT")'],{'PATH':'/usr/bin:/bin'},str(candidate),False)
  except m.CompilerOutputRefusal as error:
   observed={'refusal':str(error),'actual_exit':error.compiler_exit,'cleanup_calls':len(calls),
    'output':supervisor.dispatches[-1]['output'],'rust_compiler_dispatch':False}
finally:supervisor.close();campaign.close()
''')
        self.assertEqual(observed['refusal'],'compiler_output_publication')
        self.assertEqual(observed['actual_exit'],0)
        self.assertEqual(observed['cleanup_calls'],1)
        self.assertEqual(observed['output']['status'],'publication-failed')
        self.assertIsNone(observed['output']['stdout'])
        self.assertIsNone(observed['output']['stderr'])

    def test_native_compiler_output_requires_an_existing_owned_subreaper_before_dispatch(self):
        observed=self.child(r'''
from unittest.mock import patch
supervisor=m.CompilationSupervisor(config,{'images':images,'scope_id':'e'*64},{},None,{})
try:
 with patch.object(m.subprocess,'Popen',side_effect=AssertionError('unowned compiler was dispatched')):
  try:supervisor.execute([images['rustc']['path'],'-vV'],{},str(candidate),True)
  except m.Refusal as error:observed={'refusal':str(error),'dispatches':supervisor.dispatches}
finally:supervisor.close()
''')
        self.assertEqual(observed,{'refusal':'compiler_cleanup_scope_identity','dispatches':[]})

    def test_native_compiler_output_requires_owner_private_evidence_before_dispatch(self):
        observed=self.child(r'''
from unittest.mock import patch
records=pathlib.Path(config['records']);records.mkdir(mode=0o700)
campaign=m.Campaign(records,'a'*64);records.chmod(0o755)
supervisor=m.CompilationSupervisor(config,{'images':images,'scope_id':'e'*64},{},campaign,{})
supervisor.scope_identity=(1,2,3,4)
try:
 with patch.object(m,'native_scope_owner_identity',return_value=(1,2,3,4)), \
      patch.object(m.subprocess,'Popen',side_effect=AssertionError('nonprivate compiler was dispatched')):
  try:supervisor.execute([images['rustc']['path'],'-vV'],{},str(candidate),True)
  except m.Refusal as error:observed={'refusal':str(error),'dispatches':supervisor.dispatches}
finally:supervisor.close();campaign.close()
''')
        self.assertEqual(observed,{'refusal':'compiler_output_private_namespace','dispatches':[]})

    @unittest.skipUnless(sys.platform.startswith('linux'),'Requires actual Linux subreaper and pidfds')
    def test_native_compiler_timeout_reaps_orphan_pipe_holders_without_signalling_other_processes(self):
        unrelated=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            observed=self.child(r'''
import ctypes
library=ctypes.CDLL(None,use_errno=True)
if library.prctl(36,1,0,0,0)!=0:raise RuntimeError('actual subreaper unavailable')
scope=m.native_process_identity(os.getpid());m.NATIVE_COMPILER_DISPATCH_SECONDS=2
pid_file=base/'public-orphan-pid'
code='import pathlib,subprocess,sys;child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"]);pathlib.Path(sys.argv[1]).write_text(str(child.pid))'
def cleanup(process,deadline):return m.stop_owned_scope_children(scope,[process],deadline)
result=m.bounded_compiler_output([sys.executable,'-c',code,str(pid_file)],
 {'PATH':'/usr/bin:/bin'},str(candidate),None,cleanup)
orphan=int(pid_file.read_text());record=result.output_observation
observed={'parent_exit':result.returncode,'refusal':record['refusal'],'cleanup':record['cleanup'],
 'orphan_reaped':m.native_process_identity(orphan) is None,'orphan':orphan,
 'elapsed':record['elapsed_seconds'],'rust_compiler_dispatch':False}
''')
            self.assertEqual(observed['parent_exit'],0)
            self.assertEqual(observed['refusal'],'compiler_output_timeout')
            self.assertEqual(observed['cleanup']['status'],'REAPED')
            self.assertTrue(observed['orphan_reaped'])
            self.assertIn(observed['orphan'],[row['pid']for row in observed['cleanup']['children']])
            self.assertLess(observed['elapsed'],2)
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.terminate();unrelated.wait(timeout=5)

    @unittest.skipUnless(sys.platform.startswith('linux'),'Requires actual Linux subreaper and pidfds')
    def test_native_compiler_cleanup_identity_or_permission_failure_refuses(self):
        observed=self.child(r'''
import ctypes
from unittest.mock import patch
library=ctypes.CDLL(None,use_errno=True)
if library.prctl(36,1,0,0,0)!=0:raise RuntimeError('actual subreaper unavailable')
scope=m.native_scope_owner_identity();results={}
for mode in ['identity','permission']:
 child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
 original=m.native_process_identity;reads=[]
 def replaced(pid):
  value=original(pid)
  if pid==child.pid:
   reads.append(pid)
   if len(reads)>1:return (*value[:3],value[3]+1)
  return value
 try:
  target=patch.object(m,'native_process_identity',side_effect=replaced) if mode=='identity' else \
   patch.object(m.signal,'pidfd_send_signal',side_effect=PermissionError(1,'controlled signal refusal'))
  with target:
   try:m.stop_owned_scope_children(scope,[child],m.time.monotonic()+2);results[mode]='accepted'
   except m.Refusal as error:results[mode]=str(error)
 finally:m.stop_owned_scope_children(scope,[child],m.time.monotonic()+2)
remaining=[]
for entry in pathlib.Path('/proc').iterdir():
 if entry.name.isdecimal():
  identity=m.native_process_identity(int(entry.name))
  if identity is not None and identity[0]==os.getpid():remaining.append(int(entry.name))
observed={'results':results,'remaining_owned_children':remaining,'rust_compiler_dispatch':False}
''')
        self.assertEqual(observed['results'],{'identity':'compiler_cleanup_process_identity','permission':'compiler_cleanup_io'})
        self.assertEqual(observed['remaining_owned_children'],[])

    def test_anonymous_pipe_client_round_trip_is_transport_only(self):
        observed=self.child(r'''
declaration={'images':images,'scope_id':'e'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},None,{})
def public_transport_response(payload):
 request=json.loads(payload)
 return m.canonical({'schema':'chio.rust-compilation-response.v1','id':request['id'],'exit':7,'stdout':''})
supervisor.respond=public_transport_response
environment={**os.environ,'CHIO_COMPILATION_IPC':m.canonical(supervisor.table).decode('ascii')}
try:
 child=subprocess.Popen([sys.executable,'-B',*(['-O']*sys.flags.optimize),str(sys.argv[1]),images['rustc']['path'],'-vV'],env=environment,
                         cwd=candidate,pass_fds=supervisor.pass_fds,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 observed['transport_exit']=supervisor.wait(child)
 observed['stdout']=child.stdout.read().decode()
 observed['stderr']=child.stderr.read().decode()
finally:supervisor.close()
''')
        self.assertEqual(observed,{'transport_exit':7,'stdout':'','stderr':''})

    def pipe_authority_observation(self, modification=''):
        """Exercise the real client/parent pipes with an explicit noncompiler sink."""
        return self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration={'images':images,'scope_id':'e'*64}
environment={**config['environment'],'RUSTC':images['rustc']['path'],'RUSTC_WRAPPER':images['recorder']['path'],
 'CHIO_COMPILATION_SOURCE_BINDING':'a'*64,'CHIO_COMPILATION_SCOPE_ID':'e'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},campaign,environment)
called=[]
def public_protocol_sink(argv,env,cwd,executor,sink,selection):
 called.append({'ipc_in_request':'CHIO_COMPILATION_IPC' in env})
 sink(b'PUBLIC-PIPE-RESPONSE');return 0
m.main=public_protocol_sink
environment['CHIO_COMPILATION_IPC']=m.canonical(supervisor.table).decode('ascii')
ENVIRONMENT_MODIFICATION
try:
 child=subprocess.Popen([sys.executable,'-B',*(['-O']*sys.flags.optimize),str(sys.argv[1]),images['rustc']['path'],'-vV'],
  env=environment,cwd=candidate,pass_fds=supervisor.pass_fds,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 observed={'transport_exit':supervisor.wait(child),'stdout':child.stdout.read().decode(),
  'stderr':child.stderr.read().decode(),'calls':called,
  'event_exit':supervisor.events[-1]['exit'],'refusal':supervisor.events[-1]['refusal'],
  'dispatches':supervisor.events[-1]['dispatches'],'records':supervisor.events[-1]['records']}
finally:supervisor.close();campaign.close()
'''.replace('ENVIRONMENT_MODIFICATION', modification))

    def test_parent_authority_pipe_survives_transport_environment_addition(self):
        observed=self.pipe_authority_observation()
        self.assertEqual(observed,{'transport_exit':0,'stdout':'PUBLIC-PIPE-RESPONSE','stderr':'',
            'calls':[{'ipc_in_request':False}],'event_exit':0,'refusal':None,'dispatches':[],'records':[]})

    def test_parent_authority_pipe_refuses_changed_source_selector(self):
        observed=self.pipe_authority_observation("environment['CHIO_COMPILATION_SOURCE_BINDING']='b'*64")
        self.assertEqual(observed,{'transport_exit':86,'stdout':'','stderr':'','calls':[],
            'event_exit':86,'refusal':'compilation_request_authority','dispatches':[],'records':[]})

    def test_parent_authority_pipe_refuses_undeclared_compilation_key(self):
        observed=self.pipe_authority_observation("environment['CHIO_COMPILATION_UNDECLARED']='public-control'")
        self.assertEqual(observed,{'transport_exit':86,'stdout':'','stderr':'','calls':[],
            'event_exit':86,'refusal':'compilation_request_authority','dispatches':[],'records':[]})

    def test_parent_authority_is_not_replaced_by_launch_dictionary_mutation(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration={'images':images,'scope_id':'e'*64}
environment={**config['environment'],'RUSTC':images['rustc']['path'],'RUSTC_WRAPPER':images['recorder']['path'],
 'CHIO_COMPILATION_SOURCE_BINDING':'a'*64}
supervisor=m.CompilationSupervisor(config,declaration,{},campaign,environment)
called=[]
m.main=lambda *args:called.append(True) or 0
environment['CHIO_COMPILATION_SOURCE_BINDING']='b'*64
try:
 request={'schema':'chio.rust-compilation-request.v1','id':'f'*32,'argv':[images['rustc']['path'],'-vV'],
  'environment':environment,'cwd':str(candidate)}
 response=json.loads(supervisor.respond(m.canonical(request)))
 observed={'exit':response['exit'],'called':len(called),'refusal':supervisor.events[-1]['refusal']}
finally:supervisor.close();campaign.close()
''')
        self.assertEqual(observed,{'exit':86,'called':0,'refusal':'compilation_request_authority'})


    def selector_child(self, operation):
        return self.child(DECLARED_DRIVER_TEST_SETUP+operation)

    def test_candidate_child_optimization_matches_parent_mode(self):
        observed=self.child("observed['optimization']=sys.flags.optimize")
        self.assertEqual(observed['optimization'],sys.flags.optimize)

    def test_include_raw_directory_requirements_match_actual_path_syntax(self):
        observed=self.child(r'''
source=candidate/'input.rs';source.write_bytes(b'PUBLIC-INCLUDE-SYNTAX')
for raw in ['input.rs','input.rs/','input.rs/.','input.rs/.//']:
 try:os.stat(str(candidate)+'/'+raw);actual='regular'
 except OSError as error:actual=error.errno
 try:m.checked_include_path(raw,candidate,config);parsed='accepted'
 except (m.Refusal,OSError) as error:parsed='refused'
 observed[raw]={'actual':actual,'parsed':parsed}
''')
        self.assertEqual(observed['input.rs'],{'actual':'regular','parsed':'accepted'})
        for raw in ['input.rs/','input.rs/.','input.rs/.//']:
            self.assertEqual(observed[raw],{'actual':20,'parsed':'refused'})

    def test_depfile_plain_source_cannot_bypass_directory_syntax_check(self):
        observed=self.child(r'''
(candidate/'input.rs').write_bytes(b'PUBLIC-INCLUDE-SYNTAX')
for raw in ['input.rs','input.rs/','input.rs/.','input.rs/.//']:
 payload=('target/unit: '+raw+'\n').encode()
 try:m.parse_depfile(payload,candidate,{},config);observed[raw]='accepted'
 except (m.Refusal,OSError):observed[raw]='refused'
''')
        self.assertEqual(observed,{'input.rs':'accepted','input.rs/':'refused','input.rs/.':'refused','input.rs/.//':'refused'})

    def test_alias_directory_syntax_survives_validation_resolution_collection(self):
        observed=self.child(r'''
source=base/'toolchain/input.rs';source.write_bytes(b'PUBLIC-ALIAS-SYNTAX')
for index,text in enumerate(['input.rs','input.rs/','input.rs/.','input.rs/.//']):
 link=base/'toolchain'/('alias'+str(index));link.symlink_to(text)
 changed=copy.deepcopy(config);changed['aliases']=[{'path':str(link),'text':text,'target':str(source)}]
 changed['scopes'][2]['selection']='explicit-members';changed['scopes'][2]['members']=['input.rs',link.name]
 try:os.stat(link);actual='regular'
 except OSError as error:actual=error.errno
 campaign=None
 try:
  changed=m.validate_linux_configuration(changed,{})
  resolved=m.declared_path(link,changed)
  records=pathlib.Path(changed['records']);records.mkdir(exist_ok=True);campaign=m.Campaign(records,'a'*64)
  m.collect_linux_scope(changed,campaign);parsed='accepted'
 except (m.Refusal,OSError):parsed='refused'
 finally:
  if campaign is not None:campaign.close()
 observed[text]={'actual':actual,'parsed':parsed}
''')
        self.assertEqual(observed['input.rs'],{'actual':'regular','parsed':'accepted'})
        for text in ['input.rs/','input.rs/.','input.rs/.//']:
            self.assertEqual(observed[text],{'actual':20,'parsed':'refused'})

    def test_serialized_response_limit_is_a_typed_refusal(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration={'images':images,'scope_id':'e'*64}
environment={**config['environment'],'RUSTC':images['rustc']['path'],'RUSTC_WRAPPER':images['recorder']['path']}
supervisor=m.CompilationSupervisor(config,declaration,{},campaign,environment)
def fake_main(argv,env,cwd,executor,sink,selection):sink(b'p'*12_583_936);return 0
m.main=fake_main
try:
 request={'schema':'chio.rust-compilation-request.v1','id':'f'*32,'argv':[images['rustc']['path'],'-vV'],
          'environment':environment,'cwd':str(candidate)}
 payload=supervisor.respond(m.canonical(request));response=json.loads(payload)
 observed={'length':len(payload),'exit':response['exit'],'stdout':len(response['stdout']),
           'event_exit':supervisor.events[-1]['exit'],'refusal':supervisor.events[-1]['refusal']}
finally:supervisor.close();campaign.close()
''')
        self.assertLessEqual(observed['length'],16*1024*1024)
        self.assertEqual(observed['exit'],86)
        self.assertEqual(observed['event_exit'],86)
        self.assertEqual(observed['stdout'],0)
        self.assertEqual(observed['refusal'],'compilation_response_limit')

    def test_small_response_stays_encoded_success_observation(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration={'images':images,'scope_id':'e'*64}
environment={**config['environment'],'RUSTC':images['rustc']['path'],'RUSTC_WRAPPER':images['recorder']['path']}
supervisor=m.CompilationSupervisor(config,declaration,{},campaign,environment)
def fake_main(argv,env,cwd,executor,sink,selection):sink(b'p'*128);return 0
m.main=fake_main
try:
 request={'schema':'chio.rust-compilation-request.v1','id':'f'*32,'argv':[images['rustc']['path'],'-vV'],
          'environment':environment,'cwd':str(candidate)}
 payload=supervisor.respond(m.canonical(request));response=json.loads(payload)
 observed={'length':len(payload),'exit':response['exit'],'decoded':len(m.base64.b64decode(response['stdout'])),
           'event_exit':supervisor.events[-1]['exit'],'refusal':supervisor.events[-1]['refusal']}
finally:supervisor.close();campaign.close()
''')
        self.assertLess(observed['length'],1024)
        self.assertEqual(observed['exit'],0)
        self.assertEqual(observed['decoded'],128)
        self.assertEqual(observed['event_exit'],0)
        self.assertIsNone(observed['refusal'])

    def test_opt_in_injects_only_the_target_declared_driver(self):
        observed=self.selector_child(r'''
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration,_=m.collect_linux_scope(config,campaign)
for target,driver in zip(targets,drivers):
 raw=args+['--target',target['triple']]
 selected=m.select_compiler_dispatch(raw,candidate,config,declaration)
 observed[target['triple']]={'raw':selected['raw_compiler_argv'],'effective':selected['effective_argv'],
                           'reason':selected['reason'],'driver':selected['driver']['sha256']}
campaign.close()
''')
        for entry in observed.values():
            self.assertEqual(entry['effective'][:-2],entry['raw'])
            self.assertEqual(entry['effective'][-2],'-C')
            self.assertEqual(entry['reason'],'missing-linker-declared-driver-opt-in')
        self.assertNotEqual(observed['x86_64-unknown-linux-gnu']['driver'],observed['x86_64-unknown-linux-musl']['driver'])

    def test_missing_selection_declaration_refuses_injection(self):
        observed=self.selector_child(r'''
del config['linker_selection'];config=m.validate_linux_configuration(config,{})
try:m.select_compiler_dispatch(args,candidate,config,{'images':images});observed['missing']='accepted'
except m.Refusal as error:observed['missing']=str(error)
''')
        self.assertEqual(observed['missing'],'native_linker_selection_not_bound')

    def test_changed_driver_bytes_refuse_before_injection(self):
        observed=self.selector_child(r'''
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration,_=m.collect_linux_scope(config,campaign)
pathlib.Path(drivers[0]['path']).write_bytes(b'CHANGED-PUBLIC-DRIVER')
try:m.select_compiler_dispatch(args,candidate,config,declaration);observed['driver']='accepted'
except m.Refusal as error:observed['driver']=str(error)
campaign.close()
''')
        self.assertNotEqual(observed['driver'],'accepted')

    def test_existing_explicit_driver_must_match_selected_target(self):
        observed=self.selector_child(r'''
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration,_=m.collect_linux_scope(config,campaign)
good=args+['--target',targets[1]['triple'],'-C','linker='+drivers[1]['path']]
selected=m.select_compiler_dispatch(good,candidate,config,declaration)
observed['good']=selected['effective_argv']==good and selected['reason']=='matching-explicit-linker'
for label,extra in [('wrong-driver',['-C','linker='+drivers[0]['path']]),('response',['-C','link-arg=@raw']),
                    ('secret',['--cfg','auth_token="SYNTHETIC-OPAQUE"'])]:
 try:m.select_compiler_dispatch(args+['--target',targets[1]['triple']]+extra,candidate,config,declaration);observed[label]='accepted'
 except m.Refusal as error:observed[label]=str(error)
campaign.close()
''')
        self.assertTrue(observed['good'])
        self.assertNotIn('accepted',[observed[key] for key in ['wrong-driver','response','secret']])

    def test_closed_selection_and_complete_target_joins(self):
        observed=self.selector_child(r'''
for label,modify in [('unknown',lambda value:value['linker_selection'].update({'arbitrary_flag':'opaque'})),
 ('missing-target',lambda value:value['linker_selection']['targets'].pop()),
 ('wrong-crt',lambda value:value['linker_selection']['targets'][1].update({'crt_members':targets[0]['crt_members']}))]:
 changed=copy.deepcopy(config);modify(changed)
 try:m.validate_linux_configuration(changed,{});observed[label]='accepted'
 except m.Refusal as error:observed[label]=str(error)
''')
        self.assertNotIn('accepted',observed.values())

    def test_raw_and_effective_argument_bodies_are_separately_retained(self):
        observed=self.selector_child(r'''
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration,_=m.collect_linux_scope(config,campaign)
selected=m.select_compiler_dispatch(args,candidate,config,declaration)
retained=m.retain_compiler_dispatch(campaign,selected)
observed={'raw':json.loads((records/retained['raw_wrapper_argv']['artifact']).read_bytes()),
 'effective':json.loads((records/retained['effective_argv']['artifact']).read_bytes()),
 'raw_hash':retained['raw_wrapper_sha256'],'effective_hash':retained['effective_invocation_sha256'],
 'expected_raw_hash':m.digest([declaration['images']['recorder']['path'],*args]),
 'expected_effective_hash':m.digest(selected['effective_argv'])}
campaign.close()
''')
        self.assertEqual(observed['raw'][1:],observed['effective'][:-2])
        self.assertEqual(observed['raw_hash'],observed['expected_raw_hash'])
        self.assertEqual(observed['effective_hash'],observed['expected_effective_hash'])
        self.assertNotEqual(observed['raw_hash'],observed['effective_hash'])

    def test_primary_payload_omits_driver_only_when_opt_in_requested(self):
        observed=self.child(r'''
probe_path=pathlib.Path(sys.argv[1]).parents[1]/'target/recovery-safety-remediation/all-findings/qualification/compiler-recorder/native-successor/linker-selection-successor/public-probes/native-scope-probe.py'
spec=importlib.util.spec_from_file_location('primary_probe',probe_path);probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
commands=[]
os.environ['RUSTC_WRAPPER']=images['recorder']['path'];os.environ['RUSTC']=images['rustc']['path']
probe.endpoints=lambda:({},())
probe.subprocess.run=lambda command,**kwargs:commands.append(command) or type('Result',(),{'returncode':0})()
for label,implicit in [('explicit',False),('opt-in',True)]:
 arguments=type('Arguments',(),{'implicit_linker':implicit,'linker':images['linker']['path']})()
 probe.compile_unit(arguments,candidate/'target/work'/label,candidate/'main.rs','unit')
observed={'explicit_has_driver':any(value.startswith('linker=') for value in commands[0]),
          'opt_in_has_driver':any(value.startswith('linker=') for value in commands[1])}
''')
        self.assertEqual(observed,{'explicit_has_driver':True,'opt_in_has_driver':False})


    def test_opaque_cfg_values_refuse_before_raw_arguments_are_retained(self):
        observed=self.selector_child(r'''
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration,_=m.collect_linux_scope(config,campaign)
try:
 for label,extra in [('boolean',['--cfg','public_boolean']),('check-boolean',['--check-cfg','cfg(public_boolean,test)']),
   ('cfg-opaque',['--cfg','opaque_input="SYNTHETIC_OPAQUE_MARKER_9Q4N"']),
   ('check-opaque',['--check-cfg','cfg(opaque_input,values("SYNTHETIC_OPAQUE_MARKER_9Q4N"))'])]:
  try:
   selection=m.select_compiler_dispatch(args+extra,candidate,config,declaration)
   retained=m.retain_compiler_dispatch(campaign,selection)
   bodies=[(records/retained[key]['artifact']).read_bytes() for key in ['raw_wrapper_argv','effective_argv']]
   observed[label]={'accepted':True,'marker':any(b'SYNTHETIC_OPAQUE_MARKER_9Q4N' in body for body in bodies)}
  except m.Refusal as error:observed[label]={'accepted':False,'refusal':str(error)}
finally:campaign.close()
''')
        for label in ['boolean','check-boolean']:
            self.assertEqual(observed[label],{'accepted':True,'marker':False})
        for label in ['cfg-opaque','check-opaque']:
            self.assertEqual(observed[label],{'accepted':False,'refusal':'opaque_cfg_value'})

    def test_target_selection_uses_only_consumed_target_option(self):
        observed=self.selector_child(r'''
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
declaration,_=m.collect_linux_scope(config,campaign)
try:
 for label,extra in [('plain-remap',['--remap-path-prefix','public-old=public-new']),
  ('remap-target-text',['--remap-path-prefix','--target='+targets[1]['triple']]),
  ('gnu',['--target',targets[0]['triple']]),('musl',['--target='+targets[1]['triple']]),
  ('musl-explicit',['--target',targets[1]['triple'],'-C','linker='+drivers[1]['path']])]:
  selected=m.select_compiler_dispatch(args+extra,candidate,config,declaration)
  context,target=m.native_target_context(config,(args+extra)[1:])
  parsed=m.parse((args+extra)[1:],candidate,context)
  observed[label]={'selected':selected['target'],'parsed':parsed['target'] or targets[0]['triple'],
   'driver':selected['driver']['path']}
 try:m.select_compiler_dispatch(args+['--target',targets[0]['triple'],'--target',targets[1]['triple']],candidate,config,declaration);observed['duplicate']='accepted'
 except m.Refusal as error:observed['duplicate']=str(error)
finally:campaign.close()
''')
        for label in ['plain-remap','remap-target-text','gnu']:
            self.assertEqual(observed[label]['selected'],'x86_64-unknown-linux-gnu')
            self.assertEqual(observed[label]['selected'],observed[label]['parsed'])
            self.assertTrue(observed[label]['driver'].endswith('/linker'))
        for label in ['musl','musl-explicit']:
            self.assertEqual(observed[label]['selected'],'x86_64-unknown-linux-musl')
            self.assertEqual(observed[label]['selected'],observed[label]['parsed'])
            self.assertTrue(observed[label]['driver'].endswith('/musl-driver'))
        self.assertEqual(observed['duplicate'],'ambiguous_native_target')

    def test_exact_public_loader_chain_is_held_and_rejects_changes(self):
        observed=self.child(r'''
runtime=base/'native-runtime';directory=runtime/'usr/lib64';directory.mkdir(parents=True)
terminal=runtime/'usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2';terminal.parent.mkdir(parents=True);terminal.write_bytes(b'PUBLIC-LOADER')
first=runtime/'lib64';first.symlink_to('usr/lib64')
second=directory/terminal.name;second.symlink_to('../lib/x86_64-linux-gnu/'+terminal.name)
aliases=[{'path':str(first),'text':'usr/lib64','target':str(directory),'purpose':'public-system-elf-loader'},
 {'path':str(second),'text':'../lib/x86_64-linux-gnu/'+terminal.name,'target':str(terminal),'purpose':'public-system-elf-loader'}]
config['aliases']=aliases
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 declaration,_=m.collect_linux_scope(config,campaign)
 observed['resolved']=str(m.declared_path(first/terminal.name,config))
 observed['chains']=declaration['alias_chains']
 binding=m.linux_alias_bindings(config)
 changed=copy.deepcopy(config);changed['aliases']=aliases[1:]
 try:m.validate_linux_configuration(changed,{});observed['missing-root-hop']='accepted'
 except m.Refusal:observed['missing-root-hop']='refused'
 changed=copy.deepcopy(config);changed['aliases']=aliases[:1]
 try:m.declared_path(first/terminal.name,changed);observed['undeclared']='accepted'
 except m.Refusal:observed['undeclared']='refused'
 loop1=runtime/'loop1';loop2=runtime/'loop2';loop1.symlink_to('loop2');loop2.symlink_to('loop1')
 cyclic=copy.deepcopy(config);cyclic['aliases']=[{'path':str(loop1),'text':'loop2','target':str(loop2)}, {'path':str(loop2),'text':'loop1','target':str(loop1)}]
 try:m.declared_path(loop1,cyclic);observed['cycle']='accepted'
 except m.Refusal:observed['cycle']='refused'
 # Rename the synthetic link into retained evidence; no artifact deletion.
 second.rename(directory/'original-loader-alias');second.symlink_to('../lib/x86_64-linux-gnu/other-loader')
 try:m.verify_linux_aliases(config,binding);observed['retarget']='accepted'
 except m.Refusal:observed['retarget']='refused'
finally:campaign.close()
observed['terminal']=str(terminal)
''')
        self.assertEqual(observed['resolved'],observed['terminal'])
        self.assertEqual(observed['undeclared'],'refused')
        self.assertEqual(observed['missing-root-hop'],'refused')
        self.assertEqual(observed['cycle'],'refused')
        self.assertEqual(observed['retarget'],'refused')
        self.assertEqual(len(observed['chains']),2)
        self.assertTrue(all(chain['hops'] for chain in observed['chains']))
        self.assertTrue(all(chain['hops'][-1]['path']==chain['resolved'] for chain in observed['chains']))


    def test_declared_root_directory_uses_a_held_root_descriptor(self):
        observed=self.child(r'''
with m.declared_directory(pathlib.Path('/')) as descriptor:
 info=os.fstat(descriptor)
 actual=os.stat('/')
 observed={'same_root':(info.st_dev,info.st_ino,info.st_mode)==(actual.st_dev,actual.st_ino,actual.st_mode),
           'directory':m.stat.S_ISDIR(info.st_mode)}
''')
        self.assertEqual(observed,{'same_root':True,'directory':True})


    def test_normal_alias_targets_are_immediate_hops_and_final_images_are_separate(self):
        observed=self.child(r'''
runtime=base/'native-runtime';binary=runtime/'usr/bin';binary.mkdir(parents=True)
alternatives=runtime/'etc/alternatives';alternatives.mkdir(parents=True)
gcc=binary/'x86_64-linux-gnu-gcc-13';gcc.write_bytes(b'PUBLIC-GCC-13');gcc.chmod(0o755)
ld=binary/'x86_64-linux-gnu-ld.bfd';ld.write_bytes(b'PUBLIC-LD-BFD');ld.chmod(0o755)
entries=[(binary/'cc',str(alternatives/'cc'),alternatives/'cc'),
 (alternatives/'cc',str(binary/'gcc'),binary/'gcc'),
 (binary/'gcc','gcc-13',binary/'gcc-13'),
 (binary/'gcc-13','x86_64-linux-gnu-gcc-13',gcc),
 (binary/'ld','x86_64-linux-gnu-ld',binary/'x86_64-linux-gnu-ld'),
 (binary/'x86_64-linux-gnu-ld','x86_64-linux-gnu-ld.bfd',ld)]
config['aliases']=[]
for path,text,target in entries:
 path.symlink_to(text)
 config['aliases'].append({'path':str(path),'text':text,'target':str(target)})
config['images']['linker']={'path':str(binary/'cc'),'sha256':hashlib.sha256(gcc.read_bytes()).hexdigest()}
config=m.validate_linux_configuration(config,{})
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 declaration,_=m.collect_linux_scope(config,campaign)
 observed['compiler_driver']=declaration['images']['linker']['path']
 observed['cc']=str(m.declared_path(binary/'cc',config));observed['ld']=str(m.declared_path(binary/'ld',config))
 chains=m.linux_alias_chains(config)
 observed['chains']=chains
 observed['bindings']=m.linux_alias_bindings(config)
 changed=copy.deepcopy(config);changed['aliases']=[alias for alias in config['aliases'] if alias['path']!=str(binary/'gcc')]
 try:m.declared_path(binary/'cc',changed);observed['undeclared-hop']='accepted'
 except m.Refusal:observed['undeclared-hop']='refused'
 changed=copy.deepcopy(config);changed['aliases'][0]['target']=str(gcc)
 try:m.validate_linux_configuration(changed,{});observed['false-immediate']='accepted'
 except m.Refusal:observed['false-immediate']='refused'
 # Retain the original synthetic link object and replace only its old fixture name.
 (binary/'gcc').rename(binary/'original-gcc-alias');(binary/'gcc').symlink_to('x86_64-linux-gnu-gcc-13')
 try:m.verify_linux_aliases(config,observed['bindings']);observed['retarget']='accepted'
 except m.Refusal:observed['retarget']='refused'
finally:campaign.close()
observed['gcc-terminal']=str(gcc);observed['ld-terminal']=str(ld)
''')
        self.assertEqual(observed['compiler_driver'],observed['gcc-terminal'])
        self.assertEqual(observed['cc'],observed['gcc-terminal'])
        self.assertEqual(observed['ld'],observed['ld-terminal'])
        self.assertEqual(observed['undeclared-hop'],'refused')
        self.assertEqual(observed['false-immediate'],'refused')
        self.assertEqual(observed['retarget'],'refused')
        self.assertTrue(all(chain['hops'][-1]['path']==chain['resolved'] for chain in observed['chains']))
        self.assertTrue(any(len([hop for hop in chain['hops'] if hop['kind']=='link'])>=4 for chain in observed['chains']))


# Relocated reviewed controls use the same-module fixture namespace.
tests = sys.modules[__name__]
t = tests

class RetentionBatchTest(tests.LinuxScopeContractTest):
    def test_batch_removes_per_member_reconcile_state_and_directory_sync(self):
        observed=self.child(r'''
import contextlib
import contextlib
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
counts={'reconcile':0,'state':0,'artifact-directory-sync':0,'artifact-file-sync':0}
original_reconcile=campaign.reconcile;original_state=campaign.save_state;original_fsync=m.os.fsync
artifact_directory=os.fstat(campaign.artifacts.fd)
def reconcile():counts['reconcile']+=1;return original_reconcile()
def state():counts['state']+=1;return original_state()
def sync(fd):
 info=os.fstat(fd)
 if (info.st_dev,info.st_ino)==(artifact_directory.st_dev,artifact_directory.st_ino):counts['artifact-directory-sync']+=1
 elif m.stat.S_ISREG(info.st_mode):counts['artifact-file-sync']+=1
 return original_fsync(fd)
campaign.reconcile=reconcile;campaign.save_state=state;m.os.fsync=sync
try:
 context=campaign.retention_batch() if hasattr(campaign,'retention_batch') else contextlib.nullcontext()
 payloads=[('PUBLIC-BATCH-'+str(index)).encode()*64 for index in range(24)]
 with context:
  refs=[campaign.retain(payload) for payload in payloads]
  duplicate=campaign.retain(payloads[0])
 observed={'counts':counts,'bytes':campaign.state['content_bytes'],'expected_bytes':sum(len(payload) for payload in payloads),
  'duplicate':duplicate==refs[0], 'bodies':all((records/ref['artifact']).read_bytes()==payload for ref,payload in zip(refs,payloads))}
finally:m.os.fsync=original_fsync;campaign.close()
''')
        self.assertLessEqual(observed['counts']['reconcile'],2)
        self.assertEqual(observed['counts']['state'],1)
        self.assertEqual(observed['counts']['artifact-directory-sync'],1)
        self.assertGreaterEqual(observed['counts']['artifact-file-sync'],24)
        self.assertEqual(observed['bytes'],observed['expected_bytes'])
        self.assertTrue(observed['duplicate'] and observed['bodies'])

    def test_aborted_batch_keeps_artifacts_and_refuses_recovery(self):
        observed=self.child(r'''
import contextlib
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
payload=b'PUBLIC-PARTIAL-BATCH';ref=None
try:
 try:
  with (campaign.retention_batch() if hasattr(campaign,'retention_batch') else contextlib.nullcontext()):
   ref=campaign.retain(payload)
   raise RuntimeError('public controlled abort')
 except RuntimeError:pass
finally:campaign.close()
observed['artifact_preserved']=(records/ref['artifact']).read_bytes()==payload
try:again=m.Campaign(records,'a'*64);again.close();observed['recovery']='accepted'
except m.Refusal as error:observed['recovery']=str(error)
observed['records']=list((records/'records').iterdir())==[]
''')
        self.assertTrue(observed['artifact_preserved'] and observed['records'])
        self.assertEqual(observed['recovery'],'retention_batch_incomplete')

    def test_batch_content_quota_counts_unique_published_bytes(self):
        observed=self.child(r'''
import contextlib
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64);m.MAX_CONTENT=15
try:
 try:
  with (campaign.retention_batch() if hasattr(campaign,'retention_batch') else contextlib.nullcontext()):
   first=campaign.retain(b'PUBLIC-ONE')
   campaign.retain(b'PUBLIC-ONE')
   campaign.retain(b'PUBLIC-TWO')
  observed['quota']='accepted'
 except m.Refusal as error:observed['quota']=str(error)
 observed['preserved']=(records/first['artifact']).read_bytes()==b'PUBLIC-ONE'
 observed['second_absent']=not (records/'artifacts'/hashlib.sha256(b'PUBLIC-TWO').hexdigest()).exists()
finally:campaign.close()
''')
        self.assertEqual(observed,{'quota':'content_limit','preserved':True,'second_absent':True})

    def test_active_batch_cannot_publish_a_record(self):
        observed=self.child(r'''
import contextlib
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 with (campaign.retention_batch() if hasattr(campaign,'retention_batch') else contextlib.nullcontext()):
  campaign.retain(b'PUBLIC-BATCH')
  row=m.row_for(['/public/compiler'],{},'a'*64)
  try:campaign.publish(row);observed['publish']='accepted'
  except m.Refusal as error:observed['publish']=str(error)
 observed['records']=list((records/'records').iterdir())==[]
finally:campaign.close()
''')
        self.assertEqual(observed,{'publish':'retention_batch_active','records':True})

    def test_old_v3_namespace_is_not_a_current_writer_namespace(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir()
for name in ['artifacts','records','completions']:(records/name).mkdir()
(records/'.lock').write_bytes(b'')
(records/'.state.json').write_text(json.dumps({'schema':'chio.rust-compilation.v3','source_binding':'a'*64,'content_bytes':0,'record_count':0}))
try:campaign=m.Campaign(records,'a'*64);campaign.close();observed['writer']='accepted'
except m.Refusal as error:observed['writer']=str(error)
observed['old_state']=json.loads((records/'.state.json').read_bytes())['schema']
''')
        self.assertEqual(observed,{'writer':'campaign_binding','old_state':'chio.rust-compilation.v3'})

    def test_process_crash_after_published_artifact_refuses_recovery(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir()
code="""
import contextlib,importlib.util,os,pathlib,sys
spec=importlib.util.spec_from_file_location('crash_recorder',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
campaign=m.Campaign(pathlib.Path(sys.argv[2]),'a'*64)
with (campaign.retention_batch() if hasattr(campaign,'retention_batch') else contextlib.nullcontext()):
 campaign.retain(b'PUBLIC-CRASHED-BATCH')
 os._exit(23)
"""
result=subprocess.run([sys.executable,'-B',*(['-O']*sys.flags.optimize),'-c',code,sys.argv[1],str(records)],capture_output=True,timeout=10)
observed['child_exit']=result.returncode
artifact=records/'artifacts'/hashlib.sha256(b'PUBLIC-CRASHED-BATCH').hexdigest()
observed['artifact_preserved']=artifact.read_bytes()==b'PUBLIC-CRASHED-BATCH'
try:campaign=m.Campaign(records,'a'*64);campaign.close();observed['recovery']='accepted'
except m.Refusal as error:observed['recovery']=str(error)
observed['records']=list((records/'records').iterdir())==[]
''')
        self.assertEqual(observed,{'child_exit':23,'artifact_preserved':True,'recovery':'retention_batch_incomplete','records':True})

    def test_artifact_directory_sync_failure_cannot_complete_a_batch(self):
        observed=self.child(r'''
import contextlib
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
original=m.os.fsync;directory=os.fstat(campaign.artifacts.fd)
def sync(fd):
 current=os.fstat(fd)
 if (current.st_dev,current.st_ino)==(directory.st_dev,directory.st_ino):raise OSError('public artifact directory fault')
 return original(fd)
m.os.fsync=sync
try:
 try:
  with (campaign.retention_batch() if hasattr(campaign,'retention_batch') else contextlib.nullcontext()):campaign.retain(b'PUBLIC-FAULT-BATCH')
  observed['result']='accepted'
 except OSError:observed['result']='sync-failed'
finally:m.os.fsync=original;campaign.close()
try:again=m.Campaign(records,'a'*64);again.close();observed['recovery']='accepted'
except m.Refusal as error:observed['recovery']=str(error)
observed['complete']=list((records/'batches').glob('*.complete.json')) if (records/'batches').exists() else []
''')
        self.assertEqual(observed,{'result':'sync-failed','recovery':'retention_batch_incomplete','complete':[]})

    def test_physical_complete_pair_has_exact_cas_and_source_binding(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 with campaign.retention_batch():
  ref=campaign.retain(b'PUBLIC-COMPLETE-BATCH')
 outcome=campaign.retention_outcomes[-1]
 start=json.loads((records/outcome['start']['path']).read_bytes())
 complete=json.loads((records/outcome['complete']['path']).read_bytes())
 observed={'physical':outcome['physical_status'],'durability':outcome['durability']['status'],
  'binding':start['source_binding']==complete['source_binding']=='a'*64,
  'artifact':complete['after']['artifacts'][0]['sha256']==ref['sha256'],
  'pair':start['completion_identity']==outcome['complete']['identity'] and complete['start']==outcome['start'],
  'bytes':complete['after']['content_bytes']==len(b'PUBLIC-COMPLETE-BATCH')}
finally:campaign.close()
''')
        self.assertEqual(observed,{'physical':'complete','durability':'confirmed','binding':True,'artifact':True,'pair':True,'bytes':True})

    def test_final_sync_fault_retains_physical_pair_and_blocks_rows(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
original=m.os.fsync;batch_directory=os.fstat(campaign.batches.fd);calls=0
try:
 def sync(fd):
  global calls
  current=os.fstat(fd)
  if (current.st_dev,current.st_ino)==(batch_directory.st_dev,batch_directory.st_ino):
   calls+=1
   if calls==2:raise OSError(5,'public final completion sync fault')
  return original(fd)
 m.os.fsync=sync
 with campaign.retention_batch():campaign.retain(b'PUBLIC-FINAL-SYNC')
 outcome=campaign.retention_outcomes[-1]
 observed={'physical':outcome['physical_status'],'durability':outcome['durability']['status'],'errno':outcome['durability']['errno'],
  'pair':(records/outcome['start']['path']).is_file() and (records/outcome['complete']['path']).is_file()}
 try:campaign.publish(m.row_for(['/public/compiler'],{},'a'*64));observed['row']='accepted'
 except m.Refusal as error:observed['row']=str(error)
finally:m.os.fsync=original;campaign.close()
again=m.Campaign(records,'a'*64)
try:observed['reopen']=again.retention_recovery;observed['records']=list((records/'records').iterdir())==[]
finally:again.close()
''')
        self.assertEqual(observed,{'physical':'complete','durability':'unconfirmed','errno':5,'pair':True,'row':'retention_batch_durability_unconfirmed','reopen':'physical-only-durability-unknown','records':True})

    def test_post_retain_artifact_mutation_prevents_complete(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 try:
  with campaign.retention_batch():
   ref=campaign.retain(b'PUBLIC-ORIGINAL-BODY');(records/ref['artifact']).write_bytes(b'PUBLIC-CHANGED-BODY')
  observed['result']='accepted'
 except m.Refusal as error:observed['result']=str(error)
 observed['complete']=not list((records/'batches').glob('*.complete.json'))
finally:campaign.close()
''')
        self.assertEqual(observed,{'result':'artifact_changed','complete':True})

    def test_pair_replacement_identical_bytes_refuses_recovery(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
with campaign.retention_batch():campaign.retain(b'PUBLIC-PAIR')
complete=records/campaign.retention_outcomes[-1]['complete']['path'];campaign.close()
replacement=records/'replacement';replacement.write_bytes(complete.read_bytes());os.replace(replacement,complete)
try:again=m.Campaign(records,'a'*64);again.close();observed['recovery']='accepted'
except m.Refusal as error:observed['recovery']=str(error)
''')
        self.assertEqual(observed,{'recovery':'retention_batch_incomplete'})

    def test_added_cas_member_prevents_complete(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 try:
  with campaign.retention_batch():
   campaign.retain(b'PUBLIC-ALLOWED')
   payload=b'PUBLIC-UNREQUESTED';(records/'artifacts'/hashlib.sha256(payload).hexdigest()).write_bytes(payload)
  observed['result']='accepted'
 except m.Refusal as error:observed['result']=str(error)
 observed['complete']=not list((records/'batches').glob('*.complete.json'))
finally:campaign.close()
''')
        self.assertEqual(observed,{'result':'retention_batch_inventory_changed','complete':True})

    def test_state_sync_failure_is_incomplete_and_keeps_bytes(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
original=campaign.save_state
try:
 def state():raise OSError(5,'public state fault')
 campaign.save_state=state
 try:
  with campaign.retention_batch():ref=campaign.retain(b'PUBLIC-STATE-FAULT')
  observed['result']='accepted'
 except OSError:observed['result']='state-failed'
 observed['body']=(records/ref['artifact']).read_bytes()==b'PUBLIC-STATE-FAULT'
finally:campaign.save_state=original;campaign.close()
try:again=m.Campaign(records,'a'*64);again.close();observed['recovery']='accepted'
except m.Refusal as error:observed['recovery']=str(error)
''')
        self.assertEqual(observed,{'result':'state-failed','body':True,'recovery':'retention_batch_incomplete'})

    def test_final_sync_fault_blocks_full_collector_declaration(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
original=m.os.fsync;batch_directory=os.fstat(campaign.batches.fd);calls=0
try:
 def sync(fd):
  global calls
  current=os.fstat(fd)
  if (current.st_dev,current.st_ino)==(batch_directory.st_dev,batch_directory.st_ino):
   calls+=1
   if calls==2:raise OSError(5,'public full collector final sync fault')
  return original(fd)
 m.os.fsync=sync
 try:m.collect_linux_scope(m.validate_linux_configuration(config,{}),campaign);observed['declaration']='emitted'
 except m.Refusal as error:observed['declaration']=str(error)
 observed['physical']=campaign.retention_outcomes[-1]['physical_status']
 observed['row_count']=len(list((records/'records').iterdir()))
finally:m.os.fsync=original;campaign.close()
''')
        self.assertEqual(observed,{'declaration':'retention_batch_durability_unconfirmed','physical':'complete','row_count':0})

    def test_root_sync_failure_preserves_incomplete_batch(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
original=m.os.fsync;directory=os.fstat(campaign.directory.fd)
try:
 def sync(fd):
  info=os.fstat(fd)
  if (info.st_dev,info.st_ino)==(directory.st_dev,directory.st_ino):raise OSError(5,'public root sync fault')
  return original(fd)
 m.os.fsync=sync
 try:
  with campaign.retention_batch():ref=campaign.retain(b'PUBLIC-ROOT-FAULT')
  observed['result']='accepted'
 except OSError:observed['result']='root-sync-failed'
 observed['body']=(records/ref['artifact']).read_bytes()==b'PUBLIC-ROOT-FAULT'
 observed['physical']=campaign.retention_outcomes[-1]['physical_status']
finally:m.os.fsync=original;campaign.close()
try:again=m.Campaign(records,'a'*64);again.close();observed['recovery']='accepted'
except m.Refusal as error:observed['recovery']=str(error)
''')
        self.assertEqual(observed,{'result':'root-sync-failed','body':True,'physical':'incomplete','recovery':'retention_batch_incomplete'})

    def test_replaced_complete_inode_with_failed_quarantine_is_unusable(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
original_unlink=m.os.unlink;original_rename=m.os.rename
try:
 def unlink(name,*args,**kwargs):
  original_unlink(name,*args,**kwargs)
  if str(name).startswith('.pending-') and kwargs.get('dir_fd')==campaign.batches.fd:
   paths=list((records/'batches').glob('*.complete.json'))
   if paths:
    path=paths[0];copy=records/'copy';copy.write_bytes(path.read_bytes());os.replace(copy,path)
 def rename(*args,**kwargs):raise OSError(5,'public quarantine fault')
 m.os.unlink=unlink;m.os.rename=rename
 try:
  with campaign.retention_batch():campaign.retain(b'PUBLIC-REPLACEMENT')
  observed['result']='accepted'
 except (m.Refusal,OSError):observed['result']='refused'
finally:m.os.unlink=original_unlink;m.os.rename=original_rename;campaign.close()
try:again=m.Campaign(records,'a'*64);again.close();observed['recovery']='accepted'
except m.Refusal as error:observed['recovery']=str(error)
observed['complete_preserved']=bool(list((records/'batches').glob('*.complete.json')))
''')
        self.assertEqual(observed,{'result':'refused','recovery':'retention_batch_incomplete','complete_preserved':True})

    def test_same_batch_id_cannot_overwrite_a_previous_pair(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
original=m.uuid.uuid4
try:
 with campaign.retention_batch():campaign.retain(b'PUBLIC-FIRST-BATCH')
 outcome=campaign.retention_outcomes[-1];first=records/outcome['start']['path'];original_bytes=first.read_bytes();original_identity=(first.stat().st_dev,first.stat().st_ino)
 calls=0
 def nonce():
  global calls
  calls+=1
  return m.uuid.UUID(outcome['batch_id']) if calls==1 else original()
 m.uuid.uuid4=nonce
 try:
  with campaign.retention_batch():campaign.retain(b'PUBLIC-SECOND-BATCH')
  observed['result']='accepted'
 except FileExistsError:observed['result']='no-overwrite'
 observed['preserved']=first.read_bytes()==original_bytes and (first.stat().st_dev,first.stat().st_ino)==original_identity
finally:m.uuid.uuid4=original;campaign.close()
''')
        self.assertEqual(observed,{'result':'no-overwrite','preserved':True})

    def test_caught_retain_failure_cannot_complete_or_reset_quota(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64);m.MAX_CONTENT=15
try:
 try:
  with campaign.retention_batch():
   campaign.retain(b'PUBLIC-ONE')
   try:campaign.retain(b'PUBLIC-TWO')
   except m.Refusal:pass
  observed['completion']='accepted'
 except m.Refusal as error:observed['completion']=str(error)
 observed['bytes']=campaign.state['content_bytes']
 observed['complete']=not list((records/'batches').glob('*.complete.json'))
finally:campaign.close()
''')
        self.assertEqual(observed,{'completion':'retention_batch_incomplete','bytes':10,'complete':True})

    def test_outside_outcome_composition_is_closed_and_matches_physical_pair(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 with campaign.retention_batch():campaign.retain(b'PUBLIC-OUTSIDE-JOIN')
 outcome=campaign.retention_outcomes[-1];physical=campaign.validate_retention_batches()[0]
 observed['positive']=m.validate_retention_outcome(outcome,physical)
 observed['negatives']=[]
 for label in ['batch','source','inode','extra','qualified','errno']:
  changed=copy.deepcopy(outcome)
  if label=='batch':changed['batch_id']='f'*32
  elif label=='source':changed['source_binding']='b'*64
  elif label=='inode':changed['complete']['identity']['inode']+=1
  elif label=='extra':changed['caller_success']=True
  elif label=='qualified':changed['durability']['status']='qualified'
  else:changed['durability']['errno']=True
  try:m.validate_retention_outcome(changed,physical);observed['negatives'].append('accepted')
  except m.Refusal as error:observed['negatives'].append(str(error))
finally:campaign.close()
''')
        self.assertEqual(observed,{'positive':'confirmed','negatives':['retention_outcome_binding']*6})

    def test_old_namespace_without_lock_is_refused_without_mutation(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir()
for name in ['artifacts','records','completions']:(records/name).mkdir()
(records/'.state.json').write_text(json.dumps({'schema':'chio.rust-compilation.v3','source_binding':'a'*64,'content_bytes':0,'record_count':0}))
before={path.name:path.read_bytes() if path.is_file() else None for path in records.iterdir()}
try:campaign=m.Campaign(records,'a'*64);campaign.close();observed['writer']='accepted'
except m.Refusal as error:observed['writer']=str(error)
after={path.name:path.read_bytes() if path.is_file() else None for path in records.iterdir()}
observed['unchanged']=before==after
''')
        self.assertEqual(observed,{'writer':'campaign_binding','unchanged':True})

    def test_added_record_cannot_hide_behind_advisory_batch_counter(self):
        observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
try:
 try:
  with campaign.retention_batch():
   campaign.retain(b'PUBLIC-COUNT-BINDING')
   (records/'records'/('f'*32+'.json')).write_bytes(b'{}')
  observed['completion']='accepted'
 except m.Refusal as error:observed['completion']=str(error)
 observed['complete']=not list((records/'batches').glob('*.complete.json'))
finally:campaign.close()
''')
        self.assertEqual(observed,{'completion':'retention_batch_inventory_changed','complete':True})

class UnitPublicationTest(t.LinuxScopeContractTest):
 def test_unit_positive_binds_pair_images_and_reopen_has_unknown_sync(self):
  observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
row=m.row_for([],{},'a'*64);row.update(status='success',compiler_exit=0)
try:
 outcome=campaign.publish(row)
 rb=(records/outcome['record']['path']).read_bytes();mb=(records/outcome['completion']['path']).read_bytes()
 observed={'status':outcome['durability']['status'],'physical':outcome['physical_status'],
  'record_sha':hashlib.sha256(rb).hexdigest()==outcome['record']['sha256'],
  'marker_sha':hashlib.sha256(mb).hexdigest()==outcome['completion']['sha256'],
  'images':outcome['unit_images_sha256']==m.digest({key:json.loads(rb)[key] for key in ['compiler','inputs','outputs','depfiles']})}
finally:campaign.close()
again=m.Campaign(records,'a'*64)
try:observed['reopen']=again.publication_recovery;observed['past_outcome']=again.unit_publication_outcomes
finally:again.close()
''')
  self.assertEqual(observed,{'status':'confirmed','physical':'complete','record_sha':True,'marker_sha':True,'images':True,'reopen':'physical-only-durability-unknown','past_outcome':[]})

 def test_unit_final_sync_refuses_success_and_following_rows(self):
  observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
real=m.os.fsync;target=os.fstat(campaign.completions.fd)
def fault(fd):
 value=os.fstat(fd)
 if (value.st_dev,value.st_ino)==(target.st_dev,target.st_ino):raise OSError(5,'public unit directory sync fault')
 return real(fd)
row=m.row_for([],{},'a'*64);row.update(status='success',compiler_exit=0)
try:
 m.os.fsync=fault
 try:campaign.publish(row);observed['return']='accepted'
 except m.UnitPublicationDurabilityUnconfirmed as error:observed['return']=str(error);observed['outcome']=error.outcome['durability']['status']
 m.os.fsync=real
 try:campaign.publish(m.row_for([],{},'a'*64));observed['next']='accepted'
 except m.Refusal as error:observed['next']=str(error)
 observed['rows']=len(list((records/'records').iterdir()));observed['physical']=campaign.unit_publication_outcomes[-1]['physical_status']
finally:m.os.fsync=real;campaign.close()
''')
  self.assertEqual(observed,{'return':'unit_publication_durability_unconfirmed','outcome':'unconfirmed','next':'unit_publication_durability_unconfirmed','rows':1,'physical':'complete'})

 def test_outside_stream_failure_keeps_pair_and_blocks_new_success(self):
  observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64)
class Broken:
 def write(self,value):raise OSError(5,'public outside stream failure')
 def flush(self):raise OSError(5,'public outside stream failure')
original=sys.stderr;row=m.row_for([],{},'a'*64);row.update(status='success',compiler_exit=0)
try:
 sys.stderr=Broken()
 try:campaign.publish(row);observed['return']='accepted'
 except m.Refusal as error:observed['return']=str(error)
 sys.stderr=original
 try:campaign.retain(b'PUBLIC-AFTER-UNKNOWN');observed['next']='accepted'
 except m.Refusal as error:observed['next']=str(error)
 observed['pair']=(records/'records'/(row['invocation_id']+'.json')).is_file() and (records/'completions'/(row['invocation_id']+'.json')).is_file()
finally:sys.stderr=original;campaign.close()
''')
  self.assertEqual(observed,{'return':'unit_publication_outcome_unavailable','next':'unit_publication_durability_unconfirmed','pair':True})

 def test_live_cas_count_excess_blocks_same_process_publish_and_reopen(self):
  observed=self.child(r'''
records=pathlib.Path(config['records']);records.mkdir();campaign=m.Campaign(records,'a'*64);m.MAX_ARTIFACTS=2
try:
 campaign.retain(b'PUBLIC-ONE');campaign.retain(b'PUBLIC-TWO')
 payload=b'PUBLIC-THREE';(records/'artifacts'/hashlib.sha256(payload).hexdigest()).write_bytes(payload)
 try:campaign.publish(m.row_for([],{},'a'*64));observed['publish']='accepted'
 except m.Refusal as error:observed['publish']=str(error)
finally:campaign.close()
try:again=m.Campaign(records,'a'*64);again.close();observed['reopen']='accepted'
except m.Refusal as error:observed['reopen']=str(error)
observed['preserved']=len(list((records/'artifacts').iterdir()))
''')
  self.assertEqual(observed,{'publish':'artifact_limit','reopen':'artifact_limit','preserved':3})

 def test_fake_compiler_zero_cannot_make_main_zero_after_unit_sync_fault(self):
  operation=r'''
fake=FAKE_BODY
path=pathlib.Path(images['rustc']['path']);path.write_text(fake.replace('#!/usr/bin/env python3','#!'+sys.executable,1));path.chmod(0o755)
here=path.parent;(here/'control.json').write_text('{}');(here/'observer').mkdir()
(here/'sysroot/lib/rustlib/mock-target/lib').mkdir(parents=True);(here/'sysroot/lib/rustlib/mock-target/lib/libstd.rlib').write_bytes(b'public mock std')
source=candidate/'input.rs';source.write_text('pub fn input() -> u8 { 1 }')
records=pathlib.Path(config['records']);records.mkdir()
environment={'PATH':os.defpath,'CHIO_COMPILATION_SOURCE_ROOT':str(candidate),'CHIO_COMPILATION_RECORDS':str(records),'CHIO_COMPILATION_SOURCE_BINDING':'a'*64}
original_campaign=m.Campaign;real_sync=m.os.fsync;active=[]
class RecordingCampaign(original_campaign):
 def __init__(self,*args,**kwargs):super().__init__(*args,**kwargs);self.current_kind=None;active.append(self)
 def publish(self,row):self.current_kind=row['kind'];return super().publish(row)
def fault(fd):
 if active and active[-1].current_kind=='compilation':
  value=os.fstat(fd);target=os.fstat(active[-1].completions.fd)
  if (value.st_dev,value.st_ino)==(target.st_dev,target.st_ino):raise OSError(5,'public main unit sync fault')
 return real_sync(fd)
m.Campaign=RecordingCampaign;m.os.fsync=fault
try:
 code=m.main([str(path),str(source),'--crate-name','unit','--crate-type','rlib','--emit','dep-info,link','-o',str(candidate/'target/libunit.rlib')],environment,str(candidate))
 rows=[json.loads(p.read_bytes()) for p in (records/'records').glob('*.json')]
 unit=next(row for row in rows if row['kind']=='compilation')
 observed={'return':code,'actual_fake_exit':unit['compiler_exit'],'row_observation':unit['status'],
  'durability':active[-1].unit_publication_outcomes[-1]['durability']['status'],
  'physical':(records/unit['publication']['completion']).is_file(),
  'fake_dispatches':(here/'observer/dispatches').read_text().count('dispatch')}
finally:m.Campaign=original_campaign;m.os.fsync=real_sync
'''.replace('FAKE_BODY',repr(t.FAKE))
  observed=self.child(operation)
  self.assertEqual(observed,{'return':86,'actual_fake_exit':0,'row_observation':'success','durability':'unconfirmed','physical':True,'fake_dispatches':1})

def safe_local_control_suite():
    """Select local controls without invoking real Rust methods."""
    suite = unittest.TestSuite()
    module = sys.modules[__name__]
    for cls in [RecorderSubprocessTest, ExplicitMetadataStdinTest, RetentionBatchReconciliationTest,
                RecorderReviewRegressionTest, CompletionPublicationFailureTest,
                LinuxScopeContractTest, RetentionBatchTest, UnitPublicationTest]:
        names = (sorted(name for name in cls.__dict__ if name.startswith("test_"))
                 if cls in [RetentionBatchTest, UnitPublicationTest]
                 else unittest.defaultTestLoader.getTestCaseNames(cls))
        for name in names:
            if not name.startswith("test_actual_rustc"):
                suite.addTest(getattr(module, cls.__name__)(name))
    return suite


if __name__ == "__main__":
    if len(sys.argv) == 1:
        result = unittest.TextTestRunner(verbosity=2).run(safe_local_control_suite())
        sys.exit(not result.wasSuccessful())
    unittest.main()
