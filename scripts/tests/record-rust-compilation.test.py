"""Subprocess regression controls and actual standalone rustc recorder evidence."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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


class ActualRustCompilerTest(unittest.TestCase):
    def test_pinned_standalone_dependency_and_compiler_failure(self):
        self.assertTrue(TOOL.is_file(), "actual compiler recorder is missing")
        selected = subprocess.run(["rustup", "which", "--toolchain", "1.94.1", "rustc"],
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
        invocations = [
            [str(dependency), "--crate-name", "dependency", "--crate-type", "rlib", "--edition", "2021",
             "--emit", "dep-info,link", "-o", str(candidate / "target/libdependency.rlib")],
            [str(root), "--crate-name", "consumer", "--crate-type", "rlib", "--edition", "2021",
             "--extern", "dependency="+str(candidate / "target/libdependency.rlib"),
             "--emit", "dep-info,link", "-o", str(candidate / "target/libconsumer.rlib")],
            [str(broken), "--crate-type", "rlib", "--emit", "dep-info,link", "-o", str(candidate / "target/libbroken.rlib")]]
        summaries = []
        print_args = ["-", "--crate-name", "___", "--print=file-names", "--crate-type", "bin", "--crate-type", "rlib",
                      "--print=sysroot", "--print=split-debuginfo", "--print=crate-name", "--print=cfg"]
        probe_result = subprocess.run([sys.executable, str(TOOL), selected, *print_args], cwd=candidate,
                                      env=env, capture_output=True, timeout=30)
        (base / "cargo-print-probe.stdout").write_bytes(probe_result.stdout)
        (base / "cargo-print-probe.stderr").write_bytes(probe_result.stderr)
        self.assertEqual(probe_result.returncode, 0, probe_result.stderr)
        for index, args in enumerate(invocations):
            result = subprocess.run([sys.executable, str(TOOL), selected, *args], cwd=candidate,
                                    env=env, capture_output=True, timeout=180)
            (base / f"invocation-{index}.stdout").write_bytes(result.stdout)
            (base / f"invocation-{index}.stderr").write_bytes(result.stderr)
            summaries.append({"index": index, "exit": result.returncode})
            if index < 2:
                self.assertEqual(result.returncode, 0, result.stderr)
            else:
                self.assertEqual(result.returncode, 1, result.stderr)
        rows = [json.loads(p.read_text()) for p in (campaign / "records").glob("*.json")]
        units = [r for r in rows if r["kind"] == "compilation"]
        self.assertEqual(sorted(r["status"] for r in units), ["compiler_failed", "success", "success"])
        dep_output = next(i for r in units for i in r["outputs"] if i["path"].endswith("libdependency.rlib"))
        extern = next(i for r in units for i in r["inputs"] if i["role"] == "extern")
        self.assertEqual(dep_output["sha256"], extern["sha256"])
        (base / "summary.json").write_text(json.dumps({"invocations": summaries, "campaign": str(campaign),
            "compiler": selected, "compiler_sha256": hashlib.sha256(Path(selected).read_bytes()).hexdigest(),
            "source_binding": source_binding, "recorder_sha256": hashlib.sha256(TOOL.read_bytes()).hexdigest(),
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
import copy,hashlib,importlib.util,json,os,pathlib,subprocess,sys
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
unit=candidate/'target/libchio_credentials.rmeta';unit.write_bytes(b'rmeta public primitive image')
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
    """Select 106 reviewed local controls without invoking real Rust methods."""
    suite = unittest.TestSuite()
    module = sys.modules[__name__]
    for cls in [RecorderSubprocessTest, RecorderReviewRegressionTest, CompletionPublicationFailureTest,
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
