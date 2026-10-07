import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("source_names", ROOT / "scripts/check-source-names.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SourceNamesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        subprocess.run(["git", "init", "--quiet"], cwd=self.root, check=True)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def test_new_files_and_tracked_sources_are_checked(self):
        label = "p" + str(6)
        self.write(f"crates/example/tests/recovery_{label}.rs", f"fn {label}_setup() {{}}\n")
        self.write("scripts/setup.py", 'exchange = "CHIO_' + label.upper() + '_EXCHANGE"\n')
        subprocess.run(["git", "add", "scripts/setup.py"], cwd=self.root, check=True)
        findings = list(MODULE.violations(self.root))
        self.assertEqual(len(findings), 3)
        self.assertTrue(any("source path" in line for line in findings))
        self.assertTrue(any("scripts/setup.py:1" in line for line in findings))

    def test_numbered_prose_and_task_annotations_are_rejected(self):
        phase = "Phase " + str(2)
        task = "Task " + str(3)
        self.write("crates/example/src/lib.rs", f"// {phase}: future implementation\n// {task}: wire runtime\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 2)

    def test_prose_references_to_implementation_history_are_rejected(self):
        plan = "road" + "map"
        self.write("crates/example/src/lib.rs", "\n".join([
            f"// Tracked in the security {plan}.",
            f"// The model proves two {plan} properties.",
        ]))
        self.write("spec/model.json", '{"deferred_to":"future ' + "milestone" + ' (transport qualification)"}')
        self.write(".github/workflows/release.yml", 'ref: project/' + plan + '-04-25-2026\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 4)
        self.write("crates/example/src/lib.rs", 'const RESOURCE: &str = "repo://docs/' + plan + '";\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 2)

    def test_identifiers_diagnostics_canaries_and_metadata_are_rejected(self):
        label = "p" + str(6)
        self.write("sdks/example/setup.ts", "\n".join([
            f"const {label}_result = false;",
            f"function {label}_setup() {{}}",
            f'describe("{label.upper()} contract tests", () => {{}});',
            f'console.log("{label.upper()}_CUTPOINT");',
        ]))
        self.write("fixtures/contracts.json", '{"schema":"chio.product-' + label + '-contracts.v1"}')
        self.write("crates/example/tests/knowledge.rs", 'const CANARY: &str = "private-' + label + '-canary";')
        self.write("spec/registry.json", '{"introducedBy":"cognition-market-' + "m" + str(11) + '"}')
        # A metadata suffix is still a planning label at the end of a string.
        self.assertEqual(len(list(MODULE.violations(self.root))), 7)

    def test_milestone_environment_variables_and_annotations_are_rejected(self):
        label = "M" + str(3)
        self.write("crates/example/src/lib.rs", f'const CHILD: &str = "CHIO_NATIVE_{label}_CHILD";\n// {label} implements delivery\n')
        self.write("formal/proof.toml", '"m' + str(4).zfill(2) + '_transport_assumption" = true\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 3)

    def test_compact_and_camel_case_planning_names_are_rejected(self):
        phase = "phase" + str(4)
        self.write("sdks/example/setup.ts", f"const {phase}RootHex = '';\n")
        self.write("crates/example/src/lib.rs", f'const VERSION: &str = "{phase}-preview.v1";\n')
        label = "p" + str(12)
        self.write("scripts/setup.py", f"{label}_result = False\n{label}Result = False\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 4)

    def test_compatibility_exceptions_are_exact_and_do_not_hide_other_labels(self):
        legacy = "m" + str(8).zfill(2) + "_internal_readiness_draft"
        self.write("scripts/check-release-inputs.sh", f'key="{legacy}"\n')
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write("scripts/new-release.sh", f'key="{legacy}"\n')
        self.write("scripts/check-release-inputs.sh", f'key="{legacy}"; status="p' + str(6) + '_ready"\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 2)
        self.write("scripts/check-release-inputs.sh", f'key="{legacy}_suffix"\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 2)

    def test_root_build_targets_and_symbol_suffixes_are_rejected(self):
        label = "m" + str(11)
        self.write("Makefile", f"qualify-market-{label}:\n\ttrue\n")
        phase = "Phase" + str(4)
        self.write("scripts/labels.py", f"root_{label} = False\nresult_p" + str(6) + f" = False\n{phase}RootHex = ''\nroot{phase} = ''\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 5)

    def test_protocol_ids_crypto_severity_percentiles_and_history_are_allowed(self):
        self.write("crates/example/src/lib.rs", 'const ALG: &str = "P256";\nconst SEVERITY: &str = "P1";\n')
        self.write("crates/example/benches/latency_p99.rs", "fn p99_latency() {}\nfn verify_p256_signature() {}\n")
        self.write(".github/workflows/latency.yml", 'CHIO_SUSTAINED_P99_SECONDS: "1800"\n')
        self.write("deploy/alerts.yaml", 'priority: "P1-P5"\nrunbook: "docs/operator-runbook/incidents.md#p0-criteria"\n')
        self.write("formal/proof.toml", 'property_ids = ["P' + str(1) + '", "P' + str(2) + '"]\n# P' + str(6) + '-P' + str(10) + ' proof family\n')
        self.write("deploy/archives.json", '{"libncursesw-6.5_p20250503-r0.apk":"hash"}\n')
        self.write("fixtures/metrics.json", '{"p75_ms":100,"p999_ms":1000,"p95LatencyMs":1000}\n')
        opaque = "p" + str(6) + "A" * 62
        self.write("fixtures/signature.json", '{"sig":"' + opaque + '"}\n')
        self.write("sdks/example/package-lock.json", '{"integrity":"sha512-' + opaque + '"}\n')
        self.write("scripts/options.py", 'command = ["patch", "-p0", "input"]\n')
        self.write(".github/workflows/release.yml", 'run: grep -m1 version Cargo.toml\n')
        self.write("docs/plans/history.md", "Phase " + str(6) + "\n")
        self.write("labs/openappa-recovery/evidence/source-manifest.json", '{"branch":"integration/process-security-m' + str(4) + '"}\n')
        self.write("sdks/example/node_modules/phase_" + str(7) + "/test.py", "Phase " + str(7) + "\n")
        self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_bare_phase_tokens_are_rejected_without_contextual_severity(self):
        label = "P" + str(6)
        for content in [
            f"// Added for {label} product acceptance.",
            f"// ({label.lower()})",
            "// see P" + str(0) + "-" + label + " recovery plan",
            f'const STATE: &str = "{label}";',
            "// Phase " + "six",
            'task = "task-' + str(3) + '"',
        ]:
            with self.subTest(content=content):
                self.write("crates/security/chio-recovery/src/lib.rs", content)
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_severity_or_percentile_does_not_mask_another_planning_label(self):
        label = "p" + str(6)
        self.write("crates/example/src/lib.rs", f'const SEVERITY: &str = "P1"; // {label}\n')
        self.write("fixtures/recovery-metrics.json", '{"p95_ms":10,"note":"' + label + '"}')
        self.write("deploy/alerts.yaml", 'priority: "P1-P5" # ' + label + '\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 3)

    def test_certificate_suffix_literal_does_not_mask_planning_annotations(self):
        certificate = ".p" + str(12)
        source = 'SECRET_SUFFIXES = {".key", "' + certificate + '", ".pfx"}\n'
        path = "fixtures/recovery-product/manifest_builder.py"
        self.write(path, source)
        self.assertEqual(list(MODULE.violations(self.root)), [])
        for annotation in ["P" + str(12), certificate + "-acceptance"]:
            with self.subTest(annotation=annotation):
                self.write(path, source.rstrip() + ' # ' + annotation + '\n')
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)
        self.write(path, 'label = "' + certificate + '-acceptance"\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_gate_source_uses_the_same_semantic_literal_policy(self):
        self.write("scripts/check-source-names.py", (ROOT / "scripts/check-source-names.py").read_text())
        self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_all_text_suffixes_and_extensionless_inputs_are_scanned(self):
        for name in [
            "fixtures/status.txt", "tests/replay/audit.log", "fixtures/traces.jsonl",
            "tests/replay/proptest-regressions/.gitkeep", "scripts/build-consumer",
        ]:
            self.write(name, "# " + "P" + str(6) + " acceptance\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 5)

    def test_invalid_utf8_text_fails_closed_instead_of_skipping_file(self):
        for name in ["crates/example/src/lib.rs", "fixtures/status.txt", "scripts/run-consumer"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# consumer input\n\xff\n")
        findings = list(MODULE.violations(self.root))
        self.assertEqual(len(findings), 3)
        self.assertTrue(all("UTF-8" in finding for finding in findings))

    def test_binary_assets_are_not_text_but_their_paths_are_checked(self):
        paths = ["fixtures/example.wasm", "fixtures/example.png", "fixtures/p" + str(6) + "_example.wasm"]
        for name in paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\x00asm\x01\x00\x00\x00\xff")
        findings = list(MODULE.violations(self.root))
        self.assertEqual(len(findings), 1)
        self.assertIn("source path", findings[0])

    def test_opaque_binary_seeds_and_text_svg_coordinates_are_not_labels(self):
        path = self.root / "fuzz/corpus/decode/garbage.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\xff\xff\xff")
        self.write("integrations/example/architecture.svg", '<svg><path d="M' + str(72) + ' 34H1128"/></svg>\n')
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write("fixtures/input.bin", "P" + str(6) + " planning\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_protocol_task_ids_and_ordinary_variables_are_not_planning_labels(self):
        self.write("crates/protocol/example/src/lib.rs", 'let p' + str(1) + ' = input; let task_id = "task-' + str(1) + '";\n')
        self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_url_literals_do_not_turn_protocol_identifiers_into_comment_labels(self):
        name = "crates/protocol/example/src/lib.rs"
        for source in [
            'let task_id = "task-' + str(1) + '"; let uri = "https://example.org";',
            'let p' + str(1) + ' = input; let uri = "https://example.org"; // behavioral comment',
        ]:
            with self.subTest(source=source):
                self.write(name, source)
                self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_multiline_rust_comments_cannot_hide_bare_planning_labels(self):
        name = "crates/protocol/example/src/lib.rs"
        label = "P" + str(6)
        for source in [
            f"/* Advice introduced for:\n{label} product acceptance.\n*/\nfn pure() {{}}\n",
            f"/* outer /* nested */\n{label} product acceptance.\n*/\n",
        ]:
            with self.subTest(source=source):
                self.write(name, source)
                findings = list(MODULE.violations(self.root))
                self.assertEqual(len(findings), 1)
                self.assertIn(":2:", findings[0])

    def test_multiline_literals_and_rust_attributes_do_not_become_comments(self):
        name = "crates/protocol/example/src/lib.rs"
        for source in [
            'const TASK: &str = r#"\nhttps://example.org task-' + str(1) + '\n"#;\n',
            'const TASK: &str = "\nhttps://example.org task-' + str(1) + '\n";\n',
            '#[test] fn test() { let p' + str(1) + ' = 1; }\n',
            '#[cfg(test)] fn test() { let p' + str(1) + ' = 1; } // ordinary comment\n',
        ]:
            with self.subTest(source=source):
                self.write(name, source)
                self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write(name, 'const TASK: &str = r#"\nhttps://example.org task-' + str(1) + '\n"#; // P' + str(6) + ' product acceptance\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_c_family_multiline_comments_cannot_hide_planning_labels(self):
        for suffix in ["ts", "js", "go", "cpp", "kt"]:
            with self.subTest(suffix=suffix):
                name = "sdks/example/src/probe." + suffix
                self.write(name, '/* Added for:\nP' + str(6) + ' product acceptance.\n*/\n')
                findings = list(MODULE.violations(self.root))
                self.assertTrue(any(finding.startswith(name + ":2:") for finding in findings))

    def test_c_family_multiline_literal_urls_are_not_comment_markers(self):
        for name, source in [
            ("sdks/example/src/probe.ts", 'const task = `\nhttps://example.org task-' + str(1) + '\n`;\n'),
            ("sdks/example/src/probe.go", 'task := `\nhttps://example.org task-' + str(1) + '\n`\n'),
            ("sdks/example/src/probe.kt", 'val task = """\nhttps://example.org task-' + str(1) + '\n"""\n'),
        ]:
            with self.subTest(name=name):
                self.write(name, source)
                self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_javascript_templates_keep_comments_in_interpolated_expressions(self):
        name = "sdks/example/src/probe.ts"
        self.write(name, 'const value = `${\n /* Added for:\nP' + str(6) + ' product acceptance.\n*/ input\n}`;\n')
        findings = list(MODULE.violations(self.root))
        self.assertEqual(len(findings), 1)
        self.assertIn(":3:", findings[0])
        self.write(name, 'const pattern = /["/]/; let p' + str(1) + ' = input;\n')
        self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_control_statement_regex_and_cpp_digit_separators_are_not_quotes(self):
        for name, source in [
            ("sdks/example/src/probe.js", 'if (true) /["/]/.test("input"); let p' + str(1) + ' = 1;\n'),
            ("sdks/example/src/probe.cpp", "const int limit = 1'000; int p" + str(1) + " = limit;\n"),
        ]:
            with self.subTest(name=name):
                self.write(name, source)
                self.assertEqual(list(MODULE.violations(self.root)), [])
                self.write(name, source + '/* Added for:\nP' + str(6) + ' product acceptance.\n*/\n')
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)
                self.write(name, source)

    def test_javascript_statement_blocks_and_async_iteration_keep_regex_context(self):
        name = "sdks/example/src/probe.js"
        ordinary_variable = "let p" + str(1) + " = 1;"
        for source in [
            'async function consume(iterable) { for await (const value of iterable) /["/]/.test("input"); } ',
            'if (true) {} /["/]/.test("input"); ',
            '{ if (true) {} } /["/]/.test("input"); ',
            'function consume() {} /["/]/.test("input"); ',
            'async function consume() {} /["/]/.test("input"); ',
            'class Consumer {} /["/]/.test("input"); ',
            'class Consumer extends (function() {}) {} /["/]/.test("input"); ',
            'class Consumer extends (class {}) {} /["/]/.test("input"); ',
            'export function consume() {} /["/]/.test("input"); ',
            'export class Consumer {} /["/]/.test("input"); ',
            'export default async function consume() {} /["/]/.test("input"); ',
            'try {} catch {} /["/]/.test("input"); ',
            'switch (value) { default: {} /["/]/.test("input"); } ',
            'switch (value) { case 1: {} /["/]/.test("input"); } ',
            'label: {} /["/]/.test("input"); ',
            'const value = 1\nfunction consume() {} /["/]/.test("input"); ',
            'consume()\n{} /["/]/.test("input"); ',
            'switch (value) { case condition ? 1 : 2: {} /["/]/.test("input"); } ',
            'class Consumer { consume() { label: {} /["/]/.test("input"); } } ',
            'function consume() { return\n{} /["/]/.test("input"); } ',
        ]:
            with self.subTest(source=source):
                self.write(name, source + ordinary_variable)
                self.assertEqual(list(MODULE.violations(self.root)), [])
                self.write(name, source + ordinary_variable + ' /* Added for:\nP' + str(6) + ' product acceptance.\n*/')
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_javascript_expression_values_keep_division_and_comment_context(self):
        name = "sdks/example/src/probe.js"
        ordinary_variable = "let p" + str(1) + " = 1;"
        for source in [
            'const value = {} / "https://example.org"; ',
            'const value = ({}) / "https://example.org"; ',
            'const value = function() {} / "https://example.org"; ',
            'const value = class {} / "https://example.org"; ',
            'const value = (() => {}) / "https://example.org"; ',
            'const value =\n{} / "https://example.org"; ',
            'const value =\nfunction() {} / "https://example.org"; ',
            'const value = condition ? {} : {} / "https://example.org"; ',
            'export default {} / "https://example.org"; ',
        ]:
            with self.subTest(source=source):
                self.write(name, source + ordinary_variable)
                self.assertEqual(list(MODULE.violations(self.root)), [])
                self.write(name, source + ordinary_variable + ' /* Added for:\nP' + str(6) + ' product acceptance.\n*/')
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_rust_fragments_and_jsx_literals_keep_their_language_context(self):
        for name, source in [
            ("crates/example/src/module.inc", "fn view(input: &'static str) { let p" + str(1) + " = input; }\n"),
            ("examples/interface/probe.tsx", "const p" + str(1) + " = input; const view = <div>Don't change the authority {p" + str(1) + "}</div>;\n"),
            ("sdks/example/src/probe.cpp", 'const auto value = R"JSON(https://example.org task-' + str(1) + ')JSON";\n'),
        ]:
            with self.subTest(name=name):
                self.write(name, source)
                self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_jsx_prose_and_embedded_comments_are_checked(self):
        name = "sdks/example/src/probe.tsx"
        for source, line in [
            ('const view = <div>{/* Added for:\nP' + str(6) + ' product acceptance.\n*/ input}</div>;\n', 2),
            ('const view = <div>P' + str(6) + ' product acceptance.</div>;\n', 1),
        ]:
            with self.subTest(source=source):
                self.write(name, source)
                findings = list(MODULE.violations(self.root))
                self.assertEqual(len(findings), 1)
                self.assertIn(":" + str(line) + ":", findings[0])

    def test_svg_text_and_encoded_dependency_hashes_are_distinguished(self):
        self.write("integrations/example/architecture.svg", '<svg><text>P' + str(6) + '</text></svg>\n')
        opaque = "p" + str(6) + "A" * 62
        self.write("sdks/example/go.sum", 'example.com/library v1.0.0 h1:' + opaque + '\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_severity_counts_alert_priorities_and_package_revisions_are_not_phase_labels(self):
        self.write("scripts/recovery-audit.py", 'keys = ["open_p' + str(0) + '", "open_p' + str(1) + '"]\n')
        self.write("crates/example/src/alerts.rs", "\n".join([
            "/// Alerts API priority (P" + str(1) + "-P" + str(5) + ").",
            "// Otherwise the caller would page the P" + str(0) + " fail-open alert.",
        ]))
        self.write("deploy/packages.lock", "mpfr4-4.2.1_p" + str(1) + "-r0\n")
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write("scripts/recovery-audit.py", 'keys = ["open_p' + str(0) + '"]; note = "p' + str(6) + '"\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_formal_property_references_are_distinguished_from_phase_annotations(self):
        self.write("formal/diff-tests/tests/scope.rs", "/// P" + str(1) + ": Empty scope is a subset.\n")
        self.write("formal/Proof.lean", "-- These theorems cover P" + str(6) + "-P" + str(10) + ".\n")
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write("formal/diff-tests/tests/scope.rs", "// Added for P" + str(6) + " qualification.\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_formal_property_masks_do_not_hide_unrelated_planning_labels(self):
        examples = [
            ("formal/proof.toml", 'property_ids = ["P' + str(1) + '"] # Added for P' + str(6) + ' product acceptance.\n'),
            ("formal/Proof.lean", "-- These theorems cover P" + str(6) + "-P" + str(10) + ". Added for P" + str(2) + " product acceptance.\n"),
            ("formal/diff-tests/tests/scope.rs", "/// P" + str(1) + ": Empty scope is a subset. Added for P" + str(6) + " product acceptance.\n"),
        ]
        for name, source in examples:
            with self.subTest(name=name):
                self.write(name, source)
                findings = list(MODULE.violations(self.root))
                self.assertTrue(any(finding.startswith(name + ":") for finding in findings))

    def test_lean_block_comments_keep_property_ids_and_reject_planning_prose(self):
        name = "formal/Proof.lean"
        for source, count in [
            ('/-\n  P' + str(1) + ': Capability monotonicity\n-/\n/-- P' + str(1) + ': Capability monotonicity -/\n', 0),
            ('/-\nAdvice introduced for:\nP' + str(6) + ' product acceptance.\n-/\n', 1),
            ('def uri := "https://example.org task-' + str(1) + '"\n', 0),
        ]:
            with self.subTest(source=source):
                self.write(name, source)
                findings = list(MODULE.violations(self.root))
                self.assertEqual(len(findings), count)
                if count:
                    self.assertIn(":3:", findings[0])

    def test_formal_semantic_citations_do_not_suppress_other_annotations(self):
        name = "formal/Proof.lean"
        for source in [
            '/-\nProofs for capability monotonicity (P' + str(1) + ') and related properties.\n-/\n',
            '/-\nThese theorems make the P' + str(3) + '\nfail-closed claim machine-checked and connect revoked tokens\nto denial results for P' + str(2) + '.\n-/\n',
            '/-\nThis closes the P' + str(0) + ' soundness gap in chain binding.\n-/\n',
        ]:
            with self.subTest(source=source):
                self.write(name, source)
                self.assertEqual(list(MODULE.violations(self.root)), [])
                self.write(name, source + '-- Added for P' + str(6) + ' product acceptance.\n')
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_existing_append_only_replay_audit_is_the_only_historical_log_exception(self):
        label = "M" + str(4).zfill(2)
        self.write("tests/replay/.bless-audit.log", "# Historical " + label + " replay acceptance\n")
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write("tests/replay/new-audit.log", "# New " + label + " replay acceptance\n")
        findings = list(MODULE.violations(self.root))
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].startswith("tests/replay/new-audit.log:"))

    def test_text_source_cannot_hide_labels_by_inserting_binary_bytes(self):
        path = self.root / "scripts/example.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"\x00# invalid source\n")
        findings = list(MODULE.violations(self.root))
        self.assertEqual(len(findings), 1)
        self.assertIn("text", findings[0])

    def test_legacy_acceptance_field_is_not_a_general_symbol_exception(self):
        key = "m" + str(5) + "_acceptance_complete"
        path = "crates/products/chio-cli/src/process/commands/status.rs"
        self.write(path, f'const {key.upper()}: bool = false;\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_legacy_output_key_is_only_permitted_at_the_serialized_interface(self):
        key = "m" + str(5) + "_acceptance_complete"
        name = "crates/products/chio-cli/src/cli/process_host/call_evidence.rs"
        self.write(name, 'json!({"' + key + '": false});\n')
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write(name, 'const ' + key.upper() + ': bool = false;\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)
        self.write(name, 'json!({"' + key + '": false, "note":"p' + str(6) + '"});\n')
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)
        for source in ['// "' + key + '": false\n', 'const TEXT: &str = r#"{"' + key + '":false}"#;\n']:
            with self.subTest(source=source):
                self.write(name, source)
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_legacy_property_exception_requires_an_asserted_property_access(self):
        key = "m" + str(5) + "_acceptance_complete"
        name = "crates/products/chio-cli/tests/process_call_evidence.rs"
        self.write(name, 'assert_eq!(report["' + key + '"], false);\n')
        self.assertEqual(list(MODULE.violations(self.root)), [])
        for source in ['let keys = ["' + key + '"];\n', '// report["' + key + '"]\n']:
            with self.subTest(source=source):
                self.write(name, source)
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_historical_registry_provenance_is_exact_to_its_record_field_and_value(self):
        historical = "cognition-market-m" + str(11)
        name = "spec/schemas/registry.json"
        record = {"schema": "chio.finding.bond-observation-request.v1", "introducedBy": historical}
        self.write(name, json.dumps({"artifacts": [record]}, indent=2))
        self.assertEqual(list(MODULE.violations(self.root)), [])
        for mutation in ["record", "field", "value", "another_label"]:
            with self.subTest(mutation=mutation):
                changed = dict(record)
                if mutation == "record":
                    changed["schema"] = "chio.other.v1"
                elif mutation == "field":
                    changed["note"] = changed.pop("introducedBy")
                elif mutation == "value":
                    changed["introducedBy"] += "-p" + str(6)
                else:
                    changed["note"] = "p" + str(6)
                self.write(name, json.dumps({"artifacts": [changed]}, indent=2))
                self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_historical_coverage_provenance_is_scoped_to_the_record(self):
        label = "M" + str(10)
        name = "spec/security/coverage.yaml"
        self.write(name, "threats:\n  - id: passkey_credential_theft\n    owned_by: " + label + "\n")
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write(name, "threats:\n  - id: new_threat\n    owned_by: " + label + "\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 1)

    def test_provenance_control_is_pinned_and_cannot_grandfather_new_labels(self):
        name = "scripts/source-name-provenance.json"
        self.write(name, (ROOT / name).read_text())
        self.assertEqual(list(MODULE.violations(self.root)), [])
        self.write(name, '{"schema":"chio.source-name-provenance/v1","files":[]}\n')
        findings = list(MODULE.violations(self.root))
        self.assertEqual(len(findings), 1)
        self.assertIn("provenance", findings[0])

    def test_clean_behavioral_names_pass(self):
        self.write("crates/example/tests/recovery_confinement.rs", "fn parent_return_is_bounded() {}\n")
        self.write("fixtures/example.py", 'schema = "chio.recovery-product-contract-vectors.v1"\n')
        self.assertEqual(list(MODULE.violations(self.root)), [])

    def test_included_source_fragments_and_native_build_inputs_are_checked(self):
        label = "p" + str(5)
        for name in [
            "crates/example/src/handler.inc", "sdks/example/peer.cc", "sdks/example/peer.hxx",
            "sdks/example/Peer.swift", "sdks/example/Peer.kt", "sdks/example/Peer.cs",
        ]:
            self.write(name, f"// Phase {str(5)} implementation\n")
        for name in ["Dockerfile", "Dockerfile.sidecar", "Worker.Dockerfile"]:
            self.write(f"deploy/example/{name}", f"ENV CHIO_{label.upper()}_EXCHANGE=example\n")
        for name in ["Dockerfile.sidecar", "Worker.Dockerfile"]:
            self.write(name, f"ENV CHIO_{label.upper()}_EXCHANGE=example\n")
        self.write("CMakeLists.txt", f"set(CHIO_{label.upper()}_FIXTURES example)\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), 12)

    def test_first_party_runner_binding_and_release_inputs_are_checked(self):
        names = [
            ".clusterfuzzlite/Dockerfile", ".config/nextest.toml", ".dst/harnesses.toml",
            ".kani/harnesses.toml", ".loom/harnesses.toml", "arena/scenarios/example.toml",
            "ci-gates/runtime.toml", "config/example.json", "contracts/src/Contract.sol",
            "labs/example/src/lib.rs", "packaging/example.rb.tmpl", "supply-chain/config.toml",
            "wit/guards/world.wit",
        ]
        for name in names:
            self.write(name, "// Phase " + str(6) + " implementation\n")
        self.assertEqual(len(list(MODULE.violations(self.root))), len(names))


    @staticmethod
    def historical_artifact_prefixes():
        base = "docs/architecture/recoverable-agent-runtime/implementation"
        return (
            "docs/integrations/acceptance",
            *(f"{base}/p{number}/evidence" for number in range(7)),
            "sdks/python/chio-hermes/evidence", "audits/evidence",
            "docs/integrations/session-credentials/evidence", "docs/evidence",
            "docs/research/openappa-2026-10-01/evidence", "labs/openappa-recovery/evidence",
            "formal/mutation/evidence",
        )

    def check_source_case(self, name, content, *, refused):
        self.write(name, content)
        try:
            findings = list(MODULE.violations(self.root))
            if refused:
                self.assertTrue(findings, "prohibited source trace was accepted")
            else:
                self.assertEqual(findings, [])
        finally:
            (self.root / name).unlink()

    def test_closed_historical_artifact_locators_are_data_in_exact_sites(self):
        source = "ARTIFACT_PREFIXES = " + repr(self.historical_artifact_prefixes()) + "\n"
        for name in ["fixtures/recovery-product/manifest_builder.py", "scripts/verify-recovery-qualification.py", "scripts/run-confined-return-linux-acceptance.py"]:
            with self.subTest(name=name):
                values = self.historical_artifact_prefixes()
                if name == "scripts/run-confined-return-linux-acceptance.py":
                    values = tuple(sorted(values))
                self.check_source_case(name, "ARTIFACT_PREFIXES = " + repr(values) + "\n", refused=False)

    def test_historical_locator_values_do_not_grandfather_other_locations_and_notes(self):
        prefixes = self.historical_artifact_prefixes()
        source = "ARTIFACT_PREFIXES = " + repr(prefixes) + "\n"
        changed = prefixes[:2] + (prefixes[2] + "/other",) + prefixes[3:]
        extra = prefixes + (prefixes[1].replace("p" + str(0), "p" + str(7)),)
        approved = "fixtures/recovery-product/manifest_builder.py"
        cases = [
            ("scripts/new-builder.py", source),
            (approved, "OTHER_PREFIXES = " + repr(prefixes) + "\n"),
            (approved, source + "# " + prefixes[1] + "\n"),
            (approved, source + "COPY = " + repr(prefixes[1]) + "\n"),
            (approved, "ARTIFACT_PREFIXES = " + repr(changed) + "\n"),
            (approved, "ARTIFACT_PREFIXES = " + repr(extra) + "\n"),
            (approved, source + source),
            (approved, "def copied():\n    ARTIFACT_PREFIXES = " + repr(prefixes) + "\n"),
            (approved, "ARTIFACT_PREFIXES = list(" + repr(prefixes) + ")\n"),
        ]
        for number, (name, content) in enumerate(cases):
            with self.subTest(number=number, name=name):
                self.check_source_case(name, content, refused=True)

    def test_source_editing_workflow_comments_are_rejected(self):
        controller = "Root"
        cases = [
            ("crates/example/src/lifecycle.rs", f"// Append inside the owning tests after {controller}'s source lease.\npub fn lifecycle() {{}}\n"),
            ("scripts/check-behavior.py", f"# Sub-agent draft; merge after {controller}'s compiler lease is released.\nVALUE = 1\n"),
            ("sdks/typescript/behavior.ts", "// TODO: append the owning worker's draft after the source lease.\nexport const bounded = true;\n"),
        ]
        for name, content in cases:
            with self.subTest(name=name):
                self.check_source_case(name, content, refused=True)

    def test_delivery_task_draft_and_generated_description_labels_are_rejected(self):
        task = "A" + str(3) + "." + str(5)
        delivery = "W" + str(2) + "." + str(3)
        cases = [
            (".kani/harnesses.toml", f"# {task} commented draft but does not exist in this PR's harness file\nversion = 1\n"),
            ("spec/schema.json", json.dumps({"description": delivery + " lifecycle for the public-witness lane."})),
        ]
        for name, content in cases:
            with self.subTest(name=name):
                self.check_source_case(name, content, refused=True)

    def test_execution_owner_diagnostics_and_test_stage_notes_are_rejected(self):
        controller = "Root"
        source = f"import unittest\n@unittest.skipIf(False, 'Linux enforcement belongs to explicit {controller} probes')\ndef test_refusal(): pass\n"
        cases = [
            ("scripts/tests/check-behavior.test.py", source),
            ("crates/example/src/cleanup.rs", "// Release queued work before the expected " + "RED" + ".\npub fn cleanup() {}\n"),
        ]
        for name, content in cases:
            with self.subTest(name=name):
                self.check_source_case(name, content, refused=True)

    def test_runtime_root_contracts_and_compatibility_prose_remain_allowed(self):
        legacy_key = "m" + str(5) + "_acceptance_complete"
        cases = [
            ("crates/example/src/root.rs", "// The Root process owns the child process lifecycle.\npub enum Actor { Root }\n"),
            ("sdks/go/lease.go", "package lease\n// Root renews its authority lease under the runtime contract.\ntype Root struct {}\n"),
            ("scripts/process-model.py", "# The Root process waits for its worker response.\nclass Root: pass\ntodo = [Root]\n"),
            ("sdks/typescript/runtime.ts", "// The Root type binds the originating subject.\nexport type Root = { contract: string };\n"),
            ("spec/schema.json", json.dumps({"$schema": "https://json-schema.org/draft/2020-12/schema"})),
            ("sdks/go/schema.go", "package schema\n// JSON Schema draft 2020-12 describes the current byte contract.\n"),
            ("sdks/python/_generated/model.py", "# Generated from the schema; do not edit.\n# Source: spec/schemas/behavior.schema.json\nclass Root: pass\n"),
            ("scripts/tests/refusal.test.py", "# RED and GREEN controls verify refusal and admission behavior.\nVALUE = 1\n"),
            ("crates/products/chio-cli/src/cli/process_host/call_evidence.rs", 'fn output() { let body = json!({' + json.dumps(legacy_key) + ': false}); }\n'),
            ("crates/products/chio-cli/tests/fixtures/process-call-observation/provenance.json", json.dumps({legacy_key: False})),
            ("formal/props.toml", 'required_property_ids = ' + json.dumps(["P" + str(number) for number in (1, 2, 4)]) + '\n'),
        ]
        for name, content in cases:
            with self.subTest(name=name):
                self.check_source_case(name, content, refused=False)

    def test_workflow_literals_are_data_but_neighboring_comments_are_still_checked(self):
        controller = "Root"
        text = f"Append inside the owning tests after {controller}'s source lease."
        self.check_source_case("crates/example/src/data.rs", 'const TEXT: &str = ' + json.dumps("// " + text) + ';\n', refused=False)
        self.check_source_case("scripts/probe.py", "VALUE = " + repr("# " + text) + "\n", refused=False)
        self.check_source_case("scripts/probe.py", "VALUE = " + repr("# " + text) + " # " + text + "\n", refused=True)


    def test_unicode_comment_separators_preserve_physical_locator_lines(self):
        name = "fixtures/recovery-product/manifest_builder.py"
        for separator in ["\u2028", "\u2029", "\x85"]:
            with self.subTest(separator=repr(separator)):
                source = "# Résumé" + separator + " harmless metadata\nARTIFACT_PREFIXES = " + repr(self.historical_artifact_prefixes()) + "\n"
                self.check_source_case(name, source, refused=False)

    def test_unicode_comment_headers_do_not_hide_skip_diagnostics(self):
        controller = "Root"
        name = "scripts/check-behavior.py"
        for separator in ["\u2028", "\u2029", "\x85"]:
            with self.subTest(separator=repr(separator)):
                source = "# Résumé" + separator + " harmless metadata\nimport unittest\n" + f"@unittest.skipIf(False, 'Linux enforcement belongs to explicit {controller} probes')\ndef test_refusal(): pass\n"
                self.write(name, source)
                findings = list(MODULE.violations(self.root))
                self.assertTrue(findings)
                self.assertTrue(all("invalid" not in value for value in findings))

    def test_unicode_docstring_separators_preserve_workflow_prose(self):
        controller = "Root"
        source = '"""Résumé\u2028' + f"Append after {controller}'s source lease." + '"""\nVALUE = 1\n'
        self.check_source_case("scripts/check-behavior.py", source, refused=True)

    def test_non_ascii_skip_predicates_use_utf8_ast_columns(self):
        controller = "Root"
        source = f"import unittest\n@unittest.skipIf('café' == '', 'Linux enforcement belongs to explicit {controller} probes')\ndef test_refusal(): pass\n"
        self.check_source_case("scripts/check-behavior.py", source, refused=True)


    def test_all_syntactic_artifact_bindings_preclude_historical_masking(self):
        source = "ARTIFACT_PREFIXES = " + repr(self.historical_artifact_prefixes()) + "\n"
        bindings = [
            "def ARTIFACT_PREFIXES():\n    pass\n",
            "async def ARTIFACT_PREFIXES():\n    pass\n",
            "class ARTIFACT_PREFIXES:\n    pass\n",
            "import json as ARTIFACT_PREFIXES\n",
            "from os import path as ARTIFACT_PREFIXES\n",
            "try:\n    raise ValueError()\nexcept ValueError as ARTIFACT_PREFIXES:\n    pass\n",
            "match 1:\n    case ARTIFACT_PREFIXES:\n        pass\n",
            "match []:\n    case [*ARTIFACT_PREFIXES]:\n        pass\n",
            "match {}:\n    case {**ARTIFACT_PREFIXES}:\n        pass\n",
            "def consumer(ARTIFACT_PREFIXES):\n    pass\n",
            "from os import *\n",
        ]
        for name in ["fixtures/recovery-product/manifest_builder.py", "scripts/verify-recovery-qualification.py", "scripts/run-confined-return-linux-acceptance.py"]:
            prefix = source
            if name == "scripts/run-confined-return-linux-acceptance.py":
                prefix = "ARTIFACT_PREFIXES = " + repr(tuple(sorted(self.historical_artifact_prefixes()))) + "\n"
            for binding in bindings:
                with self.subTest(name=name, binding=binding):
                    self.check_source_case(name, prefix + binding, refused=True)

    def test_expected_red_fixture_contract_prose_remains_allowed(self):
        comment = "The invalid fixture produces the expected " + "RED; the admitted fixture produces GREEN."
        cases = [
            ("scripts/tests/guard_behavior.test.py", "# " + comment + "\nVALUE = 1\n"),
            ("crates/example/tests/guard_behavior.rs", "// " + comment + "\nfn fixtures() {}\n"),
            ("sdks/typescript/guard_behavior.test.ts", "// " + comment + "\nexport const fixture = true;\n"),
        ]
        for name, source in cases:
            with self.subTest(name=name):
                self.check_source_case(name, source, refused=False)

    def test_python_non_docstring_expressions_are_literal_data(self):
        controller = "Root"
        reason = f"Append after {controller}'s source lease."
        source = "import os\nif os.environ.get('CONTROL'):\n    " + repr(reason) + "\n"
        self.check_source_case("scripts/probe.py", source, refused=False)

    def test_all_known_unittest_skip_reason_spellings_are_checked(self):
        controller = "Root"
        reason = repr(f"Linux enforcement belongs to explicit {controller} probes")
        decorators = [
            "unittest.skipIf(False, reason=" + reason + ")",
            "unittest.skipUnless(True, reason=" + reason + ")",
            "unittest.skip(" + reason + ")",
            "unittest.skip(reason=" + reason + ")",
            "unittest.skipIf(condition=False, reason=" + reason + ")",
            "unittest.skipUnless(condition=True, reason=" + reason + ")",
        ]
        for decorator in decorators:
            with self.subTest(decorator=decorator):
                source = "import unittest\n@" + decorator + "\ndef test_refusal(): pass\n"
                self.check_source_case("scripts/tests/refusal.test.py", source, refused=True)


    def test_guard_and_regression_sources_keep_behavioral_names(self):
        for name in ["scripts/check-source-names.py", "scripts/tests/check-source-names.test.py"]:
            self.write(name, (ROOT / name).read_text())
        self.assertEqual(list(MODULE.violations(self.root)), [])


    def test_python_unicode_separators_preserve_physical_diagnostic_coordinates(self):
        controller = "Root"
        name = "scripts/tests/behavior.py"
        for separator in ["\u2028", "\u2029", "\x85"]:
            with self.subTest(separator=repr(separator)):
                source = "# Résumé" + separator + " harmless metadata\nimport unittest\n" + f"@unittest.skipIf(False, 'Linux enforcement belongs to explicit {controller} probes')\ndef test_refusal(): pass\n"
                self.write(name, source)
                self.assertEqual(list(MODULE.violations(self.root)), [name + ":3: numbered planning label in source"])
        source = '"""Résumé\u2028' + f"Append after {controller}'s source lease." + '"""\nVALUE = 1\n'
        self.write(name, source)
        self.assertEqual(list(MODULE.violations(self.root)), [name + ":1: numbered planning label in source"])

    def test_empty_and_trailing_newline_python_sources_remain_valid(self):
        name = "scripts/empty.py"
        for source in ["", "\n", "VALUE = 1\n", "# metadata\u2028 harmléss\nVALUE = 1\n"]:
            with self.subTest(source=repr(source)):
                self.check_source_case(name, source, refused=False)


if __name__ == "__main__":
    unittest.main()
