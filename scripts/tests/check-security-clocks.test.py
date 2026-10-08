#!/usr/bin/env python3
"""Calibrate the clock bypass gate against code, aliases, strings and comments."""

import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "security_clocks", root / "scripts/check-security-clocks.py"
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ClockGateTests(unittest.TestCase):
    def test_ambient_calls_and_new_ports_are_caught(self):
        found = gate.sites(
            "owner.rs",
            """
            use std::time::SystemTime as RawTime;
            trait AnotherClock { fn now(&self); }
            fn admit() { SystemTime::now(); RawTime::now(); }
        """,
        )
        self.assertEqual(found["owner.rs::admit"], 2)
        self.assertEqual(found["owner.rs::trait AnotherClock"], 1)

    def test_protocol_clock_aliases_are_caught(self):
        found = gate.sites(
            "protocol.rs",
            """
            use chrono::Utc as Wall;
            fn dispatch() { Utc::now(); Wall::now(); }
        """,
        )
        self.assertEqual(found["protocol.rs::dispatch"], 2)
        for owner in ("mcp-edge", "mcp-adapter", "a2a-adapter", "openai-adapter"):
            self.assertIn(f"crates/protocol/chio-{owner}/", gate.ROOTS)

    def test_documentation_and_native_adapter_are_not_debt(self):
        self.assertEqual(
            gate.sites(
                "owner.rs",
                """
            // SystemTime::now()
            /* trait ThirdClock {} */
            fn example() { let text = r#"SystemTime::now()"#; }
        """,
            ),
            {},
        )
        self.assertEqual(
            gate.sites(gate.ADAPTER, "fn read() { SystemTime::now(); }"), {}
        )
        self.assertEqual(gate.sites(gate.PORT, "trait Clock {}"), {})

    def test_function_paths_aliases_and_elapsed_epoch_are_caught(self):
        cases = [
            "fn admit() { option.unwrap_or_else(SystemTime::now); }",
            "type Wall = std::time::SystemTime; fn admit() { Wall::now(); }",
            "use std::time::{SystemTime as Wall}; fn admit() { Wall::now(); }",
            "fn admit() { std::time::UNIX_EPOCH.elapsed(); }",
            "fn admit() { time::OffsetDateTime::now_utc(); }",
            "use chrono::Local as Wall; fn admit() { Wall::now(); }",
            "fn admit() { Clock::unix_millis(&SystemClock); }",
            "use chio_security_types::clock::SystemClock as Host; fn admit() { Host.read(); }",
            "trait TimeSource { fn read(&self) -> Result<ClockReading, Error>; }",
        ]
        for source in cases:
            with self.subTest(source=source):
                self.assertTrue(gate.sites("owner.rs", source), source)

    def test_process_host_and_every_tcb_library_are_scanned(self):
        import json

        paths = json.loads(
            (root / "docs/security/toolchain/rust-hardening.json").read_text()
        )["tcb_libraries"].values()
        for path in [
            *paths,
            "crates/products/chio-cli/src/cli/process_host/native_broker.rs",
        ]:
            with self.subTest(path=path):
                self.assertTrue(path.startswith(gate.ROOTS), path)

    def test_database_time_cannot_bypass_the_owner_clock(self):
        sources = [
            'fn capture() { query("SELECT unixepoch()"); }',
            "fn capture() { query(r#\"SELECT strftime('%s','now')\"#); }",
            'fn capture() { query("SELECT CURRENT_TIMESTAMP, now()"); }',
            r'fn capture() { query("SELECT unixepoch(\"now\")"); }',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertTrue(
                    gate.sites("owner.rs", source)["owner.rs::capture::sql-clock"]
                )
        self.assertFalse(
            gate.sites("owner.rs", "/* SELECT unixepoch() */ // CURRENT_TIMESTAMP")
        )

    def test_inventory_only_debt_increase_is_rejected(self):
        import json

        baseline = json.loads(
            (root / "scripts/security-clock-inventory.json").read_text()
        )
        baseline["expanded_preexisting_sites"][
            "crates/products/chio-cli/src/cli/process_host/native_broker.rs::new_bypass"
        ] = 1
        with self.assertRaisesRegex(ValueError, "absent from base source"):
            gate.allowed_sites(root, baseline)

    def test_inventory_only_native_composition_promotion_is_rejected(self):
        import json

        baseline = json.loads(
            (root / "scripts/security-clock-inventory.json").read_text()
        )
        baseline["composition_sites"].append("owner.rs::admit::native-adapter")
        with self.assertRaisesRegex(ValueError, "source-pinned owners"):
            gate.allowed_sites(root, baseline)

    def test_native_effect_factory_is_a_bounded_reviewed_composition(self):
        import json
        import shutil
        import tempfile

        key = (
            "crates/platform/chio-control-plane/src/security/adapters/effect_port/"
            "dispatch.rs::production::native-adapter"
        )
        baseline = json.loads(
            (root / "scripts/security-clock-inventory.json").read_text()
        )
        allowed = gate.allowed_sites(root, baseline)
        self.assertEqual(allowed[key], 1)
        self.assertNotIn(key, baseline["sites"])
        self.assertNotIn(key, baseline["expanded_preexisting_sites"])
        path, owner, _ = key.split("::")
        self.assertEqual(gate.sites(path, (root / path).read_text())[key], 1)
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            paths = {
                gate.SCOPE_EVIDENCE,
                *(contract.split("::")[0] for contract in gate.COMPOSITION_CONTRACTS),
            }
            for source_path in paths:
                (fixture / source_path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / source_path, fixture / source_path)
            source = (fixture / path).read_text()
            (fixture / path).write_text(
                source + f"\nimpl Other {{ fn {owner}() {{ SystemClock.read(); }} }}\n"
            )
            with self.assertRaisesRegex(ValueError, "composition source changed"):
                gate.allowed_sites(fixture, baseline)

    def test_reviewed_composition_does_not_permit_another_observation(self):
        import json
        import shutil
        import tempfile

        baseline = json.loads(
            (root / "scripts/security-clock-inventory.json").read_text()
        )
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            paths = {
                gate.SCOPE_EVIDENCE,
                *(key.split("::")[0] for key in gate.COMPOSITION_CONTRACTS),
            }
            for path in paths:
                (fixture / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / path, fixture / path)
            key = next(iter(gate.COMPOSITION_CONTRACTS))
            path, owner, _ = key.split("::")
            source = (fixture / path).read_text()
            # A second impl with the same method cannot borrow the original permit.
            (fixture / path).write_text(
                source + f"\nimpl Other {{ fn {owner}() {{ SystemClock.read(); }} }}\n"
            )
            with self.assertRaisesRegex(ValueError, "composition source changed"):
                gate.allowed_sites(fixture, baseline)

    def test_real_source_categories_are_disjoint_and_bounded(self):
        import json

        baseline = json.loads(
            (root / "scripts/security-clock-inventory.json").read_text()
        )
        allowed = gate.allowed_sites(root, baseline)
        evidence = json.loads((root / gate.SCOPE_EVIDENCE).read_text())
        for category in ("sites", "expanded_preexisting_sites"):
            for key, count in baseline[category].items():
                self.assertLessEqual(count, evidence["sites"][key])
        self.assertTrue(allowed)


if __name__ == "__main__":
    unittest.main()
