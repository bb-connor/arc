#!/usr/bin/env python3
"""Calibrate the clock bypass gate against code, aliases, strings and comments."""
import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("security_clocks", root / "scripts/check-security-clocks.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ClockGateTests(unittest.TestCase):
    def test_ambient_calls_and_new_ports_are_caught(self):
        found = gate.sites("owner.rs", """
            use std::time::SystemTime as RawTime;
            trait AnotherClock { fn now(&self); }
            fn admit() { SystemTime::now(); RawTime::now(); }
        """)
        self.assertEqual(found["owner.rs::admit"], 2)
        self.assertEqual(found["owner.rs::trait AnotherClock"], 1)

    def test_documentation_and_native_adapter_are_not_debt(self):
        self.assertEqual(gate.sites("owner.rs", '''
            // SystemTime::now()
            /* trait ThirdClock {} */
            fn example() { let text = r#"SystemTime::now()"#; }
        '''), {})
        self.assertEqual(gate.sites(gate.ADAPTER, "fn read() { SystemTime::now(); }"), {})
        self.assertEqual(gate.sites(gate.PORT, "trait Clock {}"), {})


if __name__ == "__main__":
    unittest.main()
