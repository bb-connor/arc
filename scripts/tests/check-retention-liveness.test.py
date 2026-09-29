#!/usr/bin/env python3
"""Refuse incomplete retention evidence, even if libtest printed success."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("retention", Path(__file__).resolve().parents[1] / "check-retention-liveness.py")
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


class EvidenceTests(unittest.TestCase):
    def test_requires_terminal_ordered_complete_cases(self):
        success = "test result: ok. 1 passed; 0 failed; 0 ignored;\n"
        lines = [f"retention diagnostic case={i} phase=complete\n" for i in range(2)]
        complete = "".join(lines) + success
        self.assertTrue(retention.qualified(complete, 0, False, 2))
        for log, code, timeout in [(complete, -15, False), (complete, 0, True),
                                    (lines[0]+success, 0, False),
                                    ("".join(reversed(lines))+success, 0, False),
                                    (complete+lines[0], 0, False), ("".join(lines), 0, False)]:
            with self.subTest(log=log, code=code, timeout=timeout):
                self.assertFalse(retention.qualified(log, code, timeout, 2))


if __name__ == "__main__":
    unittest.main()
