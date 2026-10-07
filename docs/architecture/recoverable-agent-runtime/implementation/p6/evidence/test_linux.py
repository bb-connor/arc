"""Actual cage cases stay distinct from broader native P5 regressions."""
from pathlib import Path
import unittest

import package_record


class LinuxCaseInventoryTest(unittest.TestCase):
    def test_full_recovery_log_counts_exact_ten_linux_cage_cases(self):
        log = (Path(__file__).parent / "final-linux/native-recovery-full.log").read_text()
        cases = package_record.p5_linux_cases(log)
        self.assertEqual(len(cases), 10)
        self.assertTrue(all(case.startswith("p5_linux_") for case in cases))
        self.assertNotIn("p5_native_sensitive_observation_waits_for_real_enforcement", cases)
        altered = log.replace("p5_linux_absolute_deadline_kills_a_held_handle_without_parent_io ... ok",
                              "p5_linux_absolute_deadline_kills_a_held_handle_without_parent_io ... ignored")
        with self.assertRaises(ValueError):
            package_record.p5_linux_cases(altered)
        with self.assertRaises(ValueError):
            package_record.p5_linux_cases(log + log)


if __name__ == "__main__":
    unittest.main()
