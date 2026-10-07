"""Published adapter and installation metrics must reproduce their real inputs."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

import package_measurements


class AdoptionAuditTest(unittest.TestCase):
    def test_unmeasured_savings_or_changed_adapter_and_cli_counts_refuse(self):
        phase = Path(__file__).parent.parent
        metrics = json.loads((phase / "adoption-metrics.json").read_bytes())
        package_measurements.audit_adoption(metrics)
        for mutation in ["lines", "bytes", "file", "savings", "cli"]:
            changed = deepcopy(metrics)
            if mutation == "lines":
                changed["measured_source_files"][0]["lines"] += 1
            elif mutation == "bytes":
                changed["measured_source_files"][0]["bytes"] += 1
            elif mutation == "file":
                changed["measured_source_files"].pop()
            elif mutation == "savings":
                changed["supervisory_code_removed_lines"] = 1
            else:
                changed["cli"]["effects"] = 0
            with self.assertRaises(ValueError, msg=mutation):
                package_measurements.audit_adoption(changed)


if __name__ == "__main__":
    unittest.main()
