import copy
from pathlib import Path
import unittest
from assurance_map import build_map, verify_map


class AssuranceMapTest(unittest.TestCase):
    def test_exact_source_and_complete_system_claim_cannot_be_substituted(self):
        root = Path(__file__).resolve().parents[2]
        mapping = build_map(root)
        verify_map(root, mapping)
        self.assertFalse(mapping["full_system_proof"])
        for mutation in ["hash", "claim"]:
            changed = copy.deepcopy(mapping)
            if mutation == "hash": changed["sources"][0]["sha256"] = "0"*64
            else: changed["full_system_proof"] = True
            with self.assertRaises(ValueError): verify_map(root, changed)


if __name__ == "__main__": unittest.main()
