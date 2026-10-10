import copy
from pathlib import Path
import re
import shutil
import tempfile
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

    def test_split_begin_groups_retain_both_required_owners(self):
        root = Path(__file__).resolve().parents[2]
        mapping = build_map(root)
        self.assertEqual(mapping["schema"], "chio.recovery-assurance-map.v1")
        for group in ["ownership.close/cancel", "admission.intent/submit/native-project"]:
            with self.subTest(group=group):
                entries = [entry for entry in mapping["transitions"]
                           if entry["transitions"] == group]
                self.assertCountEqual(
                    [entry["function"] for entry in entries],
                    ["prepare_begin_tx", "publish_begin_tx"],
                )
                for entry in entries:
                    changed = copy.deepcopy(mapping)
                    changed["transitions"].remove(entry)
                    with self.assertRaisesRegex(
                        ValueError, "^assurance\\.stale_or_incomplete_source_map$"
                    ):
                        verify_map(root, changed)

    def _assert_missing_begin_declaration_is_refused(self, function):
        root = Path(__file__).resolve().parents[2]
        mapping = build_map(root)
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            for source in mapping["sources"]:
                destination = scratch / source["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / source["path"], destination)
            verify_map(scratch, build_map(scratch))
            owner = scratch / (
                "crates/platform/chio-store-sqlite/src/"
                "admission_operation_store/recovery/native.rs"
            )
            changed, count = re.subn(
                r"\bfn\s+" + re.escape(function) + r"\b",
                "fn missing_" + function,
                owner.read_text(),
            )
            self.assertEqual(count, 1)
            owner.write_text(changed)
            # Rebuild hashes so refusal must come from the missing declaration.
            with self.assertRaisesRegex(
                ValueError, "^assurance\\.missing_owner_or_cutpoint$"
            ):
                verify_map(scratch, build_map(scratch))

    def test_missing_prepare_begin_declaration_is_refused(self):
        self._assert_missing_begin_declaration_is_refused("prepare_begin_tx")

    def test_missing_publish_begin_declaration_is_refused(self):
        self._assert_missing_begin_declaration_is_refused("publish_begin_tx")


if __name__ == "__main__": unittest.main()
