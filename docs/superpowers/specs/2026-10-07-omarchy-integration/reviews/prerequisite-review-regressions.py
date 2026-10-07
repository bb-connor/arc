#!/usr/bin/env python3
"""Exercise prerequisite-plan examples and their oracles, never runtime gates."""

import copy
import json
from pathlib import Path
import re
import types
import unittest


SPEC_DIR = Path(__file__).resolve().parents[1]
PLAN_DIR = SPEC_DIR.parents[1] / "plans/2026-10-07-omarchy-integration"
PLAN = PLAN_DIR / "00-native-prerequisites.md"
DOCUMENT = PLAN.read_text()
REQUIREMENTS = json.loads(re.findall(r"^```json\n(.*?)^```", DOCUMENT, re.M | re.S)[0])
SELECTED_TUPLE = {
    "architecture": "x86_64", "pi_version": "1.0.2", "governance": "not_required",
}


def extract_helper(name):
    blocks = re.findall(r"^```python\n(.*?)^```", DOCUMENT, re.M | re.S)
    matches = [block for block in blocks if f"def {name}(" in block]
    if len(matches) != 1:
        raise AssertionError(f"Expected exactly one {name} example")
    module = types.ModuleType(name)
    exec(compile(matches[0], str(PLAN), "exec"), module.__dict__)
    return getattr(module, name)


ASSERT_INVENTORY = extract_helper("assert_profile_inventory")
ASSERT_DEFECTS = extract_helper("assert_tuple_and_evidence_refusals")


def complete_fixture(profile):
    return {
        "synthetic": True,
        "installed": dict(SELECTED_TUPLE),
        "artifacts": {name: {"synthetic": True} for name in REQUIREMENTS[profile]},
        "evidence": [{
            "acceptance_id": "AT-HST-001",
            "classification": "independent_integration",
        }],
    }


def diagnostic_model(profile, bundle, *, omit_codes=(), omit_missing=(), unknown_ok=False):
    """Small synthetic diagnostic model for testing the document's assertions.

    This deliberately cannot qualify any input. It performs no native, signature,
    freshness, filesystem or applicability verification and is not an evaluator
    implementation. The switches simulate missing checks to test the test oracle.
    """
    if profile not in REQUIREMENTS:
        return {
            "qualified": False, "missing": [],
            "invalid": ["synthetic_bundle"] if unknown_ok else ["unknown_profile"],
        }
    invalid = ["synthetic_bundle"]
    for field, selected in SELECTED_TUPLE.items():
        if bundle["installed"][field] != selected:
            invalid.append(f"tuple_mismatch:{field}")
    for evidence in bundle["evidence"]:
        if evidence["classification"] != "independent_integration":
            invalid.append(
                f"evidence_class:{evidence['acceptance_id']}:{evidence['classification']}"
            )
    return {
        "qualified": False,
        "missing": sorted(set(REQUIREMENTS[profile]) - bundle["artifacts"].keys()
                          - set(omit_missing)),
        "invalid": [code for code in invalid if code not in omit_codes],
    }


def check_inventory(requirements=REQUIREMENTS, evaluator=diagnostic_model):
    ASSERT_INVENTORY(unittest.TestCase(), requirements, evaluator, complete_fixture)


def check_defects(evaluator=diagnostic_model, base=None):
    ASSERT_DEFECTS(unittest.TestCase(), evaluator,
                   complete_fixture("project-v1") if base is None else base)


BOUNDARY_CLASSES = {"prevent", "detect_only", "advisory_only", "cannot_see"}
PLANNING_STATUSES = {"ready_after_adr", "blocked_by_adr", "deferred", "hard_skip"}
METADATA_HEADER = (
    "| Boundary scope | `boundary_class` | `planning_status` | Decision and execution gate |"
)


def boundary_metadata(document):
    lines = document.splitlines()
    if len(lines) < 5 or lines[2] != METADATA_HEADER:
        raise AssertionError("Missing separate boundary metadata immediately after title")
    rows = {}
    for line in lines[4:]:
        if not line.startswith("|"):
            break
        match = re.fullmatch(r"\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \| (.+) \|", line)
        if match is None:
            raise AssertionError("Malformed boundary metadata row")
        scope, boundary_class, planning_status, gate = match.groups()
        if scope in rows or boundary_class not in BOUNDARY_CLASSES:
            raise AssertionError("Duplicate scope or unknown boundary_class")
        if planning_status not in PLANNING_STATUSES:
            raise AssertionError("Unknown planning_status")
        rows[scope] = (boundary_class, planning_status, gate)
    if not rows:
        raise AssertionError("No boundary scopes")
    return rows


def index_metadata(document):
    rows = {}
    for line in document.splitlines():
        if not re.match(r"\| \[0[0-7] ", line):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 5:
            raise AssertionError("Index must keep separate metadata columns")
        filename = re.search(r"\]\(([^)]+)\)", cells[0]).group(1)
        mappings = []
        for cell in cells[3:]:
            pairs = re.findall(r"`([a-z_]+)=([a-z_]+)`", cell)
            if len(dict(pairs)) != len(pairs):
                raise AssertionError("Duplicate index boundary scope")
            mappings.append(dict(pairs))
        if filename in rows:
            raise AssertionError("Duplicate plan index entry")
        rows[filename] = mappings
    return rows


def check_boundary_index(document):
    indexed = index_metadata(document)
    plans = sorted(PLAN_DIR.glob("0[0-7]-*.md"))
    if len(plans) != 8 or set(indexed) != {plan.name for plan in plans}:
        raise AssertionError("Index does not cover all eight plans")
    for plan in plans:
        rows = boundary_metadata(plan.read_text())
        expected = [{scope: values[index] for scope, values in rows.items()}
                    for index in range(2)]
        if indexed[plan.name] != expected:
            raise AssertionError(f"Index metadata drift: {plan.name}")


class BoundaryMetadataTests(unittest.TestCase):
    def test_all_eight_headers_have_valid_separate_fields_and_named_gates(self):
        plans = sorted(PLAN_DIR.glob("0[0-7]-*.md"))
        self.assertEqual(len(plans), 8)
        for plan in plans:
            with self.subTest(plan=plan.name):
                rows = boundary_metadata(plan.read_text())
                self.assertGreaterEqual(len({row[0] for row in rows.values()}), 2)
                self.assertIn("blocked_by_adr", {row[1] for row in rows.values()})
                for _, planning_status, gate in rows.values():
                    if planning_status == "blocked_by_adr":
                        self.assertRegex(gate, r"Owner decisions? F[1-5]")
                    elif planning_status == "ready_after_adr":
                        self.assertIn("Accepted ADR-0011", gate)

    def test_index_matches_each_scope_class_and_status(self):
        check_boundary_index((PLAN_DIR / "README.md").read_text())

    def test_missing_metadata_field_is_rejected(self):
        for field in ("boundary_class", "planning_status"):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                boundary_metadata(DOCUMENT.replace(f"`{field}`", "`status`", 1))

    def test_unknown_class_and_non_adr_status_are_rejected(self):
        for old, new in [("`prevent`", "`observation`"),
                         ("`blocked_by_adr`", "`blocked_semantics`")]:
            with self.subTest(value=new), self.assertRaises(AssertionError):
                boundary_metadata(DOCUMENT.replace(old, new, 1))

    def test_omitted_index_scope_is_rejected(self):
        index = (PLAN_DIR / "README.md").read_text()
        with self.assertRaises(AssertionError):
            check_boundary_index(index.replace("`capability_admission=prevent`", "", 1))

    def test_index_cannot_upgrade_observation_to_prevention(self):
        index = (PLAN_DIR / "README.md").read_text()
        with self.assertRaises(AssertionError):
            check_boundary_index(index.replace("native_observation=detect_only",
                                               "native_observation=prevent", 1))


class ProfileInventoryTests(unittest.TestCase):
    def test_inventory_matches_all_release_schema_profiles(self):
        schema = json.loads((SPEC_DIR / "contracts/release-evidence.schema.json").read_text())
        self.assertEqual(set(REQUIREMENTS), set(schema["properties"]["profile_id"]["enum"]))

    def test_inventory_covers_every_phase_profile_command(self):
        selected = set()
        for number in range(1, 7):
            paths = list(PLAN_DIR.glob(f"{number:02d}-*.md"))
            self.assertEqual(len(paths), 1)
            selected.update(re.findall(r"--profile ([a-z][a-z0-9-]*)", paths[0].read_text()))
        self.assertEqual(set(REQUIREMENTS), selected)

    def test_documented_inventory_control_and_each_artifact_removal(self):
        check_inventory()

    def test_every_missing_profile_mapping_is_detected(self):
        for profile in REQUIREMENTS:
            with self.subTest(profile=profile):
                incomplete = copy.deepcopy(REQUIREMENTS)
                del incomplete[profile]
                with self.assertRaises(AssertionError):
                    check_inventory(incomplete)

    def test_extra_profile_mapping_is_detected(self):
        with self.assertRaises(AssertionError):
            check_inventory({**REQUIREMENTS, "unknown-v1": []})

    def test_each_missing_or_duplicate_gate_is_detected(self):
        for profile, artifacts in REQUIREMENTS.items():
            for artifact in artifacts:
                for duplicate in (False, True):
                    with self.subTest(profile=profile, artifact=artifact, duplicate=duplicate):
                        altered = copy.deepcopy(REQUIREMENTS)
                        if duplicate:
                            altered[profile].append(artifact)
                        else:
                            altered[profile].remove(artifact)
                        with self.assertRaises(AssertionError):
                            check_inventory(altered)

    def test_ignoring_any_missing_artifact_fails_the_documented_oracle(self):
        for artifact in sorted({name for values in REQUIREMENTS.values() for name in values}):
            with self.subTest(artifact=artifact):
                def broken(profile, bundle):
                    return diagnostic_model(profile, bundle, omit_missing={artifact})
                with self.assertRaises(AssertionError):
                    check_inventory(evaluator=broken)

    def test_unknown_profile_rejection_cannot_be_masked_by_synthetic_gate(self):
        def broken(profile, bundle):
            return diagnostic_model(profile, bundle, unknown_ok=True)
        with self.assertRaises(AssertionError):
            check_inventory(evaluator=broken)

    def test_delegation_does_not_inherit_desktop_or_repair_gates(self):
        self.assertTrue(set(REQUIREMENTS["reviewed-publish-v1"])
                        < set(REQUIREMENTS["desktop-v1"])
                        < set(REQUIREMENTS["repair-v1"]))
        self.assertEqual(set(REQUIREMENTS["delegated-v1"])
                         - set(REQUIREMENTS["reviewed-publish-v1"]),
                         {"native-delegation-profile.json"})


class DiagnosticOracleTests(unittest.TestCase):
    def test_matching_control_and_all_documented_mutants(self):
        control = complete_fixture("project-v1")
        before = copy.deepcopy(control)
        check_defects(base=control)
        self.assertEqual(control, before)
        self.assertFalse(diagnostic_model("project-v1", control)["qualified"])

    def test_synthetic_only_evaluator_fails_the_documented_oracle(self):
        def broken(_profile, _bundle):
            return {"qualified": False, "missing": [], "invalid": ["synthetic_bundle"]}
        with self.assertRaises(AssertionError):
            check_defects(broken)

    def test_omitting_each_tuple_check_fails_the_documented_oracle(self):
        for field in SELECTED_TUPLE:
            with self.subTest(field=field):
                def broken(profile, bundle):
                    return diagnostic_model(profile, bundle,
                                            omit_codes={f"tuple_mismatch:{field}"})
                with self.assertRaises(AssertionError):
                    check_defects(broken)

    def test_omitting_each_classification_check_fails_the_documented_oracle(self):
        for classification in ("source", "document", "component", "skipped", "unknown"):
            with self.subTest(classification=classification):
                def broken(profile, bundle):
                    code = f"evidence_class:AT-HST-001:{classification}"
                    return diagnostic_model(profile, bundle, omit_codes={code})
                with self.assertRaises(AssertionError):
                    check_defects(broken)

    def test_preexisting_tuple_error_cannot_be_used_as_control(self):
        for field in SELECTED_TUPLE:
            with self.subTest(field=field):
                base = complete_fixture("project-v1")
                base["installed"][field] = "mismatch"
                with self.assertRaises(AssertionError):
                    check_defects(base=base)

    def test_generic_error_cannot_replace_specific_code(self):
        def broken(profile, bundle):
            result = diagnostic_model(profile, bundle)
            if len(result["invalid"]) > 1:
                result["invalid"] = ["synthetic_bundle", "invalid_bundle"]
            return result
        with self.assertRaises(AssertionError):
            check_defects(broken)

    def test_synthetic_control_cannot_be_relabeled_real(self):
        base = complete_fixture("project-v1")
        base["synthetic"] = False
        with self.assertRaises(AssertionError):
            check_defects(base=base)


if __name__ == "__main__":
    print("Component/specification regression only; no Omarchy runtime qualification.",
          flush=True)
    unittest.main(verbosity=2)
