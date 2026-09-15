#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/check-security-wire-vectors.py"
SPEC = importlib.util.spec_from_file_location(
    "check_security_wire_vectors", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load {MODULE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


SCHEMA_ID = "https://schemas.chio.test/security/demo-v1.schema.json"
SCHEMA_PATH_ID = "https://chio.world/schemas/chio-wire/v1/security/demo.schema.json"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class SecurityWireVectorContract(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.schema_path = (
            self.root / "spec/schemas/chio-wire/v1/security/demo.schema.json"
        )
        self.inventory_path = self.schema_path.parent / "required-schema-inventory.json"
        self.root_index_path = self.root / "tests/bindings/vectors/security/v1.json"
        self.index_path = self.root_index_path.parent / "demo/index.json"
        self.positive_path = self.index_path.parent / "positive/demo.json"
        self.mutations_path = self.index_path.parent / "mutations.json"

        write_json(
            self.schema_path,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": SCHEMA_ID,
                "type": "object",
                "properties": {"schema": {"const": "demo.v1"}},
                "required": ["schema"],
                "additionalProperties": False,
            },
        )
        write_json(
            self.inventory_path,
            {
                "schema": "chio.security-required-schema-inventory.v1",
                "schemas": [{"file": "demo.schema.json", "schema_id": SCHEMA_ID}],
            },
        )
        write_json(
            self.root_index_path,
            {"schema": "chio.test-vector.security.v1", "indexes": ["demo/index.json"]},
        )
        write_json(
            self.index_path,
            {
                "schema": "chio.test-vector.demo.index.v1",
                "positive": [
                    {
                        "id": "demo",
                        "file": "positive/demo.json",
                        "schema_id": SCHEMA_ID,
                    }
                ],
                "negative": [{"id": "mutations", "file": "mutations.json"}],
            },
        )
        write_json(self.positive_path, {"schema": "demo.v1"})
        write_json(
            self.mutations_path,
            {
                "schema": "chio.test-vector.demo.mutations.v1",
                "cases": [
                    {
                        "id": "unknown_field",
                        "base": "positive/demo.json",
                        "mutation": {"op": "add", "path": "/unknown", "value": True},
                        "expected": {
                            "json_parse_valid": True,
                            "json_schema_valid": False,
                            "semantic_valid": False,
                        },
                    }
                ],
            },
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_recursive_exact_schema_happy_path(self) -> None:
        self.assertEqual(MODULE.validate_corpus(self.root), (1, 1, 1))

    def test_detector_health_semantics_are_computed_from_payload(self) -> None:
        fixture_path = (
            ROOT
            / "tests/bindings/vectors/security/active-defense/positive"
            / "detector-health-receipt-body-v1.json"
        )
        valid = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertTrue(MODULE.detector_health_semantic_valid(valid))

        mutations = []
        zero_group = json.loads(json.dumps(valid))
        zero_group["group_binding"]["group_key_hash"] = [0] * 32
        mutations.append(zero_group)
        future = json.loads(json.dumps(valid))
        future["watermark"]["unix_ms"] = future["header"]["occurred_at_unix_ms"] + 1
        mutations.append(future)
        zero_watermark = json.loads(json.dumps(valid))
        zero_watermark["watermark"]["unix_ms"] = 0
        mutations.append(zero_watermark)
        unresolved_committed = json.loads(json.dumps(valid))
        unresolved_committed["group_binding"] = {"kind": "unresolved"}
        mutations.append(unresolved_committed)
        unsafe_header = json.loads(json.dumps(valid))
        unsafe_header["header"]["occurred_at_unix_ms"] = (
            MODULE.MAX_JSON_SAFE_INTEGER + 1
        )
        mutations.append(unsafe_header)
        unsafe_watermark = json.loads(json.dumps(valid))
        unsafe_watermark["watermark"]["unix_ms"] = MODULE.MAX_JSON_SAFE_INTEGER + 1
        mutations.append(unsafe_watermark)

        contradictory = json.loads(json.dumps(valid))
        contradictory["health_kind"] = "corrupt_state"
        contradictory["watermark"] = {
            "kind": "contradictory",
            "claimed_unix_ms": str(valid["header"]["occurred_at_unix_ms"] + 1),
        }
        self.assertTrue(MODULE.detector_health_semantic_valid(contradictory))

        unresolved_contradictory = json.loads(json.dumps(contradictory))
        unresolved_contradictory["group_binding"] = {"kind": "unresolved"}
        mutations.append(unresolved_contradictory)
        wrong_health = json.loads(json.dumps(contradictory))
        wrong_health["health_kind"] = "store_unavailable"
        mutations.append(wrong_health)
        noncontradictory_claim = json.loads(json.dumps(contradictory))
        noncontradictory_claim["watermark"]["claimed_unix_ms"] = str(
            valid["header"]["occurred_at_unix_ms"] - 1
        )
        mutations.append(noncontradictory_claim)
        noncanonical_claim = json.loads(json.dumps(contradictory))
        noncanonical_claim["watermark"]["claimed_unix_ms"] = "0501"
        mutations.append(noncanonical_claim)
        overflowing_claim = json.loads(json.dumps(contradictory))
        overflowing_claim["watermark"]["claimed_unix_ms"] = str(MODULE.MAX_U64 + 1)
        mutations.append(overflowing_claim)

        for mutation in mutations:
            self.assertFalse(MODULE.detector_health_semantic_valid(mutation))

    def test_active_defense_receipt_semantics_cover_positive_and_mutation_corpus(
        self,
    ) -> None:
        vector_dir = ROOT / "tests/bindings/vectors/security/active-defense"
        index = json.loads((vector_dir / "index.json").read_text(encoding="utf-8"))
        schema_by_file = {
            entry["file"]: entry["schema_id"] for entry in index["positive"]
        }
        receipt_schema_ids = set(MODULE.ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS.values())
        observed_schema_ids = {
            schema_id
            for schema_id in schema_by_file.values()
            if schema_id in receipt_schema_ids
        }
        self.assertEqual(observed_schema_ids, receipt_schema_ids)

        for relative, schema_id in schema_by_file.items():
            if schema_id not in receipt_schema_ids:
                continue
            value = json.loads((vector_dir / relative).read_text(encoding="utf-8"))
            self.assertTrue(
                MODULE.active_defense_receipt_semantic_valid(schema_id, value),
                relative,
            )

        corpus = json.loads(
            (vector_dir / "receipt-body-mutations-v1.json").read_text(encoding="utf-8")
        )
        for case in corpus["cases"]:
            base = json.loads((vector_dir / case["base"]).read_text(encoding="utf-8"))
            mutated = MODULE.mutate_json(base, case["mutation"], vector_dir, case["id"])
            schema_id = schema_by_file[case["base"]]
            self.assertFalse(
                MODULE.active_defense_receipt_semantic_valid(schema_id, mutated),
                case["id"],
            )

    def test_failed_response_completion_accepts_failure_before_effects(self) -> None:
        fixture_path = (
            ROOT
            / "tests/bindings/vectors/security/active-defense/positive"
            / "response-completion-receipt-body-failed-before-effect-v1.json"
        )
        value = json.loads(fixture_path.read_text(encoding="utf-8"))
        schema_id = MODULE.ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS["response-completion"]
        schemas, registry = MODULE.load_schema_inventory(ROOT)
        validator = MODULE.Draft202012Validator(
            schemas[schema_id][1], registry=registry
        )

        self.assertTrue(validator.is_valid(value))
        self.assertTrue(
            MODULE.active_defense_receipt_semantic_valid(schema_id, value)
        )

    def test_response_completion_terminal_state_matrix_is_exact(self) -> None:
        vector_dir = ROOT / "tests/bindings/vectors/security/active-defense/positive"
        active = json.loads(
            (vector_dir / "response-completion-receipt-body-v1.json").read_text(
                encoding="utf-8"
            )
        )
        failed = json.loads(
            (
                vector_dir / "response-completion-receipt-body-failed-v1.json"
            ).read_text(encoding="utf-8")
        )
        schema_id = MODULE.ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS["response-completion"]

        def semantic_valid(value: object) -> bool:
            return MODULE.active_defense_receipt_semantic_valid(schema_id, value)

        self.assertTrue(semantic_valid(active))
        self.assertTrue(semantic_valid(failed))

        active_with_error = json.loads(json.dumps(active))
        active_with_error["error_code"] = "response.effect_rejected"
        self.assertFalse(semantic_valid(active_with_error))

        active_with_planned_effect = json.loads(json.dumps(active))
        active_with_planned_effect["effects"][0]["outcome"] = {"state": "planned"}
        self.assertFalse(semantic_valid(active_with_planned_effect))

        failed_before_any_effect = json.loads(json.dumps(failed))
        for effect in failed_before_any_effect["effects"]:
            effect["outcome"] = {"state": "planned"}
        self.assertTrue(semantic_valid(failed_before_any_effect))

        failed_with_mismatched_error = json.loads(json.dumps(failed))
        failed_with_mismatched_error["error_code"] = "response.different_failure"
        self.assertFalse(semantic_valid(failed_with_mismatched_error))

        failed_with_multiple_failures = json.loads(json.dumps(failed))
        failed_with_multiple_failures["effects"][1]["outcome"] = {
            "state": "apply_failed",
            "error_code": "response.effect_rejected",
        }
        self.assertFalse(semantic_valid(failed_with_multiple_failures))

        failed_with_applied_effect = json.loads(json.dumps(failed))
        failed_with_applied_effect["effects"][0]["outcome"] = {
            "state": "applied",
            "resulting_version_hash": [30] * 32,
        }
        self.assertFalse(semantic_valid(failed_with_applied_effect))

        failed_without_error = json.loads(json.dumps(failed))
        failed_without_error["error_code"] = None
        self.assertFalse(semantic_valid(failed_without_error))

        partial_with_matching_failure = json.loads(json.dumps(failed))
        partial_with_matching_failure["final_state"] = "apply_partial"
        partial_with_matching_failure["effects"][1]["outcome"] = {
            "state": "applied",
            "resulting_version_hash": [30] * 32,
        }
        self.assertTrue(semantic_valid(partial_with_matching_failure))

        partial_after_all_effects_applied = json.loads(json.dumps(failed))
        partial_after_all_effects_applied["final_state"] = "apply_partial"
        for effect in partial_after_all_effects_applied["effects"]:
            effect["outcome"] = {
                "state": "applied",
                "resulting_version_hash": [30] * 32,
            }
        self.assertTrue(semantic_valid(partial_after_all_effects_applied))

        partial_without_applied_effect = json.loads(json.dumps(failed))
        partial_without_applied_effect["final_state"] = "apply_partial"
        self.assertFalse(semantic_valid(partial_without_applied_effect))

        partial_with_mismatched_error = json.loads(
            json.dumps(partial_with_matching_failure)
        )
        partial_with_mismatched_error["error_code"] = "response.different_failure"
        self.assertFalse(semantic_valid(partial_with_mismatched_error))

        partial_with_multiple_failures = json.loads(
            json.dumps(partial_with_matching_failure)
        )
        extra_effect = json.loads(
            json.dumps(partial_with_multiple_failures["effects"][0])
        )
        extra_effect["effect"]["effect_id"] = "effect-3"
        extra_effect["effect"]["ordinal"] = 2
        partial_with_multiple_failures["effects"].append(extra_effect)
        self.assertFalse(semantic_valid(partial_with_multiple_failures))

        partial_without_error = json.loads(json.dumps(partial_with_matching_failure))
        partial_without_error["error_code"] = None
        self.assertFalse(semantic_valid(partial_without_error))

    def test_single_parent_receipts_reject_multiple_lineage(self) -> None:
        vector_dir = ROOT / "tests/bindings/vectors/security/active-defense"
        fixtures = {
            "response-state-transition": (
                "positive/response-state-transition-receipt-body-v1.json"
            ),
            "effect-transition": "positive/effect-transition-receipt-body-v1.json",
            "response-completion": (
                "positive/response-completion-receipt-body-v1.json"
            ),
            "lift-rollback-completion": (
                "positive/lift-rollback-completion-receipt-body-v1.json"
            ),
        }
        schemas, registry = MODULE.load_schema_inventory(ROOT)

        for receipt_name, relative in fixtures.items():
            schema_id = MODULE.ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS[receipt_name]
            value = json.loads((vector_dir / relative).read_text(encoding="utf-8"))
            schema = schemas[schema_id][1]
            validator = MODULE.Draft202012Validator(schema, registry=registry)

            self.assertTrue(validator.is_valid(value), receipt_name)
            self.assertTrue(
                MODULE.active_defense_receipt_semantic_valid(schema_id, value),
                receipt_name,
            )

            value["header"]["prior_receipt_ids"] = ["receipt-1", "receipt-2"]
            self.assertFalse(validator.is_valid(value), receipt_name)
            self.assertFalse(
                MODULE.active_defense_receipt_semantic_valid(schema_id, value),
                receipt_name,
            )

    def test_multiple_lineage_mutations_cover_all_single_parent_receipts(self) -> None:
        vector_dir = ROOT / "tests/bindings/vectors/security/active-defense"
        corpus = json.loads(
            (vector_dir / "receipt-body-mutations-v1.json").read_text(encoding="utf-8")
        )
        cases = {case["id"]: case for case in corpus["cases"]}
        expected = {
            "response_state_transition_multiple_prior_receipts": (
                "positive/response-state-transition-receipt-body-v1.json"
            ),
            "effect_transition_multiple_prior_receipts": (
                "positive/effect-transition-receipt-body-v1.json"
            ),
            "response_completion_multiple_prior_receipts": (
                "positive/response-completion-receipt-body-v1.json"
            ),
            "lift_rollback_multiple_prior_receipts": (
                "positive/lift-rollback-completion-receipt-body-v1.json"
            ),
        }

        for case_id, base in expected.items():
            case = cases[case_id]
            self.assertEqual(case["base"], base)
            self.assertEqual(
                case["mutation"],
                {
                    "op": "replace",
                    "path": "/header/prior_receipt_ids",
                    "value": ["receipt-1", "receipt-2"],
                },
            )
            self.assertEqual(
                case["expected"],
                {
                    "json_parse_valid": True,
                    "json_schema_valid": False,
                    "semantic_valid": False,
                },
            )

    def test_response_completion_dispatch_binding_is_exactly_paired(self) -> None:
        fixture_path = (
            ROOT
            / "tests/bindings/vectors/security/active-defense/positive"
            / "response-completion-receipt-body-v1.json"
        )
        value = json.loads(fixture_path.read_text(encoding="utf-8"))
        value["execution_dispatch"] = {
            "schema_version": 1,
            "tenant_id": "tenant-1",
            "dispatch_id": "dispatch-1",
            "action_id": "action-1",
            "plan_hash": [6] * 32,
            "executor_authority_id": "response-authority-1",
            "executor_authority_generation": 1,
            "authorization_capability_hash": [40] * 32,
            "governed_intent_hash": [41] * 32,
            "policy_decision_hash": [42] * 32,
            "approval": {"approval_mode": "automatic"},
            "authorized_at_unix_ms": 590,
        }
        value["dispatch_authorization_hash"] = [43] * 32
        schema_id = MODULE.ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS["response-completion"]
        self.assertTrue(
            MODULE.active_defense_receipt_semantic_valid(schema_id, value)
        )

        missing_authorization = json.loads(json.dumps(value))
        missing_authorization["dispatch_authorization_hash"] = None
        self.assertFalse(
            MODULE.active_defense_receipt_semantic_valid(
                schema_id, missing_authorization
            )
        )

        wrong_action = json.loads(json.dumps(value))
        wrong_action["execution_dispatch"]["action_id"] = "action-2"
        self.assertFalse(
            MODULE.active_defense_receipt_semantic_valid(schema_id, wrong_action)
        )

    def test_direct_schema_negative_is_supported(self) -> None:
        direct_negative = self.index_path.parent / "negative/demo.json"
        write_json(direct_negative, {"schema": "not-demo.v1"})
        index = json.loads(self.index_path.read_text(encoding="utf-8"))
        index["negative"].append(
            {
                "id": "direct_negative",
                "file": "negative/demo.json",
                "schema_id": SCHEMA_ID,
            }
        )
        write_json(self.index_path, index)

        self.assertEqual(MODULE.validate_corpus(self.root), (1, 1, 2))

    def test_direct_negative_exact_merge_rejects_unrelated_invalidity(self) -> None:
        schema = json.loads(self.schema_path.read_text(encoding="utf-8"))
        schema["properties"].update(
            {"left": {"type": "boolean"}, "right": {"type": "boolean"}}
        )
        schema["not"] = {"required": ["left", "right"]}
        write_json(self.schema_path, schema)

        left_path = self.index_path.parent / "positive/left.json"
        right_path = self.index_path.parent / "positive/right.json"
        direct_path = self.index_path.parent / "negative/both.json"
        write_json(left_path, {"schema": "demo.v1", "left": True})
        write_json(right_path, {"schema": "demo.v1", "right": True})
        write_json(
            direct_path,
            {"schema": "demo.v1", "left": True, "right": True},
        )

        index = json.loads(self.index_path.read_text(encoding="utf-8"))
        index["positive"].extend(
            [
                {"id": "left", "file": "positive/left.json", "schema_id": SCHEMA_ID},
                {
                    "id": "right",
                    "file": "positive/right.json",
                    "schema_id": SCHEMA_ID,
                },
            ]
        )
        index["negative"].append(
            {
                "id": "both",
                "file": "negative/both.json",
                "schema_id": SCHEMA_ID,
                "exact_merge_of": ["positive/left.json", "positive/right.json"],
            }
        )
        write_json(self.index_path, index)
        self.assertEqual(MODULE.validate_corpus(self.root), (1, 3, 2))

        write_json(
            direct_path,
            {
                "schema": "demo.v1",
                "left": True,
                "right": True,
                "unrelated": True,
            },
        )
        with self.assertRaisesRegex(MODULE.ContractError, "not the exact object merge"):
            MODULE.validate_corpus(self.root)

    def test_idless_wire_schema_has_canonical_path_identity(self) -> None:
        idless_schema = self.root / "spec/schemas/chio-wire/v1/agent/idless.schema.json"
        write_json(
            idless_schema,
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {
                    "type": {"const": "idless"},
                    "payload": {"$ref": "../security/demo.schema.json"},
                },
                "required": ["type", "payload"],
                "additionalProperties": False,
            },
        )
        idless_positive = self.index_path.parent / "positive/idless.json"
        write_json(
            idless_positive,
            {"type": "idless", "payload": {"schema": "demo.v1"}},
        )
        index = json.loads(self.index_path.read_text(encoding="utf-8"))
        index["positive"].append(
            {
                "id": "idless",
                "file": "positive/idless.json",
                "schema_id": (
                    "https://chio.world/schemas/chio-wire/v1/agent/idless.schema.json"
                ),
            }
        )
        write_json(self.index_path, index)

        self.assertEqual(MODULE.validate_corpus(self.root), (1, 2, 1))

    def test_declared_schema_path_alias_is_resolver_only(self) -> None:
        index = json.loads(self.index_path.read_text(encoding="utf-8"))
        index["positive"][0]["schema_id"] = SCHEMA_PATH_ID
        write_json(self.index_path, index)

        with self.assertRaisesRegex(MODULE.ContractError, "unknown exact schema_id"):
            MODULE.validate_corpus(self.root)

    def test_zero_count_leaf_is_rejected(self) -> None:
        index = json.loads(self.index_path.read_text(encoding="utf-8"))
        index["positive"] = []
        write_json(self.index_path, index)
        with self.assertRaisesRegex(MODULE.ContractError, "non-empty array"):
            MODULE.validate_corpus(self.root)

    def test_deleted_required_schema_is_rejected(self) -> None:
        self.schema_path.unlink()
        with self.assertRaisesRegex(MODULE.ContractError, "closed inventory mismatch"):
            MODULE.validate_corpus(self.root)

    def test_non_exact_schema_id_is_rejected(self) -> None:
        index = json.loads(self.index_path.read_text(encoding="utf-8"))
        index["positive"][0]["schema_id"] = f"{SCHEMA_ID}#almost"
        write_json(self.index_path, index)
        with self.assertRaisesRegex(MODULE.ContractError, "unknown exact schema_id"):
            MODULE.validate_corpus(self.root)

    def test_empty_root_index_is_rejected(self) -> None:
        write_json(
            self.root_index_path,
            {"schema": "chio.test-vector.security.v1", "indexes": []},
        )
        with self.assertRaisesRegex(MODULE.ContractError, "non-empty array"):
            MODULE.validate_corpus(self.root)


if __name__ == "__main__":
    unittest.main()
