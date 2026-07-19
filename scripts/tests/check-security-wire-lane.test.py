#!/usr/bin/env python3

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

ACTIVE_SCHEMAS = {
    "security-event-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/security-event-body-v1.schema.json",
    "correlated-finding-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/correlated-finding-v1.schema.json",
    "flow-denial-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/flow-denial-receipt-body-v1.schema.json",
    "declassification-consumption-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/declassification-consumption-receipt-body-v1.schema.json",
    "declassification-outcome-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/declassification-outcome-receipt-body-v1.schema.json",
    "tripwire-observation-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/tripwire-observation-receipt-body-v1.schema.json",
    "correlated-finding-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/correlated-finding-receipt-body-v1.schema.json",
    "response-plan-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/response-plan-receipt-body-v1.schema.json",
    "response-completion-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/response-completion-receipt-body-v1.schema.json",
    "lift-rollback-completion-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/lift-rollback-completion-receipt-body-v1.schema.json",
    "scheduler-health-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/scheduler-health-receipt-body-v1.schema.json",
    "response-plan-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/response-plan-v1.schema.json",
    "response-effect-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/response-effect-v1.schema.json",
    "response-state-transition-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/response-state-transition-receipt-body-v1.schema.json",
    "effect-transition-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/effect-transition-receipt-body-v1.schema.json",
    "detector-health-receipt-body-v1.schema.json": "https://chio.world/schemas/chio-wire/v1/security/detector-health-receipt-body-v1.schema.json",
}

ACTIVE_CASES = {
    "slow_cumulative_exfiltration",
    "pii_phi_adapter_round_trip",
    "canary_pre_dispatch_denial",
    "honey_tool_pre_dispatch_denial",
    "temporal_within_boundary",
    "declassification_replay",
    "session_isolation_epoch",
    "event_producer_trust",
    "truncated_lineage_no_containment",
    "overlapping_ttl_lift",
    "partial_rollback_truth",
}

ENTERPRISE_CATEGORIES = {
    "keyring_transparency",
    "secret_broker_boundary",
    "cage_enforcement",
    "protocol_primitives",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class SecurityWireLane(unittest.TestCase):
    def test_closed_schema_inventory_contains_active_surface(self) -> None:
        inventory_path = (
            ROOT / "spec/schemas/chio-wire/v1/security/required-schema-inventory.json"
        )
        inventory = load_json(inventory_path)
        entries = {entry["file"]: entry["schema_id"] for entry in inventory["schemas"]}
        for name, schema_id in ACTIVE_SCHEMAS.items():
            self.assertEqual(entries.get(name), schema_id)
            schema = load_json(inventory_path.parent / name)
            self.assertEqual(schema.get("$id"), schema_id)

    def test_recursive_index_binds_every_active_schema(self) -> None:
        root_index = load_json(ROOT / "tests/bindings/vectors/security/v1.json")
        self.assertIn("active-defense/index.json", root_index["indexes"])
        index_path = ROOT / "tests/bindings/vectors/security/active-defense/index.json"
        index = load_json(index_path)
        positives = index["positive"]
        negatives = index["negative"]
        self.assertGreater(len(positives), 0)
        self.assertGreater(len(negatives), 0)
        observed_ids = {entry["schema_id"] for entry in positives}
        self.assertEqual(observed_ids, set(ACTIVE_SCHEMAS.values()))
        for entry in positives + negatives:
            self.assertTrue((index_path.parent / entry["file"]).is_file())

    def test_active_case_source_inventory_is_exact(self) -> None:
        entrypoint = ROOT / "crates/tooling/chio-conformance/tests/active_defense.rs"
        source = entrypoint.read_text(encoding="utf-8")
        includes = set(re.findall(r'(?m)^\s*include!\("([^"]+\.rs)"\);\s*$', source))
        self.assertEqual(includes, {"active_defense/deception_dispatch.rs"})

        fragment_root = entrypoint.parent / "active_defense"
        fragments = {
            path.relative_to(entrypoint.parent) for path in fragment_root.rglob("*.rs")
        }
        self.assertEqual(fragments, {Path(include) for include in includes})
        source += "\n".join(
            (entrypoint.parent / include).read_text(encoding="utf-8")
            for include in sorted(includes)
        )
        names = set(re.findall(r"#\[test\]\s*fn\s+([a-z0-9_]+)\s*\(", source))
        self.assertEqual(names, ACTIVE_CASES)

    def test_enterprise_categories_are_nonempty(self) -> None:
        scenario_root = ROOT / "tests/conformance/native/scenarios"
        counts = {category: 0 for category in ENTERPRISE_CATEGORIES}
        for path in scenario_root.rglob("*.json"):
            category = load_json(path).get("category")
            if category in counts:
                counts[category] += 1
        self.assertTrue(all(count == 1 for count in counts.values()), counts)


if __name__ == "__main__":
    unittest.main()
