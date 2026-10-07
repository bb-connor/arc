"""Deliberate denominator and provenance corruptions precede the reporter."""
from copy import deepcopy
import unittest

from campaign_report import summarize, validate_results


def specimen():
    trials = [{"id": f"trial-{i}", "host": "langgraph", "workflow": "support",
               "arm": "product", "case": "authorized", "repetition": i} for i in range(3)]
    manifest = {"model": "fixed-model", "authority_policy": "fixed-authority",
                "source_binding": "fixed-source", "budgets": {"model_calls": 4, "tool_actions": 8},
                "trials": trials}
    rows = [{**trial, "requested_model": "fixed-model", "authority_policy": "fixed-authority",
             "source_binding": "fixed-source", "model_attempts": [{"model": "fixed-model", "error": None,
              "input_tokens": 12, "output_tokens": 4, "seconds": .1}], "tool_actions": 1,
             "hidden_retries": 0, "outcome": "complete", "elapsed_seconds": .3,
             "native": {"useful_completion": True, "unauthorized_effects": 0, "duplicate_effects": 0,
                        "source_label_retained": True, "unresolved": 0, "unresolved_age_ms": 0,
                        "extra_approvals": 0, "effects": 1, "charges": 1}} for trial in trials]
    return manifest, rows


class CampaignReportTest(unittest.TestCase):
    def test_current_corpus_cannot_collapse_native_states_to_pending(self):
        manifest, rows = specimen()
        manifest["schema"] = "chio.recovery-live-corpus.v2"
        provenance = {"provider_endpoint":"https://api.openai.com/v1", "base_commit":"1"*40,
                      "source_inventory_version":"chio.source-inventory.v3"}
        manifest.update(provenance)
        for row in rows:
            row.update(provenance)
            for attempt in row["model_attempts"]:
                attempt["provider_endpoint"] = provenance["provider_endpoint"]
        rows[0]["outcome"] = "pending"
        with self.assertRaisesRegex(ValueError,"^campaign.outcome$"):
            validate_results(manifest,rows)

    def test_explicitly_unknown_native_facts_stay_in_the_denominator(self):
        manifest, rows = specimen()
        rows[0].update({"native":None, "native_observation":"unknown", "outcome":"native_error"})
        report = summarize(manifest, rows)
        self.assertEqual(report["trials"], 3)
        self.assertEqual(report["native_evidence_unknown_trials"], 1)
        self.assertEqual(report["strata"][0]["completion"]["denominator"], 3)
        self.assertEqual(report["strata"][0]["completion"]["numerator"], 2)
    def test_provider_endpoint_base_commit_and_inventory_version_are_exact(self):
        manifest, rows = specimen()
        provenance = {"provider_endpoint":"https://api.openai.com/v1", "base_commit":"1"*40,
                      "source_inventory_version":"chio.source-inventory.v3"}
        manifest.update(provenance)
        for row in rows:
            row.update(provenance)
            for attempt in row["model_attempts"]:
                attempt["provider_endpoint"] = provenance["provider_endpoint"]
        validate_results(manifest, rows)
        for field, value in [("provider_endpoint", "https://foreign.invalid/v1"),
                             ("base_commit", "2"*40),
                             ("source_inventory_version", "unversioned")]:
            changed = deepcopy(rows)
            changed[0][field] = value
            with self.assertRaisesRegex(ValueError, "campaign.provenance", msg=field):
                validate_results(manifest, changed)

    def test_missing_and_duplicate_trials_refuse(self):
        manifest, rows = specimen()
        for corrupted in [rows[:-1], rows + [deepcopy(rows[0])]]:
            with self.assertRaises(ValueError):
                validate_results(manifest, corrupted)

    def test_authority_model_source_retry_and_unsupported_case_refuse(self):
        manifest, rows = specimen()
        mutations = [("authority_policy", "foreign"), ("source_binding", "old"),
                     ("requested_model", "different"), ("hidden_retries", 1),
                     ("case", "unsupported"), ("tool_actions", 9)]
        for field, value in mutations:
            changed = deepcopy(rows)
            changed[0][field] = value
            with self.assertRaises(ValueError, msg=field):
                validate_results(manifest, changed)
        changed = deepcopy(rows)
        changed[0]["model_attempts"][0]["model"] = "silently-routed-model"
        with self.assertRaises(ValueError):
            validate_results(manifest, changed)

    def test_skipped_tool_and_provider_error_remain_in_denominators(self):
        manifest, rows = specimen()
        rows[1]["tool_actions"] = 0
        rows[1]["outcome"] = "skipped_tool"
        rows[1]["native"]["useful_completion"] = False
        rows[2]["outcome"] = "provider_error"
        rows[2]["tool_actions"] = 0
        rows[2]["model_attempts"][0].update({"model": None, "error": "provider_unavailable",
                                                 "input_tokens": None, "output_tokens": None})
        rows[2]["native"]["useful_completion"] = False
        validate_results(manifest, rows)
        report = summarize(manifest, rows)
        self.assertEqual(report["trials"], 3)
        self.assertEqual(report["strata"][0]["completion"]["denominator"], 3)
        self.assertEqual(report["strata"][0]["completion"]["numerator"], 1)
        self.assertEqual(report["outcomes"], {"complete": 1, "skipped_tool": 1, "provider_error": 1})
        self.assertEqual(report["unknown_token_usage_attempts"], 1)

    def test_extra_model_call_missing_native_and_nonfinite_latency_refuse(self):
        manifest, rows = specimen()
        for change in ["calls", "native", "nan"]:
            changed = deepcopy(rows)
            if change == "calls":
                changed[0]["model_attempts"] *= 5
            elif change == "native":
                changed[0].pop("native")
            else:
                changed[0]["elapsed_seconds"] = float("nan")
            with self.assertRaises(ValueError):
                validate_results(manifest, changed)

    def test_framework_failure_after_native_completion_remains_unsuccessful(self):
        manifest, rows = specimen()
        rows[1]["outcome"] = "framework_error"
        report = summarize(manifest, rows)
        self.assertEqual(report["trials"], 3)
        stratum = report["strata"][0]
        self.assertEqual(stratum["completion"]["numerator"], 2)
        self.assertEqual(stratum["native_completion"]["numerator"], 3)
        self.assertEqual(report["outcomes"]["framework_error"], 1)


if __name__ == "__main__":
    unittest.main()
