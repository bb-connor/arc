"""Both original failures and the independent qualification cohort are mandatory."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[6]
sys.path.insert(0, str(ROOT / "fixtures/recovery-product"))
from test_campaign_report import specimen
from cohort_report import aggregate_cohorts, aggregate_interrupted_cohorts, aggregate_qualification_attempts
import cohort_report


class CohortReportTest(unittest.TestCase):
    def test_review_fix_attempt_preserves_five_denominators_and_exact_fix_scope(self):
        manifest, cohorts = self.cohorts()
        cohorts["initial-account-quota-failure"] = cohorts["initial-account-quota-failure"][:1]
        interruption = {"cause":"task_owned_deadline", "started_unrecorded":["trial-1"],
                        "not_started":["trial-2"], "measurement_status":"unavailable"}
        paths = {
            "crates/platform/chio-store-sqlite/src/admission_operation_store/setup.rs",
            "crates/platform/chio-store-sqlite/src/admission_operation_store/setup/service.rs",
            "crates/platform/chio-control-plane/src/recovery/tests/knowledge/setup.rs",
            "crates/platform/chio-control-plane/src/recovery/tests/knowledge/setup/cli_host.rs",
            "fixtures/recovery-product/preflight.py",
            "fixtures/recovery-product/test_campaign_runner.py",
        }
        transport = "fixtures/recovery-product/campaign_runner.py"
        custody = {transport, "fixtures/recovery-product/test_campaign_runner.py"}
        manifest["sources"] = [{"path":path,"sha256":"0"*64} for path in sorted(paths | {transport})]
        capable = deepcopy(manifest)
        capable["model"] = "capable-pinned-model"
        for row in capable["sources"]:
            if row["path"] in custody: row["sha256"] = "1"*64
        corrected = deepcopy(capable)
        corrected["framework_protocol"] = cohort_report.CORRECTED_PROTOCOL
        for row in corrected["sources"]:
            if row["path"] in custody: row["sha256"] = "2"*64
        fixed = deepcopy(corrected)
        for row in fixed["sources"]:
            if row["path"] in paths: row["sha256"] = "3"*64
        for name in ["capable-model-qualification", "corrected-framework-qualification", "review-fix-qualification"]:
            values = deepcopy(cohorts["available-account-qualification"])
            for row in values:
                row["requested_model"] = capable["model"]
                for attempt in row["model_attempts"]: attempt["model"] = capable["model"]
            cohorts[name] = values
        report = cohort_report.aggregate_review_fix_attempts(manifest, capable, corrected, fixed, cohorts, interruption)
        self.assertEqual(report["planned_trials"], 15)
        self.assertEqual(report["measured_trials"], 13)
        self.assertEqual(report["unrecorded_trials"], 2)
        self.assertEqual(set(report["cohorts"]), set(cohorts))
        self.assertEqual(report["qualification_cohort"], "review-fix-qualification")
        self.assertIsNone(report["all_planned_safety_rate"])
        for mutation in ["model", "budget", "source", "missing"]:
            changed = deepcopy(fixed)
            rows = deepcopy(cohorts)
            if mutation == "model": changed["model"] = "undeclared-model"
            elif mutation == "budget": changed["budgets"]["tool_actions"] += 1
            elif mutation == "source": changed["sources"][0]["sha256"] = corrected["sources"][0]["sha256"]
            else: rows.pop("initial-account-quota-failure")
            with self.assertRaises(ValueError, msg=mutation):
                cohort_report.aggregate_review_fix_attempts(manifest, capable, corrected, changed, rows, interruption)

    def cohorts(self):
        manifest, successful = specimen()
        failed = deepcopy(successful)
        for row in failed:
            row["outcome"] = "provider_error"
            row["tool_actions"] = 0
            row["native"]["useful_completion"] = False
            row["model_attempts"][0].update(model=None,error="provider_unavailable",input_tokens=None,output_tokens=None)
        return manifest, {"initial-account-quota-failure":failed,"available-account-qualification":successful}

    def test_original_quota_failures_remain_in_combined_denominators(self):
        manifest, cohorts = self.cohorts()
        report = aggregate_cohorts(manifest, cohorts)
        self.assertEqual(report["combined"]["trials"], 6)
        self.assertEqual(report["combined"]["strata"][0]["completion"]["denominator"], 6)
        self.assertEqual(report["combined"]["strata"][0]["completion"]["numerator"], 3)
        self.assertEqual(report["combined"]["outcomes"], {"provider_error":3,"complete":3})
        self.assertEqual(report["cohorts"]["initial-account-quota-failure"]["trials"], 3)

    def test_missing_failure_cohort_retry_and_foreign_source_refuse(self):
        manifest, cohorts = self.cohorts()
        for mutation in ["missing", "retry", "source", "duplicate"]:
            changed = deepcopy(cohorts)
            if mutation == "missing": changed.pop("initial-account-quota-failure")
            elif mutation == "retry": changed["initial-account-quota-failure"][0]["hidden_retries"] = 1
            elif mutation == "source": changed["available-account-qualification"][0]["source_binding"] = "foreign"
            else: changed["available-account-qualification"][1] = deepcopy(changed["available-account-qualification"][0])
            with self.assertRaises(ValueError, msg=mutation): aggregate_cohorts(manifest, changed)

    def test_interruption_preserves_planned_slots_and_unknown_measurements(self):
        manifest, cohorts = self.cohorts()
        cohorts["initial-account-quota-failure"] = cohorts["initial-account-quota-failure"][:1]
        interruption = {"cause":"task_owned_deadline", "started_unrecorded":["trial-1"],
                        "not_started":["trial-2"], "measurement_status":"unavailable"}
        report = aggregate_interrupted_cohorts(manifest, cohorts, interruption)
        self.assertEqual(report["planned_trials"], 6)
        self.assertEqual(report["measured_trials"], 4)
        self.assertEqual(report["unrecorded_trials"], 2)
        self.assertEqual(report["combined_completion"]["numerator"], 3)
        self.assertEqual(report["combined_completion"]["denominator"], 6)
        self.assertEqual(report["interrupted_model_calls_upper_bound"], 4)
        self.assertIsNone(report["all_planned_safety_rate"])
        with self.assertRaises(ValueError): aggregate_cohorts(manifest, cohorts)
        for field in ["started_unrecorded", "not_started"]:
            changed = deepcopy(interruption)
            changed[field] = []
            with self.assertRaises(ValueError): aggregate_interrupted_cohorts(manifest, cohorts, changed)

    def test_additional_model_retains_all_prior_denominators_and_rejects_changed_authority(self):
        manifest, cohorts = self.cohorts()
        cohorts["initial-account-quota-failure"] = cohorts["initial-account-quota-failure"][:1]
        interruption = {"cause":"task_owned_deadline", "started_unrecorded":["trial-1"],
                        "not_started":["trial-2"], "measurement_status":"unavailable"}
        capable = deepcopy(manifest)
        capable["model"] = "capable-pinned-model"
        rows = deepcopy(cohorts["available-account-qualification"])
        for row in rows:
            row["requested_model"] = capable["model"]
            for attempt in row["model_attempts"]: attempt["model"] = capable["model"]
        cohorts["capable-model-qualification"] = rows
        report = aggregate_qualification_attempts(manifest, capable, cohorts, interruption)
        self.assertEqual(report["planned_trials"], 9)
        self.assertEqual(report["measured_trials"], 7)
        self.assertEqual(report["combined_completion"]["numerator"], 6)
        self.assertEqual(report["combined_completion"]["denominator"], 9)
        self.assertIsNone(report["all_planned_safety_rate"])
        self.assertEqual(report["qualification_cohort"], "capable-model-qualification")
        changed = deepcopy(capable)
        changed["authority_policy"] = "changed"
        with self.assertRaises(ValueError): aggregate_qualification_attempts(manifest, changed, cohorts, interruption)

    def test_cli_recomputes_all_three_attempts_and_retains_prompt_provenance_gaps(self):
        manifest, cohorts = self.cohorts()
        cohorts["initial-account-quota-failure"] = cohorts["initial-account-quota-failure"][:1]
        interruption = {"cause":"task_owned_deadline", "started_unrecorded":["trial-1"],
                        "not_started":["trial-2"], "measurement_status":"unavailable"}
        capable = deepcopy(manifest)
        capable["model"] = "capable-pinned-model"
        rows = deepcopy(cohorts["available-account-qualification"])
        for row in rows:
            row["requested_model"] = capable["model"]
            for attempt in row["model_attempts"]:
                attempt["model"] = capable["model"]
        cohorts["capable-model-qualification"] = rows
        provenance = {"measurement_status":"unavailable", "qualifying":False,
                      "gaps":[{"cohort":"available-account-qualification", "id":"trial-0", "attempt":0}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in [("original",manifest), ("capable",capable),
                                ("interruption",interruption), ("gaps",provenance)]:
                (root / (name + ".json")).write_text(json.dumps(value))
            for name, values in cohorts.items():
                (root / (name + ".jsonl")).write_text("\n".join(json.dumps(row) for row in values)+"\n")
            command = [sys.executable, str(Path(__file__).with_name("cohort_report.py")),
                       "--manifest",str(root / "original.json"),
                       "--initial",str(root / "initial-account-quota-failure.jsonl"),
                       "--qualified",str(root / "available-account-qualification.jsonl"),
                       "--capable-manifest",str(root / "capable.json"),
                       "--capable",str(root / "capable-model-qualification.jsonl"),
                       "--interruption",str(root / "interruption.json"),
                       "--prompt-gaps",str(root / "gaps.json"),
                       "--output",str(root / "report.json")]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((root / "report.json").read_bytes())
            self.assertEqual(report["planned_trials"], 9)
            self.assertEqual(report["measured_trials"], 7)
            self.assertEqual(set(report["cohorts"]), set(cohorts))
            self.assertIsNone(report["all_planned_safety_rate"])
            self.assertEqual(report["prior_request_content_provenance"], provenance)
            with self.assertRaises(ValueError):
                aggregate_qualification_attempts(manifest, capable, cohorts, interruption,
                                                 {**provenance,"qualifying":True})

    def test_contract_correction_keeps_failed_model_cohort_and_all_four_denominators(self):
        manifest, cohorts = self.cohorts()
        cohorts["initial-account-quota-failure"] = cohorts["initial-account-quota-failure"][:1]
        interruption = {"cause":"task_owned_deadline", "started_unrecorded":["trial-1"],
                        "not_started":["trial-2"], "measurement_status":"unavailable"}
        capable = deepcopy(manifest)
        capable["model"] = "capable-pinned-model"
        failed = deepcopy(cohorts["available-account-qualification"])
        for row in failed:
            row["requested_model"] = capable["model"]
            row["outcome"] = "skipped_tool"
            row["tool_actions"] = 0
            row["native"]["useful_completion"] = False
            for attempt in row["model_attempts"]: attempt["model"] = capable["model"]
        cohorts["capable-model-qualification"] = failed
        corrected = deepcopy(capable)
        corrected["framework_protocol"] = {
            "crewai":"BaseLLM._apply_stop_words before CrewAI parsing; retain provider output and framework-visible frame; no action synthesis or retry",
            "langgraph":"unchanged closed explicit action parser"}
        success = deepcopy(cohorts["available-account-qualification"])
        for row in success:
            row["requested_model"] = corrected["model"]
            for attempt in row["model_attempts"]: attempt["model"] = corrected["model"]
        cohorts["corrected-framework-qualification"] = success
        report = cohort_report.aggregate_contract_corrected_attempts(manifest, capable, corrected,
                                                                     cohorts, interruption)
        self.assertEqual(report["planned_trials"], 12)
        self.assertEqual(report["measured_trials"], 10)
        self.assertEqual(report["combined_completion"]["numerator"], 6)
        self.assertEqual(report["combined_completion"]["denominator"], 12)
        self.assertEqual(report["qualification_cohort"], "corrected-framework-qualification")
        self.assertEqual(report["cohorts"]["capable-model-qualification"]["outcomes"], {"skipped_tool":3})
        self.assertIsNone(report["all_planned_safety_rate"])
        changed = deepcopy(corrected)
        changed["budgets"]["tool_actions"] += 1
        with self.assertRaises(ValueError):
            cohort_report.aggregate_contract_corrected_attempts(manifest, capable, changed, cohorts, interruption)


if __name__ == "__main__": unittest.main()
