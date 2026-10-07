"""Qualification budgets cannot be raised or satisfied by empty measurements."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

import package_measurements
from package_measurements import audit_performance


class PerformanceAuditTest(unittest.TestCase):
    def test_matched_linux_budget_and_original_absolute_ceiling_both_apply(self):
        pure = {name:{"samples":1000,"warmups":100,"p95_ns":10,"p95_ceiling_ns":ceiling}
                for name,ceiling in package_measurements.PURE_CEILINGS.items()}
        pure.update(errors=0,profile="debug")
        native = {"samples":64,"warmups":8,"replays":8,"p95_ns":100,"errors":0,
                  "profile":"debug","effect_count":72,"logical_call_charges":72}
        measurements = {"p0":{"native":native,"pure":pure},
                        "p6":{"native":{**native,"p95_ns":110},"pure":pure}}
        declaration = {"absolute_native_p95_ceiling_ns":220683049,
                       "matched_native_p95_formula":"floor(6 * Linux_P0_p95_ns / 5) + 1000000",
                       "native_samples":64,"native_warmups":8,"native_replays":8,
                       "effects_and_charges":72,"pure_samples":1000,"pure_warmups":100,
                       "pure_p95_ceilings_ns":package_measurements.PURE_CEILINGS}
        logs = {}
        for subject in measurements:
            logs[subject] = {
                "native":"P0_NATIVE_BASELINE " + json.dumps(measurements[subject]["native"])
                         + "\ntest measured_native_baseline ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n",
                "pure":"P0_PURE_BASELINE " + json.dumps(pure) + "\n"}
        good = {"passed":True,"source_stable":True,"measurements":measurements,
                "matched_native_p95_ceiling_ns":1000120,"absolute_native_p95_ceiling_ns":220683049,
                "effective_native_p95_ceiling_ns":1000120}
        self.assertEqual(package_measurements.audit_matched_performance(good,declaration,logs),good)
        for mutation in ["formula", "absolute", "empty", "faster", "unmeasured", "slow", "source"]:
            row=deepcopy(good); inputs=deepcopy(logs)
            if mutation == "formula":row["matched_native_p95_ceiling_ns"] += 1
            elif mutation == "absolute":row["absolute_native_p95_ceiling_ns"] += 1
            elif mutation == "empty":row["measurements"]["p0"]["native"]["samples"] = 0
            elif mutation == "faster":row["measurements"]["p6"]["native"]["p95_ns"] = 109
            elif mutation == "unmeasured":inputs["p0"]["native"] = ""
            elif mutation == "slow":row["measurements"]["p6"]["native"]["p95_ns"] = 1000121
            else:row["source_stable"] = False
            with self.assertRaises(ValueError,msg=mutation):
                package_measurements.audit_matched_performance(row,declaration,inputs)

        failed = deepcopy(good)
        failed["passed"] = False
        failed["measurements"]["p0"]["native"]["p95_ns"] = 200000000
        failed["measurements"]["p6"]["native"]["p95_ns"] = 224502188
        failed["matched_native_p95_ceiling_ns"] = 241000000
        failed["effective_native_p95_ceiling_ns"] = 220683049
        failed_logs = deepcopy(logs)
        for subject in failed["measurements"]:
            failed_logs[subject]["native"] = (
                "P0_NATIVE_BASELINE " + json.dumps(failed["measurements"][subject]["native"])
                + "\ntest measured_native_baseline ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n")
        self.assertEqual(package_measurements.audit_failed_matched_performance(
            failed, declaration, failed_logs), failed)
        for mutation in ["censored_failure", "invented_fast", "missing_reference", "raised_ceiling"]:
            row = deepcopy(failed); inputs = deepcopy(failed_logs)
            if mutation == "censored_failure": row["passed"] = True
            elif mutation == "invented_fast": row["measurements"]["p6"]["native"]["p95_ns"] = 219000000
            elif mutation == "missing_reference": inputs["p0"]["native"] = ""
            else: row["absolute_native_p95_ceiling_ns"] += 1
            with self.assertRaises(ValueError, msg=mutation):
                package_measurements.audit_failed_matched_performance(row, declaration, inputs)
        disguised_pass = deepcopy(good); disguised_pass["passed"] = False
        with self.assertRaises(ValueError):
            package_measurements.audit_failed_matched_performance(disguised_pass, declaration, logs)

    def test_error_empty_charge_mismatch_and_changed_ceiling_refuse(self):
        pure = {name: {"samples": 1000, "warmups": 100, "p95_ns": 10,
                      "p95_ceiling_ns": ceiling}
                for name, ceiling in {"intake": 5000000, "digest": 250000,
                                      "reduction": 250000, "graph_16_steps": 1000000}.items()}
        pure.update(errors=0, profile="debug")
        good = {"passed": True, "native_p95_ceiling_ns": 220683049, "pure": pure,
                "native": {"samples": 64, "warmups": 8, "replays": 8,
                           "p95_ns": 100, "errors": 0, "profile": "debug",
                           "effect_count": 72, "logical_call_charges": 72}}
        audit_performance(good)
        for mutation in ["error", "empty", "charges", "ceiling", "slow", "pure"]:
            row = deepcopy(good)
            if mutation == "error": row["native"]["errors"] = 1
            elif mutation == "empty": row["native"]["samples"] = 0
            elif mutation == "charges": row["native"]["logical_call_charges"] = 73
            elif mutation == "ceiling": row["native_p95_ceiling_ns"] += 1
            elif mutation == "slow": row["native"]["p95_ns"] = 220683050
            else: row["pure"]["digest"]["samples"] = 0
            with self.assertRaises(ValueError, msg=mutation): audit_performance(row)

    def test_passing_budget_cannot_substitute_an_unmeasured_faster_value(self):
        evidence = Path(__file__).parent
        actual = json.loads((evidence / "performance-reviewed.json").read_bytes())
        native = (evidence / "logs/task-5-native-performance.log").read_text()
        pure = (evidence / "logs/task-5-pure-performance.log").read_text()
        package_measurements.audit_performance_logs(actual, native, pure)
        altered = deepcopy(actual)
        altered["native"]["p95_ns"] -= 1
        audit_performance(altered)
        with self.assertRaises(ValueError):
            package_measurements.audit_performance_logs(altered, native, pure)
        for changed_native, changed_pure in [
            (native.replace("1 passed; 0 failed; 0 ignored", "0 passed; 0 failed; 1 ignored"), pure),
            (native + native, pure),
            (native, ""),
            (native, pure + pure),
        ]:
            with self.assertRaises(ValueError):
                package_measurements.audit_performance_logs(actual, changed_native, changed_pure)


if __name__ == "__main__": unittest.main()
