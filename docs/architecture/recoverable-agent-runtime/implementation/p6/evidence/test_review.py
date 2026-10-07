"""Post-review edits cannot borrow the original fresh review's verdict."""
from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import tempfile
import unittest

from cohort_report import REVIEW_FIX_PATHS


class PrimaryReviewAcceptanceTest(unittest.TestCase):
    def test_public_native_preflight_requires_eight_current_independent_cases(self):
        module = importlib.import_module("review_acceptance")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = b'{"policy":"synthetic-test"}'
            policy = hashlib.sha256(authority).hexdigest()
            (root / "authority-contract.json").write_bytes(authority)
            cases = []
            for host in ["langgraph", "crewai"]:
                for workflow in ["support", "artifact"]:
                    for arm in ["baseline", "product"]:
                        path = root / (host + "-" + workflow + "-" + arm)
                        path.mkdir()
                        native = {"native_actions":1, "useful_completion":True,
                                  "source_label_retained":True, "unauthorized_effects":0,
                                  "duplicate_effects":0, "charges":1}
                        (path / "native-evidence.json").write_text(json.dumps(native))
                        (path / "authority-contract.json").write_bytes(authority)
                        (path / "native.log").write_text("test result: ok. 1 passed; 0 failed; 0 ignored\n")
                        frames = [{"mode":"model-free", "provider_requests":0, "completion":"Action: recovery"}]
                        if host == "crewai":
                            frames[0].update(framework_stop_sequences=["\nObservation:"],
                                             framework_completion="Action: recovery")
                        cases.append({"host":host, "workflow":workflow, "arm":arm, "case":"authorized",
                                      "native":native, "outcome":{"category":"complete"},
                                      "model_free_actions":1, "provider_requests":0,
                                      "scripted_external_input":True, "model_frames":frames,
                                      "authority_policy":policy})
            result = {"cases":cases, "passed":True, "mode":"model-free-native-preflight", "provider_requests":0}
            binding = {"source_binding":"a"*64, "source_stable":True, "exit_code":0,
                       "provider_requests":0, "mode":"public-model-free-native-preflight"}
            def write(candidate):
                (root / "result.json").write_text(json.dumps(candidate))
                binding["result_sha256"] = hashlib.sha256((root / "result.json").read_bytes()).hexdigest()
                (root / "binding.json").write_text(json.dumps(binding))
            write(result)
            self.assertEqual(module.audit_public_preflight(root,"a"*64,policy)["cases"],8)
            for mutation in ["missing", "duplicate", "provider", "native", "frame"]:
                changed = deepcopy(result)
                if mutation == "missing": changed["cases"].pop()
                elif mutation == "duplicate": changed["cases"][-1] = deepcopy(changed["cases"][0])
                elif mutation == "provider": changed["cases"][0]["provider_requests"] = 1
                elif mutation == "native": changed["cases"][0]["native"]["charges"] = 0
                else: changed["cases"][-1]["model_frames"][0]["framework_completion"] = "invented"
                write(changed)
                with self.assertRaises(ValueError, msg=mutation):
                    module.audit_public_preflight(root,"a"*64,policy)
            write(result)
            with self.assertRaises(ValueError):
                module.audit_public_preflight(root,"foreign",policy)

    def test_missing_fix_unknown_edit_changed_logs_and_false_closure_refuse(self):
        module = importlib.import_module("review_acceptance")
        old = [{"path":path,"sha256":"0"*64} for path in sorted(REVIEW_FIX_PATHS)]
        new = [{"path":path,"sha256":"1"*64} for path in sorted(REVIEW_FIX_PATHS)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = {}
            logs = {
                "setup-red": "running 1 test\nassertion failed: expected_revision\ntest result: FAILED. 0 passed; 1 failed; 0 ignored\n",
                "setup-green": "\n".join("test module::" + name + " ... ok" for name in [
                    "p6_setup_every_foreign_binding_and_old_profile_refuses",
                    "p6_setup_initial_operator_bootstrap_binds_after_approval_and_restarts_once",
                    "p6_setup_preapproval_pin_binds_once_without_changing_after_capture"])
                    + "\ntest result: ok. 9 passed; 0 failed; 1 ignored\n",
                "preflight-red": "AttributeError: 'ExplicitAction' object has no attribute 'attempts'\nRan 7 tests\nFAILED (errors=1)\n",
                "preflight-green": "Ran 14 tests\nOK\n",
            }
            for name, text in logs.items():
                path = root / (name + ".log")
                path.write_text(text)
                records[name] = {"path":path.name, "sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
            proof = {"mode":"single_primary_TDD_pass_no_rereview", "fixed_findings":["P1-1","P1-2"],
                     "source_delta":module.source_delta(old,new), "runtime_source_binding":"a"*64,
                     "regressions":{
                         "setup":{"red":records["setup-red"],"green":records["setup-green"],"green_source_binding":"a"*64},
                         "preflight":{"red":records["preflight-red"],"green":records["preflight-green"],"green_source_binding":"a"*64},
                     }}
            self.assertEqual(module.audit_primary_fix(proof,old,new,root,"a"*64), proof)
            for mutation in ["missing", "unknown-edit", "scope", "source", "log", "unfixed", "mode"]:
                changed = deepcopy(proof)
                final = deepcopy(new)
                if mutation == "missing": changed["regressions"].pop("setup")
                elif mutation == "unknown-edit": final.append({"path":"crates/kernel/unknown.rs","sha256":"2"*64})
                elif mutation == "scope": changed["source_delta"].pop()
                elif mutation == "source": changed["regressions"]["setup"]["green_source_binding"] = "foreign"
                elif mutation == "log": changed["regressions"]["setup"]["red"]["sha256"] = "0"*64
                elif mutation == "unfixed": changed["fixed_findings"] = ["P1-1"]
                else: changed["mode"] = "silently_relabel_original_review"
                with self.assertRaises(ValueError, msg=mutation):
                    module.audit_primary_fix(changed,old,final,root,"a"*64)


if __name__ == "__main__": unittest.main()
