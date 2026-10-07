"""Keep the fresh review and the primary verified fix pass distinct."""
import hashlib
import json
from pathlib import Path
import re

from cohort_report import REVIEW_FIX_PATHS
from package_audit import refuse

PREFIX = "docs/architecture/recoverable-agent-runtime/implementation/p6/"
QUALIFICATION_FIX_PATHS = frozenset(PREFIX + name for name in [
    "evidence/cohort_report.py", "evidence/package_audit.py", "evidence/package_record.py",
    "evidence/package_measurements.py", "evidence/verify-package.py", "evidence/test_cohorts.py",
    "evidence/review_acceptance.py", "evidence/test_review.py", "OPERATIONS.md",
    "REPRODUCE.md", "supported-matrix.json", "evidence/verify-package-mutations.py",
    "evidence/test_measurements.py", "evidence/seal-package.py", "evidence/test_sources.py",
])
SETUP_CASES = frozenset({
    "p6_setup_every_foreign_binding_and_old_profile_refuses",
    "p6_setup_initial_operator_bootstrap_binds_after_approval_and_restarts_once",
    "p6_setup_preapproval_pin_binds_once_without_changing_after_capture",
})


def audit_public_preflight(directory, runtime_binding, authority_policy):
    from package_audit import audit_framework_frame
    result_path = directory / "result.json"
    result = json.loads(result_path.read_bytes())
    binding = json.loads((directory / "binding.json").read_bytes())
    refuse(binding["source_binding"] == runtime_binding and binding["source_stable"] is True
           and binding["exit_code"] == binding["provider_requests"] == 0
           and binding["mode"] == "public-model-free-native-preflight"
           and binding["result_sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest(),
           "public_preflight_binding")
    expected = {(host, workflow, arm) for host in ["langgraph", "crewai"]
                for workflow in ["support", "artifact"] for arm in ["baseline", "product"]}
    cases = result["cases"]
    refuse(result["passed"] is True and result["mode"] == "model-free-native-preflight"
           and result["provider_requests"] == 0 and len(cases) == 8
           and {(row["host"], row["workflow"], row["arm"]) for row in cases} == expected,
           "public_preflight_inventory")
    refuse(hashlib.sha256((directory / "authority-contract.json").read_bytes()).hexdigest()
           == authority_policy, "public_preflight_authority")
    for row in cases:
        native_directory = directory / (row["host"] + "-" + row["workflow"] + "-" + row["arm"])
        facts = json.loads((native_directory / "native-evidence.json").read_bytes())
        refuse(row["native"] == facts and facts["native_actions"] == 1
               and facts["useful_completion"] is facts["source_label_retained"] is True
               and facts["unauthorized_effects"] == facts["duplicate_effects"] == 0,
               "public_preflight_native_facts")
        log = (native_directory / "native.log").read_text()
        refuse(re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", log)
               == [("1", "0", "0")] and "FAILED" not in log, "public_preflight_native_execution")
        refuse(row["authority_policy"] == authority_policy
               == hashlib.sha256((native_directory / "authority-contract.json").read_bytes()).hexdigest()
               and row["case"] == "authorized" and row["outcome"]["category"] == "complete"
               and row["model_free_actions"] == 1 and row["provider_requests"] == 0
               and row["scripted_external_input"] is True and len(row["model_frames"]) == 1,
               "public_preflight_outcome")
        frame = row["model_frames"][0]
        refuse(frame["mode"] == "model-free" and frame["provider_requests"] == 0,
               "public_preflight_model_free")
        audit_framework_frame({**frame, "error":None}, row["host"])
    return {"cases":8, "provider_requests":0, "source_binding":runtime_binding,
            "mode":"model-free-native-preflight", "binding":binding}


def source_delta(before, after):
    old = {row["path"]:row["sha256"] for row in before}
    new = {row["path"]:row["sha256"] for row in after}
    refuse(len(old) == len(before) and len(new) == len(after), "fix_source_duplicates")
    return [{"path":path,"before_sha256":old.get(path),"after_sha256":new.get(path)}
            for path in sorted(set(old) | set(new)) if old.get(path) != new.get(path)]


def audit_primary_fix(proof, reviewed_sources, final_sources, root, runtime_binding):
    delta = source_delta(reviewed_sources, final_sources)
    runtime = {row["path"] for row in delta if not row["path"].startswith(PREFIX)}
    qualification = {row["path"] for row in delta if row["path"].startswith(PREFIX)}
    refuse(runtime == REVIEW_FIX_PATHS and qualification <= QUALIFICATION_FIX_PATHS
           and all(row["after_sha256"] is not None for row in delta)
           and proof["source_delta"] == delta, "primary_fix_scope")
    refuse(proof["mode"] == "single_primary_TDD_pass_no_rereview"
           and proof["fixed_findings"] == ["P1-1", "P1-2"]
           and proof["runtime_source_binding"] == runtime_binding
           and set(proof["regressions"]) == {"setup", "preflight"}, "primary_fix_findings")
    texts = {}
    for name, record in proof["regressions"].items():
        refuse(record["green_source_binding"] == runtime_binding, "primary_fix_current_green")
        for outcome in ["red", "green"]:
            item = record[outcome]
            relative = Path(item["path"])
            refuse(not relative.is_absolute() and ".." not in relative.parts, "primary_fix_log_path")
            path = root / relative
            refuse(path.is_file() and not path.is_symlink()
                   and hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], "primary_fix_log_hash")
            texts[name + "-" + outcome] = path.read_text()
    red = texts["setup-red"]
    green = texts["setup-green"]
    refuse("expected_revision" in red
           and "test result: FAILED. 0 passed; 1 failed; 0 ignored" in red,
           "primary_setup_behavioral_red")
    refuse(re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", green) == [("9", "0", "1")]
           and all(re.search(r"^test .*::" + name + r" \.\.\. ok$", green, re.MULTILINE) for name in SETUP_CASES)
           and "FAILED" not in green, "primary_setup_current_green")
    red = texts["preflight-red"]
    green = texts["preflight-green"]
    refuse("AttributeError" in red and "ExplicitAction" in red and "attempts" in red
           and "Ran 7 tests" in red and "FAILED (errors=1)" in red,
           "primary_preflight_behavioral_red")
    refuse("Ran 14 tests" in green and re.search(r"^OK$", green, re.MULTILINE)
           and "FAILED" not in green, "primary_preflight_current_green")
    return proof
