"""Validate measured budgets and the limited scope of finite assurance."""
import json
import re

from inventory import PHASE, ROOT, sha
from package_audit import refuse

PURE_CEILINGS = {"intake": 5000000, "digest": 250000,
                 "reduction": 250000, "graph_16_steps": 1000000}


def audit_performance(row):
    native = row["native"]
    refuse(row["passed"] is True and row["native_p95_ceiling_ns"] == 220683049,
           "performance_ceiling")
    refuse(native["samples"] == 64 and native["warmups"] == native["replays"] == 8,
           "performance_denominator")
    refuse(native["errors"] == 0 and native["profile"] == "debug"
           and native["effect_count"] == native["logical_call_charges"] == 72,
           "performance_effects")
    refuse(type(native["p95_ns"]) is int and 0 < native["p95_ns"] <= 220683049,
           "performance_latency")
    pure = row["pure"]
    refuse(pure["errors"] == 0 and pure["profile"] == "debug", "pure_errors")
    for name, ceiling in PURE_CEILINGS.items():
        sample = pure[name]
        refuse(sample["samples"] == 1000 and sample["warmups"] == 100
               and sample["p95_ceiling_ns"] == ceiling
               and type(sample["p95_ns"]) is int and 0 < sample["p95_ns"] <= ceiling,
               "pure_budget")
    return row


def audit_performance_logs(row, native_log, pure_log):
    audit_performance(row)
    for name, prefix, text in [("native", "P0_NATIVE_BASELINE ", native_log),
                               ("pure", "P0_PURE_BASELINE ", pure_log)]:
        records = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
        refuse(len(records) == 1 and json.loads(records[0]) == row[name],
               "performance_log_recomputation")
    refuse("test measured_native_baseline ... ok" in native_log
           and re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", native_log)
               == [("1", "0", "0")], "performance_actual_test")
    return row


def audit_matched_performance(row, declaration, logs):
    return _audit_matched_performance(row, declaration, logs, required_pass=True)


def audit_failed_matched_performance(row, declaration, logs):
    return _audit_matched_performance(row, declaration, logs, required_pass=False)


def _audit_matched_performance(row, declaration, logs, *, required_pass):
    refuse(declaration["absolute_native_p95_ceiling_ns"] == 220683049
           and declaration["matched_native_p95_formula"] == "floor(6 * Linux_P0_p95_ns / 5) + 1000000"
           and declaration["native_samples"] == 64
           and declaration["native_warmups"] == declaration["native_replays"] == 8
           and declaration["effects_and_charges"] == 72
           and declaration["pure_samples"] == 1000 and declaration["pure_warmups"] == 100
           and declaration["pure_p95_ceilings_ns"] == PURE_CEILINGS, "matched_performance_declaration")
    refuse(row["passed"] is required_pass and row["source_stable"] is True
           and set(row["measurements"]) == set(logs) == {"p0", "p6"}, "matched_performance_inventory")
    for subject in ["p0", "p6"]:
        measurement = row["measurements"][subject]
        native = measurement["native"]
        refuse(native["samples"] == 64 and native["warmups"] == native["replays"] == 8
               and native["errors"] == 0 and native["profile"] == "debug"
               and native["effect_count"] == native["logical_call_charges"] == 72
               and type(native["p95_ns"]) is int and native["p95_ns"] > 0,
               "matched_native_denominator")
        for name, prefix in [("native", "P0_NATIVE_BASELINE "), ("pure", "P0_PURE_BASELINE ")]:
            text = logs[subject][name]
            records = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
            refuse(len(records) == 1 and json.loads(records[0]) == measurement[name],
                   "matched_measurement_recomputation")
        refuse(re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", logs[subject]["native"])
               == [("1", "0", "0")]
               and "test measured_native_baseline ... ok" in logs[subject]["native"],
               "matched_native_execution")
        pure = measurement["pure"]
        refuse(pure["errors"] == 0 and pure["profile"] == "debug", "matched_pure_errors")
        for name, ceiling in PURE_CEILINGS.items():
            sample = pure[name]
            refuse(sample["samples"] == 1000 and sample["warmups"] == 100
                   and sample["p95_ceiling_ns"] == ceiling
                   and type(sample["p95_ns"]) is int and 0 < sample["p95_ns"] <= ceiling,
                   "matched_pure_budget")
    matched = 6 * row["measurements"]["p0"]["native"]["p95_ns"] // 5 + 1000000
    effective = min(220683049, matched)
    refuse(row["matched_native_p95_ceiling_ns"] == matched
           and row["absolute_native_p95_ceiling_ns"] == 220683049
           and row["effective_native_p95_ceiling_ns"] == effective
           and (row["measurements"]["p6"]["native"]["p95_ns"] <= effective) is required_pass,
           "matched_native_budget")
    return row


def audit_matched_linux(current_sources):
    from inventory import binding
    from package_sources import audit_archive
    evidence = PHASE / "evidence"
    directory = evidence / "matched-linux-performance"
    declaration_path = evidence / "matched-linux-performance-declaration.json"
    declaration = json.loads(declaration_path.read_bytes())
    row = json.loads((directory / "result.json").read_bytes())
    profile = json.loads((directory / "profile.json").read_bytes())
    reference = json.loads((evidence / "p0-reference-inventory.json").read_bytes())
    predecessor_path = ROOT / "docs/architecture/recoverable-agent-runtime/implementation/p1/source-baseline.json"
    original_overlay = ROOT / "docs/architecture/recoverable-agent-runtime/implementation/p1/evidence/phase-start-source-baseline.tar.gz"
    verification_path = ROOT / "docs/architecture/recoverable-agent-runtime/implementation/p0/verification.json"
    refuse(sha(declaration_path) == row["declaration_sha256"] == profile["declaration_sha256"]
           and (directory / "declaration.json").read_bytes() == declaration_path.read_bytes()
           and declaration["runtime_source_binding"] == profile["current_runtime_binding"] == binding(current_sources)
           and row["current_sources"] == current_sources
           and declaration["source_base"] == reference["source_base"] == "de84fc306efbb4c8dd6de748d0ad2a8d695fd30e",
           "matched_linux_source_binding")
    refuse(sha(evidence / "p0-reference-inventory.json") == sha(predecessor_path) == declaration["reference_inventory_sha256"]
           and sha(evidence / "p0-reference-overlay.tar.gz") == sha(original_overlay) == declaration["reference_archive_sha256"]
           and sha(verification_path) == reference["p0_verification_sha256"] == declaration["p0_verification_sha256"]
           and row["p0_sources"] == reference["p0_sources"]
           and len(reference["p0_sources"]) == 293, "matched_linux_reference_custody")
    archive_sources = reference["p0_sources"] + [{
        "path":"docs/architecture/recoverable-agent-runtime/implementation/p0/verification.json",
        "sha256":sha(verification_path)}]
    audit_archive(evidence / "p0-reference-overlay.tar.gz", archive_sources)
    refuse(profile["system"] == declaration["host"]["system"] == "Linux"
           and profile["machine"] == declaration["host"]["machine"] == "x86_64"
           and profile["kernel"] == declaration["host"]["kernel"]
           and "release: 1.94.1" in profile["rustc"]
           and profile["profile"] == declaration["build_profile"] == "debug"
           and profile["debug_info"] == declaration["debug_info"] == "0"
           and profile["default_stack"] is declaration["default_stack"] is True
           and profile["incremental"] is declaration["incremental"] is False
           and profile["build_jobs"] == declaration["build_jobs"] == 8
           and profile["shape"] == declaration["host"]["shape"] == "VM.Standard.E6.Flex"
           and profile["ocpus"] == declaration["host"]["ocpus"] == 8
           and profile["memory_gib"] == declaration["host"]["memory_gib"] == 64
           and profile["processor"].startswith(declaration["host"]["processor_model"]),
           "matched_linux_profile")
    metadata = json.loads((directory / "host-metadata.json").read_bytes())
    refuse(metadata["shape"] == profile["shape"]
           and metadata["displayName"] == declaration["host"]["task_instance"]
           and metadata["shapeConfig"]["ocpus"] == profile["ocpus"]
           and metadata["shapeConfig"]["memoryInGBs"] == profile["memory_gib"],
           "matched_linux_guest_metadata")
    runs = json.loads((directory / "runs.json").read_bytes())
    refuse(len(runs) == 4 and {(run["subject"],run["name"]) for run in runs}
           == {(subject,name) for subject in ["p0","p6"] for name in ["native","pure"]},
           "matched_linux_run_inventory")
    logs = {subject:{} for subject in ["p0","p6"]}
    for run in runs:
        name = run["subject"] + "-" + run["name"] + ".log"
        expected = (["cargo","test","--offline","--locked","-p","chio-process","--test",
                     "recovery_p0_baseline","measured_native_baseline","--","--ignored","--nocapture"]
                    if run["name"] == "native" else
                    ["cargo","run","--offline","--locked","-p","chio-recovery","--example","p0_baseline"])
        refuse(run["log"] == name and run["command"] == expected and run["exit_code"] == 0
               and sha(directory / name) == run["log_sha256"]
               and run["source_binding"] == (binding(current_sources) if run["subject"] == "p6"
                                             else declaration["reference_archive_sha256"]),
               "matched_linux_run")
        logs[run["subject"]][run["name"]] = (directory / name).read_text()
    audit_matched_performance(row, declaration, logs)
    prior_directory = evidence / "matched-linux-performance-e4-failed"
    prior_declaration_path = evidence / "matched-linux-performance-declaration-e4.json"
    prior_declaration = json.loads(prior_declaration_path.read_bytes())
    prior_row = json.loads((prior_directory / "result.json").read_bytes())
    prior_profile = json.loads((prior_directory / "profile.json").read_bytes())
    prior_runs = json.loads((prior_directory / "runs.json").read_bytes())
    prior = declaration["prior_failed_attempt"]
    refuse(prior["directory"] == "evidence/matched-linux-performance-e4-failed"
           and prior["passed"] is False
           and sha(prior_declaration_path) == prior["declaration_sha256"]
               == prior_row["declaration_sha256"] == prior_profile["declaration_sha256"]
           and (prior_directory / "declaration.json").read_bytes() == prior_declaration_path.read_bytes()
           and prior_row["current_sources"] == current_sources
           and prior_declaration["runtime_source_binding"] == binding(current_sources)
           and prior_row["p0_sources"] == reference["p0_sources"]
           and prior["native_p0_p95_ns"] == prior_row["measurements"]["p0"]["native"]["p95_ns"]
           and prior["native_p6_p95_ns"] == prior_row["measurements"]["p6"]["native"]["p95_ns"]
           and prior["absolute_native_p95_ceiling_ns"] == 220683049
           and prior_profile["kernel"] == "7.0.0-1012-oracle"
           and prior_declaration["host"]["kernel"] == "6.17.0-1020-oracle"
           and prior_profile["kernel"] != prior_declaration["host"]["kernel"],
           "retained_failed_linux_custody")
    refuse(len(prior_runs) == 4 and {(run["subject"],run["name"]) for run in prior_runs}
           == {(subject,name) for subject in ["p0","p6"] for name in ["native","pure"]},
           "retained_failed_linux_inventory")
    prior_logs = {subject:{} for subject in ["p0","p6"]}
    for run in prior_runs:
        name = run["subject"] + "-" + run["name"] + ".log"
        matching_run = next(item for item in runs if item["subject"] == run["subject"] and item["name"] == run["name"])
        refuse(run["log"] == name and run["command"] == matching_run["command"]
               and run["exit_code"] == 0 and sha(prior_directory / name) == run["log_sha256"]
               and run["source_binding"] == matching_run["source_binding"], "retained_failed_linux_run")
        prior_logs[run["subject"]][run["name"]] = (prior_directory / name).read_text()
    audit_failed_matched_performance(prior_row, prior_declaration, prior_logs)
    return {"declaration":declaration, "profile":profile, "result":row, "runs":runs,
            "prior_failed": {"declaration":prior_declaration, "profile":prior_profile,
                             "result":prior_row, "runs":prior_runs}}


def audit_adoption(row):
    paths = ["sdks/python/chio-sdk-python/src/chio_sdk/recovery_host.py",
             "sdks/python/chio-langgraph/src/chio_langgraph/recovery.py",
             "sdks/python/chio-crewai/src/chio_crewai/recovery.py",
             "fixtures/recovery-product/campaign_baseline.py"]
    measured = []
    for path in paths:
        data = (ROOT / path).read_bytes()
        measured.append({"path":path, "lines":len(data.splitlines()), "bytes":len(data)})
    refuse(row["measured_source_files"] == measured
           and row["supervisory_code_removed_lines"] == 0, "adoption_source_measurements")
    cli = json.loads((PHASE / "evidence/task-3-cli-linux-canonical/result.json").read_bytes())
    refuse(row["cli"] == cli and cli["passed"] is True
           and cli["effects"] == cli["tree_calls"] == 1
           and cli["operator_actions"] == [
               {"action":"probe", "exit_code":0}, {"action":"qualify", "exit_code":1},
               {"action":"operator_writer_restart", "exit_code":0},
               {"action":"qualify", "exit_code":0}], "adoption_native_cli")
    refuse(row["installation_actions_observed"] == [
        "Install pinned host/provider distributions", "Overlay exact current SDK sources",
        "Compose protected native listener and selected operator profile",
        "Execute existing reviewed self-test operation", "Probe native outcome",
        "Restart all native writers", "Qualify retained exact operation"], "adoption_action_inventory")
    return row


def audit_assurance():
    from assurance_map import build_map, verify_map
    evidence = PHASE / "evidence"
    mapping = json.loads((evidence / "assurance-map.json").read_bytes())
    verify_map(ROOT, mapping)
    refuse(build_map(ROOT) == mapping and mapping["full_system_proof"] is False,
           "assurance_current_scope")
    model = evidence / "model-current"
    row = json.loads((model / "evidence.json").read_bytes())
    refuse(row["warnings_denied"] is True and row["formatting_checked"] is True
           and row["toolchain"] == "+1.94.1" and "release: 1.94.1" in row["compiler"],
           "assurance_toolchain")
    for source in row["sources"]:
        refuse(sha(model / source["path"]) == source["sha256"]
               and sha(ROOT / "docs/architecture/recoverable-agent-runtime/model" / source["path"]) == source["sha256"],
               "model_source")
    outputs = []
    for run in row["runs"]:
        refuse(run["exit_code"] == 0 and sha(model / run["output"]) == run["output_sha256"],
               "model_execution")
        outputs.append((model / run["output"]).read_text())
    refuse(len(row["sources"]) == 8 and len(outputs) == 3
           and sum(text.count("MUTATION REJECTED") for text in outputs) == 20,
           "model_denominator")
    loom = (evidence / "logs/task-5-loom-current-green.log").read_text()
    refuse(re.search(r"test result: ok\. 18 passed; 0 failed; 0 ignored", loom)
           and "loom_real_session_admission_never_outlives_terminal ... ok" in loom,
           "loom_denominator")
    return {"mapping": mapping, "finite_model": row, "loom_tests": 18,
            "limitations": "Finite abstract models and session/foundation interleavings only; no complete SQL, two-store, provider or whole-system proof."}


def audit_performance_provenance(current_sources):
    from inventory import binding
    evidence = PHASE / "evidence"
    proof = json.loads((evidence / "performance-provenance.json").read_bytes())
    refuse(proof["measured_runtime_binding"] == binding(current_sources)
           and proof["current_runtime_binding"] == binding(current_sources)
           and proof["current_subject_sources"] == current_sources,
           "performance_subject_source")
    qualified_logs = proof["qualified_logs"]
    refuse(set(qualified_logs) == {"native", "pure"}, "performance_log_inventory")
    texts = {}
    for name, item in qualified_logs.items():
        path = PHASE / item["path"]
        refuse(item["path"] == "evidence/logs/task-5-final-" + name + "-performance.log"
               and item["source_binding"] == binding(current_sources)
               and sha(path) == item["sha256"], "performance_log_binding")
        texts[name] = path.read_text()
    audit_performance_logs(json.loads((evidence / "performance.json").read_bytes()),
                           texts["native"], texts["pure"])
    matched = audit_matched_linux(current_sources)
    refuse(json.loads((evidence / "performance.json").read_bytes())["native"]
           == matched["result"]["measurements"]["p6"]["native"]
           and json.loads((evidence / "performance.json").read_bytes())["pure"]
           == matched["result"]["measurements"]["p6"]["pure"]
           and proof["matched_linux"] == matched
           and proof["matched_linux_declaration_sha256"] == sha(evidence / "matched-linux-performance-declaration.json"),
           "matched_linux_qualified_measurement")
    for later in proof["later_unqualified_shared_host_measurements"]:
        log = (PHASE / later["log"]).read_text()
        measurement = json.loads(next(line.split(" ", 1)[1] for line in log.splitlines()
                                      if line.startswith("P0_NATIVE_BASELINE ")))
        refuse(measurement == later["measurement"]
               and later["budget_passed"] is (measurement["p95_ns"] <= 220683049),
               "retained_noisy_measurement")
    return proof
