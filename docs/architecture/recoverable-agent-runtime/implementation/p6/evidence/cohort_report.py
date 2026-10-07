"""Report complete sequential cohorts without replacing failed trial identities."""
from copy import deepcopy
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[6]
sys.path.insert(0, str(ROOT / "fixtures/recovery-product"))
from campaign_report import summarize, _rate

COHORTS = ("initial-account-quota-failure", "available-account-qualification")
CAPABLE_COHORT = "capable-model-qualification"
CORRECTED_COHORT = "corrected-framework-qualification"
REVIEW_FIX_COHORT = "review-fix-qualification"
REVIEW_FIX_PATHS = frozenset({
    "crates/platform/chio-store-sqlite/src/admission_operation_store/setup.rs",
    "crates/platform/chio-store-sqlite/src/admission_operation_store/setup/service.rs",
    "crates/platform/chio-control-plane/src/recovery/tests/knowledge/setup.rs",
    "crates/platform/chio-control-plane/src/recovery/tests/knowledge/setup/cli_host.rs",
    "fixtures/recovery-product/preflight.py",
    "fixtures/recovery-product/test_campaign_runner.py",
})
CORRECTED_PROTOCOL = {
    "crewai":"BaseLLM._apply_stop_words before CrewAI parsing; retain provider output and framework-visible frame; no action synthesis or retry",
    "langgraph":"unchanged closed explicit action parser"}


def aggregate_cohorts(manifest, rows_by_cohort):
    if set(rows_by_cohort) != set(COHORTS):
        raise ValueError("campaign.missing_or_extra_cohort")
    individual = {}
    combined_manifest = deepcopy(manifest)
    combined_manifest["trials"] = []
    combined_rows = []
    for cohort in COHORTS:
        rows = rows_by_cohort[cohort]
        individual[cohort] = summarize(manifest, rows)
        for trial in manifest["trials"]:
            combined_manifest["trials"].append({**trial,"id":cohort+":"+trial["id"]})
        combined_rows += [{**row,"id":cohort+":"+row["id"]} for row in rows]
    return {"schema":"chio.recovery-p6-cohort-report.v1", "cohorts":individual,
            "combined":summarize(combined_manifest, combined_rows),
            "interpretation":"Both original quota failures and the complete independent qualification cohort are retained. Account availability differs; no independent-runtime security or comparative utility superiority is inferred."}


def aggregate_interrupted_cohorts(manifest, rows_by_cohort, interruption):
    if set(rows_by_cohort) != set(COHORTS) or interruption.get("cause") != "task_owned_deadline" or interruption.get("measurement_status") != "unavailable":
        raise ValueError("campaign.unqualified_interruption")
    planned = {trial["id"]:trial for trial in manifest["trials"]}
    initial = rows_by_cohort[COHORTS[0]]
    recorded = {row["id"] for row in initial}
    started = interruption["started_unrecorded"]
    unstarted = interruption["not_started"]
    if (len(set(started)) != len(started) or len(set(unstarted)) != len(unstarted)
        or set(started) & set(unstarted) or set(started + unstarted) != set(planned) - recorded):
        raise ValueError("campaign.interruption_denominator")
    partial = deepcopy(manifest)
    partial["trials"] = [trial for trial in manifest["trials"] if trial["id"] in recorded]
    initial_report = summarize(partial, initial)
    qualified = summarize(manifest, rows_by_cohort[COHORTS[1]])
    measured = initial + rows_by_cohort[COHORTS[1]]
    total = 2 * len(manifest["trials"])
    numerator = sum(row["native"]["useful_completion"] and row["outcome"] == "complete" for row in measured)
    return {"schema":"chio.recovery-p6-interrupted-cohort-report.v1", "planned_trials":total,
            "measured_trials":len(measured), "unrecorded_trials":len(started + unstarted),
            "interrupted_started_trials":len(started), "not_started_trials":len(unstarted),
            "interrupted_model_calls_upper_bound":len(started) * manifest["budgets"]["model_calls"],
            "combined_completion":_rate(numerator, total), "all_planned_safety_rate":None,
            "cohorts":{COHORTS[0]:{"planned_trials":len(planned), "measurement_status":"interrupted",
                                    "recorded":initial_report,"interruption":interruption},
                       COHORTS[1]:qualified},
            "observed_unauthorized_effects":sum(row["native"]["unauthorized_effects"] for row in measured),
            "observed_duplicate_effects":sum(row["native"]["duplicate_effects"] for row in measured),
            "interpretation":"All planned slots remain in completion denominators. Missing interrupted measurements are unknown and cannot establish safety, label retention, latency or token usage. Qualification uses only the complete independently declared cohort; the interrupted cohort remains unsuccessful."}


def aggregate_qualification_attempts(original_manifest, capable_manifest, rows_by_cohort, interruption, prompt_gaps=None):
    if set(rows_by_cohort) != set(COHORTS + (CAPABLE_COHORT,)):
        raise ValueError("campaign.missing_qualification_attempt")
    ignore = {"model", "sources", "source_binding"}
    if ({key:value for key,value in original_manifest.items() if key not in ignore}
        != {key:value for key,value in capable_manifest.items() if key not in ignore}):
        raise ValueError("campaign.changed_matched_policy")
    if "sources" in original_manifest:
        original = {row["path"]:row["sha256"] for row in original_manifest["sources"]}
        current = {row["path"]:row["sha256"] for row in capable_manifest["sources"]}
        changes = {path for path in original if original[path] != current.get(path)}
        if set(original) != set(current) or changes != {"fixtures/recovery-product/campaign_runner.py", "fixtures/recovery-product/test_campaign_runner.py"}:
            raise ValueError("campaign.changed_native_or_matched_source")
    elif original_manifest["source_binding"] != capable_manifest["source_binding"]:
        raise ValueError("campaign.changed_source_binding")
    prior = aggregate_interrupted_cohorts(original_manifest,
             {name:rows_by_cohort[name] for name in COHORTS}, interruption)
    current = summarize(capable_manifest, rows_by_cohort[CAPABLE_COHORT])
    all_rows = [row for rows in rows_by_cohort.values() for row in rows]
    planned = prior["planned_trials"] + len(capable_manifest["trials"])
    complete = sum(row["native"]["useful_completion"] and row["outcome"] == "complete" for row in all_rows)
    report = {**prior, "schema":"chio.recovery-p6-qualification-attempts-report.v1",
            "planned_trials":planned, "measured_trials":len(all_rows),
            "combined_completion":_rate(complete, planned),
            "qualification_cohort":CAPABLE_COHORT,
            "cohorts":{**prior["cohorts"], CAPABLE_COHORT:current},
            "observed_unauthorized_effects":sum(row["native"]["unauthorized_effects"] for row in all_rows),
            "observed_duplicate_effects":sum(row["native"]["duplicate_effects"] for row in all_rows),
            "interpretation":"The interrupted quota cohort and complete unsuccessful mini-model utility cohort remain retained. Only the complete additional capable-model cohort can qualify. Exact model and the two-file precollection prompt-custody correction change; native owners, SDKs, task/authority/budget parameters and all earlier denominators remain identical. Earlier prompt-snapshot gaps are explicitly unavailable provenance. No general superiority or account-independent availability inference."}
    if prompt_gaps is not None:
        attempts = {(cohort, row["id"], index)
                    for cohort in COHORTS for row in rows_by_cohort[cohort]
                    for index in range(len(row["model_attempts"]))}
        identities = [(gap["cohort"], gap["id"], gap["attempt"]) for gap in prompt_gaps["gaps"]]
        if (prompt_gaps.get("measurement_status") != "unavailable"
            or prompt_gaps.get("qualifying") is not False
            or len(set(identities)) != len(identities)
            or not set(identities) <= attempts):
            raise ValueError("campaign.invalid_prior_request_content_provenance")
        report["prior_request_content_provenance"] = deepcopy(prompt_gaps)
    return report


def aggregate_contract_corrected_attempts(original_manifest, capable_manifest, corrected_manifest,
                                        rows_by_cohort, interruption, prompt_gaps=None):
    if set(rows_by_cohort) != set(COHORTS + (CAPABLE_COHORT, CORRECTED_COHORT)):
        raise ValueError("campaign.missing_contract_correction_attempt")
    excluded = {"sources", "source_binding", "framework_protocol"}
    if ({key:value for key,value in capable_manifest.items() if key not in excluded}
        != {key:value for key,value in corrected_manifest.items() if key not in excluded}
        or corrected_manifest.get("framework_protocol") != CORRECTED_PROTOCOL):
        raise ValueError("campaign.changed_contract_correction_policy")
    if "sources" in capable_manifest:
        before = {row["path"]:row["sha256"] for row in capable_manifest["sources"]}
        after = {row["path"]:row["sha256"] for row in corrected_manifest["sources"]}
        if (set(before) != set(after)
            or {path for path in before if before[path] != after[path]}
                != {"fixtures/recovery-product/campaign_runner.py", "fixtures/recovery-product/test_campaign_runner.py"}):
            raise ValueError("campaign.changed_contract_correction_source")
    elif capable_manifest["source_binding"] != corrected_manifest["source_binding"]:
        raise ValueError("campaign.changed_contract_correction_source")
    prior = aggregate_qualification_attempts(original_manifest, capable_manifest,
                {name:rows_by_cohort[name] for name in COHORTS + (CAPABLE_COHORT,)},
                interruption, prompt_gaps)
    current = summarize(corrected_manifest, rows_by_cohort[CORRECTED_COHORT])
    rows = [row for values in rows_by_cohort.values() for row in values]
    planned = prior["planned_trials"] + len(corrected_manifest["trials"])
    complete = sum(row["native"]["useful_completion"] and row["outcome"] == "complete" for row in rows)
    return {**prior, "schema":"chio.recovery-p6-contract-corrected-attempts-report.v1",
            "planned_trials":planned, "measured_trials":len(rows),
            "combined_completion":_rate(complete, planned), "qualification_cohort":CORRECTED_COHORT,
            "cohorts":{**prior["cohorts"], CORRECTED_COHORT:current},
            "observed_unauthorized_effects":sum(row["native"]["unauthorized_effects"] for row in rows),
            "observed_duplicate_effects":sum(row["native"]["duplicate_effects"] for row in rows),
            "interpretation":"All earlier failed cohorts and interrupted unknown slots remain retained. Only the complete corrected-framework cohort can qualify. CrewAI's declared stop sequences are applied through its pinned BaseLLM protocol before its parser; the raw provider output and visible frame are retained independently. A model without an explicit action remains unsuccessful. Native/SDK owners, tasks, authority, model, host versions, budgets and utility thresholds are unchanged. Combined completion is descriptive across implementation/model attempts, not a controlled causal comparison or general superiority claim."}


def aggregate_review_fix_attempts(original_manifest, capable_manifest, corrected_manifest,
                                 fixed_manifest, rows_by_cohort, interruption, prompt_gaps=None):
    previous = COHORTS + (CAPABLE_COHORT, CORRECTED_COHORT)
    if set(rows_by_cohort) != set(previous + (REVIEW_FIX_COHORT,)):
        raise ValueError("campaign.missing_review_fix_attempt")
    excluded = {"sources", "source_binding"}
    if ({key:value for key,value in corrected_manifest.items() if key not in excluded}
        != {key:value for key,value in fixed_manifest.items() if key not in excluded}):
        raise ValueError("campaign.changed_review_fix_policy")
    before = {row["path"]:row["sha256"] for row in corrected_manifest["sources"]}
    after = {row["path"]:row["sha256"] for row in fixed_manifest["sources"]}
    if (len(before) != len(corrected_manifest["sources"]) or len(after) != len(fixed_manifest["sources"])
        or set(before) != set(after)
        or {path for path in before if before[path] != after[path]} != REVIEW_FIX_PATHS):
        raise ValueError("campaign.changed_review_fix_source")
    prior = aggregate_contract_corrected_attempts(original_manifest, capable_manifest, corrected_manifest,
                {name:rows_by_cohort[name] for name in previous}, interruption, prompt_gaps)
    current = summarize(fixed_manifest, rows_by_cohort[REVIEW_FIX_COHORT])
    rows = [row for values in rows_by_cohort.values() for row in values]
    planned = prior["planned_trials"] + len(fixed_manifest["trials"])
    complete = sum(row["native"]["useful_completion"] and row["outcome"] == "complete" for row in rows)
    return {**prior, "schema":"chio.recovery-p6-review-fix-attempts-report.v1",
            "planned_trials":planned, "measured_trials":len(rows),
            "combined_completion":_rate(complete, planned), "qualification_cohort":REVIEW_FIX_COHORT,
            "cohorts":{**prior["cohorts"], REVIEW_FIX_COHORT:current},
            "observed_unauthorized_effects":sum(row["native"]["unauthorized_effects"] for row in rows),
            "observed_duplicate_effects":sum(row["native"]["duplicate_effects"] for row in rows),
            "interpretation":"All four prior attempts, their successes/failures and 45 unknown original slots remain retained. Only the complete separately declared current-source review-fix cohort can qualify the final runtime. The six explicit fix paths repair native setup revision binding and the shipped model-free preflight; exact model, framework protocol, tasks, authority, budgets and thresholds are unchanged. Combined rates describe attempts, not general superiority or account-independent availability."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--initial", type=Path, required=True)
    parser.add_argument("--qualified", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interruption", type=Path)
    parser.add_argument("--capable-manifest", type=Path)
    parser.add_argument("--capable", type=Path)
    parser.add_argument("--prompt-gaps", type=Path)
    parser.add_argument("--corrected-manifest", type=Path)
    parser.add_argument("--corrected", type=Path)
    parser.add_argument("--review-fix-manifest", type=Path)
    parser.add_argument("--review-fix", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    rows = {cohort:[json.loads(line) for line in path.read_text().splitlines()]
            for cohort,path in zip(COHORTS,(args.initial,args.qualified))}
    if any((args.capable_manifest, args.capable, args.prompt_gaps, args.corrected_manifest, args.corrected,
            args.review_fix_manifest, args.review_fix)):
        if not all((args.capable_manifest, args.capable, args.prompt_gaps, args.interruption)):
            parser.error("three-cohort reporting requires --capable-manifest, --capable, --prompt-gaps and --interruption")
        rows[CAPABLE_COHORT] = [json.loads(line) for line in args.capable.read_text().splitlines()]
        capable = json.loads(args.capable_manifest.read_bytes())
        interruption = json.loads(args.interruption.read_bytes())
        prompt_gaps = json.loads(args.prompt_gaps.read_bytes())
        if args.corrected_manifest or args.corrected or args.review_fix_manifest or args.review_fix:
            if not args.corrected_manifest or not args.corrected:
                parser.error("corrected-framework reporting requires --corrected-manifest and --corrected")
            rows[CORRECTED_COHORT] = [json.loads(line) for line in args.corrected.read_text().splitlines()]
            corrected = json.loads(args.corrected_manifest.read_bytes())
            if args.review_fix_manifest or args.review_fix:
                if not args.review_fix_manifest or not args.review_fix:
                    parser.error("review-fix reporting requires --review-fix-manifest and --review-fix")
                rows[REVIEW_FIX_COHORT] = [json.loads(line) for line in args.review_fix.read_text().splitlines()]
                report = aggregate_review_fix_attempts(manifest, capable, corrected,
                    json.loads(args.review_fix_manifest.read_bytes()), rows, interruption, prompt_gaps)
            else:
                report = aggregate_contract_corrected_attempts(manifest, capable, corrected, rows, interruption, prompt_gaps)
        else:
            report = aggregate_qualification_attempts(manifest, capable, rows, interruption, prompt_gaps)
    else:
        report = aggregate_interrupted_cohorts(manifest, rows, json.loads(args.interruption.read_bytes())) if args.interruption else aggregate_cohorts(manifest, rows)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False)+"\n")
    print("Retained", report.get("planned_trials", report.get("combined", {}).get("trials")), "planned trial denominators")


if __name__ == "__main__": main()
