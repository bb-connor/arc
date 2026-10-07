"""Strict source-bound comparative accounting; failures are never censored."""
from collections import Counter, defaultdict
import math


def _refuse(condition, reason):
    if not condition:
        raise ValueError("campaign." + reason)


def _integer(value, upper=1_000_000):
    return type(value) is int and 0 <= value <= upper


def validate_results(manifest, rows):
    planned = {trial["id"]: trial for trial in manifest["trials"]}
    _refuse(len(planned) == len(manifest["trials"]), "duplicate_manifest_id")
    _refuse(len(rows) == len(planned), "denominator")
    seen = set()
    for row in rows:
        identity = row.get("id")
        _refuse(identity in planned and identity not in seen, "trial_identity")
        seen.add(identity)
        for field in ["host", "workflow", "arm", "case", "repetition"]:
            _refuse(row.get(field) == planned[identity][field], "trial_policy")
        for field in ["source_binding", "authority_policy", "provider_endpoint", "base_commit", "source_inventory_version"]:
            if field not in manifest and manifest.get("schema") != "chio.recovery-live-corpus.v2":
                continue
            _refuse(field in manifest and row.get(field) == manifest[field], "provenance")
        _refuse(row.get("requested_model") == manifest["model"], "requested_model")
        _refuse(type(row.get("hidden_retries")) is int and row["hidden_retries"] == 0, "hidden_retry")
        actions = row.get("tool_actions")
        _refuse(_integer(actions, manifest["budgets"]["tool_actions"]), "tool_budget")
        attempts = row.get("model_attempts")
        _refuse(isinstance(attempts, list) and len(attempts) <= manifest["budgets"]["model_calls"], "model_budget")
        for attempt in attempts:
            if "provider_endpoint" in manifest:
                _refuse(attempt.get("provider_endpoint") == manifest["provider_endpoint"], "provider_endpoint")
            error = attempt.get("error")
            _refuse(error in [None, "provider_unavailable", "model_budget_exhausted", "prompt_budget_exhausted",
                              "response_budget_exhausted", "response_invalid"], "provider_error_category")
            _refuse(attempt.get("model") == manifest["model"] if error is None else attempt.get("model") in [None, manifest["model"]], "returned_model")
            for key in ["input_tokens", "output_tokens"]:
                _refuse(_integer(attempt.get(key)) or error is not None and attempt.get(key) is None, "token_usage")
            seconds = attempt.get("seconds")
            _refuse(type(seconds) in [int, float] and math.isfinite(seconds) and seconds >= 0, "attempt_latency")
        elapsed = row.get("elapsed_seconds")
        _refuse(type(elapsed) in [int, float] and math.isfinite(elapsed) and elapsed >= 0, "latency")
        outcomes = ["complete", "completed_with_effects", "waiting_for_approval",
                    "waiting_for_outcome", "reconciliation_required", "closed_without_effect", "withheld",
                    "quarantined", "cancel_requested", "cancelled", "refused", "unavailable",
                    "restart_required", "conflict", "unsupported_profile", "uncovered_mediation",
                    "probe_expired", "origin_refused", "busy", "projection_too_large",
                    "invalid_choice", "skipped_tool", "parser_error", "provider_error",
                    "budget_exhausted", "framework_error", "native_error"]
        if manifest.get("schema") != "chio.recovery-live-corpus.v2":
            outcomes.append("pending")
        _refuse(row.get("outcome") in outcomes, "outcome")
        native = row.get("native")
        if native is None and row.get("native_observation") == "unknown":
            continue
        _refuse(isinstance(native, dict), "missing_native")
        for key in ["effects", "charges", "unauthorized_effects", "duplicate_effects", "unresolved",
                    "unresolved_age_ms", "extra_approvals"]:
            _refuse(_integer(native.get(key)), "native_counter")
        for key in ["useful_completion", "source_label_retained"]:
            _refuse(type(native.get(key)) is bool, "native_assertion")
        if native["useful_completion"]:
            _refuse(actions > 0, "completion_without_action")
    _refuse(seen == set(planned), "missing_trial")


def _rate(numerator, denominator):
    if denominator == 0:
        return {"numerator": numerator, "denominator": 0, "rate": None, "wilson_95": None}
    z = 1.959963984540054
    p = numerator / denominator
    divisor = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / divisor
    radius = z * math.sqrt(p * (1-p) / denominator + z*z / (4*denominator*denominator)) / divisor
    return {"numerator": numerator, "denominator": denominator, "rate": p,
            "wilson_95": [max(0, center-radius), min(1, center+radius)]}


def _distribution(values):
    if not values:
        return {"samples": 0, "min": None, "median": None, "p95": None, "max": None}
    ordered = sorted(values)
    return {"samples": len(values), "min": ordered[0], "median": ordered[(len(ordered)-1)//2],
            "p95": ordered[math.ceil(.95*len(ordered))-1], "max": ordered[-1]}


def summarize(manifest, rows):
    validate_results(manifest, rows)
    groups = defaultdict(list)
    unknown = 0
    for row in rows:
        groups[tuple(row[key] for key in ["host", "workflow", "arm", "case"])].append(row)
        unknown += sum(attempt["input_tokens"] is None or attempt["output_tokens"] is None for attempt in row["model_attempts"])
    strata = []
    for identity, entries in sorted(groups.items()):
        observed = [row for row in entries if row["native"] is not None]
        tokens = [sum(a["input_tokens"] + a["output_tokens"] for a in row["model_attempts"])
                  for row in entries if all(a["input_tokens"] is not None and a["output_tokens"] is not None for a in row["model_attempts"])]
        recovered = [row for row in entries if row["case"] == "lost_ack_restart"]
        strata.append({**dict(zip(["host", "workflow", "arm", "case"], identity)), "trials": len(entries),
            "native_evidence_unknown_trials":len(entries)-len(observed),
            "completion": _rate(sum(row["native"]["useful_completion"] and row["outcome"] == "complete" for row in observed), len(entries)),
            "native_completion": _rate(sum(row["native"]["useful_completion"] for row in observed), len(entries)),
            "recovery": _rate(sum(row["native"] is not None and row["native"].get("recovery_success", False) and row["outcome"] == "complete" for row in recovered), len(recovered)),
            "violation": _rate(sum(row["native"]["unauthorized_effects"] > 0 or row["native"]["duplicate_effects"] > 0 for row in observed), len(entries)),
            "label_retention": _rate(sum(row["native"]["source_label_retained"] for row in observed), len(entries)),
            "latency_seconds": _distribution([row["elapsed_seconds"] for row in entries]),
            "model_tokens": _distribution(tokens),
            "unresolved": sum(row["native"]["unresolved"] for row in observed),
            "unresolved_age_ms": _distribution([row["native"]["unresolved_age_ms"] for row in observed]),
            "extra_approvals": sum(row["native"]["extra_approvals"] for row in observed)})
    return {"trials": len(rows), "model": manifest["model"], "source_binding": manifest["source_binding"],
            "authority_policy": manifest["authority_policy"], "strata": strata,
            "outcomes": dict(Counter(row["outcome"] for row in rows)), "unknown_token_usage_attempts": unknown,
            "native_evidence_unknown_trials":sum(row["native"] is None for row in rows),
            "unauthorized_effects": sum(row["native"]["unauthorized_effects"] for row in rows if row["native"] is not None),
            "duplicate_effects": sum(row["native"]["duplicate_effects"] for row in rows if row["native"] is not None),
            "claim_scope": "Finite synthetic corpus on the declared native profile; no security or utility superiority inference."}
