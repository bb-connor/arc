#!/usr/bin/env python3

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


ROOT_INDEX_SCHEMA = "chio.test-vector.security.v1"
INVENTORY_SCHEMA = "chio.security-required-schema-inventory.v1"
WIRE_SCHEMA_URI_BASE = "https://chio.world/schemas/chio-wire/v1/"
DETECTOR_HEALTH_SCHEMA_ID = (
    f"{WIRE_SCHEMA_URI_BASE}security/detector-health-receipt-body-v1.schema.json"
)
BROKER_AUDIT_COMPARISON_BODY_SCHEMA_ID = (
    f"{WIRE_SCHEMA_URI_BASE}security/broker-audit-comparison-body-v1.schema.json"
)
BROKER_AUDIT_COMPARISON_ENVELOPE_SCHEMA_ID = (
    f"{WIRE_SCHEMA_URI_BASE}security/broker-audit-comparison-envelope-v1.schema.json"
)
BROKER_AUDIT_RUNNER_BODY_SCHEMA_ID = (
    f"{WIRE_SCHEMA_URI_BASE}security/broker-audit-runner-authorization-body-v1.schema.json"
)
BROKER_AUDIT_RUNNER_ENVELOPE_SCHEMA_ID = (
    f"{WIRE_SCHEMA_URI_BASE}security/broker-audit-runner-authorization-envelope-v1.schema.json"
)
BROKER_AUDIT_SCHEMA_IDS = {
    BROKER_AUDIT_COMPARISON_BODY_SCHEMA_ID,
    BROKER_AUDIT_COMPARISON_ENVELOPE_SCHEMA_ID,
    BROKER_AUDIT_RUNNER_BODY_SCHEMA_ID,
    BROKER_AUDIT_RUNNER_ENVELOPE_SCHEMA_ID,
}
ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS = {
    name: f"{WIRE_SCHEMA_URI_BASE}security/{name}-receipt-body-v1.schema.json"
    for name in (
        "correlated-finding",
        "declassification-consumption",
        "declassification-outcome",
        "flow-denial",
        "lift-rollback-completion",
        "response-completion",
        "response-plan",
        "response-state-transition",
        "scheduler-health",
        "tripwire-observation",
        "effect-transition",
    )
}
MAX_JSON_SAFE_INTEGER = 9_007_199_254_740_991
MAX_U64 = 18_446_744_073_709_551_615


class ContractError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"{path}: invalid JSON: {error}") from error


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label}: expected an object")
    return value


def require_nonempty_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list) or not value:
        raise ContractError(f"{label}: expected a non-empty array")
    return value


def is_json_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def is_nonzero_digest(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 32
        and all(is_json_integer(item) and 0 <= item <= 255 for item in value)
        and any(item != 0 for item in value)
    )


def parse_canonical_u64(value: Any) -> int | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 20
        or any(character < "0" or character > "9" for character in value)
        or (len(value) > 1 and value[0] == "0")
    ):
        return None
    parsed = int(value)
    return parsed if parsed <= MAX_U64 else None


def active_defense_header_valid(value: Any, require_prior: bool) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "occurred_at_unix_ms",
        "tenant_id",
        "transition_id",
        "prior_receipt_ids",
    }:
        return False
    occurred_at = value.get("occurred_at_unix_ms")
    priors = value.get("prior_receipt_ids")
    return (
        value.get("schema_version") == 1
        and is_json_integer(occurred_at)
        and 1 <= occurred_at <= MAX_JSON_SAFE_INTEGER
        and is_identifier(value.get("tenant_id"))
        and is_identifier(value.get("transition_id"))
        and isinstance(priors, list)
        and (not require_prior or bool(priors))
        and len(priors) <= 64
        and all(is_identifier(prior) for prior in priors)
        and priors == sorted(set(priors))
    )


def active_defense_policy_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"policy_version", "policy_hash"}
        and is_identifier(value.get("policy_version"))
        and is_nonzero_digest(value.get("policy_hash"))
    )


def active_defense_response_valid(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value)
        == {
            "policy",
            "plan_hash",
            "action_id",
            "trigger_finding_id",
            "trigger_finding_hash",
            "trigger_finding_receipt_id",
            "affected_set_hash",
            "plan_expires_at_unix_ms",
        }
        and active_defense_policy_valid(value.get("policy"))
        and is_nonzero_digest(value.get("plan_hash"))
        and is_identifier(value.get("action_id"))
        and is_identifier(value.get("trigger_finding_id"))
        and is_nonzero_digest(value.get("trigger_finding_hash"))
        and is_identifier(value.get("trigger_finding_receipt_id"))
        and is_nonzero_digest(value.get("affected_set_hash"))
        and is_json_integer(value.get("plan_expires_at_unix_ms"))
        and 0 < value["plan_expires_at_unix_ms"] <= MAX_JSON_SAFE_INTEGER
    )


def active_defense_dispatch_approval_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    mode = value.get("approval_mode")
    if mode == "automatic":
        return set(value) == {"approval_mode"}
    version = value.get("admission_operation_version")
    return (
        mode == "governed"
        and set(value)
        == {
            "approval_mode",
            "admission_operation_id",
            "admission_operation_version",
            "approval_set_hash",
        }
        and is_identifier(value.get("admission_operation_id"))
        and is_json_integer(version)
        and 1 <= version <= MAX_JSON_SAFE_INTEGER
        and is_nonzero_digest(value.get("approval_set_hash"))
    )


def active_defense_execution_dispatch_valid(
    value: Any, header: dict[str, Any], response: dict[str, Any]
) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "tenant_id",
        "dispatch_id",
        "action_id",
        "plan_hash",
        "executor_authority_id",
        "executor_authority_generation",
        "authorization_capability_hash",
        "governed_intent_hash",
        "policy_decision_hash",
        "approval",
        "authorized_at_unix_ms",
    }:
        return False
    generation = value.get("executor_authority_generation")
    authorized_at = value.get("authorized_at_unix_ms")
    return (
        value.get("schema_version") == 1
        and value.get("tenant_id") == header.get("tenant_id")
        and is_identifier(value.get("dispatch_id"))
        and value.get("action_id") == response.get("action_id")
        and value.get("plan_hash") == response.get("plan_hash")
        and is_identifier(value.get("executor_authority_id"))
        and is_json_integer(generation)
        and 1 <= generation <= MAX_JSON_SAFE_INTEGER
        and all(
            is_nonzero_digest(value.get(field))
            for field in (
                "plan_hash",
                "authorization_capability_hash",
                "governed_intent_hash",
                "policy_decision_hash",
            )
        )
        and active_defense_dispatch_approval_valid(value.get("approval"))
        and is_json_integer(authorized_at)
        and 0 < authorized_at <= header.get("occurred_at_unix_ms", 0)
        and authorized_at < response.get("plan_expires_at_unix_ms", 0)
    )


def active_defense_completion_binding_valid(
    value: dict[str, Any], header: dict[str, Any], response: dict[str, Any]
) -> bool:
    generation = value.get("response_generation")
    dispatch = value.get("execution_dispatch")
    authorization_hash = value.get("dispatch_authorization_hash")
    dispatch_pair_valid = (dispatch is None and authorization_hash is None) or (
        active_defense_execution_dispatch_valid(dispatch, header, response)
        and is_nonzero_digest(authorization_hash)
    )
    return (
        dispatch_pair_valid
        and is_json_integer(generation)
        and 1 <= generation <= MAX_JSON_SAFE_INTEGER
        and is_nonzero_digest(value.get("response_body_hash"))
    )


def active_defense_effect_valid(value: Any, tenant_id: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "effect_id",
        "ordinal",
        "kind",
        "target",
        "contribution_hash",
        "observed_base_version_hash",
    }:
        return False
    kind = value.get("kind")
    target = value.get("target")
    if not isinstance(target, dict):
        return False
    target_type = target.get("target_type")
    accepted_target = {
        "escalate_alert": "tenant",
        "throttle_session": "session",
        "restrict_egress": "session",
        "suspend_session": "session",
        "suspend_capability_set": "capability_set",
        "freeze_issuance": "lineage",
    }.get(kind)
    expected_target_members = {
        "tenant": {"target_type", "tenant_id"},
        "session": {"target_type", "session_id"},
        "lineage": {"target_type", "lineage_id"},
        "capability_set": {"target_type", "affected_set_hash"},
    }.get(target_type)
    if accepted_target != target_type or set(target) != expected_target_members:
        return False
    if target_type == "tenant":
        target_valid = (
            is_identifier(target.get("tenant_id"))
            and target.get("tenant_id") == tenant_id
        )
    elif target_type == "capability_set":
        target_valid = is_nonzero_digest(target.get("affected_set_hash"))
    else:
        target_valid = is_identifier(
            target.get("session_id")
            if target_type == "session"
            else target.get("lineage_id")
        )
    ordinal = value.get("ordinal")
    return (
        target_valid
        and is_identifier(value.get("effect_id"))
        and is_json_integer(ordinal)
        and 0 <= ordinal <= 65_535
        and is_nonzero_digest(value.get("contribution_hash"))
        and is_nonzero_digest(value.get("observed_base_version_hash"))
    )


def active_defense_effects_valid(values: Any, tenant_id: Any) -> bool:
    if not isinstance(values, list) or not 1 <= len(values) <= 64:
        return False
    effect_ids: list[Any] = []
    for index, effect in enumerate(values):
        if (
            not active_defense_effect_valid(effect, tenant_id)
            or effect.get("ordinal") != index
            or effect.get("effect_id") in effect_ids
        ):
            return False
        effect_ids.append(effect.get("effect_id"))
    return True


def active_defense_outcome_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    state = value.get("state")
    if state in {"planned", "requested", "rollback_requested", "no_rollback_required"}:
        return set(value) == {"state"}
    if state in {"applied", "restored"}:
        return set(value) == {"state", "resulting_version_hash"} and is_nonzero_digest(
            value.get("resulting_version_hash")
        )
    if state in {"apply_failed", "rollback_failed"}:
        return set(value) == {"state", "error_code"} and is_identifier(
            value.get("error_code")
        )
    return False


def active_defense_outcome_effects_valid(values: Any, tenant_id: Any) -> bool:
    if not isinstance(values, list) or not 1 <= len(values) <= 64:
        return False
    effects: list[Any] = []
    for item in values:
        if not isinstance(item, dict) or set(item) != {"effect", "outcome"}:
            return False
        effect = item.get("effect")
        if (
            not active_defense_effect_valid(effect, tenant_id)
            or effect.get("ordinal") != len(effects)
            or effect.get("effect_id") in effects
            or not active_defense_outcome_valid(item.get("outcome"))
        ):
            return False
        effects.append(effect.get("effect_id"))
    return True


def active_defense_response_transition_valid(
    value: dict[str, Any], header: dict[str, Any], response: dict[str, Any]
) -> bool:
    required_fields = {
        "header",
        "response",
        "generation",
        "from_state",
        "to_state",
        "cause",
        "applying_lease_expires_at_unix_ms",
        "error_code",
    }
    fence_fields = {"scheduler_lease_owner_id", "scheduler_fencing_token"}
    fields = set(value)
    if fields != required_fields and fields != required_fields | fence_fields:
        return False
    has_scheduler_fence = fence_fields <= fields
    if has_scheduler_fence and not (
        is_identifier(value.get("scheduler_lease_owner_id"))
        and is_json_integer(value.get("scheduler_fencing_token"))
        and 1 <= value["scheduler_fencing_token"] <= MAX_JSON_SAFE_INTEGER
    ):
        return False
    generation = value.get("generation")
    if not is_json_integer(generation) or not 1 <= generation <= MAX_JSON_SAFE_INTEGER:
        return False
    error_code = value.get("error_code")
    if error_code is not None and not is_identifier(error_code):
        return False
    transition = (value.get("from_state"), value.get("to_state"))
    expected_cause = {
        ("planned", "awaiting_approval"): "approval_requested",
        ("planned", "applying"): "apply_started",
        ("awaiting_approval", "applying"): "approval_satisfied",
        ("applying", "applying"): "applying_lease_renewed",
        ("applying", "active"): "apply_completed",
        ("planned", "cancelled"): "operator_cancelled",
        ("awaiting_approval", "cancelled"): "operator_cancelled",
        ("planned", "expired"): "plan_expired",
        ("awaiting_approval", "expired"): "plan_expired",
        ("active", "expiring"): "plan_expired",
        ("apply_partial", "rolling_back"): "rollback_requested",
        ("active", "rolling_back"): "rollback_requested",
        ("expiring", "rolling_back"): "rollback_requested",
        ("rollback_partial", "rolling_back"): "rollback_retry",
        ("rolling_back", "lifted"): "rollback_completed",
        ("rolling_back", "rollback_partial"): "rollback_failed",
        ("planned", "failed"): "validation_failed",
        ("awaiting_approval", "failed"): "validation_failed",
        ("applying", "failed"): "validation_failed",
        ("applying", "apply_partial"): (
            "applying_lease_expired"
            if error_code == "response.applying_lease_expired"
            else "validation_failed"
        ),
    }.get(transition)
    if expected_cause is None or value.get("cause") != expected_cause:
        return False
    if transition == ("applying", "applying") and not has_scheduler_fence:
        return False
    lease = value.get("applying_lease_expires_at_unix_ms")
    if value.get("to_state") == "applying":
        lease_valid = (
            is_json_integer(lease)
            and header["occurred_at_unix_ms"]
            < lease
            <= response["plan_expires_at_unix_ms"]
        )
    else:
        lease_valid = lease is None
    needs_error = value.get("to_state") in {
        "failed",
        "apply_partial",
        "rollback_partial",
    }
    expiry_valid = (
        value.get("cause") != "plan_expired"
        or header["occurred_at_unix_ms"] >= response["plan_expires_at_unix_ms"]
    )
    return lease_valid and needs_error == (error_code is not None) and expiry_valid


def active_defense_effect_transition_valid(
    value: dict[str, Any], tenant_id: Any
) -> bool:
    required_fields = {
        "header",
        "response",
        "effect",
        "generation",
        "scheduler_fencing_token",
        "outcome",
    }
    fields = set(value)
    if fields != required_fields and fields != required_fields | {
        "scheduler_lease_owner_id"
    }:
        return False
    generation = value.get("generation")
    fencing = value.get("scheduler_fencing_token")
    effect = value.get("effect")
    outcome = value.get("outcome")
    if (
        not is_json_integer(generation)
        or not 1 <= generation <= MAX_JSON_SAFE_INTEGER
        or not is_json_integer(fencing)
        or not 1 <= fencing <= MAX_JSON_SAFE_INTEGER
        or (
            "scheduler_lease_owner_id" in value
            and not is_identifier(value.get("scheduler_lease_owner_id"))
        )
        or not active_defense_effect_valid(effect, tenant_id)
        or not active_defense_outcome_valid(outcome)
    ):
        return False
    state = outcome.get("state")
    if state in {"planned", "no_rollback_required"}:
        return False
    return not (
        state in {"rollback_requested", "restored", "rollback_failed"}
        and effect.get("kind") == "escalate_alert"
    )


def active_defense_receipt_semantic_valid(schema_id: str, value: Any) -> bool:
    name = next(
        (
            name
            for name, candidate in ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS.items()
            if candidate == schema_id
        ),
        None,
    )
    if name is None or not isinstance(value, dict):
        return False
    require_prior = name in {
        "correlated-finding",
        "lift-rollback-completion",
        "response-completion",
        "response-plan",
        "response-state-transition",
        "scheduler-health",
        "effect-transition",
    }
    header = value.get("header")
    if not active_defense_header_valid(header, require_prior):
        return False
    if name in {
        "response-state-transition",
        "effect-transition",
        "response-completion",
        "lift-rollback-completion",
    } and len(header["prior_receipt_ids"]) != 1:
        return False
    tenant_id = header["tenant_id"]

    if name == "flow-denial":
        return (
            set(value)
            == {
                "header",
                "policy",
                "request_hash",
                "source_label_hash",
                "destination_label_hash",
                "guard_evidence_hash",
                "denial_code",
                "event_id",
            }
            and active_defense_policy_valid(value.get("policy"))
            and all(
                is_nonzero_digest(value.get(field))
                for field in (
                    "request_hash",
                    "source_label_hash",
                    "destination_label_hash",
                    "guard_evidence_hash",
                )
            )
        )

    if name in {"declassification-consumption", "declassification-outcome"}:
        expected = {
            "header",
            "policy",
            "grant_id",
            "grant_hash",
            "request_hash",
            "event_id",
        }
        expected |= (
            {"state"}
            if name == "declassification-consumption"
            else {"from_state", "to_state"}
        )
        if (
            set(value) != expected
            or not active_defense_policy_valid(value.get("policy"))
            or not is_nonzero_digest(value.get("grant_hash"))
            or not is_nonzero_digest(value.get("request_hash"))
        ):
            return False
        if name == "declassification-consumption":
            return value.get("state") == "consumed_pending_dispatch"
        return value.get("from_state") == "consumed_pending_dispatch" and value.get(
            "to_state"
        ) in {"released", "dispatch_failed", "outcome_unknown"}

    if name == "tripwire-observation":
        return (
            set(value)
            == {
                "header",
                "policy",
                "request_id",
                "request_hash",
                "event_id",
                "tripwire_kind",
                "artifact_id_hash",
                "artifact_version_hash",
                "observation_hash",
                "severity",
            }
            and active_defense_policy_valid(value.get("policy"))
            and all(
                is_nonzero_digest(value.get(field))
                for field in (
                    "request_hash",
                    "artifact_id_hash",
                    "artifact_version_hash",
                    "observation_hash",
                )
            )
        )

    if name == "correlated-finding":
        expected = {
            "header",
            "policy",
            "finding_id",
            "finding_hash",
            "rule_id",
            "rule_version_hash",
            "group_key_hash",
            "ordered_event_ids",
            "ordered_evidence_digests",
            "ordered_source_receipt_ids",
            "first_event_time_unix_ms",
            "last_event_time_unix_ms",
            "lineage_seed",
        }
        event_ids = value.get("ordered_event_ids")
        evidence = value.get("ordered_evidence_digests")
        sources = value.get("ordered_source_receipt_ids")
        first = value.get("first_event_time_unix_ms")
        last = value.get("last_event_time_unix_ms")
        return (
            set(value) == expected
            and active_defense_policy_valid(value.get("policy"))
            and all(
                is_nonzero_digest(value.get(field))
                for field in ("finding_hash", "rule_version_hash", "group_key_hash")
            )
            and isinstance(event_ids, list)
            and bool(event_ids)
            and len(event_ids) == len(set(event_ids))
            and isinstance(evidence, list)
            and isinstance(sources, list)
            and len(event_ids) == len(evidence) == len(sources)
            and all(is_nonzero_digest(digest) for digest in evidence)
            and header["prior_receipt_ids"] == sorted(set(sources))
            and is_json_integer(first)
            and is_json_integer(last)
            and 0 < first <= last <= header["occurred_at_unix_ms"]
        )

    if not active_defense_response_valid(value.get("response")):
        return False
    response = value["response"]
    if name == "response-state-transition":
        return active_defense_response_transition_valid(value, header, response)
    if name == "effect-transition":
        return active_defense_effect_transition_valid(value, tenant_id)
    if name == "response-plan":
        created = value.get("plan_created_at_unix_ms")
        return (
            set(value) == {"header", "response", "plan_created_at_unix_ms", "effects"}
            and response["trigger_finding_receipt_id"] in header["prior_receipt_ids"]
            and is_json_integer(created)
            and 0 < created <= header["occurred_at_unix_ms"]
            and created < response["plan_expires_at_unix_ms"]
            and active_defense_effects_valid(value.get("effects"), tenant_id)
        )
    if name in {"response-completion", "lift-rollback-completion"}:
        expected = {
            "header",
            "response",
            "execution_dispatch",
            "dispatch_authorization_hash",
            "response_generation",
            "response_body_hash",
            "final_state",
            "effects",
        }
        if name == "response-completion":
            expected.add("error_code")
        if set(value) != expected or not (
            len(header["prior_receipt_ids"]) == 1
            and active_defense_completion_binding_valid(value, header, response)
            and active_defense_outcome_effects_valid(value.get("effects"), tenant_id)
        ):
            return False
        effects = value["effects"]
        outcomes = [item["outcome"]["state"] for item in effects]
        if name == "response-completion":
            if any(
                state not in {"planned", "applied", "apply_failed"}
                for state in outcomes
            ):
                return False
            applied = outcomes.count("applied")
            planned = outcomes.count("planned")
            apply_failed = outcomes.count("apply_failed")
            effect_count = len(outcomes)
            resolved_count = applied + planned + apply_failed
            failed_shape = (
                planned == effect_count
                or (apply_failed == 1 and planned + apply_failed == effect_count)
            )
            error_code = value.get("error_code")
            apply_failure_codes = [
                item["outcome"]["error_code"]
                for item in effects
                if item["outcome"]["state"] == "apply_failed"
            ]
            failed_error_matches = (
                not apply_failure_codes or apply_failure_codes == [error_code]
            )
            return {
                "active": applied == effect_count and error_code is None,
                "apply_partial": (
                    applied > 0
                    and resolved_count == effect_count
                    and apply_failed <= 1
                    and is_identifier(error_code)
                    and failed_error_matches
                ),
                "failed": (
                    failed_shape
                    and is_identifier(error_code)
                    and failed_error_matches
                ),
            }.get(value.get("final_state"), False)
        rollback_failures = 0
        for item in effects:
            state = item["outcome"]["state"]
            reversible = item["effect"]["kind"] != "escalate_alert"
            if state == "rollback_failed":
                rollback_failures += 1
            if not (
                (state in {"restored", "rollback_failed"} and reversible)
                or state in {"planned", "apply_failed"}
                or (state == "no_rollback_required" and not reversible)
            ):
                return False
        return {
            "lifted": rollback_failures == 0,
            "rollback_partial": rollback_failures > 0,
        }.get(value.get("final_state"), False)
    if name == "scheduler-health":
        first = value.get("first_failure_at_unix_ms")
        attempts = value.get("attempts")
        fencing = value.get("scheduler_fencing_token")
        return (
            set(value)
            == {
                "header",
                "response",
                "event_id",
                "first_failure_at_unix_ms",
                "attempts",
                "scheduler_fencing_token",
                "error_code",
                "evidence_hash",
            }
            and is_nonzero_digest(value.get("evidence_hash"))
            and is_json_integer(first)
            and 0 < first <= header["occurred_at_unix_ms"]
            and is_json_integer(attempts)
            and 0 < attempts <= 4_294_967_295
            and is_json_integer(fencing)
            and 0 < fencing <= MAX_JSON_SAFE_INTEGER
        )
    return False


def detector_health_semantic_valid(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "header",
        "policy",
        "rule_id",
        "rule_version_hash",
        "group_binding",
        "event_id",
        "health_kind",
        "watermark",
        "evidence_hash",
    }:
        return False

    header = value.get("header")
    if not isinstance(header, dict) or set(header) != {
        "schema_version",
        "occurred_at_unix_ms",
        "tenant_id",
        "transition_id",
        "prior_receipt_ids",
    }:
        return False
    observed_at = header.get("occurred_at_unix_ms")
    prior_receipts = header.get("prior_receipt_ids")
    if (
        header.get("schema_version") != 1
        or not is_json_integer(observed_at)
        or not 1 <= observed_at <= MAX_JSON_SAFE_INTEGER
        or not is_identifier(header.get("tenant_id"))
        or not is_identifier(header.get("transition_id"))
        or not isinstance(prior_receipts, list)
        or len(prior_receipts) > 64
        or any(not is_identifier(receipt) for receipt in prior_receipts)
        or prior_receipts != sorted(set(prior_receipts))
    ):
        return False

    policy = value.get("policy")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"policy_version", "policy_hash"}
        or not is_identifier(policy.get("policy_version"))
        or not is_nonzero_digest(policy.get("policy_hash"))
        or not is_identifier(value.get("rule_id"))
        or not is_nonzero_digest(value.get("rule_version_hash"))
        or not is_identifier(value.get("event_id"))
        or not is_nonzero_digest(value.get("evidence_hash"))
        or value.get("health_kind")
        not in {
            "corrupt_event",
            "corrupt_state",
            "state_overflow",
            "store_conflict",
            "store_unavailable",
            "truncated_scan",
        }
    ):
        return False

    group_binding = value.get("group_binding")
    if not isinstance(group_binding, dict):
        return False
    group_kind = group_binding.get("kind")
    if group_kind == "unresolved":
        if set(group_binding) != {"kind"}:
            return False
    elif group_kind == "resolved":
        if set(group_binding) != {"kind", "group_key_hash"} or not is_nonzero_digest(
            group_binding.get("group_key_hash")
        ):
            return False
    else:
        return False

    watermark = value.get("watermark")
    if not isinstance(watermark, dict):
        return False
    watermark_kind = watermark.get("kind")
    if watermark_kind == "unknown":
        return set(watermark) == {"kind"}
    if watermark_kind == "contradictory":
        claimed = parse_canonical_u64(watermark.get("claimed_unix_ms"))
        return (
            set(watermark) == {"kind", "claimed_unix_ms"}
            and group_kind == "resolved"
            and value.get("health_kind") == "corrupt_state"
            and claimed is not None
            and (
                claimed == 0 or claimed > observed_at or claimed > MAX_JSON_SAFE_INTEGER
            )
        )
    if watermark_kind != "committed" or set(watermark) != {"kind", "unix_ms"}:
        return False
    unix_ms = watermark.get("unix_ms")
    return (
        group_kind == "resolved"
        and is_json_integer(unix_ms)
        and 1 <= unix_ms <= MAX_JSON_SAFE_INTEGER
        and unix_ms <= observed_at
    )


ED25519_FIELD = 2**255 - 19
ED25519_ORDER = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_FIELD - 2, ED25519_FIELD)) % ED25519_FIELD
ED25519_I = pow(2, (ED25519_FIELD - 1) // 4, ED25519_FIELD)
ED25519_IDENTITY = (0, 1)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def ed25519_recover_x(y: int, sign: int) -> int | None:
    if y >= ED25519_FIELD:
        return None
    y_squared = y * y % ED25519_FIELD
    x_squared = (y_squared - 1) * pow(
        ED25519_D * y_squared + 1, ED25519_FIELD - 2, ED25519_FIELD
    ) % ED25519_FIELD
    x = pow(x_squared, (ED25519_FIELD + 3) // 8, ED25519_FIELD)
    if (x * x - x_squared) % ED25519_FIELD != 0:
        x = x * ED25519_I % ED25519_FIELD
    if (x * x - x_squared) % ED25519_FIELD != 0:
        return None
    if x == 0 and sign != 0:
        return None
    if x & 1 != sign:
        x = ED25519_FIELD - x
    return x


def ed25519_decode_point(encoded: bytes) -> tuple[int, int] | None:
    if len(encoded) != 32:
        return None
    raw = int.from_bytes(encoded, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    x = ed25519_recover_x(y, sign)
    return None if x is None else (x, y)


def ed25519_add(
    left: tuple[int, int], right: tuple[int, int]
) -> tuple[int, int]:
    left_x, left_y = left
    right_x, right_y = right
    product = ED25519_D * left_x * right_x * left_y * right_y % ED25519_FIELD
    x = (left_x * right_y + left_y * right_x) * pow(
        1 + product, ED25519_FIELD - 2, ED25519_FIELD
    ) % ED25519_FIELD
    y = (left_y * right_y + left_x * right_x) * pow(
        1 - product, ED25519_FIELD - 2, ED25519_FIELD
    ) % ED25519_FIELD
    return x, y


def ed25519_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = ED25519_IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = ed25519_add(result, addend)
        addend = ed25519_add(addend, addend)
        scalar >>= 1
    return result


ED25519_BASE_Y = 4 * pow(5, ED25519_FIELD - 2, ED25519_FIELD) % ED25519_FIELD
ED25519_BASE_X = ed25519_recover_x(ED25519_BASE_Y, 0)
if ED25519_BASE_X is None:
    raise RuntimeError("invalid embedded Ed25519 base point")
ED25519_BASE = (ED25519_BASE_X, ED25519_BASE_Y)


def ed25519_verify(public_key_hex: Any, signature_hex: Any, message: bytes) -> bool:
    if (
        not isinstance(public_key_hex, str)
        or len(public_key_hex) != 64
        or not isinstance(signature_hex, str)
        or len(signature_hex) != 128
    ):
        return False
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    public_point = ed25519_decode_point(public_key)
    encoded_r = signature[:32]
    r_point = ed25519_decode_point(encoded_r)
    scalar_s = int.from_bytes(signature[32:], "little")
    if public_point is None or r_point is None or scalar_s >= ED25519_ORDER:
        return False
    if (
        ed25519_multiply(public_point, 8) == ED25519_IDENTITY
        or ed25519_multiply(r_point, 8) == ED25519_IDENTITY
    ):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(), "little"
    ) % ED25519_ORDER
    left = ed25519_multiply(ED25519_BASE, scalar_s)
    right = ed25519_add(r_point, ed25519_multiply(public_point, challenge))
    return left == right


def is_lower_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def broker_audit_runner_body_semantic_valid(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "auditId",
        "deploymentId",
        "brokerInstanceId",
        "tenantScope",
        "runnerId",
        "referenceSource",
        "referenceCommitmentSha256",
        "capabilitySha256",
        "proofSha256",
        "canonicalRequestSha256",
        "providerAdapterId",
        "providerAdapterVersion",
        "credentialProvider",
        "revocationAuthorityDomain",
        "issuedAtUnixSeconds",
        "expiresAtUnixSeconds",
    }:
        return False
    identifiers = (
        "auditId",
        "deploymentId",
        "brokerInstanceId",
        "tenantScope",
        "runnerId",
        "referenceSource",
        "providerAdapterId",
        "credentialProvider",
        "revocationAuthorityDomain",
    )
    digests = (
        "referenceCommitmentSha256",
        "capabilitySha256",
        "proofSha256",
        "canonicalRequestSha256",
    )
    issued = value.get("issuedAtUnixSeconds")
    expires = value.get("expiresAtUnixSeconds")
    version = value.get("providerAdapterVersion")
    return (
        value.get("schema") == "chio.broker-audit-runner-authorization.v1"
        and all(is_identifier(value.get(field)) for field in identifiers)
        and all(is_lower_hex(value.get(field), 64) for field in digests)
        and is_json_integer(version)
        and version > 0
        and is_json_integer(issued)
        and issued > 0
        and is_json_integer(expires)
        and issued < expires
        and expires - issued <= 300
    )


def broker_audit_comparison_body_semantic_valid(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "issuedAtUnixSeconds",
        "capabilitySha256",
        "proofSha256",
        "canonicalRequestSha256",
        "authorityContextSha256",
        "auditIdSha256",
        "governedAuditIntentSha256",
        "auditAuthorizationSha256",
        "runnerAuthorizationSha256",
        "referenceSourceSha256",
        "brokerOutboundProjectionCommitmentSha256",
        "referenceOutboundProjectionCommitmentSha256",
        "projectionsEqual",
        "networkDispatchCount",
        "accountingMutationCount",
        "rawCredentialReturned",
    }:
        return False
    digests = (
        "capabilitySha256",
        "proofSha256",
        "canonicalRequestSha256",
        "authorityContextSha256",
        "auditIdSha256",
        "governedAuditIntentSha256",
        "auditAuthorizationSha256",
        "runnerAuthorizationSha256",
        "referenceSourceSha256",
        "brokerOutboundProjectionCommitmentSha256",
        "referenceOutboundProjectionCommitmentSha256",
    )
    equal = (
        value.get("brokerOutboundProjectionCommitmentSha256")
        == value.get("referenceOutboundProjectionCommitmentSha256")
    )
    return (
        value.get("schema") == "chio.broker-audit-comparison.v1"
        and is_json_integer(value.get("issuedAtUnixSeconds"))
        and value["issuedAtUnixSeconds"] > 0
        and all(is_lower_hex(value.get(field), 64) for field in digests)
        and isinstance(value.get("projectionsEqual"), bool)
        and value["projectionsEqual"] == equal
        and value.get("networkDispatchCount") == 0
        and value.get("accountingMutationCount") == 0
        and value.get("rawCredentialReturned") is False
    )


def broker_audit_signed_envelope_semantic_valid(
    value: Any, runner: bool
) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "body",
        "signer",
        "algorithm",
        "signature",
    }:
        return False
    body = value.get("body")
    if runner:
        body_valid = broker_audit_runner_body_semantic_valid(body)
        message = b"chio.broker-audit-runner-authorization-signature.v1\0" + canonical_json(
            body
        )
    else:
        body_valid = broker_audit_comparison_body_semantic_valid(body)
        message = canonical_json(
            {
                "domain": "chio.broker-audit-comparison-signature.v1\0",
                "body": body,
            }
        )
    return (
        body_valid
        and value.get("algorithm") == "ed25519"
        and ed25519_verify(value.get("signer"), value.get("signature"), message)
    )


def broker_audit_pair_semantic_valid(comparison: Any, runner: Any) -> bool:
    if not broker_audit_signed_envelope_semantic_valid(
        comparison, False
    ) or not broker_audit_signed_envelope_semantic_valid(runner, True):
        return False
    comparison_body = comparison["body"]
    runner_body = runner["body"]
    runner_digest = hashlib.sha256(
        b"chio.broker-audit-runner-authorization-digest.v1\0"
        + canonical_json(runner)
    ).hexdigest()
    governed_intent = hashlib.sha256(
        b"chio.broker-audit-intent.v1\0"
        + canonical_json(
            {
                "schema": "chio.broker-audit-intent.v1",
                "auditId": runner_body["auditId"],
                "runnerAuthorizationSha256": runner_digest,
            }
        )
    ).hexdigest()
    audit_id = hashlib.sha256(
        b"chio.broker-audit-id.v1\0" + runner_body["auditId"].encode("utf-8")
    ).hexdigest()
    reference_source = hashlib.sha256(
        b"chio.broker-audit-reference-source.v1\0"
        + runner_body["referenceSource"].encode("utf-8")
    ).hexdigest()
    return (
        comparison["signer"] != runner["signer"]
        and runner_body["issuedAtUnixSeconds"]
        <= comparison_body["issuedAtUnixSeconds"]
        < runner_body["expiresAtUnixSeconds"]
        and all(
            comparison_body[field] == runner_body[field]
            for field in (
                "capabilitySha256",
                "proofSha256",
                "canonicalRequestSha256",
            )
        )
        and comparison_body["runnerAuthorizationSha256"] == runner_digest
        and comparison_body["governedAuditIntentSha256"] == governed_intent
        and comparison_body["auditIdSha256"] == audit_id
        and comparison_body["referenceSourceSha256"] == reference_source
    )


def security_semantic_valid(schema_id: str, value: Any) -> bool | None:
    if schema_id == BROKER_AUDIT_RUNNER_BODY_SCHEMA_ID:
        return broker_audit_runner_body_semantic_valid(value)
    if schema_id == BROKER_AUDIT_RUNNER_ENVELOPE_SCHEMA_ID:
        return broker_audit_signed_envelope_semantic_valid(value, True)
    if schema_id == BROKER_AUDIT_COMPARISON_BODY_SCHEMA_ID:
        return broker_audit_comparison_body_semantic_valid(value)
    if schema_id == BROKER_AUDIT_COMPARISON_ENVELOPE_SCHEMA_ID:
        return broker_audit_signed_envelope_semantic_valid(value, False)
    if schema_id == DETECTOR_HEALTH_SCHEMA_ID:
        return detector_health_semantic_valid(value)
    if schema_id in ACTIVE_DEFENSE_RECEIPT_SCHEMA_IDS.values():
        return active_defense_receipt_semantic_valid(schema_id, value)
    return None


def safe_relative(base: Path, relative: Any, allowed_root: Path, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ContractError(f"{label}: expected a non-empty relative path")
    posix = PurePosixPath(relative)
    if posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
        raise ContractError(f"{label}: unsafe relative path {relative!r}")
    resolved = (base / Path(*posix.parts)).resolve()
    try:
        resolved.relative_to(allowed_root.resolve())
    except ValueError as error:
        raise ContractError(
            f"{label}: path escapes corpus root: {relative!r}"
        ) from error
    if not resolved.is_file():
        raise ContractError(f"{label}: missing file {resolved}")
    return resolved


def load_schema_inventory(
    repo_root: Path,
) -> tuple[dict[str, tuple[Path, Any]], Registry]:
    wire_root = repo_root / "spec/schemas/chio-wire/v1"
    security_root = wire_root / "security"
    inventory_path = security_root / "required-schema-inventory.json"
    inventory = require_object(load_json(inventory_path), str(inventory_path))
    if inventory.get("schema") != INVENTORY_SCHEMA:
        raise ContractError(f"{inventory_path}: invalid schema discriminator")
    entries = require_nonempty_list(
        inventory.get("schemas"), f"{inventory_path}: schemas"
    )

    declared: dict[str, str] = {}
    declared_ids: set[str] = set()
    ordered_files: list[str] = []
    for index, raw_entry in enumerate(entries):
        entry = require_object(raw_entry, f"{inventory_path}: schemas[{index}]")
        if set(entry) != {"file", "schema_id"}:
            raise ContractError(
                f"{inventory_path}: schemas[{index}] must contain exactly file and schema_id"
            )
        file_name = entry.get("file")
        schema_id = entry.get("schema_id")
        if (
            not isinstance(file_name, str)
            or not file_name.endswith(".schema.json")
            or PurePosixPath(file_name).name != file_name
        ):
            raise ContractError(
                f"{inventory_path}: schemas[{index}] has an unsafe file"
            )
        if not isinstance(schema_id, str) or not schema_id:
            raise ContractError(
                f"{inventory_path}: schemas[{index}] has an invalid schema_id"
            )
        if file_name in declared:
            raise ContractError(f"{inventory_path}: duplicate file {file_name}")
        if schema_id in declared_ids:
            raise ContractError(f"{inventory_path}: duplicate schema_id {schema_id}")
        declared[file_name] = schema_id
        declared_ids.add(schema_id)
        ordered_files.append(file_name)

    if ordered_files != sorted(ordered_files):
        raise ContractError(f"{inventory_path}: schemas must be sorted by file")
    actual = {path.name for path in security_root.glob("*.schema.json")}
    if set(declared) != actual:
        omitted = sorted(actual - set(declared))
        deleted = sorted(set(declared) - actual)
        raise ContractError(
            f"{inventory_path}: closed inventory mismatch; omitted={omitted}; missing={deleted}"
        )

    schemas_by_id: dict[str, tuple[Path, Any]] = {}
    resources_by_id: dict[str, tuple[Path, Resource[Any]]] = {}
    for path in sorted(wire_root.rglob("*.schema.json")):
        schema = require_object(load_json(path), str(path))
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as error:
            raise ContractError(f"{path}: invalid JSON Schema: {error}") from error

        relative = path.relative_to(wire_root).as_posix()
        path_schema_id = f"{WIRE_SCHEMA_URI_BASE}{relative}"
        declared_schema_id = schema.get("$id")
        has_declared_schema_id = isinstance(declared_schema_id, str) and bool(
            declared_schema_id
        )

        path_validation_schema = schema
        if declared_schema_id != path_schema_id:
            path_validation_schema = {**schema, "$id": path_schema_id}

        resource_schemas = [(path_schema_id, path_validation_schema)]
        if has_declared_schema_id and declared_schema_id != path_schema_id:
            resource_schemas.append((declared_schema_id, schema))
        for resource_id, resource_schema in resource_schemas:
            if (
                resource_id in resources_by_id
                and resources_by_id[resource_id][0] != path
            ):
                raise ContractError(
                    f"duplicate wire schema resolver identity {resource_id}: "
                    f"{resources_by_id[resource_id][0]} and {path}"
                )
            resources_by_id[resource_id] = (
                path,
                Resource.from_contents(resource_schema),
            )

        exact_schema_id = (
            declared_schema_id if has_declared_schema_id else path_schema_id
        )
        exact_validation_schema = (
            schema if has_declared_schema_id else path_validation_schema
        )
        if (
            exact_schema_id in schemas_by_id
            and schemas_by_id[exact_schema_id][0] != path
        ):
            raise ContractError(
                f"duplicate wire schema identity {exact_schema_id}: "
                f"{schemas_by_id[exact_schema_id][0]} and {path}"
            )
        schemas_by_id[exact_schema_id] = (path, exact_validation_schema)

    for file_name, expected_id in declared.items():
        path = security_root / file_name
        schema = require_object(load_json(path), str(path))
        if schema.get("$id") != expected_id:
            raise ContractError(
                f"{path}: $id {schema.get('$id')!r} does not match inventory {expected_id!r}"
            )
    resources = [
        (resource_id, resource)
        for resource_id, (_, resource) in resources_by_id.items()
    ]
    return schemas_by_id, Registry().with_resources(resources)


def pointer_parts(pointer: Any, label: str) -> list[str]:
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise ContractError(f"{label}: invalid JSON pointer {pointer!r}")
    if not pointer:
        return []
    return [
        part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")
    ]


def pointer_get(document: Any, pointer: Any, label: str) -> Any:
    current = document
    for part in pointer_parts(pointer, label):
        if isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError) as error:
                raise ContractError(
                    f"{label}: missing array element {part!r}"
                ) from error
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise ContractError(f"{label}: missing object member {part!r}")
    return current


def pointer_parent(document: Any, pointer: Any, label: str) -> tuple[Any, str]:
    parts = pointer_parts(pointer, label)
    if not parts:
        raise ContractError(f"{label}: root replacement is not supported")
    parent = document
    for part in parts[:-1]:
        if isinstance(parent, list):
            try:
                parent = parent[int(part)]
            except (ValueError, IndexError) as error:
                raise ContractError(
                    f"{label}: missing array element {part!r}"
                ) from error
        elif isinstance(parent, dict) and part in parent:
            parent = parent[part]
        else:
            raise ContractError(f"{label}: missing object member {part!r}")
    return parent, parts[-1]


def mutate_json(
    base: Any, mutation: dict[str, Any], index_root: Path, label: str
) -> Any:
    operation = mutation.get("op")
    if operation == "append_bytes":
        raise ContractError(f"{label}: append_bytes must be applied to source bytes")
    document = copy.deepcopy(base)
    parent, key = pointer_parent(document, mutation.get("path"), label)
    if operation == "remove":
        if isinstance(parent, list):
            try:
                parent.pop(int(key))
            except (ValueError, IndexError) as error:
                raise ContractError(f"{label}: remove target does not exist") from error
        elif isinstance(parent, dict) and key in parent:
            del parent[key]
        else:
            raise ContractError(f"{label}: remove target does not exist")
    elif operation in {"add", "replace"}:
        if "value" not in mutation:
            raise ContractError(f"{label}: {operation} requires value")
        if isinstance(parent, list):
            try:
                index = len(parent) if key == "-" else int(key)
            except ValueError as error:
                raise ContractError(f"{label}: invalid array index {key!r}") from error
            if operation == "add":
                if index < 0 or index > len(parent):
                    raise ContractError(f"{label}: add index is out of bounds")
                parent.insert(index, copy.deepcopy(mutation["value"]))
            else:
                if index < 0 or index >= len(parent):
                    raise ContractError(f"{label}: replace index is out of bounds")
                parent[index] = copy.deepcopy(mutation["value"])
        elif isinstance(parent, dict):
            if operation == "replace" and key not in parent:
                raise ContractError(f"{label}: replace target does not exist")
            parent[key] = copy.deepcopy(mutation["value"])
        else:
            raise ContractError(f"{label}: mutation parent is not a container")
    elif operation == "replace_from_related":
        related_path = safe_relative(
            index_root,
            mutation.get("related_file"),
            index_root,
            f"{label}: related_file",
        )
        related = load_json(related_path)
        value = pointer_get(related, mutation.get("related_path", ""), label)
        if isinstance(parent, list):
            try:
                parent[int(key)] = copy.deepcopy(value)
            except (ValueError, IndexError) as error:
                raise ContractError(
                    f"{label}: replace target does not exist"
                ) from error
        elif isinstance(parent, dict) and key in parent:
            parent[key] = copy.deepcopy(value)
        else:
            raise ContractError(f"{label}: replace target does not exist")
    else:
        raise ContractError(f"{label}: unsupported mutation operation {operation!r}")
    return document


def validate_corpus(repo_root: Path) -> tuple[int, int, int]:
    schemas_by_id, registry = load_schema_inventory(repo_root)
    corpus_root = (repo_root / "tests/bindings/vectors/security").resolve()
    root_path = corpus_root / "v1.json"
    root_index = require_object(load_json(root_path), str(root_path))
    if root_index.get("schema") != ROOT_INDEX_SCHEMA:
        raise ContractError(f"{root_path}: invalid schema discriminator")
    root_indexes = require_nonempty_list(
        root_index.get("indexes"), f"{root_path}: indexes"
    )

    visited_indexes: set[Path] = set()
    positive_count = 0
    negative_count = 0
    schema_ids_seen: set[str] = set()

    def visit(index_path: Path) -> None:
        nonlocal positive_count, negative_count
        resolved_index = index_path.resolve()
        if resolved_index in visited_indexes:
            raise ContractError(f"{index_path}: duplicate or cyclic index reference")
        visited_indexes.add(resolved_index)
        index = require_object(load_json(index_path), str(index_path))
        if not isinstance(index.get("schema"), str) or not index["schema"]:
            raise ContractError(f"{index_path}: missing schema discriminator")

        child_indexes = index.get("indexes", [])
        if child_indexes is not None:
            if not isinstance(child_indexes, list):
                raise ContractError(f"{index_path}: indexes must be an array")
            for position, relative in enumerate(child_indexes):
                child = safe_relative(
                    index_path.parent,
                    relative,
                    corpus_root,
                    f"{index_path}: indexes[{position}]",
                )
                visit(child)

        positives = require_nonempty_list(
            index.get("positive"), f"{index_path}: positive"
        )
        negatives = require_nonempty_list(
            index.get("negative"), f"{index_path}: negative"
        )
        positive_by_file: dict[str, tuple[str, Path]] = {}
        local_ids: set[str] = set()
        for position, raw_entry in enumerate(positives):
            label = f"{index_path}: positive[{position}]"
            entry = require_object(raw_entry, label)
            fixture_id = entry.get("id")
            schema_id = entry.get("schema_id")
            relative = entry.get("file")
            if (
                not isinstance(fixture_id, str)
                or not fixture_id
                or fixture_id in local_ids
            ):
                raise ContractError(
                    f"{label}: id must be non-empty and unique within the index"
                )
            if not isinstance(schema_id, str) or schema_id not in schemas_by_id:
                raise ContractError(f"{label}: unknown exact schema_id {schema_id!r}")
            fixture_path = safe_relative(
                index_path.parent, relative, corpus_root, f"{label}: file"
            )
            if relative in positive_by_file:
                raise ContractError(f"{label}: duplicate fixture file {relative!r}")
            value = load_json(fixture_path)
            schema_path, schema = schemas_by_id[schema_id]
            errors = sorted(
                Draft202012Validator(schema, registry=registry).iter_errors(value),
                key=lambda error: tuple(str(part) for part in error.absolute_path),
            )
            if errors:
                detail = "; ".join(
                    f"/{'/'.join(map(str, error.absolute_path))}: {error.message}"
                    for error in errors[:5]
                )
                raise ContractError(
                    f"{fixture_path}: rejected by exact schema {schema_path}: {detail}"
                )
            semantic_valid = security_semantic_valid(schema_id, value)
            if semantic_valid is False:
                raise ContractError(
                    f"{fixture_path}: positive failed semantic validation for {schema_id}"
                )
            local_ids.add(fixture_id)
            positive_by_file[str(relative)] = (schema_id, fixture_path)
            schema_ids_seen.add(schema_id)
            positive_count += 1

        audit_comparison_file = "positive/broker-audit-comparison-envelope-v1.json"
        audit_runner_file = "positive/broker-audit-runner-authorization-envelope-v1.json"
        audit_pair_present = {
            audit_comparison_file,
            audit_runner_file,
        }.intersection(positive_by_file)
        if audit_pair_present:
            if audit_pair_present != {audit_comparison_file, audit_runner_file}:
                raise ContractError(
                    f"{index_path}: broker audit comparison and runner vectors must coexist"
                )
            comparison = load_json(positive_by_file[audit_comparison_file][1])
            runner = load_json(positive_by_file[audit_runner_file][1])
            if not broker_audit_pair_semantic_valid(comparison, runner):
                raise ContractError(
                    f"{index_path}: broker audit vectors failed cryptographic runtime binding"
                )

        negative_ids: set[str] = set()
        for position, raw_entry in enumerate(negatives):
            label = f"{index_path}: negative[{position}]"
            entry = require_object(raw_entry, label)
            negative_id = entry.get("id")
            if (
                not isinstance(negative_id, str)
                or not negative_id
                or negative_id in negative_ids
            ):
                raise ContractError(
                    f"{label}: id must be non-empty and unique within the index"
                )

            if "schema_id" in entry:
                direct_keys = {"id", "file", "schema_id"}
                if set(entry) not in (direct_keys, direct_keys | {"exact_merge_of"}):
                    raise ContractError(
                        f"{label}: a direct negative must contain exactly id, file, schema_id, "
                        "and optional exact_merge_of"
                    )
                schema_id = entry.get("schema_id")
                if not isinstance(schema_id, str) or schema_id not in schemas_by_id:
                    raise ContractError(
                        f"{label}: unknown exact schema_id {schema_id!r}"
                    )
                fixture_path = safe_relative(
                    index_path.parent, entry.get("file"), corpus_root, f"{label}: file"
                )
                value = load_json(fixture_path)
                if "exact_merge_of" in entry:
                    merge_sources = require_nonempty_list(
                        entry.get("exact_merge_of"), f"{label}: exact_merge_of"
                    )
                    if len(merge_sources) < 2:
                        raise ContractError(
                            f"{label}: exact_merge_of must name at least two positive fixtures"
                        )
                    merged: dict[str, Any] = {}
                    seen_sources: set[str] = set()
                    for source_position, source_relative in enumerate(merge_sources):
                        source_label = f"{label}: exact_merge_of[{source_position}]"
                        if not isinstance(source_relative, str):
                            raise ContractError(
                                f"{source_label}: expected a positive fixture file"
                            )
                        if source_relative in seen_sources:
                            raise ContractError(
                                f"{source_label}: duplicate positive fixture {source_relative!r}"
                            )
                        if source_relative not in positive_by_file:
                            raise ContractError(
                                f"{source_label}: {source_relative!r} is not a positive fixture "
                                "in this index"
                            )
                        source_schema_id, source_path = positive_by_file[
                            source_relative
                        ]
                        if source_schema_id != schema_id:
                            raise ContractError(
                                f"{source_label}: schema_id {source_schema_id!r} does not match "
                                f"direct negative schema_id {schema_id!r}"
                            )
                        source = require_object(
                            load_json(source_path), str(source_path)
                        )
                        for key, member in source.items():
                            if key in merged and merged[key] != member:
                                raise ContractError(
                                    f"{source_label}: member {key!r} conflicts with an earlier "
                                    "merge source"
                                )
                            merged[key] = copy.deepcopy(member)
                        seen_sources.add(source_relative)
                    if value != merged:
                        raise ContractError(
                            f"{fixture_path}: direct negative is not the exact object merge of "
                            "exact_merge_of"
                        )
                schema_path, schema = schemas_by_id[schema_id]
                if Draft202012Validator(schema, registry=registry).is_valid(value):
                    raise ContractError(
                        f"{fixture_path}: direct negative was accepted by exact schema {schema_path}"
                    )
                negative_ids.add(negative_id)
                schema_ids_seen.add(schema_id)
                negative_count += 1
                continue

            mutation_path = safe_relative(
                index_path.parent, entry.get("file"), corpus_root, f"{label}: file"
            )
            mutation_set = require_object(load_json(mutation_path), str(mutation_path))
            cases = require_nonempty_list(
                mutation_set.get("cases"), f"{mutation_path}: cases"
            )
            case_ids: set[str] = set()
            for case_position, raw_case in enumerate(cases):
                case_label = f"{mutation_path}: cases[{case_position}]"
                case = require_object(raw_case, case_label)
                case_id = case.get("id")
                base_relative = case.get("base")
                if not isinstance(case_id, str) or not case_id or case_id in case_ids:
                    raise ContractError(
                        f"{case_label}: id must be non-empty and unique"
                    )
                if base_relative not in positive_by_file:
                    raise ContractError(
                        f"{case_label}: base {base_relative!r} is not a positive fixture in this index"
                    )
                expected = require_object(
                    case.get("expected"), f"{case_label}: expected"
                )
                for key in ("json_parse_valid", "json_schema_valid", "semantic_valid"):
                    if not isinstance(expected.get(key), bool):
                        raise ContractError(
                            f"{case_label}: expected.{key} must be boolean"
                        )
                if expected["semantic_valid"]:
                    raise ContractError(
                        f"{case_label}: a negative case cannot be semantically valid"
                    )

                schema_id, base_path = positive_by_file[str(base_relative)]
                base_bytes = base_path.read_bytes()
                mutation = require_object(
                    case.get("mutation"), f"{case_label}: mutation"
                )
                operation = mutation.get("op")
                parse_valid = True
                mutated_value: Any = None
                try:
                    if operation == "append_bytes":
                        raw_hex = mutation.get("hex")
                        if not isinstance(raw_hex, str):
                            raise ContractError(
                                f"{case_label}: append_bytes requires hex"
                            )
                        mutated_value = json.loads(base_bytes + bytes.fromhex(raw_hex))
                    else:
                        base_value = json.loads(base_bytes)
                        if operation == "replace_from_related":
                            related_relative = case.get("related_positive")
                            if related_relative not in positive_by_file:
                                raise ContractError(
                                    f"{case_label}: related_positive is not a positive fixture"
                                )
                            mutation = dict(mutation)
                            mutation["related_file"] = related_relative
                        mutated_value = mutate_json(
                            base_value, mutation, index_path.parent, case_label
                        )
                except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                    parse_valid = False
                if parse_valid != expected["json_parse_valid"]:
                    raise ContractError(
                        f"{case_label}: parse validity was {parse_valid}, expected {expected['json_parse_valid']}"
                    )
                schema_valid = False
                if parse_valid:
                    _, schema = schemas_by_id[schema_id]
                    schema_valid = Draft202012Validator(
                        schema, registry=registry
                    ).is_valid(mutated_value)
                if schema_valid != expected["json_schema_valid"]:
                    raise ContractError(
                        f"{case_label}: schema validity was {schema_valid}, expected {expected['json_schema_valid']}"
                    )
                checked_semantic_valid = security_semantic_valid(
                    schema_id, mutated_value
                )
                if schema_id in BROKER_AUDIT_SCHEMA_IDS and checked_semantic_valid is None:
                    raise ContractError(
                        f"{case_label}: broker audit mutation has no semantic verifier"
                    )
                if checked_semantic_valid is not None:
                    semantic_valid = parse_valid and checked_semantic_valid
                    if semantic_valid != expected["semantic_valid"]:
                        raise ContractError(
                            f"{case_label}: semantic validity for {schema_id} was "
                            f"{semantic_valid}, expected {expected['semantic_valid']}"
                        )
                case_ids.add(case_id)
                negative_count += 1
            negative_ids.add(negative_id)

    seen_root_entries: set[str] = set()
    for position, relative in enumerate(root_indexes):
        if not isinstance(relative, str) or relative in seen_root_entries:
            raise ContractError(
                f"{root_path}: indexes[{position}] must be a unique string"
            )
        seen_root_entries.add(relative)
        child = safe_relative(
            root_path.parent, relative, corpus_root, f"{root_path}: indexes[{position}]"
        )
        visit(child)

    if positive_count == 0 or negative_count == 0 or not schema_ids_seen:
        raise ContractError(
            "security wire corpus must have non-zero positives, negatives, and schemas"
        )
    return len(visited_indexes), positive_count, negative_count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args()
    try:
        indexes, positives, negatives = validate_corpus(args.repo_root.resolve())
    except ContractError as error:
        print(f"security wire vector contract failed: {error}", file=sys.stderr)
        return 1
    print(
        f"OK security wire vectors: indexes={indexes} positives={positives} negatives={negatives}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
