import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic_core import PydanticSerializationError

from chio_sdk._generated.agent.tool_call_request_schema import (
    ChioAgentmessageToolCallRequest,
)
from chio_sdk._generated.capability.aggregate_budget_root_binding_body_schema import (
    ChioAggregateBudgetRootBindingBody,
)
from chio_sdk._generated.capability.aggregate_budget_root_binding_schema import (
    ChioSignedAggregateBudgetRootBinding,
)
from chio_sdk._generated.capability.aggregate_budget_root_commitment_schema import (
    ChioAggregateBudgetRootCommitment,
)
from chio_sdk._generated.capability.aggregate_family_preservation_evidence_schema import (
    ChioAggregateFamilyPreservationEvidence,
)
from chio_sdk._generated.capability.aggregate_invocation_budget_schema import (
    ChioAggregateInvocationBudget,
)
from chio_sdk._generated.capability.governed_approval_token_body_schema import (
    ChioGovernedApprovalTokenBody,
)
from chio_sdk._generated.capability.governed_approval_token_schema import (
    ChioSignedGovernedApprovalToken,
)
from chio_sdk._generated.capability.threshold_approval_proposal_body_schema import (
    ChioThresholdApprovalProposalBody,
)
from chio_sdk._generated.capability.threshold_approval_proposal_schema import (
    ChioSignedThresholdApprovalProposal,
)
from chio_sdk._generated.capability.verified_approval_set_schema import (
    ChioVerifiedThresholdApprovalSet,
)
from chio_sdk._generated.kernel.capability_list_schema import (
    ChioKernelmessageCapabilityList,
)
from chio_sdk._generated.security.correlated_finding_v1_schema import (
    ChioCorrelatedFindingV1,
)
from chio_sdk._generated.security.correlated_finding_receipt_body_v1_schema import (
    ChioCorrelatedFindingReceiptBodyV1,
)
from chio_sdk._generated.security.declassification_consumption_receipt_body_v1_schema import (
    ChioDeclassificationConsumptionReceiptBodyV1,
)
from chio_sdk._generated.security.declassification_outcome_receipt_body_v1_schema import (
    ChioDeclassificationOutcomeReceiptBodyV1,
)
from chio_sdk._generated.security.detector_health_receipt_body_v1_schema import (
    ChioDetectorHealthReceiptBodyV1,
    GroupBinding,
)
from chio_sdk._generated.security.effect_transition_receipt_body_v1_schema import (
    ChioEffectTransitionReceiptBodyV1,
)
from chio_sdk._generated.security.flow_denial_receipt_body_v1_schema import (
    ChioFlowDenialReceiptBodyV1,
)
from chio_sdk._generated.security.lift_rollback_completion_receipt_body_v1_schema import (
    ChioLiftOrRollbackCompletionReceiptBodyV1,
)
from chio_sdk._generated.security.response_completion_receipt_body_v1_schema import (
    ChioResponseCompletionReceiptBodyV1,
)
from chio_sdk._generated.security.response_effect_v1_schema import ChioResponseEffectV1
from chio_sdk._generated.security.response_plan_v1_schema import ChioResponsePlanV1
from chio_sdk._generated.security.response_plan_receipt_body_v1_schema import (
    ChioResponsePlanReceiptBodyV1,
)
from chio_sdk._generated.security.response_state_transition_receipt_body_v1_schema import (
    ChioResponseStateTransitionReceiptBodyV1,
)
from chio_sdk._generated.security.security_event_body_v1_schema import (
    ChioSecurityEventBodyV1,
)
from chio_sdk._generated.security.scheduler_health_receipt_body_v1_schema import (
    ChioSchedulerHealthReceiptBodyV1,
)
from chio_sdk._generated.security.tripwire_observation_receipt_body_v1_schema import (
    ChioTripwireObservationReceiptBodyV1,
)
from chio_sdk._generated.trust_control.admission_capture_metadata_schema import (
    ChioAuthoritativeAdmissionCaptureReceiptProjection,
)
from chio_sdk._generated.trust_control.admission_request_binding_schema import (
    ChioAdmissionOperationRequestBindingProjection,
)
from chio_sdk._generated.trust_control.budget_invocation_admission_evidence_schema import (
    ChioBudgetInvocationAdmissionEvidence,
)


ROOT = Path(__file__).resolve().parents[4]
ACTIVE_DEFENSE_VECTORS = (
    ROOT / "tests/bindings/vectors/security/active-defense/positive"
)
PROTOCOL_VECTORS = ROOT / "tests/bindings/vectors/security/protocol-primitives"
PROTOCOL_MODEL_BY_ID = {
    "aggregate_root_commitment": ChioAggregateBudgetRootCommitment,
    "aggregate_root_binding_body": ChioAggregateBudgetRootBindingBody,
    "aggregate_root_binding": ChioSignedAggregateBudgetRootBinding,
    "aggregate_invocation_budget": ChioAggregateInvocationBudget,
    "capability_list_delegation_family": ChioKernelmessageCapabilityList,
    "aggregate_family_preservation": ChioAggregateFamilyPreservationEvidence,
    "threshold_proposal_body": ChioThresholdApprovalProposalBody,
    "threshold_proposal": ChioSignedThresholdApprovalProposal,
    "governed_token_body_alice": ChioGovernedApprovalTokenBody,
    "governed_token_alice": ChioSignedGovernedApprovalToken,
    "governed_token_body_bob": ChioGovernedApprovalTokenBody,
    "governed_token_bob": ChioSignedGovernedApprovalToken,
    "tool_call_request_singular_approval": ChioAgentmessageToolCallRequest,
    "tool_call_request_list_approval": ChioAgentmessageToolCallRequest,
    "verified_approval_set": ChioVerifiedThresholdApprovalSet,
    "admission_request_binding": ChioAdmissionOperationRequestBindingProjection,
    "budget_admission_evidence": ChioBudgetInvocationAdmissionEvidence,
    "admission_capture_metadata": ChioAuthoritativeAdmissionCaptureReceiptProjection,
}


def apply_json_mutation(value, mutation):
    segments = mutation["path"].removeprefix("/").split("/")
    parent = value
    for segment in segments[:-1]:
        parent = parent[int(segment)] if isinstance(parent, list) else parent[segment]
    target = segments[-1]
    if mutation["op"] in {"add", "replace"}:
        if isinstance(parent, list):
            parent[int(target)] = mutation["value"]
        else:
            parent[target] = mutation["value"]
    elif mutation["op"] == "remove":
        if isinstance(parent, list):
            del parent[int(target)]
        else:
            del parent[target]
    else:
        raise AssertionError(f"unsupported mutation operation {mutation['op']}")


@pytest.mark.parametrize(
    ("model", "file_name"),
    [
        (ChioSecurityEventBodyV1, "security-event-body-v1.json"),
        (ChioCorrelatedFindingV1, "correlated-finding-v1.json"),
        (ChioResponsePlanV1, "response-plan-v1.json"),
        (ChioResponseEffectV1, "response-effect-v1.json"),
        (
            ChioResponseStateTransitionReceiptBodyV1,
            "response-state-transition-receipt-body-v1.json",
        ),
        (
            ChioResponseStateTransitionReceiptBodyV1,
            "response-state-transition-receipt-body-renewal-v1.json",
        ),
        (
            ChioEffectTransitionReceiptBodyV1,
            "effect-transition-receipt-body-v1.json",
        ),
        (
            ChioEffectTransitionReceiptBodyV1,
            "effect-transition-receipt-body-legacy-v1.json",
        ),
        (
            ChioDetectorHealthReceiptBodyV1,
            "detector-health-receipt-body-v1.json",
        ),
        (
            ChioDetectorHealthReceiptBodyV1,
            "detector-health-receipt-body-contradictory-v1.json",
        ),
        (
            ChioDetectorHealthReceiptBodyV1,
            "detector-health-receipt-body-unknown-v1.json",
        ),
        (ChioFlowDenialReceiptBodyV1, "flow-denial-receipt-body-v1.json"),
        (
            ChioDeclassificationConsumptionReceiptBodyV1,
            "declassification-consumption-receipt-body-v1.json",
        ),
        (
            ChioDeclassificationOutcomeReceiptBodyV1,
            "declassification-outcome-receipt-body-v1.json",
        ),
        (
            ChioTripwireObservationReceiptBodyV1,
            "tripwire-observation-receipt-body-v1.json",
        ),
        (
            ChioCorrelatedFindingReceiptBodyV1,
            "correlated-finding-receipt-body-v1.json",
        ),
        (ChioResponsePlanReceiptBodyV1, "response-plan-receipt-body-v1.json"),
        (
            ChioResponsePlanReceiptBodyV1,
            "response-plan-receipt-body-two-effects-v1.json",
        ),
        (
            ChioResponseCompletionReceiptBodyV1,
            "response-completion-receipt-body-v1.json",
        ),
        (
            ChioResponseCompletionReceiptBodyV1,
            "response-completion-receipt-body-failed-v1.json",
        ),
        (
            ChioLiftOrRollbackCompletionReceiptBodyV1,
            "lift-rollback-completion-receipt-body-v1.json",
        ),
        (
            ChioLiftOrRollbackCompletionReceiptBodyV1,
            "lift-rollback-completion-receipt-body-nonreversible-v1.json",
        ),
        (ChioSchedulerHealthReceiptBodyV1, "scheduler-health-receipt-body-v1.json"),
    ],
)
def test_generated_security_type_decodes_reencodes_and_rejects(model, file_name):
    source = json.loads(
        (ACTIVE_DEFENSE_VECTORS / file_name).read_text(encoding="utf-8")
    )
    decoded = model.model_validate(source)
    reencoded = decoded.model_dump(mode="json", by_alias=True, exclude_unset=True)
    assert json.dumps(reencoded, sort_keys=True, separators=(",", ":")) == json.dumps(
        source, sort_keys=True, separators=(",", ":")
    )

    source["unknown"] = True
    with pytest.raises(ValidationError):
        model.model_validate(source)


def test_generated_detector_health_type_rejects_mutation_corpus():
    vector_dir = ROOT / "tests/bindings/vectors/security/active-defense"
    corpus = json.loads((vector_dir / "mutations-v1.json").read_text(encoding="utf-8"))
    for case in corpus["cases"]:
        if not case["id"].startswith("detector_health_"):
            continue
        value = json.loads((vector_dir / case["base"]).read_text(encoding="utf-8"))
        apply_json_mutation(value, case["mutation"])
        with pytest.raises(ValidationError):
            ChioDetectorHealthReceiptBodyV1.model_validate(value)


def test_generated_detector_health_type_revalidates_assignment_and_serialization():
    source = json.loads(
        (ACTIVE_DEFENSE_VECTORS / "detector-health-receipt-body-v1.json").read_text(
            encoding="utf-8"
        )
    )
    unresolved = GroupBinding.model_validate({"kind": "unresolved"})

    assigned = ChioDetectorHealthReceiptBodyV1.model_validate(source)
    with pytest.raises(ValidationError):
        assigned.group_binding = unresolved

    bypassed = ChioDetectorHealthReceiptBodyV1.model_validate(source)
    object.__setattr__(bypassed, "group_binding", unresolved)
    with pytest.raises((PydanticSerializationError, ValueError)):
        bypassed.model_dump(mode="json", by_alias=True)


def test_generated_receipt_types_cover_semantic_mutation_corpus():
    vector_dir = ROOT / "tests/bindings/vectors/security/active-defense"
    corpus = json.loads(
        (vector_dir / "receipt-body-mutations-v1.json").read_text(encoding="utf-8")
    )
    model_by_stem = {
        "flow-denial-receipt-body-v1.json": ChioFlowDenialReceiptBodyV1,
        "declassification-consumption-receipt-body-v1.json": ChioDeclassificationConsumptionReceiptBodyV1,
        "declassification-outcome-receipt-body-v1.json": ChioDeclassificationOutcomeReceiptBodyV1,
        "tripwire-observation-receipt-body-v1.json": ChioTripwireObservationReceiptBodyV1,
        "correlated-finding-receipt-body-v1.json": ChioCorrelatedFindingReceiptBodyV1,
        "response-plan-receipt-body-v1.json": ChioResponsePlanReceiptBodyV1,
        "response-plan-receipt-body-two-effects-v1.json": ChioResponsePlanReceiptBodyV1,
        "response-state-transition-receipt-body-v1.json": ChioResponseStateTransitionReceiptBodyV1,
        "response-state-transition-receipt-body-renewal-v1.json": ChioResponseStateTransitionReceiptBodyV1,
        "effect-transition-receipt-body-v1.json": ChioEffectTransitionReceiptBodyV1,
        "effect-transition-receipt-body-legacy-v1.json": ChioEffectTransitionReceiptBodyV1,
        "response-completion-receipt-body-v1.json": ChioResponseCompletionReceiptBodyV1,
        "response-completion-receipt-body-failed-v1.json": ChioResponseCompletionReceiptBodyV1,
        "lift-rollback-completion-receipt-body-v1.json": ChioLiftOrRollbackCompletionReceiptBodyV1,
        "lift-rollback-completion-receipt-body-nonreversible-v1.json": ChioLiftOrRollbackCompletionReceiptBodyV1,
        "scheduler-health-receipt-body-v1.json": ChioSchedulerHealthReceiptBodyV1,
    }
    semantic_check = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check-security-wire-vectors.py")],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert semantic_check.returncode == 0, semantic_check.stderr
    generated_rejections = 0
    rejected_ids = set()
    required_generated_rejections = {
        "correlated_finding_receipt_unsafe_first_event_time",
        "correlated_finding_receipt_unsafe_last_event_time",
        "response_plan_receipt_unsafe_header_time",
        "response_plan_receipt_unsafe_expiry",
        "response_plan_receipt_unsafe_created_time",
        "response_state_transition_unsafe_generation",
        "response_state_transition_unsafe_applying_lease",
        "effect_transition_zero_generation",
        "effect_transition_unsafe_generation",
        "effect_transition_unsafe_fencing_token",
        "scheduler_health_unsafe_first_failure",
        "scheduler_health_attempts_overflow_u32",
        "scheduler_health_unsafe_fencing_token",
    }
    for case in corpus["cases"]:
        stem = Path(case["base"]).name
        value = json.loads((vector_dir / case["base"]).read_text(encoding="utf-8"))
        apply_json_mutation(value, case["mutation"])
        try:
            model_by_stem[stem].model_validate(value)
        except ValidationError:
            generated_rejections += 1
            rejected_ids.add(case["id"])
    assert generated_rejections > 0
    assert required_generated_rejections <= rejected_ids


def test_generated_protocol_type_preserves_security_fields():
    index = json.loads((PROTOCOL_VECTORS / "index.json").read_text(encoding="utf-8"))
    assert len(index["positive"]) == 18
    assert len({entry["id"] for entry in index["positive"]}) == 18
    assert len({entry["file"] for entry in index["positive"]}) == 18
    assert set(PROTOCOL_MODEL_BY_ID) == {entry["id"] for entry in index["positive"]}
    for entry in index["positive"]:
        source = json.loads((PROTOCOL_VECTORS / entry["file"]).read_text(encoding="utf-8"))
        model = PROTOCOL_MODEL_BY_ID[entry["id"]]
        decoded = model.model_validate(source)
        reencoded = decoded.model_dump(
            mode="json", by_alias=True, exclude_none=False, exclude_unset=True
        )
        assert json.dumps(
            reencoded, sort_keys=True, separators=(",", ":")
        ) == json.dumps(source, sort_keys=True, separators=(",", ":")), entry["id"]

        unknown = dict(source)
        unknown["unknown"] = True
        with pytest.raises(ValidationError):
            model.model_validate(unknown)


def test_protocol_schema_and_generated_models_cover_exact_negative_corpus():
    # Generated Pydantic shapes and the authoritative JSON Schema validator form
    # the Python conformance pipeline. Schema-valid cases must still decode.
    checked = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/check-protocol-primitives-vectors.py"),
            "--report-json",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert checked.returncode == 0, checked.stderr
    validation_report = json.loads(checked.stdout)
    assert validation_report["direct"] == {
        "id": "tool_call_request_both_approval_forms",
        "json_parse_valid": True,
        "json_schema_valid": False,
        "semantic_valid": False,
    }
    validated_by_id = {
        result["id"]: result for result in validation_report["cases"]
    }
    index = json.loads((PROTOCOL_VECTORS / "index.json").read_text(encoding="utf-8"))
    protocol_by_base = {
        entry["file"]: (entry["id"], entry["schema_id"])
        for entry in index["positive"]
    }
    corpus = json.loads(
        (PROTOCOL_VECTORS / "mutations-v1.json").read_text(encoding="utf-8")
    )
    assert len(corpus["cases"]) == 20
    assert len({case["id"] for case in corpus["cases"]}) == 20
    structural_rejections = 1
    semantic_rejections = 0
    for case in corpus["cases"]:
        base_bytes = (PROTOCOL_VECTORS / case["base"]).read_bytes().removesuffix(b"\n")
        if case["mutation"]["op"] == "append_bytes":
            mutated_bytes = base_bytes + bytes.fromhex(case["mutation"]["hex"])
            source = json.loads(mutated_bytes)
            assert json.dumps(
                source, sort_keys=True, separators=(",", ":")
            ).encode("utf-8") != mutated_bytes
        else:
            source = json.loads(base_bytes)
            apply_json_mutation(source, case["mutation"])
        assert case["expected"]["json_parse_valid"] is True
        assert case["expected"]["semantic_valid"] is False
        model_id, _schema_id = protocol_by_base[case["base"]]
        validated = validated_by_id[case["id"]]
        assert validated["json_parse_valid"] is case["expected"]["json_parse_valid"]
        assert validated["semantic_valid"] is case["expected"]["semantic_valid"]
        schema_valid = validated["json_schema_valid"]
        assert schema_valid is case["expected"]["json_schema_valid"], case["id"]
        if case["expected"]["json_schema_valid"]:
            semantic_rejections += 1
            model = PROTOCOL_MODEL_BY_ID[model_id]
            model.model_validate(source)
        else:
            structural_rejections += 1
    assert structural_rejections == 8
    assert semantic_rejections == 13
    assert structural_rejections + semantic_rejections == 21


def test_both_approval_forms_vector_tracks_authoritative_exclusion():
    schema = json.loads(
        (
            ROOT / "spec/schemas/chio-wire/v1/agent/tool_call_request.schema.json"
        ).read_text(encoding="utf-8")
    )
    vector = json.loads(
        (
            PROTOCOL_VECTORS / "negative/tool-call-request-both-approval-forms-v1.json"
        ).read_text(encoding="utf-8")
    )

    excluded_fields = schema["not"]["required"]
    assert set(excluded_fields) == {"approval_token", "approval_tokens"}
    assert all(field in vector for field in excluded_fields)
