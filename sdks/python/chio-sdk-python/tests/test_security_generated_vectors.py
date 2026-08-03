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
from chio_sdk._generated.capability.governed_transaction_intent_schema import (
    ChioGovernedTransactionIntent,
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
from chio_sdk._generated.security.declassification_grant_schema import (
    FlowIdentifier as DeclassificationFlowIdentifier,
    TargetLabel,
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
from chio_sdk._generated.security.information_label_schema import InformationLabel
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
from chio_sdk._generated.trust_control.partition_escrow_admission_evidence_schema import (
    ChioPartitionEscrowAdmissionEvidence,
)
from chio_sdk._generated.trust_control.partition_escrow_allocation_set_schema import (
    ChioSignedPartitionEscrowAllocationSet,
)
from chio_sdk._generated.trust_control.partition_escrow_quota_commitment_schema import (
    ChioSignedPartitionEscrowQuotaCommitment,
)
from chio_sdk._generated.trust_control.partition_escrow_receipt_metadata_schema import (
    ChioPartitionEscrowFinancialReceiptMetadata,
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
    "governed_active_response_intent": ChioGovernedTransactionIntent,
    "tool_call_request_singular_approval": ChioAgentmessageToolCallRequest,
    "tool_call_request_list_approval": ChioAgentmessageToolCallRequest,
    "tool_call_request_full_security": ChioAgentmessageToolCallRequest,
    "verified_approval_set": ChioVerifiedThresholdApprovalSet,
    "admission_request_binding": ChioAdmissionOperationRequestBindingProjection,
    "budget_admission_evidence": ChioBudgetInvocationAdmissionEvidence,
    "budget_admission_evidence_partition_escrow": ChioBudgetInvocationAdmissionEvidence,
    "partition_escrow_quota_commitment": ChioSignedPartitionEscrowQuotaCommitment,
    "admission_capture_metadata": ChioAuthoritativeAdmissionCaptureReceiptProjection,
    "admission_capture_metadata_partition_escrow": (
        ChioAuthoritativeAdmissionCaptureReceiptProjection
    ),
    "partition_escrow_receipt_metadata": ChioPartitionEscrowFinancialReceiptMetadata,
    "partition_escrow_admission_evidence": ChioPartitionEscrowAdmissionEvidence,
    "partition_escrow_allocation_set": ChioSignedPartitionEscrowAllocationSet,
}

JCS_MAX_SAFE_INTEGER = (1 << 53) - 1


def _jcs_string(value):
    escaped = []
    short_escapes = {
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
        '"': '\\"',
        "\\": "\\\\",
    }
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ValueError("JCS strings must not contain lone surrogates")
        if character in short_escapes:
            escaped.append(short_escapes[character])
        elif codepoint < 0x20:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(character)
    return '"' + "".join(escaped) + '"'


def _jcs_utf16_sort_key(value):
    _jcs_string(value)
    encoded = value.encode("utf-16-be")
    return tuple(
        int.from_bytes(encoded[offset : offset + 2], "big")
        for offset in range(0, len(encoded), 2)
    )


def _jcs_text(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if type(value) is int:
        if not -JCS_MAX_SAFE_INTEGER <= value <= JCS_MAX_SAFE_INTEGER:
            raise ValueError("JCS corpus integers must be IEEE-754 safe integers")
        return str(value)
    if isinstance(value, float):
        raise TypeError("floating-point values are outside this corpus JCS profile")
    if isinstance(value, list):
        return "[" + ",".join(_jcs_text(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JCS object keys must be strings")
        members = (
            _jcs_string(key) + ":" + _jcs_text(value[key])
            for key in sorted(value, key=_jcs_utf16_sort_key)
        )
        return "{" + ",".join(members) + "}"
    raise TypeError(f"unsupported JCS corpus value {type(value).__name__}")


def jcs_bytes(value):
    return _jcs_text(value).encode("utf-8")


def fixture_payload(path):
    payload = path.read_bytes()
    return payload[:-1] if payload.endswith(b"\n") else payload


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
            ChioResponseCompletionReceiptBodyV1,
            "response-completion-receipt-body-failed-before-effect-v1.json",
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
    payload = fixture_payload(ACTIVE_DEFENSE_VECTORS / file_name)
    source = json.loads(payload)
    decoded = model.model_validate(source)
    reencoded = decoded.model_dump(mode="json", by_alias=True, exclude_unset=True)
    assert jcs_bytes(reencoded) == payload

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


def test_corpus_jcs_orders_object_keys_by_utf16_code_units():
    value = {"\ue000": 1, "\U00010000": 2}
    expected = '{"\U00010000":2,"\ue000":1}'.encode("utf-8")
    assert jcs_bytes(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        1.5,
        JCS_MAX_SAFE_INTEGER + 1,
        -(JCS_MAX_SAFE_INTEGER + 1),
        "\ud800",
        {"\udfff": None},
    ],
)
def test_corpus_jcs_rejects_values_outside_its_bounded_profile(value):
    with pytest.raises((TypeError, ValueError)):
        jcs_bytes(value)


def test_generated_protocol_type_preserves_security_fields():
    index = json.loads((PROTOCOL_VECTORS / "index.json").read_text(encoding="utf-8"))
    assert len(index["positive"]) == 26
    assert len({entry["id"] for entry in index["positive"]}) == 26
    assert len({entry["file"] for entry in index["positive"]}) == 26
    assert set(PROTOCOL_MODEL_BY_ID) == {entry["id"] for entry in index["positive"]}
    for entry in index["positive"]:
        payload = fixture_payload(PROTOCOL_VECTORS / entry["file"])
        source = json.loads(payload)
        model = PROTOCOL_MODEL_BY_ID[entry["id"]]
        decoded = model.model_validate(source)
        if entry["id"] == "tool_call_request_full_security":
            declassification_grant = decoded.declassification_grant
            assert declassification_grant is not None
            target_label = InformationLabel.model_validate(
                source["declassification_grant"]["body"]["target_label"]
            )
            grant_body = declassification_grant.body.model_copy(
                update={"target_label": target_label.root}
            )
            declassification_grant = declassification_grant.model_copy(
                update={"body": grant_body}
            )
            decoded = decoded.model_copy(
                update={"declassification_grant": declassification_grant}
            )
        reencoded = decoded.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=False,
            exclude_unset=True,
            serialize_as_any=True,
        )
        assert jcs_bytes(reencoded) == payload, entry["id"]

        if entry["id"] == "governed_active_response_intent":
            assert decoded.root.kind == "active_response_plan"
        elif entry["id"] == "tool_call_request_full_security":
            assert decoded.capability_token.aggregate_invocation_budget is not None
            assert decoded.supplemental_authorization is not None
            assert decoded.governed_intent is not None
            assert decoded.governed_intent.root.kind == "tool_invocation"
            assert decoded.approval_tokens is not None
            assert len(decoded.approval_tokens) == 2
            assert decoded.approval_token is None
            assert "approval_token" not in source
            assert decoded.threshold_approval_proposal is not None
            assert decoded.declassification_grant is not None

        unknown = dict(source)
        unknown["unknown"] = True
        with pytest.raises(ValidationError):
            model.model_validate(unknown)


def test_generated_declassification_target_label_preserves_nested_fields_and_schema():
    source = {
        "compartments": ["compartment:clinical", "compartment:billing"],
        "kind": "known",
        "owners": {
            "owner:care-team": [
                "owner:care-team",
                "reader:auditor",
            ]
        },
    }
    label = TargetLabel.model_validate(source)
    assert label.model_dump(mode="json") == source

    schema = TargetLabel.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"compartments", "kind", "owners"}
    assert set(schema["properties"]) == {"compartments", "kind", "owners"}
    compartments_schema = schema["properties"]["compartments"]
    assert compartments_schema["type"] == "array"
    assert compartments_schema["maxItems"] == 64
    assert compartments_schema["uniqueItems"] is True
    assert set(compartments_schema["items"]) == {"$ref"}

    owners_schema = schema["properties"]["owners"]
    assert owners_schema["type"] == "object"
    assert owners_schema["maxProperties"] == 64
    assert "patternProperties" not in owners_schema
    flow_schema = DeclassificationFlowIdentifier.model_json_schema()
    flow_schema.pop("title", None)
    assert owners_schema["propertyNames"] == flow_schema
    readers_schema = owners_schema["additionalProperties"]
    assert readers_schema["type"] == "array"
    assert readers_schema["maxItems"] == 256
    assert readers_schema["uniqueItems"] is True
    assert set(readers_schema["items"]) == {"$ref"}
    reader_ref = readers_schema["items"]["$ref"]
    assert reader_ref.startswith("#/$defs/")
    referenced_flow_schema = schema["$defs"][reader_ref.rsplit("/", 1)[1]].copy()
    referenced_flow_schema.pop("title", None)
    assert referenced_flow_schema == flow_schema
    assert compartments_schema["items"]["$ref"] == reader_ref

    TargetLabel.model_validate(
        {
            "compartments": [f"compartment:{index}" for index in range(64)],
            "kind": "known",
            "owners": {f"owner:{index}": [] for index in range(64)},
        }
    )
    TargetLabel.model_validate(
        {
            "compartments": [],
            "kind": "known",
            "owners": {
                "x" * 256: [f"reader:{index}" for index in range(256)],
            },
        }
    )

    with pytest.raises(ValidationError):
        TargetLabel.model_validate(
            {
                "compartments": [],
                "kind": "known",
                "owners": {},
                "unexpected": True,
            }
        )
    with pytest.raises(ValidationError):
        TargetLabel.model_validate(
            {
                "compartments": [],
                "kind": "unknown",
                "owners": {},
            }
        )
    with pytest.raises(ValidationError):
        TargetLabel.model_validate(
            {
                "compartments": ["compartment:duplicate"] * 2,
                "kind": "known",
                "owners": {},
            }
        )
    with pytest.raises(ValidationError):
        TargetLabel.model_validate(
            {
                "compartments": [],
                "kind": "known",
                "owners": {"owner:care-team": ["reader:duplicate"] * 2},
            }
        )
    with pytest.raises(ValidationError):
        TargetLabel.model_validate(
            {
                "compartments": [f"compartment:{index}" for index in range(65)],
                "kind": "known",
                "owners": {},
            }
        )
    with pytest.raises(ValidationError):
        TargetLabel.model_validate(
            {
                "compartments": [],
                "kind": "known",
                "owners": {f"owner:{index}": [] for index in range(65)},
            }
        )
    with pytest.raises(ValidationError):
        TargetLabel.model_validate(
            {
                "compartments": [],
                "kind": "known",
                "owners": {
                    "owner:care-team": [f"reader:{index}" for index in range(257)],
                },
            }
        )
    for invalid_owner in (
        "",
        " owner:invalid",
        "owner:invalid ",
        "\x00owner:invalid",
        "\x7fowner:invalid",
        "x" * 257,
    ):
        with pytest.raises(ValidationError):
            TargetLabel.model_validate(
                {
                    "compartments": [],
                    "kind": "known",
                    "owners": {invalid_owner: []},
                }
            )
    for missing in ("compartments", "kind", "owners"):
        incomplete = dict(source)
        incomplete.pop(missing)
        with pytest.raises(ValidationError):
            TargetLabel.model_validate(incomplete)


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
    assert len(corpus["cases"]) == 43
    assert len({case["id"] for case in corpus["cases"]}) == 43
    structural_rejections = 1
    semantic_rejections = 0
    for case in corpus["cases"]:
        base_bytes = (PROTOCOL_VECTORS / case["base"]).read_bytes().removesuffix(b"\n")
        if case["mutation"]["op"] == "append_bytes":
            mutated_bytes = base_bytes + bytes.fromhex(case["mutation"]["hex"])
            source = json.loads(mutated_bytes)
            assert jcs_bytes(source) != mutated_bytes
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
    assert structural_rejections == 16
    assert semantic_rejections == 28
    assert structural_rejections + semantic_rejections == 44


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
