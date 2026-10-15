"""Dispatch launch fields preserve required nulls and exact scalar types."""

from copy import deepcopy
import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
import respx

from chio_sdk.client import ChioClient, _jsonable
from chio_sdk.models import generated
from chio_sdk._generated.kernel.caller_dispatch_authorization_schema import (
    NativeLaunch as CallerNativeLaunch,
)
from chio_sdk._generated.security.tool_flow_declaration_schema import ToolFlowDeclaration


_CASES = json.loads(
    (Path(__file__).resolve().parents[4] / "tests/bindings/fixtures/protocol-primitives-v1.json")
    .read_text(encoding="utf-8")
)["cases"]
_NATIVE = {"receipt_id": "a" * 64, "receipt_sha256": "b" * 64}
_WORKER = {
    "kind": "container",
    "launch_attempt": 2,
    "launch_ref": {"record_id": "c" * 64, "record_sha256": "d" * 64},
}
_LAUNCHES = [
    pytest.param({"native_launch": None, "worker_profile": None}, id="both-null"),
    pytest.param({"native_launch": _NATIVE, "worker_profile": None}, id="native-only"),
    pytest.param({"native_launch": None, "worker_profile": _WORKER}, id="worker-only"),
    pytest.param({"native_launch": _NATIVE, "worker_profile": _WORKER}, id="both-present"),
]
_SURFACES = [
    pytest.param(
        generated.ChioSignedCallerDispatchAuthorization,
        ("authorization", "committed", "dispatch_commit", "dispatch_launch"),
        id="caller-authorization",
    ),
    pytest.param(
        generated.ChioDurableAdmissionReceiptMetadata,
        ("retained_dispatch_commit", "dispatch_launch"),
        id="admission-receipt",
    ),
]


def _case(name):
    return deepcopy(next(case["instance"] for case in _CASES if case["name"] == name))


def _document(model, launch):
    authorization = _case("caller-dispatch-authorization")
    commit = authorization["authorization"]["committed"]["dispatch_commit"]
    commit["dispatch_launch"] = deepcopy(launch)
    if model is generated.ChioSignedCallerDispatchAuthorization:
        return authorization
    return {
        "schema": "chio.admission-receipt.v1",
        "operation_id": "a" * 64,
        "request_id": "fixture-request",
        "request_namespace_digest": "b" * 64,
        "request_binding_hash": "c" * 64,
        "projected_operation_version": 2,
        "projected_state": "outcome_unknown_after_dispatch",
        "projected_dispatch_state": "terminal",
        "trusted_time_unix_ms": 100,
        "coordinator_lease_id": "fixture-coordinator",
        "coordinator_lease_epoch": 1,
        "store_fence": deepcopy(commit["store_fence"]),
        "retained_dispatch_commit": commit,
        "compensation_status": "not_compensated",
        "tool_outcome_id": None,
        "tool_outcome_version": None,
    }


def _errors(error):
    return [(entry["type"], entry["loc"]) for entry in error.errors()]


@pytest.mark.parametrize("model,path", _SURFACES)
@pytest.mark.parametrize("launch", _LAUNCHES)
def test_dispatch_launch_null_and_object_values_round_trip(model, path, launch):
    document = _document(model, launch)
    parsed = model.model_validate(document)
    assert parsed.model_dump(mode="json", by_alias=True, exclude_unset=True) == document
    reparsed = model.model_validate_json(parsed.model_dump_json(by_alias=True))
    assert reparsed.model_dump(mode="json", by_alias=True, exclude_unset=True) == document


@pytest.mark.parametrize("model,path", _SURFACES)
@pytest.mark.parametrize(
    "missing", [("native_launch",), ("worker_profile",), ("native_launch", "worker_profile")]
)
def test_dispatch_launch_requires_both_keys_even_when_nullable(model, path, missing):
    launch = {"native_launch": _NATIVE, "worker_profile": _WORKER}
    for name in missing:
        del launch[name]
    with pytest.raises(ValidationError) as error:
        model.model_validate(_document(model, launch))
    assert _errors(error.value) == [("missing", (*path, name)) for name in missing]


@pytest.mark.parametrize("model,path", _SURFACES)
@pytest.mark.parametrize(
    "attempt,error_type",
    [(True, "int_type"), ("2", "int_type"), (2.0, "int_type"),
     (0, "greater_than_equal"), (4294967296, "less_than_equal")],
)
def test_worker_attempt_rejects_coercion_and_out_of_range_values(model, path, attempt, error_type):
    launch = deepcopy({"native_launch": _NATIVE, "worker_profile": _WORKER})
    launch["worker_profile"]["launch_attempt"] = attempt
    with pytest.raises(ValidationError) as error:
        model.model_validate(_document(model, launch))
    assert _errors(error.value) == [(error_type, (*path, "worker_profile", "launch_attempt"))]


@pytest.mark.parametrize("model,path", _SURFACES)
def test_dispatch_launch_rejects_unknown_properties(model, path):
    launch = {"native_launch": _NATIVE, "worker_profile": _WORKER, "unknown": 1}
    with pytest.raises(ValidationError) as error:
        model.model_validate(_document(model, launch))
    assert _errors(error.value) == [("extra_forbidden", (*path, "unknown"))]


@pytest.mark.parametrize(
    "model,value",
    [
        (CallerNativeLaunch, {"receipt_id": None, "receipt_sha256": "b" * 64}),
        (ToolFlowDeclaration, {"egress": False, "output_label": None}),
    ],
)
def test_dispatch_nullable_fields_do_not_relax_other_security_properties(model, value):
    with pytest.raises(ValidationError) as error:
        model.model_validate(value)
    assert _errors(error.value) == [("value_error", ())]
    assert error.value.errors()[0]["msg"] == (
        "Value error, security properties must be omitted instead of null"
    )


@pytest.mark.parametrize("launch", _LAUNCHES)
def test_typed_authorization_http_serialization_preserves_dispatch_launch(launch):
    document = _document(generated.ChioSignedCallerDispatchAuthorization, launch)
    parsed = generated.ChioSignedCallerDispatchAuthorization.model_validate(document)
    assert _jsonable(parsed) == document
    assert _jsonable(parsed.authorization) == document["authorization"]


@pytest.mark.parametrize("launch", _LAUNCHES)
@pytest.mark.parametrize("typed", [False, True], ids=["dict", "model"])
@respx.mock
async def test_report_mediated_execution_preserves_signed_authorization(launch, typed):
    authorization = _document(generated.ChioSignedCallerDispatchAuthorization, launch)
    report = _case("caller-delivery-report-explicit-null")
    response = {
        "status": "reconciled",
        "protocol": "chio.caller-delivery.v1",
        "execution_authorized": False,
        "receipt": _case("receipt-internal-origin"),
    }
    route = respx.post("http://127.0.0.1:9090/v1/caller/report").mock(
        return_value=httpx.Response(200, json=response)
    )
    presented = (
        generated.ChioSignedCallerDispatchAuthorization.model_validate(authorization)
        if typed else authorization
    )
    async with ChioClient("http://127.0.0.1:9090") as client:
        assert await client.report_mediated_execution(
            control_token="fixture-control", authorization=presented, report=report
        ) == response
    assert route.call_count == 1
    assert json.loads(route.calls.last.request.content) == {
        "protocol": "chio.caller-delivery.v1", "authorization": authorization, "report": report
    }
