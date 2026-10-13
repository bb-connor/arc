"""Native response state preservation is independent of advisory category precedence."""
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from chio_sdk.recovery import RecoveryClient
from chio_sdk.recovery_errors import RecoveryError
from chio_sdk.recovery_host import RecoveryHostOutcome, RecoveryHostSession

ROOT = Path(__file__).resolve().parents[4]
CASES = json.loads((ROOT / "sdks/tests/recovery-response-states.json").read_text())
COMMAND = b'{"command":{"kind":"inspect_workflow","workflow_id":"workflow"},"command_id":"command","schema":"chio.recovery.command.v1","version":1}'


def test_examples_cover_every_native_wire_state():
    schema = json.loads((ROOT / "spec/schemas/chio-wire/v1/recovery/command-response.schema.json").read_text())
    properties = schema["properties"]
    effects = {schema["$defs"][row["$ref"].rsplit("/", 1)[1]]["properties"]["kind"]["const"]
               for row in properties["effect"]["oneOf"]}
    assert {effect["kind"] for effect in CASES["effects"]} == effects
    assert set(CASES["controls"]) == set(properties["control"]["enum"])
    assert {release["kind"] for release in CASES["releases"]} == {
        row["properties"]["kind"]["const"] for row in properties["release"]["oneOf"]}


@pytest.mark.parametrize("effect", CASES["effects"], ids=lambda value: value["kind"])
@pytest.mark.parametrize("control", CASES["controls"])
@pytest.mark.parametrize("release", CASES["releases"], ids=lambda value: value["kind"])
def test_client_and_host_retain_orthogonal_native_states(effect, control, release):
    # The Cartesian product exercises decoding/projection, not native reachability.
    native = {"command_id": "command", "workflow_id": "workflow", "revision": 1,
              "effect": effect, "control": control, "release": release}
    async def run():
        wires = []
        def serve(request):
            wires.append(json.loads(request.content))
            return httpx.Response(200, json={"status": native})
        transport = httpx.MockTransport(serve)
        client = RecoveryClient("http://localhost:1", transport=transport)
        try:
            response = await client.execute("synthetic-capability", COMMAND)
            assert response.status.model_dump(mode="json", by_alias=True) == native
        finally:
            await client.aclose()
        session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
                                      {"inspect": COMMAND}, transport=transport)
        projection = (await session.execute("inspect")).as_dict()
        assert projection["effect"] == effect["kind"]
        assert projection["control"] == control
        assert projection["release"] == release["kind"]
        assert set(projection) == {"category", "command_id", "workflow_id", "effect", "control", "release"}
        assert len(wires) == 2 and session.attempts == 1
        assert all(wire["command"].encode() == COMMAND for wire in wires)
    asyncio.run(run())


@pytest.mark.parametrize("case", CASES["errors"], ids=lambda value: value["code"])
def test_fixed_errors_retain_exact_code_through_host_projection(case):
    async def run():
        calls = []
        def serve(request):
            calls.append(request)
            return httpx.Response(case["status"], text=case["code"])
        transport = httpx.MockTransport(serve)
        client = RecoveryClient("http://localhost:1", transport=transport)
        try:
            with pytest.raises(RecoveryError) as captured:
                await client.execute("synthetic-capability", COMMAND)
            assert captured.value.code.value == case["code"]
        finally:
            await client.aclose()
        session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
                                      {"inspect": COMMAND}, transport=transport)
        projection = (await session.execute("inspect")).as_dict()
        assert projection["error_code"] == case["code"]
        assert set(projection) == {"category", "error_code"}
        assert len(calls) == 2 and session.attempts == 1
    asyncio.run(run())


@pytest.mark.parametrize("body", ["secret-upstream-diagnostic", "recovery.authority_denied",
                                 "recovery.restart_required\n"])
def test_untrusted_error_bodies_never_become_framework_metadata(body):
    async def run():
        session = RecoveryHostSession("http://localhost:1", "synthetic-capability",
            {"inspect": COMMAND}, transport=httpx.MockTransport(
                lambda _: httpx.Response(503, text=body)))
        assert (await session.execute("inspect")).as_dict() == {
            "category": "refused", "error_code": "recovery.refused_or_unavailable"}
    asyncio.run(run())


@pytest.mark.parametrize("field", ["effect", "control", "release", "error_code"])
def test_public_outcome_rejects_open_diagnostic_fields(field):
    with pytest.raises(ValueError):
        RecoveryHostOutcome("refused", **{field: "secret-diagnostic"})


def test_legacy_outcome_constructor_does_not_invent_native_state():
    assert RecoveryHostOutcome("refused").as_dict() == {"category": "refused"}

