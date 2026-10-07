"""Raw recovery ingress refuses ambiguity before generated JSON validation."""
from __future__ import annotations

import copy
import json
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from chio_sdk._generated.recovery.confined_limits_schema import ConfinedLimitsV1
from chio_sdk._generated.recovery.recovery_setup_probe_schema import RecoverySetupProbeV1
from chio_sdk.recovery import RecoveryClient

ROOT = Path(__file__).resolve().parents[4]
POSITIVE = json.loads((ROOT / "spec/vectors/recovery/v1/authority-positive.json").read_bytes())
PRODUCT = json.loads((ROOT / "spec/vectors/recovery/v1/product-contracts.json").read_bytes())["cases"]
PROBE = next(case["body"] for case in PRODUCT if case["name"] == "signed-recovery-setup-probe.schema.json")


def receipt_wire(field: str, payload: str, *, result: str = "null") -> bytes:
    value = copy.deepcopy(POSITIVE["command_result"])
    receipt = value["original_response"]["receipt"]
    target = receipt["action"] if field == "parameters" else receipt
    target[field] = "receipt-json-placeholder"
    value["original_response"]["result"] = "opaque-json-placeholder"
    source = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    source = source.replace('"receipt-json-placeholder"', payload, 1)
    return source.replace('"opaque-json-placeholder"', result, 1).encode()


async def decode_response(wire: bytes):
    calls = []
    client = RecoveryClient("http://localhost:1", transport=httpx.MockTransport(
        lambda request: calls.append(request) or httpx.Response(200, content=wire)))
    try:
        return await client.execute("capability-canary", b"{}")
    finally:
        await client.aclose()
        assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("revision", ['"revision":1,"revision":1', '"revision":-0', '"revision":1e0', '"revision":1.0'])
async def test_response_rejects_raw_counter_tokens_and_duplicate_members(revision):
    source = ('{"status":{"command_id":"command","workflow_id":"workflow",' + revision
              + ',"control":"active","effect":{"kind":"never_admitted"},"release":{"kind":"not_available"}}}')
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(source.encode())


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["duplicate body", "negative zero", "exponent integer", "fractional integer", "boolean domain version"])
async def test_setup_qualify_rejects_raw_proof_before_transport(mutation):
    source = json.dumps(PROBE, sort_keys=True, separators=(",", ":"))
    if mutation == "duplicate body":
        source = '{"body":' + json.dumps(PROBE["body"], sort_keys=True, separators=(",", ":")) + ',' + source[1:]
    elif mutation == "boolean domain version":
        changed = source.replace('"domain_version":1', '"domain_version":true', 1)
        assert changed != source
        source = changed
    else:
        token = {"negative zero": "-0", "exponent integer": "1e3", "fractional integer": "1000.0"}[mutation]
        changed = source.replace('"issued_at_unix_ms":1000', '"issued_at_unix_ms":' + token, 1)
        assert changed != source
        source = changed
    calls = []
    client = RecoveryClient("http://localhost:1", transport=httpx.MockTransport(
        lambda request: calls.append(request) or httpx.Response(503, text="recovery.unavailable")))
    try:
        with pytest.raises(ValueError, match=r"^recovery\.invalid_command$"):
            await client.setup_qualify("capability-canary", source.encode())
        assert calls == []
    finally:
        await client.aclose()


@pytest.mark.parametrize("version", [True, 1.0])
def test_typed_setup_probe_refuses_equal_non_integer_versions(version):
    RecoverySetupProbeV1.model_validate_json(json.dumps(PROBE["body"]), strict=True)
    changed = copy.deepcopy(PROBE["body"])
    changed["domain_version"] = version
    with pytest.raises(ValidationError):
        RecoverySetupProbeV1.model_validate(changed, strict=True)
    with pytest.raises(ValidationError):
        RecoverySetupProbeV1.model_validate_json(json.dumps(changed), strict=True)


@pytest.mark.parametrize("field", ["launches", "tool_calls", "model_calls"])
def test_typed_confinement_limits_refuse_boolean_literal_counters(field):
    value = {
        "children": 1, "depth": 1, "input_bytes": 1024, "diagnostic_bytes": 1024,
        "launches": 1, "tool_calls": 0, "model_calls": 0, "wall_clock_ms": 1000,
    }
    ConfinedLimitsV1.model_validate_json(json.dumps(value), strict=True)
    value[field] = bool(value[field])
    with pytest.raises(ValidationError):
        ConfinedLimitsV1.model_validate_json(json.dumps(value), strict=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["metadata", "parameters"])
async def test_numeric_literal_rules_preserve_arbitrary_receipt_and_tool_boolean_values(field):
    payload = '{"domain_version":true,"version":false,"max_values":true}'
    response = await decode_response(receipt_wire(field, payload, result=payload))
    retained = response.original_response.receipt
    receipt_value = retained.action.parameters if field == "parameters" else retained.metadata
    expected = {"domain_version": True, "version": False, "max_values": True}
    assert receipt_value == expected
    assert response.original_response.result == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["metadata", "parameters"])
async def test_response_preserves_signed_receipt_json_with_large_lossless_tool_result(field):
    signed = '{"confidence":0.5,"delta":-1,"nested":[-9007199254740991,9007199254740991,1e-7],"unicode":"日本😀"}'
    opaque = ('{"fraction":0.123456789012345678901,"huge":9007199254740993,"negative":-9007199254740993,'
              '"nested":[1e309,-0,1.0,1e0],"text":"' + "a" * 70000 + '","unicode":"日本😀"}')
    wire = receipt_wire(field, signed, result=opaque)
    assert 65536 < len(wire) <= 262144
    response = await decode_response(wire)
    receipt = response.original_response.receipt
    retained = receipt.action.parameters if field == "parameters" else receipt.metadata
    assert retained == {"confidence": 0.5, "delta": -1, "nested": [-9007199254740991, 9007199254740991, 1e-7], "unicode": "日本😀"}
    result = response.original_response.result
    assert type(result["huge"]) is int and result["huge"] == 9007199254740993
    assert type(result["negative"]) is int and result["negative"] == -9007199254740993
    assert result["fraction"].source == "0.123456789012345678901"
    assert result["fraction"].to_decimal() == Decimal("0.123456789012345678901")
    assert [value.source for value in result["nested"]] == ["1e309", "-0", "1.0", "1e0"]
    assert result["text"] == "a" * 70000 and result["unicode"] == "日本😀"
    with pytest.raises(TypeError):
        json.dumps(result)
    with pytest.raises(ValueError):
        response.model_dump_json()


@pytest.mark.asyncio
async def test_response_refuses_implicit_tool_number_rounding_serialization():
    response = await decode_response(receipt_wire("metadata", '{"delta":-1}', result='{"real":0.123456789012345678901}'))
    with pytest.raises(TypeError):
        json.dumps(response.original_response.result)
    with pytest.raises(ValueError):
        response.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize("token", ["9" * 5000, "1e" + "9" * 5000], ids=["large integer", "large exponent"])
async def test_opaque_numeric_tokens_do_not_inherit_pydantic_conversion_limits(token):
    response = await decode_response(receipt_wire("metadata", '{"delta":-1}', result=token))
    assert response.original_response.result.source == token


@pytest.mark.asyncio
async def test_response_accepts_exact_full_byte_ceiling_for_opaque_result():
    empty = receipt_wire("metadata", '{"delta":-1}', result='""')
    wire = receipt_wire("metadata", '{"delta":-1}', result='"' + "a" * (262144 - len(empty)) + '"')
    assert len(wire) == 262144
    response = await decode_response(wire)
    assert response.original_response.result == "a" * (262144 - len(empty))


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["metadata", "parameters"])
@pytest.mark.parametrize("token", ["-0", "1.0", "1e0", "9007199254740992", "-9007199254740992", "1e309", "1e-400", "0.123456789012345678901", "0.12345678901234567"])
async def test_response_rejects_unsafe_or_precision_losing_signed_receipt_numbers(field, token):
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(receipt_wire(field, token))


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["metadata", "parameters"])
@pytest.mark.parametrize("payload", ['{"delta":-1,"delta":0.5}', '{"delta":-1,"\\u0064elta":0.5}', '"\\ud800"', '{"\\udc00":0.5}', "NaN", "Infinity"])
async def test_response_rejects_duplicate_unicode_and_non_json_receipt_values(field, payload):
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(receipt_wire(field, payload))


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["metadata", "parameters"])
@pytest.mark.parametrize("budget", ["depth", "entries", "nodes", "strings", "escaped strings", "numeric bytes"])
async def test_response_charges_foundation_limits_to_signed_receipt_json(field, budget):
    payload = {
        "depth": "[" * 17 + "true" + "]" * 17,
        "entries": "[" + ",".join("null" for _ in range(257)) + "]",
        "nodes": json.dumps([[None] * 256 for _ in range(17)], separators=(",", ":")),
        "strings": '"' + "a" * 32769 + '"',
        "escaped strings": '"' + "\\u0061" * 6000 + '"',
        "numeric bytes": json.dumps([[-9007199254740991] * 256 for _ in range(14)], separators=(",", ":")),
    }[budget]
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(receipt_wire(field, payload))


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["metadata", "parameters"])
async def test_response_accepts_bounded_signed_receipt_integer_arrays(field):
    payload = json.dumps([[-9007199254740991] * 256 for _ in range(13)], separators=(",", ":"))
    response = await decode_response(receipt_wire(field, payload))
    receipt = response.original_response.receipt
    retained = receipt.action.parameters if field == "parameters" else receipt.metadata
    assert retained == [[-9007199254740991] * 256 for _ in range(13)]


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["metadata", "parameters"])
@pytest.mark.parametrize("token", ["-9007199254740991", "9007199254740991", "-1.25", "0.000001", "1e-7", "0.12345678901234566", "5e-324"])
async def test_response_accepts_canonical_signed_receipt_scalar_boundaries(field, token):
    response = await decode_response(receipt_wire(field, token))
    receipt = response.original_response.receipt
    retained = receipt.action.parameters if field == "parameters" else receipt.metadata
    assert retained == json.loads(token)
    if "." not in token and "e" not in token:
        assert type(retained) is int


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", ['{"dup":1,"dup":2}', '"\\ud800"', "NaN", "Infinity", "[" * 63 + "0" + "]" * 63])
async def test_opaque_result_keeps_full_syntax_unicode_and_depth_bounds(payload):
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(receipt_wire("metadata", '{"delta":-1}', result=payload))


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", ["[" + ",".join("0" for _ in range(5000)) + "]", "[" * 62 + "-1.25e+2" + "]" * 62])
async def test_opaque_result_does_not_inherit_foundation_container_or_depth_limits(payload):
    response = await decode_response(receipt_wire("metadata", '{"delta":-1}', result=payload))
    assert response.original_response.result is not None


@pytest.mark.asyncio
async def test_invalid_utf8_response_is_a_closed_category():
    wire = receipt_wire("metadata", '"invalid-utf8-marker"').replace(b"invalid-utf8-marker", b"\xff")
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(wire)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ['"timestamp":1710000000', '"revision":13', '"operation_version":8'])
@pytest.mark.parametrize("token", ["-0", "-1", "0.5", "1e0", "9007199254740992"])
async def test_receipt_json_does_not_relax_typed_unsigned_fields(field, token):
    wire = receipt_wire("metadata", '{"delta":-1,"confidence":0.5}')
    if field.startswith('"timestamp"'):
        timestamp = POSITIVE["command_result"]["original_response"]["receipt"]["timestamp"]
        field = '"timestamp":' + str(timestamp)
    replacement = field.split(":")[0] + ":" + token
    changed = wire.replace(field.encode(), replacement.encode(), 1)
    assert changed != wire
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(changed)


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["missing result", "unknown response field", "unknown receipt field"])
async def test_response_projection_preserves_closed_shape_refusals(mutation):
    value = copy.deepcopy(POSITIVE["command_result"])
    if mutation == "missing result":
        del value["original_response"]["result"]
    elif mutation == "unknown response field":
        value["original_response"]["unknown"] = True
    else:
        value["original_response"]["receipt"]["unknown"] = True
    with pytest.raises(RuntimeError, match=r"^recovery\.invalid_response$"):
        await decode_response(json.dumps(value, separators=(",", ":")).encode())


def test_lossless_number_conversion_is_explicit_and_exact():
    from chio_sdk import LosslessJsonNumber
    number_type = LosslessJsonNumber
    value = number_type("1e-3")
    assert value.source == "1e-3" and value.to_decimal() == Decimal("0.001")
    assert value.to_float() == 0.001
    assert number_type("18446744073709551615").to_int() == 18446744073709551615
    for token in ["1e309", "0.123456789012345678901", "9007199254740993"]:
        with pytest.raises(ValueError):
            number_type(token).to_float()
    with pytest.raises(ValueError):
        value.to_int()
    with pytest.raises((AttributeError, TypeError)):
        value.source = "changed"
    with pytest.raises(TypeError):
        json.dumps(value)
    for source in ["NaN", "Infinity", "-Infinity", "1\n", "01", "+1", "1e", "1" * 262145]:
        with pytest.raises(ValueError):
            number_type(source)
