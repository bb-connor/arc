"""Signed receipts returned by the sidecar must keep their original keys."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from chio_sdk.client import ChioClient
from chio_sdk.errors import ChioError
from chio_sdk.models import ChioReceipt

BASE = "http://127.0.0.1:9090"
REPO_ROOT = Path(__file__).resolve().parents[4]


def _load(relative: str) -> dict:
    return json.loads((REPO_ROOT / relative).read_text(encoding="utf-8"))


def _receipt_vector(case_id: str) -> dict:
    cases = _load("tests/bindings/vectors/receipt/v1.json")["cases"]
    return next(case for case in cases if case["id"] == case_id)


def _compact(value: object) -> str:
    return json.dumps(value, separators=(",", ":"))


def _inject_once(text: str, anchor: str, inserted: str) -> str:
    assert text.count(anchor) == 1, anchor
    return text.replace(anchor, anchor + inserted, 1)


def _forgeries(receipt_text: str, *, enclosing: str = "{}") -> list[tuple[str, str]]:
    """Duplicate keys inserted ahead of the signed values, so last-wins keeps them."""
    prefix, suffix = enclosing.split("{}")
    return [
        (
            "nested action.parameters",
            prefix
            + _inject_once(receipt_text, '"parameters":{', '"path":"/etc/shadow",')
            + suffix,
        ),
        (
            "nested metadata",
            prefix + _inject_once(receipt_text, '"metadata":{', '"surface":"forged",') + suffix,
        ),
        (
            "top-level receipt tool_name",
            prefix + receipt_text.replace("{", '{"tool_name":"shell_exec",', 1) + suffix,
        ),
    ]


def _advisory_report() -> dict:
    return {
        "signature_valid": True,
        "signer_trusted": True,
        "receipt_id_valid": True,
        "parameter_hash_valid": True,
        "receipt_kind": "advisory_evaluation",
        "boundary_class": "advisory_only",
        "trust_level": "advisory",
        "result": "allow",
        "authorized": False,
        "signer_key_hex": "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
        "ok": False,
    }


def _wrapper_template() -> str:
    return (
        '{"schema":"chio.sidecar.advisory-evaluation.v1","authorization":false,'
        '"authorizationBasis":"advisory_only","receipt":{}}'
    )


def test_handle_response_rejects_duplicate_keys_in_signed_receipt() -> None:
    receipt = _receipt_vector("allow_receipt")["receipt"]
    compact = _compact(receipt)
    assert ChioClient._handle_response(httpx.Response(200, content=compact.encode())) == receipt
    for label, forged in _forgeries(compact):
        assert json.loads(forged) == receipt, label
        with pytest.raises(ChioError) as error:
            accepted = ChioClient._handle_response(httpx.Response(200, content=forged.encode()))
            pytest.fail(f"duplicate keys in {label} were decoded: {accepted}")
        assert error.value.code == "INVALID_RESPONSE", label


def test_handle_response_rejects_protocol_primitives_raw_cases() -> None:
    corpus = _load("tests/bindings/fixtures/protocol-primitives-v1.json")
    names = []
    for case in corpus["raw_cases"]:
        text = case["instance_text"]
        with pytest.raises(ChioError) as error:
            ChioClient._handle_response(httpx.Response(200, content=text.encode()))
            pytest.fail(f"raw case {case['name']} was decoded")
        assert error.value.code == "INVALID_RESPONSE"
        names.append(case["name"])
    assert names == ["receipt-duplicate-id", "receipt-duplicate-parameter"]


def test_handle_response_keeps_numbers_and_strings_as_json_loads() -> None:
    for text in (
        '{"max":18446744073709551615,"min":-9223372036854775808,"wide":1180591620717411303424}',
        '{"zero":-0,"float_zero":-0.0,"exp":1e2,"padded":0.10,"small":1.5e-7,"big":1E+21}',
        '{"nested":[{"a":1.0},[2,[3.25]],{"b":{"c":null,"d":true}}]}',
        '{"text":"caf\\u00e9 \\u2028 \\ud83d\\ude00 tab\\t","raw":"café"}',
    ):
        decoded = ChioClient._handle_response(httpx.Response(200, content=text.encode()))
        assert repr(decoded) == repr(json.loads(text)), text


@respx.mock
async def test_advisory_evaluation_rejects_duplicate_keys_before_verification() -> None:
    receipt = _receipt_vector("advisory_evaluation_receipt")["receipt"]
    compact = _compact(receipt)
    verify_route = respx.post(f"{BASE}/v1/receipts/verify").mock(
        return_value=httpx.Response(200, json=_advisory_report())
    )
    evaluate_route = respx.post(f"{BASE}/v1/evaluate/advisory")
    arguments = {
        "capability_id": "cap-bindings-001",
        "tool_server": "srv-files",
        "tool_name": "file_read",
        "parameters": {"mode": "read", "path": "/workspace/docs/private.md"},
    }

    evaluate_route.mock(
        return_value=httpx.Response(
            200, content=_wrapper_template().replace("{}", compact).encode()
        )
    )
    async with ChioClient(BASE) as client:
        accepted = await client.evaluate_tool_call_advisory(**arguments)
    assert isinstance(accepted, ChioReceipt)
    assert verify_route.call_count == 1

    for label, forged in _forgeries(compact, enclosing=_wrapper_template()):
        assert json.loads(forged)["receipt"] == receipt, label
        verified_before = verify_route.call_count
        evaluate_route.mock(return_value=httpx.Response(200, content=forged.encode()))
        async with ChioClient(BASE) as client:
            with pytest.raises(ChioError) as error:
                forged_receipt = await client.evaluate_tool_call_advisory(**arguments)
                pytest.fail(
                    f"duplicate keys in {label} were accepted after "
                    f"{verify_route.call_count - verified_before} verification call(s): "
                    f"{forged_receipt!r}"
                )
        assert error.value.code == "INVALID_RESPONSE", label
        assert verify_route.call_count == verified_before, label
