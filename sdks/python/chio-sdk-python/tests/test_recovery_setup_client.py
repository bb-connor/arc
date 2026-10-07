"""Setup SDK carries exact Rust proof bytes and never decides readiness."""
import json
from pathlib import Path
import httpx
import pytest
from chio_sdk.recovery import RecoveryClient

CASES = json.loads((Path(__file__).resolve().parents[4] / "spec/vectors/recovery/v1/product-contracts.json").read_text())["cases"]
PROBE = next(v["body"] for v in CASES if v["name"] == "signed-recovery-setup-probe.schema.json")
REPORT = next(v["body"] for v in CASES if v["name"] == "signed-recovery-setup-report.schema.json")

@pytest.mark.asyncio
async def test_setup_transports_exact_probe_and_one_qualification_request():
    calls = []
    def respond(request):
        body = json.loads(request.content); calls.append((request.url.path, body))
        return httpx.Response(200, json=PROBE if request.url.path.endswith("probe") else REPORT)
    client = RecoveryClient("https://host.example", transport=httpx.MockTransport(respond))
    proof = json.dumps(PROBE, sort_keys=True, separators=(",", ":")).encode()
    try:
        assert (await client.setup_probe("cap", "self-test")).model_dump(mode="json") == PROBE
        assert (await client.setup_qualify("cap", proof)).model_dump(mode="json") == REPORT
        assert calls[0] == ("/v1/recovery/setup/probe", {"capability": "cap", "workflow_id": "self-test"})
        assert calls[1][1]["probe"].encode() == proof
        assert len(calls) == 2
    finally:
        await client.aclose()

@pytest.mark.asyncio
async def test_setup_invalid_proof_refuses_before_network():
    calls = []
    client = RecoveryClient("https://host.example", transport=httpx.MockTransport(lambda r: calls.append(r)))
    try:
        for proof in [b"\xff", b"x" * 32769]:
            with pytest.raises(ValueError, match="^recovery\\."):
                await client.setup_qualify("cap", proof)
        assert calls == []
    finally:
        await client.aclose()
