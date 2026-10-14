"""explanation SDK advice has its own wire contract and cannot return a full report."""
import json
from pathlib import Path
import httpx
import pytest
from chio_sdk.recovery import RecoveryClient
POSITIVE=json.loads((Path(__file__).resolve().parents[4]/'spec/vectors/recovery/v1/explanation-positive.json').read_text())
@pytest.mark.asyncio
async def test_explanation_view_is_one_request_with_no_full_basis():
    calls=[]
    async def response(request):
        calls.append(request)
        return httpx.Response(200,json=POSITIVE['view'])
    client=RecoveryClient('https://host.example',transport=httpx.MockTransport(response))
    try:
        view=await client.explain('protected-capability','workflow')
        assert view.body.projection.summary.value=='alternatives_under_snapshot'
        assert len(calls)==1 and calls[0].url.path=='/v1/recovery/explain'
        assert 'snapshot_digest' not in view.body.model_dump()
    finally:
        await client.aclose()
@pytest.mark.asyncio
@pytest.mark.parametrize('reply',[POSITIVE['report'],dict(POSITIVE['view'],private_basis='private-canary')])
async def test_full_report_or_leaking_extra_fields_are_refused_without_retry(reply):
    calls=[]
    async def response(request):
        calls.append(request)
        return httpx.Response(200,json=reply)
    client=RecoveryClient('https://host.example',transport=httpx.MockTransport(response))
    try:
        with pytest.raises(RuntimeError,match='^recovery.invalid_response$'):
            await client.explain('protected-capability','workflow')
        assert len(calls)==1
    finally:
        await client.aclose()
