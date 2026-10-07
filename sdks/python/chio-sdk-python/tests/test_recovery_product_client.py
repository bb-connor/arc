"""Product transport preserves native identity and does not infer authority."""
import json
from pathlib import Path
import httpx
import pytest
from chio_sdk.recovery import RecoveryClient

ROOT = Path(__file__).resolve().parents[4]
CASES = json.loads((ROOT / 'spec/vectors/recovery/v1/product-contracts.json').read_text())['cases']
REPORT = next(v['body'] for v in CASES if v['schema'] == 'decision-report.schema.json' and v['schema_valid'] and v['valid'])
PROPOSAL = next(v['body'] for v in CASES if v['schema'] == 'policy-maintenance-proposal.schema.json' and v['schema_valid'] and v['valid'])

@pytest.mark.asyncio
async def test_product_client_canonical_report_proposal_and_no_retry():
    requests = []
    def handle(request):
        data = json.loads(request.content); requests.append((request.url.path, data))
        if request.url.path.endswith('reports/read'):
            body = REPORT
        else:
            body = json.loads(data.get('report', data.get('proposal', '{}')))
        if 'reports' in request.url.path:
            reply = {'domain_version': 1, 'id': 'retained-report', 'digest': [7] * 32, 'report': body,
                     'label': {'kind': 'known', 'owners': {}, 'compartments': []}, 'influence': {'commitment': [8] * 32, 'externally_influenced': True, 'unknown': True}}
        else:
            reply = {'domain_version': 1, 'digest': [9] * 32, 'proposal': body,
                     'label': {'kind': 'known', 'owners': {}, 'compartments': []}, 'influence': {'commitment': [10] * 32, 'externally_influenced': True, 'unknown': True}}
        return httpx.Response(200, json=reply)
    client = RecoveryClient('https://host.example', transport=httpx.MockTransport(handle))
    try:
        canonical = json.dumps(REPORT, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        first = await client.submit_report('capability-canary', 'stable-report-command', canonical)
        assert first.id.root == 'retained-report'
        second = await client.read_report('capability-canary', first.id.root)
        assert second.report.model_dump(mode='json') == REPORT
        result = await client.propose_policy('capability-canary', json.dumps(PROPOSAL).encode())
        assert result.proposal.model_dump(mode='json') == PROPOSAL
        assert len(requests) == 3
        assert requests[0][1]['report'] == canonical.decode()
        assert requests[0][1]['command_id'] == 'stable-report-command'
    finally:
        await client.aclose()

@pytest.mark.asyncio
@pytest.mark.parametrize('reply', [httpx.Response(503, text='private-error-canary'), httpx.Response(200, json={})])
async def test_product_refusal_never_retries_or_exposes_raw_error(reply):
    calls = []
    client = RecoveryClient('https://host.example', transport=httpx.MockTransport(lambda request: calls.append(request) or reply))
    try:
        with pytest.raises(RuntimeError, match='^recovery\\.') as error:
            await client.submit_report('private-capability-canary', 'stable-report-command', json.dumps(REPORT).encode())
        assert 'canary' not in str(error.value)
        assert len(calls) == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize('route', ['report', 'policy'])
async def test_native_product_view_retains_large_valid_audience_labels(route):
    # The native product projection fixture uses the same 255 shared readers
    # and owner, with each shared reader at its decoded 256-byte ceiling.
    # The complete protected record and public view fit the native 256 KiB cap.
    readers = [f'reader-{index:03}-' + '"' * 245 for index in range(255)]
    readers.append('owner-000')
    label = {'kind': 'known', 'owners': {'owner-000': sorted(readers)}, 'compartments': []}
    influence = {'commitment': [8] * 32, 'externally_influenced': True, 'unknown': True}
    if route == 'report':
        from chio_sdk._generated.recovery.decision_report_view_schema import DecisionReportViewV1
        model = DecisionReportViewV1
        reply = {'domain_version': 1, 'id': 'retained-report', 'digest': [7] * 32,
                 'report': REPORT, 'label': label, 'influence': influence}
    else:
        from chio_sdk._generated.recovery.policy_maintenance_view_schema import PolicyMaintenanceViewV1
        model = PolicyMaintenanceViewV1
        reply = {'domain_version': 1, 'digest': [9] * 32, 'proposal': PROPOSAL,
                 'label': label, 'influence': influence}
    wire = json.dumps(reply, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    assert 65536 < len(wire) <= 262144
    # Prove this is a valid public DTO before testing the transport reader.
    expected = model.model_validate_json(wire, strict=True)
    assert expected.label.model_dump(mode='json') == label
    calls = []
    client = RecoveryClient('https://host.example', transport=httpx.MockTransport(
        lambda request: calls.append(request) or httpx.Response(200, content=wire)))
    try:
        if route == 'report':
            actual = await client.read_report('capability-canary', 'retained-report')
        else:
            actual = await client.propose_policy('capability-canary', json.dumps(PROPOSAL).encode())
        assert actual.label.model_dump(mode='json') == label
        assert len(calls) == 1
    finally:
        await client.aclose()


@pytest.mark.parametrize('mutation', ['duplicate', 'fraction', 'negative zero', 'unsafe integer', 'unicode', 'trailing'])
def test_large_product_view_reader_refuses_ambiguous_raw_metadata(mutation):
    from chio_sdk.recovery_wire import read_product_view_wire

    text = '"' + 'x' * 70000 + '"'
    source = '{"text":' + text + ',"version":1}'
    assert read_product_view_wire(source.encode())[0]['version'].source == '1'
    if mutation == 'duplicate':
        source = source[:-1] + ',"version":1}'
    elif mutation == 'unicode':
        source = source[:-1] + ',"invalid":"\\ud800"}'
    elif mutation == 'trailing':
        source += 'true'
    else:
        token = {'fraction': '1.0', 'negative zero': '-0', 'unsafe integer': '9007199254740992'}[mutation]
        source = source.replace('"version":1', '"version":' + token)
    with pytest.raises((ValueError, UnicodeError)):
        read_product_view_wire(source.encode())


def test_product_view_profile_retains_native_allocation_caps_and_other_route_limits():
    from chio_sdk.recovery_wire import read_product_view_wire, read_response_wire

    for refused in [b'"' + b'x' * 262144 + b'"', b'[' * 65 + b'null' + b']' * 65]:
        with pytest.raises(ValueError):
            read_product_view_wire(refused)
    assert read_product_view_wire(b'[' * 64 + b'null' + b']' * 64)
    # Other responses retain their foundation limits, even when their global
    # HTTP body would fit the larger product-view delivery ceiling.
    large = b'"' + b'x' * 70000 + b'"'
    with pytest.raises(ValueError):
        read_response_wire(large)
