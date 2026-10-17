import * as sdk from '../dist/index.js';

const encoder = new TextEncoder();

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function receiptBody(contentHash) {
  return {
    id: 'rcpt-workers-1',
    timestamp: 1710000200,
    capability_id: 'cap-workers-1',
    tool_server: 'srv-files',
    tool_name: 'file_read',
    action: {
      parameters: { mode: 'read', path: '/workspace/docs/roadmap.md' },
      parameter_hash: '035350b0e6a021a4c924a149111944945e94d12f6d8a5e24e4461e7009ebf929',
    },
    decision: { verdict: 'allow' },
    receipt_kind: 'mediated_decision',
    boundary_class: 'prevent',
    tool_origin: 'caller_executed',
    redaction_mode: 'none',
    content_hash: contentHash,
    policy_hash: '0'.repeat(64),
    evidence: [],
    trust_level: 'mediated',
    kernel_key: '0'.repeat(64),
  };
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/__chio_workers_smoke') {
      return sdk.default.fetch(request);
    }
    if (url.pathname !== '/__chio_workers_roundtrip') {
      return new Response('not found', { status: 404 });
    }

    const seedA = await sdk.mint_signing_seed_hex();
    const seedB = await sdk.mint_signing_seed_hex();
    const canonical = encoder.encode('{"shown":"to-the-human"}');
    const body = receiptBody(await sha256Hex(canonical));
    const input = JSON.stringify({ body, canonical_content: [...canonical] });

    const receipt = await sdk.sign_receipt(input, seedA);
    const envelope = encoder.encode(JSON.stringify(receipt));
    const stored = JSON.parse(JSON.stringify(receipt));
    const trusted = await sdk.verify_receipt(envelope, receipt.kernel_key);
    const untrusted = await sdk.verify_receipt(envelope);

    return Response.json({ seedA, seedB, kernelKey: receipt.kernel_key, parameters: stored.action.parameters, metadata: stored.metadata, trusted, untrusted });
  },
};
