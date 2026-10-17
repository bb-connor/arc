import * as sdk from '../dist/index.js';

const encoder = new TextEncoder();

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// Hand-written JSON text: a JS object literal cannot carry an own `__proto__`
// key or a u64::MAX integer.
const PARAMETERS_CANONICAL =
  '{"__proto__":{"x":null},"mode":"read","nest":{"a":null},"path":"/workspace/docs/roadmap.md"}';
const METADATA = '{"__proto__":{"polluted":"yes"},"big":18446744073709551615,"k":{"n":null}}';

async function signingInput(canonical) {
  const contentHash = await sha256Hex(canonical);
  const parameterHash = await sha256Hex(encoder.encode(PARAMETERS_CANONICAL));
  return (
    '{"body":{"id":"rcpt-workers-1","timestamp":1710000200,"capability_id":"cap-workers-1",' +
    '"tool_server":"srv-files","tool_name":"file_read",' +
    `"action":{"parameters":${PARAMETERS_CANONICAL},"parameter_hash":"${parameterHash}"},` +
    '"decision":{"verdict":"allow"},"receipt_kind":"mediated_decision","boundary_class":"prevent",' +
    '"tool_origin":"caller_executed","redaction_mode":"none",' +
    `"content_hash":"${contentHash}","policy_hash":"${'0'.repeat(64)}","evidence":[],` +
    `"metadata":${METADATA},"trust_level":"mediated","kernel_key":"${'0'.repeat(64)}"},` +
    `"canonical_content":[${[...canonical].join(',')}]}`
  );
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
    const signed = await sdk.sign_receipt(await signingInput(canonical), seedA);

    // The stored form is the signer's canonical text, passed through storage as-is.
    const stored = JSON.parse(JSON.stringify({ value: signed.receipt_json })).value;
    const kernelKey = signed.receipt.kernel_key;
    const trusted = await sdk.verify_receipt(stored, kernelKey);
    const untrusted = await sdk.verify_receipt(stored);
    const tampered = await sdk.verify_receipt(stored.replace('"read"', '"write"'), kernelKey);

    const view = signed.receipt;
    return Response.json({
      seedA,
      seedB,
      kernelKey,
      stored,
      trusted,
      untrusted,
      tampered,
      view: {
        metadataProtoIsObjectPrototype: Object.getPrototypeOf(view.metadata) === Object.prototype,
        metadataOwnProto: Object.hasOwn(view.metadata, '__proto__'),
        parametersOwnProto: Object.hasOwn(view.action.parameters, '__proto__'),
        inheritedPollution: ({}).polluted ?? null,
        nestedNull: view.metadata.k.n,
        bigIsExact: BigInt(view.metadata.big) === 18446744073709551615n,
      },
    });
  },
};
