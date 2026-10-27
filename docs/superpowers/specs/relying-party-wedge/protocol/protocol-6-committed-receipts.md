<!--
Target: spec/PROTOCOL.md
Insertion point: new unnumbered subsection after "### Receipt Identity And DAG", before "### 6.1 Receipt Semantics And Decisions".
Move the text below this comment into place unchanged; drop this comment.
-->

### Committed Receipts And Disclosure

Status: specified, not implemented. Implementations emit and accept the formats in the sections this one names until this line is removed.

Sections in force until then: the section 6 receipt field table, "WYSIWYS Signing Invariant", 6.4 and 14.

`chio.receipt.v1` has one format: committed. Arguments and results appear in a
receipt as salted commitments. Plaintext appears only for fields a signed root
policy (section 5.6.4) authorizes for that tool. This applies to every
receipt producer.

Body changes:

1. `action.parameters` and `action.parameter_hash` are replaced by
   `action.parameter_commitment` and optional `action.parameters_inline`.
2. `content_hash` is replaced by `content_commitment` and optional
   `result_inline`. The signer recomputes the commitment from the content
   preimage and the salt inside its own trust boundary, so the WYSIWYS
   invariant holds.
3. `redaction_mode` is replaced by a `disclosure` block.
4. A top-level `authority` block is present whenever the exercised capability
   carries `root_anchor`.
5. A receipt with an `authority` block omits `tenant_id`; signing fails
   otherwise. The tenant is carried only as the delegation context commitment
   and the unsigned tenant tag (section 5.6.8).

```json
{
  "action": {
    "parameter_commitment": { "alg": "sha256-salted", "value": "sha256:9b1f...", "salt_ref": "params" },
    "parameters_inline": { "query": "acme renewal" }
  },
  "content_commitment": { "alg": "sha256-salted", "value": "sha256:44aa...", "salt_ref": "content" },
  "disclosure": {
    "policy_digest": "sha256:aa90...",
    "parameter_inline_fields": ["/query"],
    "result_inline_fields": []
  },
  "authority": {
    "root_anchor": { "kind": "oauth_id_jag", "context_digest": "sha256:...", "root_policy_digest": "sha256:...", "anchored_at": 1792234795, "assertion_exp": 1792235090 },
    "chain_digest": "sha256:c0de...",
    "chain_depth": 0,
    "holder": "caller"
  }
}
```

Commitments:

- `value = SHA-256(domain || salt || preimage)`, where `domain` is
  `chio.receipt.parameters.v1\0` or `chio.receipt.content.v1\0`, `salt` is 32
  bytes drawn per receipt per field from the producer's host RNG, and
  `preimage` is the canonical preimage: RFC 8785 canonical arguments for
  parameters, the WYSIWYS content preimage for outputs. The salt is fixed
  length, so the concatenation is unambiguous.
- A verifier selects the domain from the commitment's position in the receipt,
  never from the opening.
- The content preimage has three forms. A value output uses the canonical JSON
  of the result. An empty output (no result) uses the zero-length byte string,
  so its commitment is `SHA-256(domain || salt)`. A stream output uses the
  concatenation of the lowercase hex SHA-256 of each canonical chunk; a stream
  with no chunks is an empty output. A verifier derives the preimage from its
  own copy of the output (or from the absence of one) and never from an
  opening's `payload`: a `payload: null` opening is salt only and supplies no
  preimage, so the literal `null` is never an output preimage. Per-chunk
  digests are not written to any signed field, metadata or evidence, because
  they are unsalted.
- Salts are never in the signed body. They are returned to the producer's host
  with the signed receipt and written to the disclosure store keyed by
  `(receipt_id, salt_ref)` where a store exists.
- `chain_digest = SHA-256("chio.receipt.chain-digest.v1\0" || canonical_json([root, ..., parent, leaf]))`
  over the full signed tokens.
- Decoding is strict (section 4.5): an unknown member in a commitment,
  `disclosure`, `authority` or its `root_anchor` rejects the receipt at
  decode. `parameters_inline` and `result_inline` are opaque caller data.

Disclosure:

- The root policy's `disclosure.default` is `committed`, the only allowed
  value.
- `tools.<server/tool>.parameters.inline_fields` and
  `.result.inline_fields` are RFC 6901 JSON pointers. Only listed fields may
  appear in plaintext in a receipt for that tool. A tool not listed is fully
  committed.
- Inline fields are copied into `action.parameters_inline` or `result_inline`
  as a sparse object containing only those pointers. The commitments still
  cover the full arguments and the full result.
- `disclosure.policy_digest` is required when either inline list is non-empty
  and must name the loaded root policy. The inline lists must equal the
  policy's lists for that tool. A receipt with no inline fields omits
  `policy_digest`, and both lists are empty.
- A verifier holding the policy checks that every inline field was authorized
  and, when openings are available, that each inline value matches the opened
  commitment.
- Producers without a root policy emit fully committed receipts.
- Guard `evidence` entries and `metadata` must not contain argument or result
  values outside the inline fields. Guards declare which evidence fields are
  safe under committed disclosure; undeclared fields are dropped before
  signing. A guard that marks a field required and unsafe fails at load.

Signing failures (the call denies):

- `parameters_inline` or `result_inline` contains a pointer the root policy
  does not authorize for that tool;
- an inline list is non-empty without a root policy;
- a receipt with `authority` carries `tenant_id`;
- salt generation fails.

A disclosure-store write failure after signing still appends the receipt,
because receipts are authority. The opening is marked lost, an operator alert
fires, and that commitment stays permanently hiding.

#### `chio.receipt-disclosure.v1`

An unsigned, self-verifying opening:

```json
{
  "schema": "chio.receipt-disclosure.v1",
  "receipt_id": "5a1f...c4",
  "openings": [
    { "salt_ref": "params", "salt": "b64u:...", "payload": null },
    { "salt_ref": "content", "salt": "b64u:...", "payload": { "...": "canonical result" } },
    { "salt_ref": "anchor.sub", "salt": "b64u:...", "payload": "00u1abcd..." }
  ]
}
```

- An opening with a `salt` and `payload: null` is valid only in the caller
  copy (WIRE_PROTOCOL section 3.6), in `caller` bundles, and in a PDP response
  to the enforcement point that sent the arguments (section 6.1).
- A verifier opens a commitment by recomputing it. A mismatch marks that field
  `rejected` and the receipt as tampered disclosure.
- A verifier rejects an opening document in which the same `salt` value appears
  for more than one `salt_ref`, and marks the receipt as tampered disclosure. A
  producer draws a fresh salt for every field.
- Decoding is strict (section 4.5): an unknown member in the document or in
  any opening rejects it. `payload` is an opaque value.
- Deleting a receipt's openings from the disclosure store makes its
  commitments permanently hiding and leaves the signed receipt valid.

#### Producer salt sources

| Producer | Salt source |
|---|---|
| Hosted kernel (`chio-kernel`, `serve-http`, `api protect`, `chio run`, `chio mcp serve`) | OS RNG through the `Rng` seam |
| Portable core (`chio-kernel-core`) | host-supplied `Rng` |
| Browser and Workers WASM (`chio-kernel-browser`) | `globalThis.crypto.getRandomValues` |
| Mobile (`chio-kernel-mobile`) | OS RNG |
| C ABI (`chio-cpp-kernel-ffi`) | OS RNG inside the library |
| Security producers (cage, secret broker and other `chio.receipt.v1` emitters) | host `Rng` passed into their signing path |
| Other std processes (control plane, HTTP authority, ACP proxy, OpenTelemetry receipt exporter, product CLIs) | OS RNG through the `Rng` seam |
| Harness, conformance and fixture generators | a seeded deterministic `Rng` through the same seam; their output is fixture material only |

A producer draws salts from the `Rng` seam of the process that signs.

FFI and WASM adapters pass the unsigned body plus the parameter and content
preimages, and the core computes commitments and salts. No adapter supplies a
content hash or commitment for the core to sign. The same holds for every
producer: no signing path accepts a caller-supplied hash or commitment, so a
producer that relays a call passes its preimages to the signer.

HTTP calls mediated by the HTTP authority sign `chio.receipt.v1` like every
other producer: `tool_server` is `http`, `tool_name` is the method and route
pattern, the canonical HTTP request is the parameter preimage, and the
response status with the response body is the content preimage. There is no
separate HTTP receipt artifact.

#### Export profiles

`chio.evidence_export_manifest.v1` carries:

- `disclosure_profile`, closed:
  - `caller`: receipts for one tenant; salts for those receipts' parameters
    and content and for the tenant's own principal and tenant commitments; no
    payloads.
  - `auditor_full`: salts and payloads.
  - `auditor_hash_only`: no salts and no payloads.
- `tenant_tags`: required for `caller`, sorted by `key_id`, one keyed index
  value per loaded tag generation. The bundle contains only receipts whose
  stored `(tag_key_id, tag)` is in the set, and each receipt's stored tag is
  listed in `disclosure/receipt-tenant-tags.ndjson`, so a verifier checks that
  every exported receipt's tag is in the manifest set.
- Artifact roles `capability_presentation`, `delegation_context`,
  `root_policy`, `enterprise_provider_identity` (the identity projection of
  every provider record a bundle's roots name), `idp_key_snapshot`,
  `idp_artifact` (retained ID-JAG, auditor profiles only),
  `receipt_disclosure`, `revocation_entry`, `revocation_request`,
  `settlement_closure` and `pdp_decision_receipt`.

The provider's enabled state is not in any bundle.

The manifest is signed by the kernel key through
`chio.evidence_export_commitment.v1`. Export refuses salt-only openings in
auditor profiles, and refuses a `caller` export without `tenant_tags`. A
tenant confirms a bundle is its own by opening the subject and tenant
commitments with the included salts. The verifier report carries
`tenant_confirmed` and `principals_confirmed`. Each is true only when the
commitments covering the exported receipts form a nonempty set that covers
every exported receipt and every one of them opens: tenant commitments with
the caller's tenant value, subject commitments against a principal the
caller supplies. An empty bundle, a receipt without `authority`, or a
missing context, opening or caller value leaves the member false.
