# Signed JSON input boundaries

This inventory accompanies correction 1F of the security assurance work. It
records the actual input check before signature verification or digesting. It is
not a claim that the whole TCB migration is complete. Production simulation now
uses the signed receipt boundary described below.

The input contract follows the payload's numeric domain:

- External I-JSON text uses `canonical_json_bytes_from_str` before typed
  deserialization. Duplicate keys, rounded numeric aliases and integers outside
  the I-JSON range reject. Whitespace and key ordering can be canonicalized.
- Native signed typed JSON includes full-width financial and lifecycle `u64`
  values. `UntrustedJsonText::decode_signed` reads tokens directly, rejects duplicate
  keys at every depth, and rejects lossy numeric lexemes before returning a value.
  Typed and canonical serializers preserve the same signed data. The verifier
  then reconstructs the typed signing body and verifies its signature. This is
  the production numeric contract, not a backwards-compatibility decoder.

| Boundary | Current entry point and protection | Disposition |
|---|---|---|
| Authority deployment file | `chio-active-response-authority/config.rs::load_runtime_config`: bounded no-follow file, typed decode, validate, `canonical_json_bytes(&deployment) == original bytes` | Equality rejects aliases before the configuration digest is used; retain required mode and schema v2. |
| Authority SQLite payloads | `chio-active-response-authority/store.rs::decode_canonical`: bounded decode and exact canonical byte equality | Retain equality before logical-store digest and signature checks. `prepare_logical_records` only reparses bytes this process just constructed. |
| Signed tool/cage manifest file | `chio-manifest/admission.rs::read_existing_signed_manifest`: bounded file, then `UntrustedJsonText::decode_signed` before typed decoding; `input_schema` contains arbitrary JSON | Token validation rejects nested duplicate keywords and rounded fractional aliases. Existing signed schemas permit whole-valued floats and full-width integers, so the precision-preserving parser is required here too. All 68 manifest unit/integration tests passed, including alias refusal and ordinary/pretty/canonical serializer roundtrips. |
| Broker daemon configuration and authenticated payloads | `daemon_runtime.rs::load_existing`, `daemon.rs::decode_canonical_payload`, `authority_ipc.rs` request/response, and `ipc_client.rs::decode_canonical_response`: typed or value canonicalization followed by original-byte equality | Equality already prevents normalization aliases. Keep it before signature/reservation or dispatch. It also preserves the established full-width integer wire contract. |
| Broker direct execute and prepared connection | `service_parts/part_03.rs::decode_canonical_ipc_request` parses the exact bounded envelope; daemon `execute` and `prepare_dispatch` use `decode_canonical_payload` before authority checks. Prepared execution additionally compares the entire frame digest; client outcome payloads use `decode_canonical_response`. | Existing canonical equality covers the signed payload before dispatch. The prepared endpoint's preliminary typed decode does not grant execution authority; the production handler still applies canonical and signed-registration checks. This disposition is source review, not a new native-runner qualification. |
| Active-response authority IPC | `active_response_authority/protocol.rs` and `client.rs`: bounded frame, typed decode, exact original-byte equality before exchange verification | Retain equality and authenticated tenant/deployment/store/request binding. |
| Tool and child receipt `raw_json` | `receipt_store/support/receipt_verify.rs::decode_verified_chio_receipt` and `decode_verified_child_receipt`: `UntrustedJsonText::decode_signed` validates tokens before typed decoding and existing signature/action-hash verification | P1 repair implemented. The full receipt-store library subset passed 350 tests (2 existing scale tests ignored) before equivalent shared-module relocation. Nested duplicate and precision-alias refusal, full-u64 preservation and both historical writer encodings have dedicated regressions. All four relocated-reader regressions, both default/no-default shared-parser tests, the unchanged 43 canonical tests and strict all-target Clippy passed. Independent review accepted this bounded repair. No history is rewritten. |
| Receipt checkpoint `statement_json` | `parse_persisted_checkpoint_row`: directly decodes `KernelCheckpointBody`, then cross-checks columns, signature and chain. The cached-head append path directly decodes the same type and compares its authenticated body digest and mirrored columns. | Source review found a closed `deny_unknown_fields` body with integer and string/hash/key fields, no floats or arbitrary JSON maps. Direct struct decoding already rejects duplicate fields and fractional integer aliases. Ordinary whitespace/key ordering remain compatible; no blanket I-JSON narrowing or extra per-append signature verification was added. |
| Signed receipt lineage readback | Both ordinary and retained `ReceiptLineageStatement` readers share `decode_verified_lineage_statement`: token-preserving parsing, signature verification, and requested-child binding. | Rejects changed signed bodies and valid statements substituted for another child. The mixed lineage table also contains unsigned backfill metadata; this change covers APIs that return signed statements. |
| Signed economy readback | `decode_verified_signed_export` protects all 40 stored export readers in `underwriting_credit.rs`, `liability_market.rs` and `liability_claims.rs`, including reports, provider resolution, supersession and predecessor comparisons. | Token parsing rejects duplicate keys and precision aliases before typed decode; signature verification now runs on read as well as insertion. Embedded signer integrity is not independent signer authorization. Historical ordinary/pretty/canonical encodings and full-width monetary values are retained. |
| Keyring stored canonical records | `chio-keyring/lib.rs::from_bounded_json`, used by signed event/checkpoint/activation/time/router and witness/verifier readers: bounded typed decode, then exact original-byte equality with canonical serialization | All writers use canonical bytes. The shared reader now rejects whitespace, escaped-string and ordering aliases before returning the signed value, while preserving full-width `u64`. The alias regression failed before repair; all 79 keyring tests pass, including signed timestamp preservation, durable restart, coherent synchronization snapshots and semantic vectors. |
| Keyring canonical IPC and enterprise receipts | `ipc.rs::read_canonical_frame`, `enterprise_receipt.rs::from_canonical_bytes`: bounded typed decode plus exact original-byte equality | Alias rejection is explicit. Signature and role checks remain separate and required. |
| Simulation report | The native receipt store applies `UntrustedJsonText::decode_signed` before typed receipt decoding and signature verification; `validate_response_simulation_receipt_binding` decodes closed report metadata, reconstructs the complete receipt body and recomputes the model. | Uses the native signed receipt numeric contract. Independent verification requires the expected signer and deployment digest. The advisory report cannot be decoded as live admission or dispatch authority. See [production response simulation](../reviews/2026-09-27-production-response-simulation.md). |

The direct broker execute/prepared, checkpoint, signed lineage and economy
entries above were inspected in the next execution batch. The [readback
checkpoint](../reviews/2026-09-27-signed-readback.md) records the implementation
and focused evidence. This is a census of the named entry points, not a proof
that every signed JSON decoder in the workspace has been enumerated. The
[simulation checkpoint](../reviews/2026-09-27-production-response-simulation.md)
records the report implementation and its focused verification separately.

## Constrained input migration (2026-09-27)

`chio_core_types::canonical::UntrustedJsonText` now owns the parsing decision.
It borrows the original bounded text, so database readback does not copy a large
string just to mark it untrusted. It has no raw accessor, implicit string
conversion, serde implementation or payload-bearing Debug. `from_wire` checks
byte bounds and UTF-8; `new` marks an already bounded owner buffer. Neither
constructor asserts signature validity or authorization.

- `canonicalize`: strict external I-JSON.
- `decode_signed`: token-preserving native JSON with full-width integers.
- `decode_canonical`: exact canonical wire/storage bytes, followed by the
  caller's existing signature, role and binding checks.

Receipt, signed export, lineage, manifest, keyring, broker IPC/config and
response-authority owners use this API. The old public parser entry point was
removed. Broker credential mutation retains its dedicated zeroizing parser;
closed checkpoint bodies retain their typed integer-only decoder. These are
explicit contracts, not permissive fallbacks. The constructor census and the
remaining raw decoders in migrated files are pinned in
[trust-boundary-inventory.json](trust-boundary-inventory.json), checked by
`scripts/check-trust-boundaries.py`. The September 28 expansion below also pins decoder-bearing files across
`crates/`. The gate requires review when a new file or decoder spelling appears;
it does not infer the trust classification of arbitrary APIs.

`UntrustedJsonError` supplies registered rule codes, redacted Display/Debug and
inspectable sources. Receipt-store waiter snapshots share the original parser
error through `Arc`, preserving its variant and source. Wire `PortError` remains
a deliberate code-only projection; response-authority decode/canonical/frame
rules retain their existing protocol codes.

Broker IPC has its own bounded diagnostic grammar. JSON and clock errors map to
distinct `signed_json_*` and `clock_*` reasons, with `chio.broker.` on signed
execute-failure receipts. Their local typed sources retain the registered URNs.
Putting a full URN after the broker prefix would create an invalid diagnostic;
the signed-envelope regression rejects that former mapping and verifies the
correctly bound failure receipt.

## September 28 continuation

The bounded reader now also owns federation authority profiles, issuance and
revocation requests, peer pins, portable passport envelopes, classifier field
paths, declassification request hashes, and broker audit/provision/receipt readers.
Public signed input keeps the lossless native integer contract. Stored and IPC
canonical records enforce exact bytes before their existing signatures and bindings.
Broker and authority input errors retain the structured parser source.

Authority private-key custody now uses exact canonical JSON and zeroizing seed
fields. Its Debug output is redacted, and its serialized writer returns a
zeroizing string. Canonical private decoding also wipes string values and keys
in the intermediate value tree. String escaping writes directly into the output.
No compatibility parser accepts older pretty-printed custody.
The FROST store likewise uses constrained readers for all persisted record forms.

At that checkpoint the source gate inventoried 44 constrained constructors and ten sealed
result types; it ignores decoder spellings inside comments and literals. This
expands the reviewed owners, not the claim to every decoder in the workspace.

## Signed-reader batch (2026-09-28)

The source gate now pins 114 constrained-reader constructor occurrences in 88
registered signed-reader files. Its wider lexical census contains 556 files and
1,881 decoder spellings, including imported serde aliases, `from_reader`,
`Deserializer` and custom `Deserialize` implementations. Multiplicity is retained.
New decoder files fail until their disposition is recorded. The source filter
excludes named test modules and masks `cfg(test)` items; it is not Rust name
resolution and can include test fragments with unconventional names.

The file dispositions deliberately separate 447 `raw-input-baseline` files,
86 typed-value conversion files, 14 example/fuzz files and nine reviewed signed
owners that still contain individually classified raw conversions. A baseline
entry does not establish that input is unsigned, authenticated or safe. Those 447
files remain semantic review work; packet 10.2 is open.

| Migrated owner | Enforced boundary |
| --- | --- |
| Credentials and financial passports | Bounded original bytes before `Value`; native integers retained; bundled source artifacts require exact canonical bytes, artifact digests and existing source-signer checks. |
| JWT and SD-JWT | Shared strict header/payload reader; segment bounds before base64 allocation; Ed25519 signature over the original compact preimage. SD-JWT also requires its supported signed header, bounds disclosures and preserves holder/disclosure-digest checks. |
| Passport, issuance and certification registries | Bounded file reads, strict JSON, existing artifact validation plus exact map-key identity. Lifecycle timestamps must be present and nonzero. Stored challenge/request identity and expiry must agree with their row projections. |
| Reputation policy files | Explicit YAML extension remains local operator configuration. JSON determines signed shape before typed decoding; malformed signed documents cannot fall through to a plain-policy/YAML interpretation. |
| Finding purchase, recovery, status and finding artifacts | Shared exact typed-canonical reader with existing explicit I-JSON preflight. Duplicate canonical serialization was removed. |
| DSSE and FROST | Bounded DSSE payload before base64 allocation and PAE construction; exact statement and embedded-receipt canonical bytes; exact completed FROST authorization bytes. Existing signature, roster, epoch and binding checks remain separate. |
| Federation transport | Catchup, fanout, revocation and bilateral messages apply bounded strict decoding before their existing authenticated lane checks. |
| Durable SQLite evidence | Tool outcomes, admission participants and projections, nonce/output/egress evidence, attested Finding batches and outbox use bounded original-byte decoding while retaining canonical/digest/row checks. These records are not all independently signed. |
| IOU settlement | Insert/read verify the envelope signature; readback requires canonical bytes and matches receipt ID, tenant, IOU ID, amount, currency, timestamp and issuer to their stored projections. Embedded issuer integrity is not independent issuer authorization. |

The [execution record](../reviews/2026-09-28-signed-reader-tenant-execution.md)
records focused tests and calibrated production-reader bypasses. No hosted or
workspace-wide qualification follows from this reader migration.
