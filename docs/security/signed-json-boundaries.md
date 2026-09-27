# Signed JSON input boundaries

This inventory accompanies correction 1F of the security assurance work. It
records the actual input check before signature verification or digesting. It is
not a claim that the production simulation report or the whole TCB migration is
complete. The explanatory comment in `chio-core-types/src/canonical.rs` remains
unchanged.

Two existing wire contracts need different treatment:

- New external JSON text uses `canonical_json_bytes_from_str` before typed
  deserialization. Duplicate keys, rounded numeric aliases and integers outside
  the I-JSON range reject. Whitespace and key ordering can be canonicalized.
- Stored receipt JSON includes both ordinary typed serialization and canonical
  serialization, with signed financial `u64` values above `2^53-1`. Applying
  the I-JSON integer restriction or requiring whole-document canonical byte
  equality would make valid history unreadable. `canonical::parse_legacy_signed_json` parses
  tokens directly, rejects duplicate keys at every depth and validates original
  number lexemes against the two existing serializers before returning a value.
  Whitespace, key ordering, ordinary float serialization and full-width integers
  retain their established meaning. Over-precise numeric aliases reject. This
  compatibility reader does not change the external I-JSON input contract.

| Boundary | Current entry point and protection | Disposition |
|---|---|---|
| Authority deployment file | `chio-active-response-authority/config.rs::load_runtime_config`: bounded no-follow file, typed decode, validate, `canonical_json_bytes(&deployment) == original bytes` | Equality rejects aliases before the configuration digest is used; retain required mode and schema v2. |
| Authority SQLite payloads | `chio-active-response-authority/store.rs::decode_canonical`: bounded decode and exact canonical byte equality | Retain equality before logical-store digest and signature checks. `prepare_logical_records` only reparses bytes this process just constructed. |
| Signed tool/cage manifest file | `chio-manifest/admission.rs::read_existing_signed_manifest`: bounded file, then `canonical::parse_legacy_signed_json` before typed decoding; `input_schema` contains arbitrary JSON | Token validation rejects nested duplicate keywords and rounded fractional aliases. Existing signed schemas permit whole-valued floats and full-width integers, so the compatibility parser is required here too. All 68 manifest unit/integration tests passed, including alias refusal and ordinary/pretty/canonical serializer roundtrips. |
| Broker daemon configuration and authenticated payloads | `daemon_runtime.rs::load_existing`, `daemon.rs::decode_canonical_payload`, `authority_ipc.rs` request/response, and `ipc_client.rs::decode_canonical_response`: typed or value canonicalization followed by original-byte equality | Equality already prevents normalization aliases. Keep it before signature/reservation or dispatch. It also preserves the established full-width integer wire contract. |
| Broker direct execute and prepared connection | `service_parts/part_03.rs::decode_canonical_ipc_request` parses the exact bounded envelope; daemon `execute` and `prepare_dispatch` use `decode_canonical_payload` before authority checks. Prepared execution additionally compares the entire frame digest; client outcome payloads use `decode_canonical_response`. | Existing canonical equality covers the signed payload before dispatch. The prepared endpoint's preliminary typed decode does not grant execution authority; the production handler still applies canonical and signed-registration checks. This disposition is source review, not a new native-runner qualification. |
| Active-response authority IPC | `active_response_authority/protocol.rs` and `client.rs`: bounded frame, typed decode, exact original-byte equality before exchange verification | Retain equality and authenticated tenant/deployment/store/request binding. |
| Tool and child receipt `raw_json` | `receipt_store/support/receipt_verify.rs::decode_verified_chio_receipt` and `decode_verified_child_receipt`: `canonical::parse_legacy_signed_json` validates tokens before typed decoding and existing signature/action-hash verification | P1 repair implemented. The full receipt-store library subset passed 350 tests (2 existing scale tests ignored) before equivalent shared-module relocation. Nested duplicate and precision-alias refusal, full-u64 preservation and both historical writer encodings have dedicated regressions. All four relocated-reader regressions, both default/no-default shared-parser tests, the unchanged 43 canonical tests and strict all-target Clippy passed. Independent review accepted this bounded repair. No history is rewritten. |
| Receipt checkpoint `statement_json` | `parse_persisted_checkpoint_row`: directly decodes `KernelCheckpointBody`, then cross-checks columns, signature and chain. The cached-head append path directly decodes the same type and compares its authenticated body digest and mirrored columns. | Source review found a closed `deny_unknown_fields` body with integer and string/hash/key fields, no floats or arbitrary JSON maps. Direct struct decoding already rejects duplicate fields and fractional integer aliases. Ordinary whitespace/key ordering remain compatible; no blanket I-JSON narrowing or extra per-append signature verification was added. |
| Signed receipt lineage readback | Both ordinary and retained `ReceiptLineageStatement` readers share `decode_verified_lineage_statement`: token-preserving compatibility parsing, signature verification, and requested-child binding. | Rejects changed signed bodies and valid statements substituted for another child. The mixed lineage table also contains unsigned backfill metadata; this change covers APIs that return signed statements. |
| Signed economy readback | `decode_verified_signed_export` protects all 40 stored export readers in `underwriting_credit.rs`, `liability_market.rs` and `liability_claims.rs`, including reports, provider resolution, supersession and predecessor comparisons. | Compatibility parsing rejects duplicate keys and precision aliases before typed decode; signature verification now runs on read as well as insertion. Embedded signer integrity is not independent signer authorization. Historical ordinary/pretty/canonical encodings and full-width monetary values are retained. |
| Keyring stored canonical records | `chio-keyring/lib.rs::from_bounded_json`, used by signed event/checkpoint/activation/time/router and witness/verifier readers: bounded typed decode, then exact original-byte equality with canonical serialization | All writers use canonical bytes. The shared reader now rejects whitespace, escaped-string and ordering aliases before returning the signed value, while preserving full-width `u64`. The alias regression failed before repair; all 79 keyring tests pass, including signed timestamp preservation, durable restart, coherent synchronization snapshots and semantic vectors. |
| Keyring canonical IPC and enterprise receipts | `ipc.rs::read_canonical_frame`, `enterprise_receipt.rs::from_canonical_bytes`: bounded typed decode plus exact original-byte equality | Alias rejection is explicit. Signature and role checks remain separate and required. |
| Simulation report | Production report input/receipt composition does not exist yet | External text must use the strict entry point. The new report must declare this rule and must never be decoded as live execution authority. |

The direct broker execute/prepared, checkpoint, signed lineage and economy
entries above were inspected in the next execution batch. The [readback
checkpoint](../reviews/2026-09-27-signed-readback.md) records the implementation
and focused evidence. This is a census of the named entry points, not a proof
that every signed JSON decoder in the workspace has been enumerated. Production
simulation/report parsing remains open with its parent implementation.
