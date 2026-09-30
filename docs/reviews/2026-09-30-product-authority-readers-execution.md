# Product authority readers execution

Date: September 30, 2026. Base: `7525fcdf0c83adf6fddb88063dd75485d91b2554`.
Branch: `packet/3-retention-accounting`, worktree `/tmp/arc-security-launch`.
Scope: the [28-reader plan](../superpowers/plans/2026-09-30-product-authority-readers.md).
Implementation is local; this record does not establish hosted or release qualification.

## Delivered contracts

- [x] API-protect: all six baseline files disposed, including removal of the
  unused private permissive nonce middleware. HTTP bodies and encoded authority
  headers are bounded before original-byte, duplicate-aware decoding. Local
  parser causes survive behind stable public rejection codes. SQLite receipt
  rows are byte-capped in SQL before text materialization, with the same bound
  applied on writes.
- [x] API-protect time and reservation ownership: proxy, embedded HTTP authority,
  mediation kernel, replay stores and reaper share the service clock. Its wall
  and monotonic high-water fence is serialized with observation. TTL ambiguity,
  zero lifetime, overflow and invalid validity windows reject. Request IDs have
  shape, live-count and checked-deadline bounds, indexed expiry and opaque
  generation ownership. The kernel mutex covers durable reuse checks, claim,
  authorization and cleanup. Successful claims extend through the actual signed
  nonce expiry; stale cleanup cannot release a newer owner.
- [x] CLI: all 13 selected process/evidence/replay readers have explicit
  contracts. Private files and nested signed receipt strings preserve original
  bytes and typed rejection causes. Broker classification rejects ambiguous
  documents while retaining the complete original payload digest. Ordinary
  worker JSON keeps its lossless decimal-equivalence contract, including `1e0`
  and trailing-zero spellings. Signed receipt validation retains strict I-JSON,
  pinned signer, schema and action checks. Replay uses per-record, aggregate
  byte and record-count budgets, with exact canonical embedded argument bytes.
- [x] Proof-room: all nine baseline files have explicit contracts. Regular-file
  reads are bounded and reject final-component symlinks on Unix. Installed and
  standalone collectors share actual-byte and entry budgets. Uploads validate
  depth, path collisions and total directory/file entries before creating paths.
  JSON-RPC evidence binds the protocol version and response ID before selection.
  Original bytes remain the signature and digest inputs.
- [x] Proof-result custody and errors: public verification returns the sealed
  `VerifiedProofRoomBundle`; doctor and upload output consume the exact verified
  manifest identity and digest. Fixture-only bypasses cannot mint this result.
  Typed local errors survive core verification and CLI adapters; HTTP clients
  receive stable public codes. The result is registered in the private-field and
  no-`Deserialize` source gate, with a compile-fail deserialization test.
- [x] Semantic inventory: 27 active baseline readers reviewed and one retired;
  the lexical baseline falls from 278 to 250. Per-file contracts and supporting
  decoder owners are registered, and the gate protects the reviewed owner set.
  See [all 28 dispositions](artifacts/2026-09-30-product-authority-readers/reviewed-readers.json).

Bounds are 16 MiB per general CLI/proof artifact, 1 MiB for private CLI host files
and stored API receipts, 8 MiB per replay record, 64 MiB per replay corpus and
10,000 corpus records/files. Proof collection permits 4,096 entries, depth 64 and
128 MiB actual bytes; uploads additionally have a 32 MiB transport cap. These are
resource ceilings, not grants of authority.

## Review and focused validation

One whole-batch independent review found four issues, all repaired: ordinary
numeric spelling regression, request-reservation lifetime/cleanup races, upload
directory amplification, and missing cumulative collection budgets. Implementation
was inline. The final module moves retain existing file-size caps.

Final focused validation passes **557 tests**, with no failures or ignored tests:

| Check | Terminal result |
| --- | --- |
| API-protect library | 217 passed |
| Proof-room library | 108 passed |
| CLI process/evidence/replay/proof filters | 196 passed, 474 outside these filters |
| HTTP-authority filters | 35 passed, 67 outside these filters |
| Sealed proof-result deserialization compile-fail | 1 passed |
| Trust boundaries, file hygiene, changed-file formatting | Passed |

[Commands, source hashes and raw terminal logs](artifacts/2026-09-30-product-authority-readers/README.md)
are retained with the earlier failed attempts. The CLI container scenarios use
an engine double with real local supervision/journal behavior. Their passing
result does not qualify native container enforcement. Cargo emitted the existing
unused-patch warnings. No full workspace build or lint was run for this batch.

Early validation exposed fixture directories that lacked required private modes,
two CLI tests using the old malformed-JSON field, and assertions expecting old
public or canonical-input errors. The fixtures now establish explicit private
permissions; rejection assertions require the current code or typed cause. No
production ownership checks were relaxed. The initial attempted red run stopped
at compilation and is not evidence of a demonstrated failing regression test.

The clock, accounting, negative-assertion and wire-schema ratchets pass in their
configured scopes. Their existing totals remain 154 clock sites, 1,257 weak
assertions at 1,175 sites, and 163 duplicated schema identifiers. The accounting
gate's zero unchecked sites does not close the separate 85 pending semantic
arithmetic entries. These gates and tests do not establish broad threat closure.

Limits of this batch: concurrent hostile filesystem mutation, downstream
cryptographic implementation correctness, all remaining product/protocol readers,
native x86_64 qualification and hosted/M5 acceptance require their own evidence.
No push, merge, release or external activation is performed here.

## Next substantial chunk

Execute the [26 CLI proof and authority readers](artifacts/2026-09-30-product-authority-readers/next-readers.json):

1. Proof collection, assembly, export, doctor, environment, risk, explanation and
   fixture readers. Carry original bytes, bounded collection and verified-result
   identity through command output and artifact production.
2. Authority administration, active-response input, certificates, runtime
   operations/orchestration/signing, and passport verification. Review actual
   authorization and signer custody before replacing each decoder.
3. Trust, credit, liability, receipt explanation, runtime attestation and
   underwriting input owners. Preserve exact rejection causes and prove that
   projected fields cannot substitute for authenticated input.
4. Dispose each original reader in the semantic inventory, repair demonstrated
   clock/deadline/accounting defects, and run the corresponding focused negative
   and positive controls. Add no pre-ship compatibility paths.

This is 26 of the 55 remaining CLI baseline files. The remaining security roadmap
also retains other protocol/product owners, declaration/module work, retention
root-cause acceptance, sanitizer/formal correspondence, supply-chain source
audits, and exact-candidate hosted/M5 delivery gates.
