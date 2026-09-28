# Sealed FROST ceremony execution

Implemented locally on September 27-28, 2026, on `packet/3-retention-accounting`
in `/tmp/arc-security-launch`, starting at `21c831d39678`. No subagents were used.
The source checkout and preexisting `output/` were preserved.

## Result

Every participant registers a separate X25519 sealing key. Round two now emits
only authenticated ciphertext envelopes using X25519, HKDF-SHA256 and
ChaCha20-Poly1305. Canonical metadata binds the ceremony, roster, epoch, round,
sender, recipient, sealing key and ephemeral key. The sender signs metadata
plus ciphertext with its separate Ed25519 transport key. Roster validation
rejects missing, duplicate, noncanonical and low-order sealing keys. Encoding,
context, signature, agreement and authentication failures remain distinct.

The public transcript contains all directed ciphertext envelopes. Completion
consumes only authenticated local opened shares. SQLite additionally requires
the recorded round-one transcript, exact committed outbound envelopes and exact
durably accepted inbound envelopes. It refuses replacement by freshly sealed
messages even when they contain the same valid shares.

The local sealing seed and DKG secret share one authenticated encrypted custody
bundle. Inbox acceptance atomically commits the encrypted share, envelope digest,
projection and authority commit. Exact retries are idempotent before and after
restart. A second authenticated, decryptable message commits terminal ceremony
failure before returning its error. Failure survives restart and disables cached
signer preparation, commitments and shares after completion. Retrying needs a
fresh epoch. The unshipped schema has no compatibility decoder or migration.

Opened plaintext has private fields, no serde implementation, redacted Debug and
an observed wiping drop path. Completion owns the opened values. Two production
byte borrows remain, both in the encrypted inbox custody owner. Provider shared
secret storage was inspected at `third_party/aws-lc-rs-chio/src/evp_pkey.rs`; it
uses `Zeroizing<Vec<u8>>`. This is an ownership and implementation check, not a
proof that every compiler or backend temporary is erased.

All FROST store record readers now use the bounded exact-canonical decoder,
including signer/coordinator checkpoints, rotations and verification shares.
The sealed wire schema is registered, documented and pinned. Fuzz ownership,
20 public corpus seeds and Docker/fuzz dependency mirrors are updated. No new
crypto package version was introduced.

## Focused evidence

Raw logs and diagnostic scripts are retained under
`/tmp/chio-frost-sealed-20260927/`.

| Boundary | Passing evidence |
| --- | --- |
| Authority implementation | `authority-tests-final.log`: 16 library cases; `sealing-final.log` subsequently passes all five sealing cases, adding one case for 17 distinct library cases. The explicit vector generator remains ignored in ordinary runs. |
| Ceremony consumers and fuzz entry | `fuzz-entry-tests.log`: four integration cases, including the exact shared fuzz entry on 20 seeds and 2,000 deterministic mutations plus oversized input. |
| Inbox, restart and transcript binding | `inbox-final.log`: all 12 cases pass, including external-write fencing, conflict after completion, deletion recovery, exact retries and both transcript substitution refusals. |
| Signer and activation | `store-tests-4.log`: seven signer cases and two activation cases pass. |
| Store records and recovery | `store-library-final.log`: 11 cases pass, including canonical record input, real transaction rollback injection and four FROST connection recovery phases. |
| Plaintext API sealing | `doctests-final.log`: both compile-fail serde checks pass. |
| Strict lint and source gates | `clippy-final-4.log`: owning authority/SQLite libraries and dependencies pass strict Clippy. Trust gate: 22 constructors, 85 tenant tables, 170 SQL contracts; all seven calibrations pass. Wire/schema registry, file hygiene and Docker mirror checks pass. |
| Independent crypto implementation | `independent-vectors-final.log`: Python cryptography independently reproduces all 20 signatures and ciphertexts, computes agreement from both participants, derives HKDF material and verifies exact plaintext fixtures. |

The three-of-five ceremony test produces a real threshold signature. The
plaintext drop observer covers all 20 recipient pairs. Fixture private keys and
shares are deterministic test data. No runtime keys were exported to evidence.

## Retained failures and corrections

The first compile checks exposed a nested module path and SQLite statement
lifetime, both corrected. Two further builds used stale dependencies while API
edits were in progress; the final owner runs were serialized. An initial
rollback fixture wrote from a second connection and correctly hit the serving
owner fence. The actual atomicity regression now installs a temporary trigger
on the owning connection, refuses the projection write after share insertion,
asserts complete rollback, removes the fault and retries successfully.

`outbound-regression-red.log` reproduces acceptance of freshly resealed outbound
messages. The production completion binding was strengthened and
`inbox-final.log` verifies refusal. Signature hex now requires lowercase so
alternate spelling cannot create a false conflicting envelope. The schema
manifest also had a stale response-plan hash; deterministic regeneration fixes
it together with the new schema and manifest self-hash.

Clippy also exposed an existing nested conditional in the simulator and two
receipt-writer functions over the parameter limit. The conditional was collapsed;
writer calls now pair command with its permit and reuse the existing durability
qualification struct. Ownership and response ordering are unchanged. Earlier
Clippy failures remain in `clippy-final*.log`; no lint was suppressed.

## Scope

This closes the local FROST step-two implementation and its focused acceptance
corpus. Sustained fuzzing, independent final review, native qualification,
workspace/hosted candidate qualification, integration and release remain distinct
acceptance work. The broader reader/proof census, complete tenant runtime matrix,
arithmetic inventory, clock migration and historical retention-stall disposition
are tracked separately in the execution ledger; this record does not close them.
