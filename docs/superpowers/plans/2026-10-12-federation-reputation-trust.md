# Federation reputation trust selection

Reconcile FEDERATION-RAW-SIGNER against main `66f976ab27` before changing code.
The existing issuance contract excludes keys outside the admitted authority
view. Federation reputation evaluation must use that same trust boundary
without loading private signing custody just to verify receipts.

1. Add expected-safe controls for receipts signed by a recovered authority and
   by its displaced local key. Exercise the real policy evaluator and receipt
   store, with a fixed trusted clock. Preserve the Original result.
2. If confirmed, obtain receipt-verification keys from the admitted service
   authority. Fail closed when reputation is required and authority is
   unavailable. Preserve policies that do not require reputation.
3. Run the focused federation and authority controls, strict control-plane
   Clippy, and affected static inventories. Ask Claude to review, then publish
   a separate PR on main.

No changes to unrelated reputation consumers, receipt scoring, authority
activation, signing custody or repository settings are included.

## Reproduction and review scope

Original `3d58fded9a` fails the three expected-safe assertions: recovered
receipts contribute zero, displaced custody contributes reputation, and a
zero-threshold reputation policy accepts without an authority. The policy with
no reputation requirement passes. Each receipt first passes a direct scoring
control under its own explicitly trusted signer. The earlier future-clock
fixture failure and quota-scoring false positive are retained separately.

The repair follows the existing current-trust reputation contract. Rotation
keeps verification-only issuers through their configured deadline; recovery,
revocation and retirement remove their authority. A rotation/revocation control
checks this behavior. Counting receipts after issuer retirement would require a
separate timestamp-aware historical trust contract; archived keys must not be
added to the current trust set without that check.

## Verification

Tested repair: `374dd2b820aba803cde9d3fe9d531254ea5ae05c`. Rust 1.95.0,
locked/offline Cargo, two build jobs and serial tests. The repair source and
tests are byte-identical after rebasing onto main. Claude approved the current
trust contract at 2026-10-12T16:51:12Z.

- Original: 3 intended failures and one no-reputation control pass. `/tmp/federation-original-receipt-only.log`, SHA-256 `3516829e2c67a4e6087fa8b873ed558505bd75804fbf1fc91b6ccbc04456c901`.
- Repair: 27 focused passes. `/tmp/federation-green.log`, SHA-256 `8fac3383a1a4086a201f3df2fe33e91922b8d8c90acc2fe0ced607a6418010cf`.
- Strict Clippy: all control-plane targets, warnings denied. `/tmp/federation-clippy.log`, SHA-256 `5f2bb7ee61b2e06a821a2880abd47643465c9d579c7dedf018a157a7f6ddf43e`.

Focused command: `cargo test --locked --offline -p chio-control-plane --lib -- federation_reputation_trust:: governance_authority:: reputation_trust_excludes_an_authority_key_that_is_not_currently_readable`.
Strict command: `cargo clippy --locked --offline -p chio-control-plane --all-targets -- -D warnings`.
Rust hygiene and the clock inventory pass. All 256 formal source bindings match;
the generated 65-row/179-artifact coverage inventory matches. These are static
checks, not new proof execution. Hosted and broader native acceptance are not
claimed by this focused repair.
