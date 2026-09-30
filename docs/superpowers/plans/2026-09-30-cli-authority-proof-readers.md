# CLI authority and proof readers implementation plan

Execute inline under the existing authorization, from local commit
`943482d2cb82a1cf466584b47aee6b509c921d90` on `packet/3-retention-accounting`.
The exact 26-file scope is `docs/reviews/artifacts/2026-09-30-product-authority-readers/next-readers.json`.
Spec: the next chunk in `docs/reviews/2026-09-30-product-authority-readers-execution.md`
and authority-boundary item 2 of `docs/reviews/2026-09-28-remaining-security-work.md`.

- [x] Shared CLI input owners: bounded regular-file and stream reads, original
  duplicate-aware JSON, explicit JSON/YAML format selection, bounded duplicate-aware
  YAML, typed local causes, private signing-key reads and fallible fenced time.
  Use `cli/input/` modules for format and collection owners; preserve ordinary
  worker numeric contracts from the prior batch.
- [x] Authority/admin, runtime signing, certificates and passport: migrate original
  inputs and preserve signature checks; remove the selected manifest-v1 migration
  branch and its now-unused conversion machinery. Reject invalid/overflowing
  lifetimes, bound remote responses, prevent read-only trust queries from creating
  signing keys, and bind certificate queries to an exact session identity.
- [x] Proof collection/assembly/export/doctor/environment/risk/explanation/fixtures:
  bound original artifacts and aggregate traversal/collection; bind exported and
  reported identities to the verified input; reject invalid format instead of
  falling back; keep embedded fixture construction separate from verification.
- [x] Trust/credit/liability/receipt/attestation/underwriting: strict original
  file inputs, literal enum projections, retained causes and clear diagnostic
  versus authenticated output contracts.
- [x] Record each semantic disposition, focused positive and negative evidence,
  one final whole-batch review, local conventional commit and next concrete queue.

All input helpers produce data, not authorization. Original bytes remain the
digest/signature inputs. Defaults: 16 MiB per document, 128 MiB per collection,
4,096 entries and depth 64; retain tighter existing owner-specific limits. YAML
allows one document with string keys, bounded expansion and no duplicate keys.
Canonical-only owners require byte equality. No pre-ship compatibility paths.

Validation: original duplicate keys, JSON/YAML fallback, collection limits,
proof export substitution, literal enum injection, exact session selection,
clock faults and deadline overflow, plus existing changed-owner scenarios.
Batch implementation before expensive compilation; use focused CLI/library
checks and existing source gates. No push, merge, release or cloud activation.
