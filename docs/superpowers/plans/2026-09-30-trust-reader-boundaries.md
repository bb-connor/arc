# Trust reader boundaries

Base: `6ef28e8f4ddccb7f344a179d2415844a3410f815`, branch
`packet/3-retention-accounting`, isolated checkout `/tmp/arc-security-launch`.
Scope: all 35 paths pinned in the provider batch's `next-readers.json`, plus
helpers and direct consumers needed to implement those boundaries coherently.

Spec: mechanisms B and C of `2026-09-26-unrepresentable-defects-design.md`;
remaining-security-work item 2; `docs/security/signed-json-boundaries.md`.

## Tasks

1. Attestation, credentials and buyer imports: validate bounded original input,
   preserve native signed integers and signature semantics, retain typed parser
   causes behind safe public failures. Review validated custom decoders honestly.
2. Custody, TEE, remote signing and federation: enforce bounds before retention,
   reject ambiguous original input before projection or verification, enforce
   canonical wire contracts where promised, preserve cryptographic/replay gates.
3. Pheromone runtime/relay and persisted/exchanged evidence: strict bounded
   readers with native integer preservation, exact canonical contracts where
   required, and no trust or durable delivery from partial or ambiguous evidence.
4. One final independent review, focused package/feature checks, semantic reader
   inventory, evidence hashes, roadmap update and local conventional commit.

## Verification and decisions

- Add production-linked negative controls for duplicates, bounds, canonical
  drift and original-input loss, plus positive native integer and trust gates.
- Batch focused tests after implementation under the user's action-first
  instruction. No repeated per-edit builds or claim of a per-fix red/green run.
- One read-only reviewer, no delegated implementation. Fix material findings.
- Inspect existing validated custom deserializers and record their real contract;
  lexical baseline entries are review debt, not proof of a vulnerability.
- Keep unrelated `output/` untouched. No push, merge, publication or activation.
- Local reader qualification does not close M5, hosted/native-enforcement,
  supply-chain or operator acceptance boundaries.

## Completion

All four tasks are complete as local source work and focused qualification.
The [execution record](../../reviews/2026-09-30-trust-reader-boundaries-execution.md)
records the contracts, review resolutions, exact evidence and residual gates.
The final 20-package campaign passes 1,964 tests with zero failures and three
existing ignored cases; CLI test consumers also compile with Iroh enabled.
The 35 pinned reader paths have dispositions and 131 baseline files remain.
No cap/exemption increases, compatibility aliases or dependency version changes
were introduced. Existing credential/FROST custom decoders retain their separate
authentication contracts. The mobile kernel's other readers remain baseline,
and packaged Apple artifacts require separate rebuild/qualification.

The existing isolated branch is retained with a local conventional commit.
The next pinned chunk is 33 guard/security readers. No push, merge, publication
or live activation is included in this delivery.
