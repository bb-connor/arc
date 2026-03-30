# ARC Rename and Gap Synthesis

**Date:** 2026-03-25
**Primary sources:**
- `docs/research/DEEP_RESEARCH_1.md`
- `docs/VISION.md`
- `docs/STRATEGIC_ROADMAP.md`
- `.planning/PROJECT.md`
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`

## Why the rename goes first

The deep research document makes the strongest strategic case for `ARC`
(`Attested Rights Channel`) as the product identity:

- it names the differentiator directly: attested rights, bounded spend, and
  verifiable receipts
- it fits the "economic security" framing better than the older transport-first
  ARC expansion
- it positions the system as a governance and evidence layer that can sit under
  MCP, A2A, ACP, x402, and future payment or identity rails

Because the current repo, docs, SDKs, CLI, standards drafts, and portable-trust
artifacts still carry `ARC` across nearly every layer, the rename is not a
copy task. It is a compatibility and migration milestone.

## Rename blast radius

The rename must inventory and resolve all of these surfaces:

- Rust workspace members and crate names (`arc-*`)
- CLI binary and commands (`arc ...`)
- SDK package names and import paths (`@arc-protocol/sdk`, `arc-ts`,
  `arc-py`, `arc-go`)
- repository metadata, release scripts, docs, dashboards, examples, and
  standards drafts
- protocol/profile/schema names and examples
- portable-trust identities such as `did:arc`
- signed artifact families: receipts, passports, verifier policies,
  certifications, and evidence packages

The key requirement is that the rename must not silently orphan legacy PACT
artifacts or make old deployments unverifiable.

## Remaining product gaps after v2.4

The deep research and doc review converge on four real gap clusters:

1. Product identity and narrative drift
   The implementation is ahead of parts of the docs, and the current ARC name
   undersells the "economic security" thesis that the research supports.

2. Governed transactions and payment rails
   The budget and truthful-settlement substrate exists, but the real x402 /
   ACP-style bridge surfaces, approval artifacts, and reconciliation workflows
   are still missing.

3. Portable trust, certification, and federation maturity
   Passports, identity federation, and certification exist, but public
   discovery, lifecycle, distribution, and conservative cross-org trust
   semantics are not yet complete.

4. Risk, attestation, and actual launch closure
   Insurer-facing feeds, assurance-tier issuance based on attested runtimes,
   formal proof closure, and final GA/launch evidence are still open.

## Recommended milestone ladder

### v2.5 ARC Rename and Identity Realignment

Make `ARC` the real product name across code, packages, CLI, docs, and spec
surfaces, while preserving a deliberate migration and compatibility contract.

### v2.6 Governed Transactions and Payment Rails

Turn the "economic security" thesis into real product surfaces:
governed-transaction intent, approval tokens, x402 bridge, ACP/SPT bridge,
truthful settlement linkage, and reconciliation/operator flows.

### v2.7 Portable Trust, Certification, and Federation Maturity

Finish the portable trust story:
enterprise identity propagation, passport lifecycle/status/distribution,
certification discovery/public registry, and conservative cross-org reputation
distribution.

### v2.8 Risk, Attestation, and Launch Closure

Turn the evidence substrate into external trust:
insurer-facing behavioral feeds, attested runtime assurance tiers, formal proof
cleanup, and a real GA decision with aligned standards and launch materials.

## Early decisions that must be resolved in v2.5

- Whether `did:arc` becomes `did:arc`, dual-resolves, or stays frozen for
  compatibility
- Whether remaining deprecated Pact-era CLI and SDK shims remain for one cycle
  or are removed under a new major version
- Which schema IDs and wire markers are renamed versus explicitly frozen
- Whether artifact conversion tooling is required for old signed objects
- How the repo and package rename sequence avoids breaking qualification and
  release automation halfway through the transition
