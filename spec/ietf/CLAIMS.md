# Claim review for draft-whelan-chio-protocol-00

Review date: 2026-10-02. Target: the completed Chio security-roadmap release, explicitly requested by the owner.

The draft leads with Chio as a modern Rust kernel for agentic operating systems and specifies the execution authority, accounting, governance, recovery, and evidence responsibilities of that kernel. The review covers every document section, every BCP 14-bearing source block, the revised wire forms, and the applicable external standards.

## Current review

- [Findings, roadmap coverage, source selection, and release reconciliation](reviews/2026-10-02/README.md).
- [Pinned branch and source manifest](reviews/2026-10-02/source-manifest.json).
- [Every normative source block, its section, digest, and review basis](reviews/2026-10-02/normative-inventory.json).
- [Independent wire/schema and signing-input verification](reviews/2026-10-02/wire-verification.json).
- [Build, standards, and rendered-document verification](reviews/2026-10-02/verification.md).

The source baseline is the combined security integration plus the newer retention/accounting and runtime-boundary work, with separate review of divergent assurance branches. The main-based September 30 ledger remains available as [historical provenance](reviews/2026-10-02/previous-claims.md).

## Meaning of the review basis

**Inherited wire requirement**: the requirement is unchanged in normalized text from the previously reviewed draft. Its prior source review is preserved. A section-level comparison also checked the newer source for relevant changes.

**Source update**: a changed or added wire requirement has a corresponding structure or validation path in the selected security snapshot. Static source and independent schema/signing-input checks establish the documented contract, not end-to-end runtime acceptance.

**Release requirement**: the requirement specifies the completed production profile requested by the owner, including security obligations synthesized across roadmap components. The review report identifies the explicit source-to-release reconciliation items. It is not a claim that an old helper or every current adapter enforces the requirement.

**External standard**: the requirement or correction follows a cited primary specification. The release implementation must agree with it.

The normative inventory is an exhaustive navigation and coverage aid. It does not turn a source citation, digest, or automated keyword scan into proof of runtime correctness. Public-source availability, deployment qualification, and Datatracker publication are separate actions.
