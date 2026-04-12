# MERCURY Embedded OEM

**Date:** 2026-04-03  
**Audience:** product, engineering, partner, and review-platform teams

---

## Purpose

This document freezes the bounded embedded OEM lane selected for `v2.48`.

The lane is intentionally narrow:

- one embedded OEM package family over the existing assurance-suite,
  governance-workbench, supervised-live, proof, and inquiry truth artifacts
- one partner surface only: `reviewer_workbench_embed`
- one manifest-based SDK surface only: `signed_artifact_bundle`
- one reviewer population only: `counterparty_review`
- one fail-closed partner-owner and Mercury support-owner boundary

It does not approve a generic SDK platform, multiple partner surfaces, a
multi-partner OEM program, trust-network services, or ARC-Wall work.

---

## Selected Embedded Surface

The selected embedded path is:

- partner surface: `reviewer_workbench_embed`
- SDK surface: `signed_artifact_bundle`
- reviewer population: `counterparty_review`

Those names are deliberate. Mercury is not shipping a broad SDK family here.
It is shipping one manifest plus one signed artifact bundle that lets one
partner review workbench embed bounded Mercury evidence inside an existing
system of work.

The workflow sentence remains unchanged:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

Embedded OEM packaging may narrow how the evidence is staged for the partner,
but it must not create a second truth path.

---

## Operational Owners

- partner owner: `partner-review-platform-owner`
- support owner: `mercury-embedded-ops`

The partner owner owns ingestion and acknowledgement of the bounded partner
bundle. The Mercury support owner owns fail-closed recovery whenever the
required profile, manifest, assurance, governance, reviewer, qualification, or
delivery artifacts are missing or inconsistent.

---

## Scope Boundary

Supported in `v2.48`:

- one embedded OEM profile contract
- one embedded OEM package contract
- one partner SDK manifest over one reviewer-workbench surface
- one copied counterparty-review bundle derived from the validated assurance
  lane
- one fail-closed delivery acknowledgement and support boundary

Not supported in `v2.48`:

- additional partner surfaces
- multi-partner OEM breadth
- generic SDK platform or multi-language client breadth
- trust-network services
- ARC-Wall and companion-product work

---

## Canonical Commands

Export the bounded embedded OEM package and partner bundle:

```bash
cargo run -p arc-mercury -- embedded-oem export --output target/mercury-embedded-oem-export
```

Generate the validation package and explicit next-step decision:

```bash
cargo run -p arc-mercury -- embedded-oem validate --output target/mercury-embedded-oem-validation
```

These commands must remain wrappers over the existing ARC evidence export,
Mercury proof/inquiry packaging, supervised-live qualification artifacts,
governance-workbench decision package, and assurance-suite bundle. ARC stays
generic; Mercury stays opinionated.
