# MERCURY Product Surface Audit

**Date:** 2026-04-04  
**Audience:** founders, product, engineering, and anyone trying to understand
what MERCURY actually is right now

---

## Why This Exists

MERCURY grew by repeatedly adding new bounded `export` and `validate` lanes on
top of ARC. That preserved ARC purity, but it also created a misleading shape:
the repo now contains many lane-specific package surfaces that look like equal
product capabilities even when they are mostly variations on the same bundle-
generation pattern.

This document is the corrective explanation.

Read this before adding a new MERCURY lane, extending GTM claims, or treating
every post-launch document as a distinct long-term product surface.

---

## What MERCURY Really Is

At its core, MERCURY is:

- a product-specific evidence layer on top of ARC
- one dedicated CLI and schema family for regulated trading workflow evidence
- one packaging system for proof, inquiry, review, and decision artifacts

The most real parts of MERCURY today are:

- proof and inquiry packaging over ARC evidence
- pilot and supervised-live capture for the core controlled change workflow
- reviewer-facing package generation for bounded audiences

Those are durable product primitives.

---

## What The Code Actually Looks Like

As of this audit:

- [commands.rs](../../crates/arc-mercury/src/commands.rs) is `13,478` lines
- [main.rs](../../crates/arc-mercury/src/main.rs) is `740` lines
- [arc-mercury-core lib](../../crates/arc-mercury-core/src/lib.rs) exposes `25`
  core modules
- [commands.rs](../../crates/arc-mercury/src/commands.rs) exposes `42` public
  CLI handlers

That is too much surface for a product that still fundamentally centers on one
core workflow sentence:

> Controlled release, rollback, and inquiry evidence for AI-assisted execution
> workflow changes.

The codebase is therefore carrying two different things at once:

- real Mercury substrate
- repeated lane-specific bundle scaffolding

---

## Capability Buckets

### 1. Core Mercury substrate

These are the stable foundations:

- `proof`
- `inquiry`
- `verify`
- receipt metadata and bundle manifests

Primary files:

- [proof_package.rs](../../crates/arc-mercury-core/src/proof_package.rs)
- [bundle.rs](../../crates/arc-mercury-core/src/bundle.rs)
- [receipt_metadata.rs](../../crates/arc-mercury-core/src/receipt_metadata.rs)

This is real product substrate, not accidental scaffolding.

### 2. Evidence capture for the core workflow

These extend the same bounded workflow rather than inventing new commercial
surfaces:

- `pilot`
- `supervised_live`

Primary files:

- [pilot.rs](../../crates/arc-mercury-core/src/pilot.rs)
- [supervised_live.rs](../../crates/arc-mercury-core/src/supervised_live.rs)

This is still real product work.

### 3. Review and distribution package families

These are arguably legitimate bounded package families, though they already
show some repetition:

- `downstream_review`
- `governance_workbench`
- `assurance_suite`
- `embedded_oem`
- `trust_network`

These are still understandable as reviewer/distribution variants over the same
proof chain.

### 4. Commercial and post-launch lane chain

This is where repetition becomes dominant:

- `release_readiness`
- `controlled_adoption`
- `reference_distribution`
- `broader_distribution`
- `selective_account_activation`
- `delivery_continuity`
- `renewal_qualification`
- `second_account_expansion`
- `portfolio_program`
- `second_portfolio_program`
- `third_program`
- `program_family`
- `portfolio_revenue_boundary`

These lanes are not all fake, but many are near-isomorphic:

- stage one prior bundle
- copy forward evidence files
- write a new manifest
- write a new approval or handoff artifact
- write a new package json
- write a new validation report and decision record

That means much of the later ladder is packaging repetition, not a sequence of
fundamentally new runtime capabilities.

---

## The Honest Assessment

The early Mercury milestones were useful because they:

- separated Mercury from ARC generic crates
- established a typed Mercury package surface
- proved export and validation over the ARC substrate

The later Mercury milestones increasingly optimized for continuing the lane
pattern rather than re-evaluating the product shape.

So the repo now overstates the amount of distinct product capability it has.

The best way to describe the current state is:

- MERCURY has a real evidence-packaging substrate
- MERCURY has a real core workflow capture path
- MERCURY has several real reviewer/export surfaces
- MERCURY also has a large amount of repeated post-launch commercial lane
  scaffolding that should be collapsed or abstracted

---

## What Should Happen Next

### Immediate decisions

- Do not add another MERCURY lane until the CLI surface is reduced.
- Do not treat every post-launch lane document as a permanent independent
  product capability.
- Keep ARC generic and Mercury opinionated.

### Engineering cleanup

The next engineering work should be a refactor, not another expansion lane.

Priority order:

1. Split [commands.rs](../../crates/arc-mercury/src/commands.rs) by concern:
   core packaging, capture modes, reviewer distribution, and commercial-stage
   lanes.
2. Introduce reusable lane scaffolding so `export` and `validate` stop being
   hand-written for each near-identical stage.
3. Collapse the post-launch commercial chain into a smaller number of
   capability families rather than preserving every named step as a first-class
   code surface.

### Product cleanup

MERCURY needs one explicit product answer:

- evidence-packaging product
- operator workflow product
- or a hybrid with a deliberately small surface

Until that answer is written down, adding more package lanes will keep
inflating the codebase faster than it increases real product clarity.

---

## Working Rule

When evaluating a proposed new MERCURY feature, ask:

1. Does this add a new durable Mercury primitive?
2. Or does it just add another named package around the same prior evidence?

If the answer is the second one, prefer refactoring or parameterizing an
existing lane instead of adding a new one.
