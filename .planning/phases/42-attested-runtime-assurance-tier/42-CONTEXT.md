# Phase 42 Context

## Goal

Bind runtime attestation evidence to issuance, approval, and budget policy
through explicit assurance tiers.

## Current Code Reality

- ARC already has DPoP-bound identity, governed approvals, and multi-dimensional
  budget semantics, but it has no explicit attestation evidence model.
- The deep research frames attestation as a later multiplier that should tighten
  or loosen trust decisions, not replace the existing policy kernel.
- Budget and approval surfaces introduced in `v2.6` give ARC a natural place to
  attach assurance tiers once attestation evidence is modeled explicitly.
- Launch closure later in `v2.8` needs a concrete answer to "what stronger
  rights or budgets are unlocked by a stronger runtime?"

## Decisions For This Phase

- Attestation is an input to policy, issuance, and approval decisions rather
  than a separate trust system.
- Assurance tiers must be explicit and operator-visible.
- Missing or invalid attestation fails closed when a policy tier requires it.
- The attestation contract should stay adapter/input-oriented so ARC does not
  become a TEE platform.

## Risks

- Attestation claims can be oversold if tier semantics are vague.
- Runtime-specific evidence formats can leak too deeply into core policy types.
- Assurance tiers can bypass existing least-privilege controls if they are
  treated as a blanket trust upgrade.

## Phase 42 Execution Shape

- 42-01: define the attestation evidence and tier model
- 42-02: implement attestation-aware issuance and policy enforcement
- 42-03: add docs and regression coverage for assurance-tier decisions
