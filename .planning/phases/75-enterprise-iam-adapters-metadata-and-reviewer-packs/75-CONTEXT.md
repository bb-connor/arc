# Phase 75: Enterprise IAM Adapters, Metadata, and Reviewer Packs - Context

## Goal

Package ARC's authorization profile into machine-readable metadata and
reviewer-facing evidence bundles that enterprise IAM teams can evaluate
without reverse-engineering ARC internals.

## Why This Phase Exists

Having a profile on paper is not enough. Enterprises need concrete metadata,
examples, and review artifacts that tie ARC authorization context back to
signed receipts and governed decisions.

## Scope

- enterprise-facing metadata endpoints or artifacts
- reviewer packs showing end-to-end intent, approval, auth context, and receipt
  traceability
- adapters or reporting surfaces for enterprise integration review
- documentation for operators preparing IAM reviews

## Out of Scope

- final conformance qualification
- public marketplace certification work
- changing the core governed rights model
