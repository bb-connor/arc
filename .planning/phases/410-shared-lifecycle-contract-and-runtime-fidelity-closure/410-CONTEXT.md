---
phase: 410
milestone: v3.16
title: Shared Lifecycle Contract and Runtime Fidelity Closure
status: complete locally 2026-04-15
created: 2026-04-15
---

# Phase 410 Context

## Goal

Converge claim-eligible surfaces on one shared lifecycle and fidelity contract.

## Why This Exists

`v3.15` made A2A and ACP much more truthful, but the stronger thesis still
needs lifecycle and fidelity semantics to come from one shared runtime model
rather than surface-local adapted behavior.

## Must Become True

- stream, cancel, resume, and partial-output semantics come from one shared
  lifecycle contract
- publication and fidelity gating use runtime evidence rather than schema hints
  alone
- compatibility helpers remain isolated and non-claim-eligible
