# ARC Extension SDK Profile

## Purpose

This document defines ARC's shipped extension contract for the `v2.29`
official-stack milestone.

It freezes:

- which ARC surfaces remain canonical truth
- which seams are replaceable extension points
- how custom implementations negotiate against the official first-party stack
- which fail-closed rules preserve ARC trust when extensions supply storage,
  transport, evidence, or execution

## Scope

The profile covers:

- `arc.extension-inventory.v1`
- `arc.official-stack.v1`
- `arc.extension-manifest.v1`
- `arc.extension-negotiation.v1`
- `arc.extension-qualification-matrix.v1`

The profile does not cover:

- real external rail execution or settlement dispatch
- autonomous insurer-grade pricing beyond current delegated envelopes
- permissionless plugin execution outside named extension points
- extensions that can redefine signed ARC truth or widen trust without local
  policy activation

## Terminology

| Term | Meaning |
| --- | --- |
| canonical truth | ARC-owned signed artifacts and local policy decisions that extensions may not redefine |
| extension point | Named replaceable seam with a fixed contract and privilege envelope |
| official stack | ARC's first-party implementation package over those named extension points |
| custom extension | Non-official implementation that targets a named extension point under the same contract |
| fail closed | Reject or refuse activation instead of widening trust on mismatch |

## Reference Artifacts

- `docs/standards/ARC_EXTENSION_INVENTORY.json`
- `docs/standards/ARC_OFFICIAL_STACK.json`
- `docs/standards/ARC_EXTENSION_MANIFEST_EXAMPLE.json`
- `docs/standards/ARC_EXTENSION_QUALIFICATION_MATRIX.json`

## Normative Claims

- canonical truth stays ARC-owned:
  capability scope, approval binding, receipts, checkpoints, local policy
  activation, trust activation, and signed ARC artifact schemas are not
  replaceable extension points
- extensions are admitted only through named seams:
  authority backends, stores, tool-server connections, resource or prompt
  providers, and the MCP/A2A bridge layer
- every extension point declares:
  contract path, stability, isolation modes, evidence modes, privilege
  envelope, whether custom implementations are allowed, and which official
  first-party components define the baseline
- the official stack is one machine-readable first-party package over those
  seams and may expose more than one deployment profile, but every profile
  still resolves only to first-party components
- a custom extension must declare:
  target extension point, supported official profiles, ARC contract version,
  supported official components, supported schema contracts, and its runtime
  envelope
- negotiation fails closed when:
  the extension targets an unknown point, mismatches the ARC contract version,
  targets the wrong official stack package, claims unsupported privileges or
  isolation, omits required subject/signer/freshness checks for evidence-
  capable execution, or claims truth mutation or trust widening
- extension points that can import evidence or dispatch execution require
  explicit local policy activation; remote visibility or adapter presence never
  equals trust admission
- qualification is not hand-waved:
  ARC records both positive and negative extension cases in a machine-readable
  compatibility matrix, and fail-closed cases must record the rejection codes
  that preserved the boundary

## Official Stack Boundary

The first-party official stack currently names these implementation families:

- local and remote capability-authority backends
- local and remote receipt, revocation, and budget stores
- native ARC service components
- the first-party MCP adapter
- the first-party A2A adapter

Custom implementations may replace only the specific extension points they
target. They do not gain authority to redefine capability, receipt, or policy
truth, and they do not become trusted merely by being discoverable.

## Qualification Reading

The shipped qualification matrix proves three things:

1. first-party official profiles compose under one package contract
2. custom implementations can interoperate with that package when they stay
   inside the named envelope
3. version mismatch, policy bypass, unsigned evidence, privilege escalation,
   and truth-mutation attempts fail closed
