# Phase 57: SPIFFE/SVID Workload Identity Mapping - Context

## Goal

Map workload identity material such as SPIFFE IDs and SVID-backed runtime
identity into explicit ARC identity and policy surfaces.

## Why This Phase Exists

ARC already accepts normalized runtime-attestation evidence, but workload
identity is still mostly opaque to the core and policy layers. The next
milestone needs one explicit contract for how workload identity is parsed,
bound, and exposed to policy instead of treating upstream verifier inputs as
anonymous metadata.

## Scope

- define typed workload-identity mapping rules
- bind mapped identity into ARC runtime and policy context explicitly
- preserve fail-closed behavior for malformed, mismatched, or unsupported
  workload identifiers

## Out of Scope

- cloud-attestation verifier adapters
- trust-policy rebinding for stronger economic rights
- operator qualification and runbooks
