# Phase 59: Attestation Trust Policy and Runtime-Assurance Rebinding - Context

## Goal

Make attestation trust policy explicit and bind verified workload or
attestation evidence back into ARC issuance, approval, and runtime-assurance
decisions.

## Why This Phase Exists

Phases 57 and 58 establish identity mapping and at least one real verifier
bridge. ARC still needs a policy layer that says which verifiers are trusted,
how long evidence is valid, and how stronger verified evidence can narrow or
widen runtime-assurance semantics.

## Scope

- define attestation trust policy inputs
- bind verified evidence into runtime-assurance or policy decisions explicitly
- preserve least-privilege semantics and fail-closed verifier handling

## Out of Scope

- milestone-wide qualification and runbooks
- any generic theorem claim beyond executable behavior
