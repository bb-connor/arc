# Phase 24 Research

## Findings

1. `README.md` still used a pre-release/scoped-`v1` framing even though the
   repository had already closed `v2.2` and defined `v2.3`.
2. `docs/release/RELEASE_CANDIDATE.md` and `docs/release/RELEASE_AUDIT.md`
   still described the older scoped `v1` release candidate instead of the
   current production-candidate surface.
3. `packages/sdk/arc-ts/package.json` already used `@arc-protocol/sdk`, but
   the README still advertised `@arc/sdk`.
4. Python and Go SDK READMEs were mostly accurate but still needed explicit
   alignment to the current `v2.3` protocol and release docs.
5. There were no dedicated standards-submission artifacts yet for receipts or
   portable trust.
6. There was no explicit GA checklist or risk register, which meant the
   launch-readiness claim would still rely too much on prose and roadmap state.

## Chosen Cut

- `24-01`: align README, SDK docs, and release-candidate docs to the current
  production contract
- `24-02`: add repository-local standards profiles for receipts and portable
  trust
- `24-03`: add the GA checklist, risk register, and updated release audit
