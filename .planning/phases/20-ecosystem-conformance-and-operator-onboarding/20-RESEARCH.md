# Phase 20: Ecosystem Conformance and Operator Onboarding - Research

**Researched:** 2026-03-25
**Domain:** Operator onboarding, regression coverage, and milestone closeout
artifacts
**Confidence:** HIGH

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| ECO-01 | Conformance and CI coverage prove the new A2A auth, lifecycle, and certification-registry flows across supported operator surfaces | The adapter library suite plus CLI certification and provider-admin integration suites already hit the right surfaces and just need to be treated as milestone verification lanes |
| ECO-02 | Docs, examples, and operator/admin surfaces are sufficient to onboard an A2A partner or certified tool server | The existing A2A and certification guides are the right operator entry points and can be updated without inventing a new documentation system |

</phase_requirements>

## Summary

Phase 20 should avoid creating ceremony. The strongest closeout is to make the
shipped behavior easy to verify and easy to adopt, using the existing test
harnesses and operator docs that already frame these surfaces.

The important constraint is truthful documentation. The guides should explain
only what is actually implemented in v2.2 and keep future partner-network or
public-registry ideas clearly out of scope.

## Recommended Architecture

### Coverage
- use the adapter library test suite as the A2A auth/lifecycle regression lane
- use `certify.rs` integration tests for certification registry parity
- use `provider_admin.rs` as the admin compatibility regression

### Documentation
- update `A2A_ADAPTER_GUIDE.md` for request shaping, partner admission, and
  durable task correlation
- update `ARC_CERTIFY_GUIDE.md` for verify and registry-backed flows
- record milestone-visible deltas in `CHANGELOG.md`

### Closeout
- create phase artifacts for 17 through 20
- update roadmap, requirements, project state, and milestone summary documents
- run roadmap analysis after the planning update

## Validation Strategy

- `cargo test -p arc-a2a-adapter --lib -- --nocapture`
- `cargo test -p arc-cli --test certify -- --nocapture`
- `cargo test -p arc-cli --test provider_admin -- --nocapture`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs roadmap analyze`

## Conclusion

Phase 20 is successful when v2.2 is not only implemented, but supportable:
operators can follow the docs, tests prove the surfaces, and the planning
records trace the milestone end to end.
