# Phase 207: MERCURY Shared Proof-Profile Interoperability and Reviewer Distribution Path - Context

**Gathered:** 2026-04-03
**Status:** Complete

<domain>
## Phase Boundary

Implement one repo-native trust-network export path that composes the
embedded-OEM lane into one bounded shared proof, inquiry, witness, and
interoperability bundle for counterparty review.

</domain>

<decisions>
## Implementation Decisions

### CLI and Export Surface
- add a dedicated `trust-network` command to the `mercury` binary
- keep the export path composed from the embedded-OEM lane rather than a new
  truth path
- emit one bounded trust-network summary, manifest, proof package, inquiry
  package, witness record, and trust-anchor record

### Reviewer Distribution
- keep the reviewer path bounded to the same `counterparty_review` package
  family
- reuse the same qualification and reviewer artifacts from the embedded-OEM
  lane
- add dedicated CLI tests proving the export shape and validation path

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `commands.rs` already composes each Mercury lane on top of the previous one
- `embedded-oem` already stages the partner bundle and reviewer package family
- `cli.rs` already tests export and validate flows for every bounded Mercury lane

### Integration Points
- `main.rs` must expose the new command
- `commands.rs` must generate trust-network export and validation bundles
- `README.md` and the new trust-network docs must point to the same command names

</code_context>

<deferred>
## Deferred Ideas

- multiple reviewer populations in the trust-network lane
- generic trust-service APIs
- ARC-Wall-specific exports

</deferred>
