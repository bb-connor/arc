# Inline checkpoint handoff review

Reviewed directly by the implementing agent under the user's no-subagent
instruction. This is an inline review, not an independent code review.

The first version checked for incompatible local/external checkpoint records
before acquiring a journal transaction. That allowed concurrent writers to both
select first custody. Selection now uses `Journal::retain_before`: the absence
check and insertion share one immediate transaction. Local checkpoint creation
excludes an external request; external export excludes a local checkpoint,
evidence bundle, submission or decision. Exact retries preserve original bytes.
The regression verifies that an external handoff prevents a subsequent local
checkpoint write and that valid external import can still complete.

Reviewed source provenance: export reads original native records and invokes the
kernel's qualified execution exporter; import requires the exact retained request,
native projection and original output before checking all pinned source bindings.
Artifact CLI handles disable startup reconciliation and have no functioning
funding observer. Financial claim/decision/payout/refund retain their existing
original-authority verification. No new operation, hold or payment path is added.

Reviewed key and custody boundaries: operator enrollment is a separate
administrative input, not a request-derived trust root. Fresh signing checks
original keys and current authority standing. SQLite serializes first signing and
commits the whole request/response before publication. Replay validates retained
signatures and original bytes without private-key access. Missing database/row,
corrupted response and changed requests fail. Provider import authenticates both
status signatures and denies observed revocation before retaining a checkpoint.

Reviewed failure ordering: an output-file conflict leaves existing bytes intact
after operator response custody commits. The same response remains retrievable
without keys. Partial first provider import can complete using the original
checkpoint. Loss after Finding issuance cannot be repaired by a replacement
response. Existing capture-waiver, earned-child and execution-custody SIGKILL
regressions pass on the unchanged final executable.

Reviewed public artifacts: requests/enrollment/responses use canonical typed
bounded input, exact output files, existing pinned authority roles and no new
financial backing claim. Public fixtures contain no key seeds or capability
tokens. Receipt actions contain the public W0 input. The Python implementation
verifies both actual operator-produced witnesses and rejects the mismatched
submitted result while preserving the valid execution-authority assessment.

Limits retained explicitly: one administrator in the reproduction, transferred
fixture keys, one receipt per enrolled log, local custody without an external
rollback anchor, no external revocation feed, no independent checkpoint signer
implementation, no remote CI, no public-chain qualification and no real funds.
