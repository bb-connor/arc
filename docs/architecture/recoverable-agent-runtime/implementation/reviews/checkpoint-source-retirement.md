# Checkpoint source retirement

`CK-LEGACY-RETIREMENT-SOURCE-01` has a bounded local closure at source commit
`7f5163ac4e8d0ef10f8ca0af41f2c8ea82542b69`. Independent specification and quality
reviews passed with no findings on the exact nine committed files. Confidence
is high for this contract. The runtime remains unqualified.

Retirement now preserves the physical key selected by the identity-safe loader,
checks its canonical checkpoint envelope, and retires that authenticated source.
A colliding foreign legacy revision slot no longer replaces the requested
checkpoint's source. Existing administration, audience, transaction and protected
reference checks remain intact. There is no production API or schema change.

The regression fixture writes typed predecessor originals before normal cold
activation, using real broker seals and the protected writer. It creates no
ownership index, Ready marker, loan or modern checkpoint alias. This models the
predecessor format; it does not qualify a historical executable. Positive public
reads and restores precede retirement. Tests then cover foreign-owner retention,
actual retirement-write rollback, own collection, foreign restore, replay,
reopen and revision advancement without reset. Rollback compares every recovery
record's key/version/payload plus event and commit counts, rather than every
historical event's bytes.

| Execution | Recorded result |
| --- | --- |
| Genuine pre-fix regression | Requested retirement failed after positive cold-source/read/restore/pin controls. |
| Final clock guards and retirement regressions | 4 passed, 0 failed, 0 ignored. |
| Store checkpoint module | 14 passed, 0 failed, 0 ignored. |
| Corrected chunked custody/reopen case | 1 passed, 0 failed, 0 ignored; 1180.70 seconds of test execution, within the unchanged 1200-second command bound. |
| Earlier full Control Plane checkpoint module | 21 passed, 2 failed, 0 ignored. This failed run is preserved and was not replaced by a claimed full-suite pass. |

The long case originally exhausted its signed 600-second capability while
performing slow fixture work. Only that synchronous test now opts into the
existing thread-bound Kernel clock, shared with fixture time. Guard tests cover
nesting, unwinding and thread isolation. Production time, receipt identifiers and
capability lifetime are unchanged. The passing case retains the original signed
capability and process identity across delivery, acknowledgement loss, replay
and reopen.

Strict lints remain failed. Default Store Clippy reports the same 248 normalized
diagnostics as its recorded baseline, with no additions or removals. The feature
configuration reports 247 diagnostics without a pre-change feature baseline;
two mentions of a changed file concern unchanged imports, and none concern
added or changed lines. Control Plane Clippy reports 10 diagnostics at nine
locations in unchanged files. These failures receive no lint acceptance credit.
The other full-module failure remains in the native-recipient setup prerequisite,
before its intended checkpoint restore. That dependency remains unresolved.

The canonical register preserves all three original obligations and records
their satisfaction through an additive successor. This closes only the additional
checkpoint P2. `E-knowledge-01` still needs revalidation, and
`R2-R-checkpoint-01` remains open. No canonical finding, candidate issue, phase
or broader qualification gate is closed by this repair.

Source pins, exact commands, raw failed and passing logs, independent reviews
and installation readback are retained in
`target/recovery-pr/current-review-followup/runtime-integration-successor-20261009/checkpoint-retirement/`.
The register's successor pins the source and review reports. `HANDOFF-final.md`
summarizes the execution limits; `installation.json` verifies that committed
source equals the reviewed and executed bytes.

The independent CI repair at `f7ed089c5b9506a58b314a5de6efe1c4ad1f76a0` adds
the exact stacked PR base to required CI and keeps the direct FIPS trigger
complementary. Both independent reviews, routing controls, validators,
actionlint and existing workflow tests passed. The actual
[required workflow run](https://github.com/bb-connor/arc/actions/runs/37988251384)
was created for that commit; its observed 23 queued and two skipped jobs provide
no hosted qualification. Its source and review packet is the adjacent
`ci-readiness/` directory. Later heads require their own hosted results.
