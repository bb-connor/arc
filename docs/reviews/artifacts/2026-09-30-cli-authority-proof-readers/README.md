# CLI authority and proof-reader evidence

Base: `943482d2cb82a1cf466584b47aee6b509c921d90`, local branch
`packet/3-retention-accounting`, worktree `/tmp/arc-security-launch`.
Implementation is local and has not been pushed, merged or release-qualified.

[Source hashes](source-hashes.json) identify all 52 changed/new Rust-source and
crate-manifest files. [Qualification metadata](qualification.json) records the
platform, compiler and executable hashes. [Reader dispositions](reviewed-readers.json)
cover the exact 26-file batch; [supporting owners](supporting-owners.json) include
the removed manifest converter and typed error adapters. One independent review
and all nine resolutions are recorded in [review-resolutions.md](review-resolutions.md).

| Check | Terminal result | Evidence |
| --- | --- | --- |
| CLI authority/proof/trust/input unit filters | 92 passed, 601 outside filters | [unit-final.log](unit-final.log) |
| Real CLI collection/export/explain/verify/fixture integration | 129 passed, 18 server cases outside filters | [proof-final.log](proof-final.log) |
| Manifest v2 | 25 passed | [manifest-binding-final.log](manifest-binding-final.log) |
| SDK vectors | 8 passed, 8 regeneration helpers ignored | [manifest-binding-final.log](manifest-binding-final.log) |
| Changed-file formatting and Rust file hygiene | Passed | [format](format.log), [hygiene](file-hygiene.log) |
| Trust boundaries and semantic census | Passed; 223 baseline files remain, 29 in CLI | [gate](trust-boundaries.log), [census](inventory.log) |
| Clock/accounting/assertion/schema ratchets | Passed in configured scopes | [clocks](clock-ratchet.log), [accounting](accounting-ratchet.log), [assertions](assertion-ratchet.log), [schemas](schema-ratchet.log) |

Total: **254 passing tests**. No workspace-wide build or lint campaign was run.
No Windows or native enforcement qualification is inferred from these tests.

Build environment: `CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`,
`CARGO_INCREMENTAL=0`, `CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`.
The terminal CLI compilation was:

```sh
cargo test -p chio-cli --bin chio --test proof_cli_contract --no-run --locked --message-format=json
```

The resulting `chio` unit-test executable ran these libtest filters together:
`input::`, `active_defense_migration::`, `active_response_authority::`,
`passport::`, `cert::`, `chio_dispatch::runtime::`, `dispatch_cli::proof::`,
`trust_commands_cli::`, `admin::`, with `--test-threads=2`.
The `proof_cli_contract` executable ran `export::`, `explain::`, `collect::`,
`verify::`, `fixture::`, also with two test threads. Its subprocesses exercise
the actual newly compiled `chio` command.

```sh
cargo test -p chio-cli -p chio-manifest -p chio-binding-helpers --test manifest_v2 --test vector_fixtures --locked
python3 scripts/check-trust-boundaries.py
python3 scripts/check-rust-file-hygiene.py
python3 scripts/check-security-clocks.py
python3 scripts/check-accounting-arithmetic.py
python3 scripts/check-negative-assertions.py
python3 scripts/check-wire-schemas.py
```

The CLI package in the manifest/vector command preserves dependency-feature
unification with the CLI build; that command does not run every CLI target.
Changed `.rs` and `.inc` files additionally pass `rustfmt --edition 2021 --check
--config skip_children=true`, including modules hidden from workspace formatting
by existing `include!` roots. No file-size cap was increased.

[Compiler attempts](compiler-attempts.log) preserve failed diagnostics and terminal
build status. Only trailing blank lines are normalized in retained logs. Early errors were mechanical module paths/imports/test fixture
construction and the runtime tempfile dependency initially remaining dev-only.
[Initial unit failures](unit-initial.log) concerned a direct noncanonical reason
without a nested source and an invalid fixture trust level. Those controls now
assert the real typed reason and valid signed receipt semantics.

[Initial proof failures](proof-initial.log) and the
[expanded run](proof-expanded-initial.log) rejected their inputs but exposed a
loss of actionable public reasons. The final adapters preserve concrete native
causes and expose only selected static diagnostics. Assertions retain specific
reasons and integrity/schema exit codes. The symlink diagnostic and malformed
manifest assertion now target the current owner rejection.

The [initial schema failure](schema-initial.log) required acknowledging removal
of the manifest-v1 declaration. The [snapshot update](schema-update.log) retires
that identifier and refreshes four existing report line anchors; the final gate
passes. The clock inventory still has 154 occurrences, the assertion baseline
1,257 assertions at 1,175 sites, and the schema lock 163 duplicated identifiers.
The separate 85 pending semantic arithmetic entries remain open.

The [next 29 CLI readers](next-readers.json) are the next concrete execution
queue. Broader protocol/product review, structural/declaration work, retention,
sanitisers/formal correspondence, source audits and hosted/M5 gates remain
separate acceptance boundaries.
