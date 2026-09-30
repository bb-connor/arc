# Remaining CLI reader evidence

Base: `da4086017f`; branch `packet/3-retention-accounting`; local Linux aarch64.
The [execution record](../../2026-09-30-cli-remaining-readers-execution.md) describes
the delivered contracts and remaining acceptance boundaries.

## Scope and review

- [29 reader contracts](reviewed-readers.json) dispose the preceding handoff.
- [Supporting owners](supporting-owners.json) include bounded collection/archive
  custody, wiping profile fields and fallible relay time. The transport callback
  change does not dispose that transport's independent reader debt.
- [Review resolutions](review-resolutions.md) record the one independent review
  and the repairs. No second independent approval is claimed.
- [Next readers](next-readers.json) pin the 28-file protocol continuation.

## Commands and terminal evidence

Build environment: `CARGO_TARGET_DIR=/home/connor/chio-security-target-6d-final`,
`CARGO_INCREMENTAL=0`, `CHIO_CHECKOUT_ROOT=/tmp/arc-security-launch`.

```sh
cargo test -p chio-cli -p chio-control-plane --features chio-cli/iroh \
  --bin chio --lib --test native_mcp_demo_provision --test mcp_wrap_e2e \
  --test workflow_preflight --no-run --locked --message-format=json
```

Cargo JSON output identified the exact executable paths. Tests invoke those
executables directly with `CHIO_CHECKOUT_ROOT` set. The CLI unit selection is:

```text
input:: archive:: dispatch_cli::finding_cmd:: chio_dispatch::pheromone::
chio_dispatch::treaty:: mcp_cli::cage_policy:: mcp_cli::provision::
mcp_cli::wrap:: runtime_cli:: lineage:: market::
```

The three integration executables run in full; the control-plane library uses
`finding_operator_profile`. This does not run every CLI or control-plane test.

The final build passes, with **266 tests passing**: 247 selected CLI units,
9 native provisioning fixtures, 2 MCP end-to-end tests, 7 workflow preflight
tests and 1 partial-profile custody test. All listed inventory and formatting
checks pass.

Final terminal results and source/binary identities are in
[qualification.json](qualification.json) and [source-hashes.json](source-hashes.json).
The successful integration controls exercise local fixtures and signed admission;
they do not qualify live x86_64 host enforcement.

Inventory checks:

```sh
python3 scripts/check-trust-boundaries.py
python3 scripts/check-rust-file-hygiene.py
python3 scripts/check-security-clocks.py
python3 scripts/check-accounting-arithmetic.py
python3 scripts/check-negative-assertions.py
python3 scripts/check-wire-schemas.py
```

Changed `.rs` and `.inc` files pass `rustfmt --edition 2021 --check --config
skip_children=true`. The wire snapshot removes only the retired status-floor v1
identifier. No size limit or assertion/clock ratchet was relaxed. The arithmetic
scanner's zero findings apply to its configured scope; the separate semantic
review inventory still has 85 pending entries.

## Failed attempts retained

- [Initial build](build.log) and [diagnostics](build-diagnostics.log): missing
  import, fallible-clock propagation and the removed optional-key fixture.
- [Second build](build-2.log) and [diagnostics](build-2-diagnostics.log): succeeded;
  its selected unit run had [231 passes and 14 failures](unit-initial.log).
- Those failures concerned old string-error assertions, unsafe fixture key modes,
  and a mocked publish digest inconsistent with its artifact. Tests now inspect
  typed causes, supply private fixtures, and bind the actual artifact digest.
- [Third build](build-3.log) and [diagnostics](build-3-diagnostics.log): one missing
  constant qualifier in the updated test assertion; corrected before the retry.
- [Fourth build](build-4.log) and [245 passing units](unit-pre-custody-replay.log)
  qualified the main repairs. Final implementer review then closed private
  initialization replay custody and added two owner controls. The fifth build
  includes all final source and formatting changes.
- [Initial file hygiene](file-hygiene-initial.log), [wire snapshot](wire-initial.log),
  [trust inventory](trust-boundaries.log), and [format check](format-initial.log)
  failures remain visible. Resolutions are a real reloader module split, deletion
  of the obsolete wire identity, removal of a test-only reader registration, and
  restoration of the repository's Rust 2021 formatting.

Only trailing whitespace and terminal blank lines are normalized in retained logs. Initial failures are
not counted as passing evidence. No per-fix red/green campaign is claimed. Optional
TEE backends, workspace-wide builds/clippy, hosted CI, M5, merge, publication and
external activation are outside this local batch.
