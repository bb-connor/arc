# Local qualification evidence

See the [execution record](../../2026-09-29-security-module-boundaries-execution.md)
for scope, results, rulings and remaining gates. `manifest.json` hashes the
retained logs and inventories. This directory is local evidence, not hosted
qualification or release acceptance.

- `review-focused-results.json`: final broker/control commands, terminal exits
  and elapsed time after the ownership fixes. Detailed output is in the matching
  `*-review-final.log` files.
- `final-focused-results.json`: SQLite integration and native ledger qualification,
  plus the earlier control selection. `ports-*`, `helper-*`, `chio_cage*` and
  `nono-*` retain the other focused results.
- `compiler-privacy-red.json`: actual sibling accesses compiled before the final
  fixes. `compiler-privacy-green.json`: the compiler rejects those accesses after
  the fixes; Cargo exit 101 is expected for these negative probes.
- `final-test-inventory.json`: no original test cases removed; one added
  control-plane reconstruction test. The helper entrypoint integration test is
  added separately. Before/final inventories retain every exact test name.
- `release-package-red.log` and `release-package-green.log`: the source gate
  catches the old release package and passes after its correction. The hostile
  enforcement suite also tests a reintroduced old package command.
- `clippy-review-final.log`, other gate logs and `helper-artifact.txt`: terminal
  compiler/source checks and the measured aarch64 musl artifact.
- `ledger-*`, `host-crash-*`, `capture-*` and `chio_control_plane-tests.log`:
  investigated failures. The parallel campaign was stopped and is not green.
  The host crash and obsolete ledger assertion are repaired; native-flow policy
  expiry under debug-profile load remains an open fixture qualification issue.
- `progress.md`: execution ledger, including every ruling and final task status.

`compiler-privacy.py` can repeat the compiler probes from an isolated checkout
root. Pass an output directory as its first argument. It temporarily appends
negative probes to real transport/orchestration modules and restores the files
in `finally` blocks. Run it without concurrent source edits or Cargo commands.
It is retained as reproducible review evidence; it is not a new hosted CI job.

No native x86_64 enforcement, complete broker process campaign, full parallel
native-flow suite, full-workspace campaign or hosted run is claimed here.
