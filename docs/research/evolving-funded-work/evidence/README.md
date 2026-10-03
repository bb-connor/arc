# Evidence boundaries

The current composed result is
`../../dynamic-delegation/evidence/qualified-evolving-funded-work.json`.
Its source inventory, exact 21 commands, terminal exit codes and output hashes
are in the adjacent `qualification.json`. `qualification-final.log` here is
the concise terminal campaign transcript. The prior qualified campaign remains
in that directory's `history/`; it is not relabeled as evidence for this source.

`chain-regressions.json` records a supplementary run of the six opt-in Rust
chain tests. Its canonical source-inventory digest must match the 21-command
record's `source_files`, and `source_unchanged` must be true. Its two output
streams retain the actual runner summary, including filtered tests.

Other logs here are development history. Compiler, dependency, fixture and
integration failures remain failures. Files named `red` include both intended
semantic failures and unsuccessful setup attempts; the review identifies the
specific intended route-removal failure. `integration-fifteenth.log` records
the successful prequalification trajectory, superseded for current qualification
by the source-bound campaign. These logs are not additional independent trials.

Raw command output is retained byte-for-byte, including test-runner whitespace.
Public signed artifacts are included in the qualified trajectory. Private
receiver databases and signing keys are excluded from this package.
