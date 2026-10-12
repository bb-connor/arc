# xtask architecture

## Responsibility and boundary

This package is a workspace binary with no public library target.
`cli::Cli` parses the command tree, `dispatch::dispatch` selects handlers,
and `main` converts handler results into process exit status. The Cargo alias
for `xtask` invokes the package with arguments after `--`.

The task runner owns developer gate orchestration and artifact generation.
Individual handlers define their evidence boundary: schema validation checks
instances, formal mirrors check registered source digests, and launch acceptance
runs configured verifiers unless schema-only mode was selected.

## Structure

| Modules | Responsibility |
| --- | --- |
| `cli`, `dispatch`, `error` | Arguments, aliases, handler routing, failures |
| `support` | Invocation checkout discovery, temporary directories, file helpers |
| `codegen` | Rust, TypeScript, Go, Python generators and error regeneration |
| `scenarios`, `vectors`, `eval_receipt_regen` | Scenario schema checks and frozen fixtures |
| `fixtures` and its facet modules | Manifest-directed schemas, metadata, imperative checks |
| `crate_paths`, `adapter_no_bypass` | Configuration references and adapter source gates |
| `formal_mirrors`, `proof_coverage` | Source digests and verification evidence reports |
| `formal` | ITF parsing and ReceiptBeforeAllow regression generation |
| `qualify`, `launch_acceptance` | Matrix checks and acceptance bundle assembly |
| `rust_packages` | Offline preview registry, package closure, external consumer |
| `snippets_subcommand` | Editor snippet regeneration and drift checking |

Rust codegen calls `chio-spec-codegen` in process. TypeScript uses its installed
`json2ts`, Python invokes its pinned generator through `uv`, and Go delegates
to the SDK regeneration script. The tool lock records generator expectations.
Fixture dispatch is split across pheromone and runtime facet modules because
those handlers run different validation and orchestration sequences.

## Data and control flow

Clap parses nested command groups or retained flat aliases. Both generation
spellings reach the same handlers. A bare invocation prints the help tree;
unknown commands fail at parsing, and reserved command leaves return errors.

`workspace_root` canonicalizes the current directory and walks ancestors.
It checks the workspace manifest and the explicit `xtask` and `chio-core`
package names. If invocation begins within a package, that package must be an
explicit member. Git boundaries stop selection of an unrelated containing
checkout. Compiled source paths and Cargo manifest environment variables
are not checkout selectors.

Scenario validation scans JSON files in `tests/conformance/scenarios` and
indexes schema `$id` values. A string `$schema` resolves through that index
or the supported URI path mapping. Failures accumulate into a nonzero result;
instances without a string declaration contribute to the skip count.

Rust generation checks use temporary staging for the consolidated wire file
and module marker, then compare state-machine outputs. Error generation
checks stage the table and module marker. The normal writing paths target
their configured repository outputs; `--check` reports byte drift.

## Trust and invariants

`codegen_argv` refuses conflicting language selectors; a check invocation
without a language reaches the Rust default. Fixture manifests must enumerate
the known facets. Named Cargo filters require a reported nonzero passed count
so an empty test selection cannot satisfy a fixture gate.

Formal mirror checks normalize registered Rust symbols and compare recorded
hashes. `--bless` rewrites hashes after validation. Digest agreement describes
registered source alignment; the model and its verifier supply proof evidence.

ITF conversion accepts the ReceiptBeforeAllow replay family, limits trace input
to 16 MiB, decodes a violation witness, and derives the output filename from
the trace hash. It refuses a divergent existing output. Rust preview assembly
requires a new output directory outside the checkout and committed source
unless dirty-source labeling is explicitly enabled.

Bounded qualification validates the matrix's scope, entrypoint, gate conditions,
and referenced artifacts. Launch acceptance's schema-only mode records an
unverified verdict. Full mode invokes its verifier corpus and assembles outputs.
Some fixture and release handlers execute subprocesses; task names and reduced
modes should be chosen according to the required evidence and available tools.

## Dependencies

Clap supplies argument validation. Serde, JSON, YAML, and TOML libraries decode
gate inputs. SHA-256 binds vectors, symbols, and package artifacts. `syn`,
`quote`, and `proc-macro2` inspect Rust syntax; `toml_edit` preserves manifest
structure while blessing digests. `chio-spec-validate` and `chio-spec-codegen`
provide schema operations, and `chio-eval-receipt` supplies golden report data.
`chio-formal-diff-tests` is a development dependency for replay tests.

## Verification

`cargo test -p xtask` covers CLI aliases, mutually exclusive modes, unknown
facets, schema checks, empty Cargo selections, path resolution, source-digest
validation, and evidence report parsing. `tests/workspace_root.rs` exercises a
reused binary against separate invocation checkouts and rejected nested roots.
`tests/itf_to_regression.rs` checks deterministic output and malformed traces;
`tests/qualify_parity.rs` checks the bounded matrix entrypoint spelling.

The [README](README.md) uses the read-only crate-path gate as its example.
[Generator pins](codegen-tools.lock.toml) record external tool versions;
the [certification contract](../spec/PROTOCOL.md#12-certification-contract)
defines the separate signed certification surface.
