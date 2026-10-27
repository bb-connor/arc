# xtask

`xtask` is Chio's workspace task binary. It dispatches schema generation,
fixture gates, scenario validation, formal evidence checks, and release artifact
assembly. The Cargo alias in `.cargo/config.toml` runs this package.

## Usage

From the intended workspace root, validate configuration references to crate paths:

```sh
cargo xtask check crate-paths
```

This command reads repository configuration and reports unresolved crate references.
It requires no service, generator tool, or generated-file rewrite. The handler
also recognizes final filename globs and requires at least one matching entry.

Task root discovery starts from the invocation's current directory, including
when an executable was compiled in another worktree. Run a saved binary from
the intended checkout or a member subdirectory. An unrelated Git repository,
Cargo workspace, or nonmember package stops root discovery.

## Commands

| Command family | Implemented work |
| --- | --- |
| `gen` | Rust/TS/Go/Python bindings, errors, snippets, vectors, proof coverage |
| `check` | Adapter boundaries, crate paths, formal mirrors, named fixture facets, web3-free closure |
| `validate-scenarios` | Validate each scenario declaring a string `$schema` |
| `qualify bounded-chio` | Validate the bounded matrix and referenced artifacts |
| `verify launch-acceptance` | Assemble a Proof Room acceptance bundle |
| `formal itf-to-regression` | Convert the ReceiptBeforeAllow ITF replay family |
| `release rust-preview` | Assemble an offline registry and external consumer |

Generation leaves support `--check` for drift detection. Formal mirrors use
check mode by default and write recorded hashes with `--bless`.
Fixture gates accept `--schema-only` or `--negative-only` as mutually exclusive
modes; their full handlers can run Cargo, CLI, shell, or dashboard checks.
`check web3-free-closure` reads the modes in `ci-gates/web3-free-closure.toml`
and resolves each mode's roots on their own (`cargo tree -p <root> -e
normal,features`, plus `--features <set>` for an opt-in mode). The `default`
mode fails if a closure reaches a web3 or finding-market package or enables a
`web3` or `finding-market` feature; the `web3` mode requires settlement and
web3 crates and denies finding-market ones; the `web3-finding-market` mode
requires both. Each failure names the root, the mode and the item; a denied
item also carries the inverted path back to the root, the root's direct
dependencies that reach it, and the `cargo tree -i` command that shows every
path. `--mode <name>` and `--root <crate>` (both repeatable) limit the run to
listed entries; an unlisted name, a malformed policy file or a failed
`cargo tree` is an error. The gate implements
[ADR-0035](../docs/adr/ADR-0035-web3-free-distribution.md) and is not yet
required in CI.

```sh
cargo xtask check web3-free-closure
cargo xtask check web3-free-closure --mode default --root chio-core-types
```

Flat aliases retain `codegen`, `errors regen`, `snippets regen`,
`freeze-vectors`, and `eval-receipt-regen` spellings.

## Guarantees

- `support::workspace_root` selects the current checkout and verifies its
  explicit `xtask` and `chio-core` members and package names.
- `dispatch::codegen_argv` rejects supplying both positional and flagged
  language selectors. `codegen --check` defaults to Rust when neither is supplied.
- `scenarios::validate_scenarios` fails for an unresolvable declared schema
  and reports scenarios without a string `$schema` as skipped.
- Rust and error generation checks compare staged bytes with committed
  outputs; the Rust check also verifies generated state-machine outputs.

## Status

The package ships one binary, has no library target, and is marked
`publish = false`. The `fuzz`, `mutants`, `supply-chain`, and `tools` groups
have reserved leaves that return errors. Acceptance assembly's `--schema-only`
mode records `schema-only-unverified`; full acceptance runs its configured
verifiers. Bounded qualification checks its declared matrix contract and files.

`cargo test -p xtask` covers argument dispatch, gate validation, invocation
checkout selection, and ITF regression conversion. Command-specific external
tools and fixture requirements live in each handler and its configuration.

## Related

- [Architecture](ARCHITECTURE.md)
- [Certification contract](../spec/PROTOCOL.md#12-certification-contract)
- [Schema generator](../crates/tooling/chio-spec-codegen/README.md)
- [Schema validator](../crates/tooling/chio-spec-validate/README.md)
- [Generator tool pins](codegen-tools.lock.toml)

## License

[Apache-2.0](../LICENSE)
