# Supported Wasmtime security migration

The guard runtime moves from Wasmtime 46.0.3 to supported 48.0.5 to repair
RUSTSEC-2026-0316 and RUSTSEC-2026-0327. Its default real component backend
and asynchronous component support remain enabled. No advisory suppression
is introduced for either finding.

The upstream advisory bounds require at least 48.0.3 for dynamic-record
lifting and at least 48.0.4 for callback result-count validation:

- <https://rustsec.org/advisories/RUSTSEC-2026-0316.html>
- <https://rustsec.org/advisories/RUSTSEC-2026-0327.html>

Upstream 48.0.5 declares Rust 1.95.0 as its minimum. The workspace minimum
therefore deliberately moves to Rust 1.95 and its pinned toolchain to
1.95.0. Current build/MSRV workflow lanes and their contract controls use
that version. The explicit lower minima of the core/security types and
historical standalone formal-model qualification remain unchanged.

The supported 36.0.17 LTS alternative was examined: it repairs the relevant
advisory bounds but lacks the `wasmtime::component::HasSelf` API used by
the current host adapter. Version 49.0.2 requires Rust 1.96.0. Choosing
48.0.5 preserves the current adapter API while taking the supported repair.

The narrow graph update advances Wasmtime/Pulley, matching Cranelift and
wasm-tools dependencies in the root, standalone fuzz and generated CLI-only
Docker workspaces. Cargo-vet refreshes genuine configured upstream
audit feeds and publisher metadata. The newly selected cpp_demangle is an
owned, provenance-tracked backport of its actual upstream transparent-layout
repair; its original registry release receives no new certificate.

A fresh isolated Rust 1.95.0 guard build and all-target test run pass,
including 29 real sandbox escape regressions and the Rust guard examples.
The added callback tests compile a correctly typed asynchronous component
and reject zero, two and 32 callback results before execution.
Six TypeScript artifact-dependent cases remain explicitly ignored; absent
optional Go/Python artifacts do not establish those SDK qualifications.
All-target/all-feature Clippy passes on Rust 1.95.0. Two equivalent match
guards keep the fuzz generator's existing import refusal and first-function
selection; its actual component allow/deny controls both pass.
Current production builder parity covers all five Dockerfiles. The security
runner's actual new archive, package and image qualifications are recorded
separately in [the image migration record](../../docs/security/execution-image-inputs-rust195.md).
Workspace-wide and cross-platform acceptance are separate required checks.
