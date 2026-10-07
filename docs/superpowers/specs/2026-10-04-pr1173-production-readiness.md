# PR 1173 production readiness

The requested outcome is a qualified production candidate for the verifiable-work
integration, starting at `14477aaac8998f623bf49f9fd4dac6966c2d6cff`. Work is
authorized inline, without subagents, in the existing isolated worktree. The
security and recovery agents' other checkouts remain separately owned.

The refreshed baseline has 76 successful checks, seven failures, eight skips and
two cancellations. Actual x86 native host, worker, installed consumer recovery,
SDK parity and Drogon checks now pass. The remaining failures are Cargo Vet,
advisory scanning, PostgreSQL native qualification, two stale crypto test
inventories and two Kani lanes. Cancelled mutation and fuzz campaigns are not
passing evidence.

## Required properties

1. Every selected CI test and proof must run. Exact inventories include the new
   pending-intent and typed-proposal regressions. Kani uses a pinned released
   compiler plus upstream PR 4819's signature repair, compatible with workspace
   Rust 1.95; no MSRV bypass, smaller proof
   selection or weakened assertion is acceptable.
2. Remediate the reported dependency vulnerabilities through supported patched
   versions, removal of unnecessary vulnerable dependencies, or a reviewed
   source fix when upstream has no release. Do not add advisory suppressions.
   Preserve unrelated lockfile selections where the resolver permits it.
3. Cargo Vet must pass with genuine audit evidence. Checksum and provenance
   checks establish source identity, not safety. Review the AWS-LC Rust wrapper's
   unsafe/FFI, secret lifecycle, parsing and build boundaries, plus the local
   fork separately. Reuse the recorded exact-source sys audits only after
   verifying their scope and pinned versions. New dependency audits require the
   same standard or existing trusted upstream audit records.
4. PostgreSQL remains the actual TLS-verified durable resource. Preserve least
   privilege roles, capability-derived lease ownership, fencing, receipt
   verification and uncertain-effect recovery without redispatch. The caged
   executable must not gain ambient socket/connect or process creation rights.
   Reuse the existing prepared broker and native transport architecture where
   it satisfies these requirements. Specify its concrete composition before
   implementing a new transport boundary.
5. Completion requires source-bound local qualification and terminal hosted
   results for the exact pushed SHA. Failed and cancelled attempts remain
   retained with their identities. Review the final changes in a separate pass.

## Architecture decisions

Repair existing gates in place. Kani 0.68.0 ships nightly-2026-08-21, avoiding the
0.67.0 compiler/MSRV mismatch. The release has a compiler assertion defect fixed
upstream in PR 4819. Rebuild only the compiler from the exact release with that
one-line fix; retain rustc, CBMC, the proof selection and proof options. Bind the
cache to the compiler hash and source revision. Require a successful proof and
an unsupported-intrinsic rejection before accepting the installation.

Reuse merged security prerequisite PR 1168, including its completed AWS-LC
source review, exact repaired fork, authenticated reconstruction gate and
Wasmtime 48.0.5 with Rust 1.95. Retain this branch's additional source patches,
SDK membership, signed receipt verification and Docker source-closure checks.
The two new npm tooling advisory dispositions in that prerequisite remain open
for this task until repaired; inherited scanner success does not close them.
There is no Wasmtime WASI dependency in the selected guard backend. Retest the
existing guard boundary rather than changing its security model.

For PostgreSQL, broadening native-standard-v1 is rejected: it would change every
consumer's isolation to accommodate one resource. A parallel authority or
settlement system is also rejected. The resource belongs behind the existing
authenticated host/broker boundary, with a confined tool receiving only the
already authorized operation. A focused subordinate design will pin this route
against the current native broker interfaces before implementation.

## Scope of the verdict

This closes the identified production candidate blockers. It does not establish
the paper's independent-operation or economic research claims, merge the PR,
publish a release, or authorize a production deployment. Those are different
acceptance boundaries and must remain accurately labelled.

## Primary references

- [Kani 0.68.0 release](https://github.com/model-checking/kani/releases/tag/kani-0.68.0)
- [Pinned Kani compiler](https://github.com/model-checking/kani/blob/kani-0.68.0/rust-toolchain.toml)
- [Kani signature repair](https://github.com/model-checking/kani/pull/4819)
- [Audited dependency prerequisite](https://github.com/bb-connor/arc/pull/1168)
- [Wasmtime host allocation advisory](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-jqpg-j7w6-42pr)
- [Prepared broker connections](../../security/broker-prepared-connections.md)
- [Supply-chain review policy](../../../supply-chain/README.md)
