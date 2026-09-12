# Paper Evidence Ledger

This file maps the paper's results to the implementation, tests, proofs, and
measurements that support them. It is a review aid, not part of the protocol.

Target venue: USENIX Security 2027 (submission cycle to be confirmed).

## Supported results

| Result | Evidence | Scope |
| --- | --- | --- |
| Receiver-owned treaty checks run before a cross-organization tool call. | `ChioRuntimeAdmissionHook::evaluate`; runtime admission tests; dispatch-capable admission benchmarks | Trusted runtime classification, kernel, and stores |
| Request metadata cannot install the receiver's trust roots or dynamic trust bundle. | `treaty_ref_from_request` reads identifiers and digests only and resolves artifacts from `RuntimeAdmissionStores`; request-smuggling tests cover the explicit denylist | Provisioning outside the request path is an operational control |
| Two distinct configured keys sign the same canonical treaty-bound predicate. | `verify_chio_bilateral_dsse_envelope`; strict bilateral verifier tests | Proves key control, not independent organizational control |
| Accepted treaty material remains bound to the request and signed receipt. | `VerifiedFederationTreatyMaterial`; kernel federation and receipt tests | Applies to the tested construction and receipt paths; the admission-report digest is bound from the local accepted report, not compared with a peer-supplied value |
| A treaty continuation is consumed once and replay denies. | Runtime admission tests for accepted, stale, replayed, and released continuations | Consumed during admission evaluation; released only on pre-dispatch denial or abort; durability depends on the configured store |
| Peer pins, ladder-manifest freshness, and the revocation epoch are checked in offline buyer review. | `verify_chio_bilateral_invocation` called from `verify_package`; buyer-review tests | The pre-dispatch hook does not perform these checks |
| The Lean finite-domain checker implements the stated implication for every receipt in its supplied domain. | `finite_refinement_sound`; `finite_refinement_exact` in `ReceiptPredicate.lean` | The caller is responsible for choosing a complete domain; Rust complexity limits are outside the theorem |
| The independent Rust interpreter agrees with the runtime bounded evaluator on the test corpus. | `treaty_predicate_diff.rs`; every atom; 1,024 cases for each compound property | Inputs are within the runtime limits; this is differential testing, not extraction or a Rust refinement proof |
| All 20 named negative cases return the expected denial. | `treaty-runtime-negative-corpus.json`; matrix runner | Named attacks only; five cases run through the admission hook, three through the strict operational verifier, six through the envelope verifier or signer, three through the partial verifier, three through pure runtime-core validators |
| An admitted cross-organization call pays the full pre-dispatch hook cost and dispatches exactly once. | Criterion allow benchmark with a dispatch counter equal to the iteration count and a signed SQLite receipt | Single-host release-profile configuration; in-memory admission store, SQLite receipt store |
| A unanimous policy denial leaves the tool uninvoked and writes a signed denial receipt. | Criterion deny benchmark with a dispatch counter held at zero and a signed SQLite denial receipt | The fixture returns at the policy-summary check, before treaty-binding comparison and signature verification |
| The local three-vendor workflow produces and verifies a complete buyer package. | Runtime harness, buyer CLI, package verifier | Deterministic loopback, not separately administered deployment |
| A rejection leaves the verifier as a code from a closed set fixed at compile time, never as the diagnostic that names the compared values. | `RejectionCode` with `VerifierError::redacted` and `BilateralCoSigningError::redacted`; `VerifierFailure::from_error`; `tampered_package_report_carries_the_code_and_no_package_data` and `tampered_package_report_crosses_the_boundary_as_a_code` assert that a tampered package's exported report carries `subject.digest_mismatch` and none of the package's digests, fingerprints, or verdict strings | Covers the in-process bilateral verifier, the co-signing error type, and the exported buyer report. The report's code is a section 7.1 code for a bilateral rejection and a buyer-stage category otherwise. The iroh co-sign lane's `WireReply::Err` detail is not yet reduced to a code. Log output on the verifier's own host is unchanged |

## Measurement environment

All reported measurements come from one run on the Linux aarch64 Neoverse-N1
workstation. The benchmark records the host identity (CPU model, online
cores, memory, kernel, rustc) in `bench/results/bilateral-admission-environment.json`
and exposes it to the paper through the `\PSHost*` and `\PSRustcVersion`
macros, so the prose cannot describe a different machine from the one that
produced the result files. The MacBook Pro results previously retained under
`bench/results` are superseded and are not cited anywhere.

## Measurements

<!-- BEGIN GENERATED MEASUREMENTS -->
- Host: Neoverse-N1, 12 cores, 46.9 GiB, Linux 6.17.0-1020-oracle aarch64, rustc 1.94.1.
- Samples: 100 runs per workflow path after 2 warm-up runs; 100 Criterion samples per component.
- Pre-dispatch treaty denial: 11.173 ms p50, 26.578 ms p99, 12.222 ms mean (95 percent CI 11.392 to 13.245 ms) over 300 invocations.
- Pre-dispatch treaty allow: 15.933 ms p50, 34.131 ms p99, 17.899 ms mean (95 percent CI 16.475 to 19.888 ms) over 200 invocations.
- Complete buyer workflow: 2.390 s p50 and 2.509 s p99.
- Producer workflow: 2.196 s p50 and 2.591 s p99.
- Sustained load: 58.7 calls per second over 60 s with 40975.3 KiB of receipt store growth.
- Buyer package: 51,843 bytes.
- Negative matrix: 20 cases.
<!-- END GENERATED MEASUREMENTS -->

The complete-workflow result includes three-vendor process orchestration,
SQLite receipt and authority stores, a JSON admission store, package
generation, buyer CLI startup, schema validation, and semantic review. It is
not receiver-hook latency.

## Not established

- Two configured keys do not prove two independent organizations.
- The Lean development does not verify the Rust runtime.
- A finite test domain does not cover receipts omitted from that domain.
- The denial benchmark does not bound the allow-path verification cost; it
  measures a policy-summary early exit plus the signed denial receipt.
- The single-host experiment does not estimate wide-area or concurrent
  deployment behavior.
- The buyer package does not prove remote process integrity or legal effect.
