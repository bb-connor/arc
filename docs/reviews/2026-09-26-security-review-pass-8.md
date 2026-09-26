# Security review, pass 8, September 26, 2026

Continued project review on `integration/process-security-m4` at `c78e7921e4`,
run while Wave 1 lanes A and R execute, on surfaces none of them own. Findings
are numbered `U`. Every count below is from a lexical scan of production files
with test directories excluded; inline `#[cfg(test)]` modules inside production
files are not excluded, so counts of things tests also do (`map_err`, `unsafe`)
are upper bounds, and counts of things tests rarely do (schema declarations,
struct derives, dependency edges) are close to exact.

**Judgment: two findings widen earlier ones by an order of magnitude (the
`map_err` discard disease is TCB-wide, and wire-schema duplication crosses crate
boundaries), one is new and Linus-shaped (a sandbox init helper that links an
HTTP client), one is a confidentiality gap in a wire type that no transport yet
exercises (FROST round-2 packages), and two sweeps come back clean in ways worth
preserving.**

## U1. High: the rejection-provenance disease is TCB-wide, not a quarantine problem

Pass 2's R2 counted 112 `map_err(|_| ...)` discards in `chio-quarantine` plus the
kernel's response coordinator. Across the whole security TCB:

| Measure | Count |
| --- | --- |
| `map_err(\|_\| ...)` discards in production files | **up to 2,102** (`chio-store-sqlite` 833, `chio-control-plane` 359, `chio-kernel` 324, `chio-secret-broker` 164, `chio-quarantine` 105, `chio-cage` 104, `chio-keyring` 46, `chio-decoy` 40, `chio-security-types` 38, `chio-security-kernel` 32) |
| error-enum variants whose only payload is a `String` or `&'static str` | **291** (`chio-kernel` 133, `chio-store-sqlite` 67, `chio-core-types` 40, `chio-kernel-core` 11, `chio-cage` 10, `chio-secret-broker` 9) |
| variants that preserve a cause through `#[source]` or `#[from]` | **82** |

Twenty-five discards for every preservation. The 291 stringly variants are the
"stringly kernel-seam errors" the cognition-market review recorded in July, now
confirmed inside the security TCB with the kernel as the worst offender. A caller
cannot match on a `String`; it either ignores the error or parses prose.

**Consequence for the plan.** Correction 1D is correctly scoped to the response
path, because that is what Packet 1's tests need. Mechanism C of the
unrepresentable-defects design is a TCB-wide migration, and the store crate, with
833 discards on the durability path, is where a lost cause costs the most at
3 a.m. The design document now says so.

**Confidence:** high on the ratio, which no test-module noise could invert;
upper-bound on the absolute discard count.

## U2. Medium: the sandbox init helper links an HTTP client

`chio-cage` ships the confinement helper binary `chio-cage-init`, the static-PIE
program that applies seccomp and Landlock and then `exec`s the confined tool. Its
crate's normal-dependency graph is **344 unique crates**, identical with default
features disabled (the crate's two features are enforcement toggles, not
dependency toggles). The graph includes `tokio`, `hyper`, `hyper-util`, `reqwest`,
`tower-http`, `rustls-webpki`, `aws-lc-rs`, `aws-lc-sys`, `regex`, `fancy-regex`,
`serde_json` and `tracing`. `chio-secret-broker` is at 640; `chio-keyring` at 94;
`chio-security-types`, correctly, at 10.

The cause is structural: `chio-cage` depends on `chio-core` and `chio-manifest`,
and those pull the platform. The helper inherits everything because it lives in
the same crate as the library.

Why it matters beyond taste. The helper is the most privileged program in the
system's runtime: it runs before confinement exists, often as root during
provisioning (boundary finding P1 #1), and every crate in its graph is in its
trust base. The ledger's static-PIE and ELF checks prove the artifact has no
dynamic dependencies; they say nothing about what was compiled into it. A
sandbox helper with an HTTP client in its binary is the kind of thing an
auditor screenshots.

**Fix (hardening spec H11).** Split the helper into its own crate depending only
on the plan and envelope types, `seccompiler-chio` and `nono-chio`, with a
dependency budget enforced by a gate (`cargo tree --edges normal` unique-crate
count under a committed ceiling, and a deny-list of `tokio`, `hyper`, `reqwest`,
`rustls`, `regex` for that crate). Measure the actual `chio-cage-init` graph on
the musl target first; the ceiling is set from what the helper genuinely needs,
not guessed.

**Confidence:** high on the counts (`cargo tree`, no build); the
dependency-on-`chio-core` cause is read from the manifest; the exact minimal set
is the lane's first measurement.

## U3. Medium: wire-schema duplication crosses crate boundaries

Refining pass-7's H10 numbers: of the 55 schema values declared in more than one
file, **54 are declared in more than one crate**. `chio.receipt.v1` is declared in
six files across five crates (`chio-core-types`, `chio-enterprise-export`,
`chio-trust-market-context`, `chio-cli` twice, `chio-proof-room`). The runtime
attestation schemas are declared identically in `chio-core-types`,
`chio-appraisal` and `chio-control-plane`. A version bump in one crate is a
silent producer-consumer disagreement with the other four, and H10's snapshot
would catch the *bump* but not the *disagreement*; only a single registry does.
The spec now records the cross-crate figure and the `WireSchema` registry as the
fix.

## U4. Measured, for Lane K: the `unsafe` ledger

34 crates contain `unsafe`; 210 `unsafe {` blocks against 195 `// SAFETY`
comments. The gap H1's lint will expose is **16 blocks in five crates**:
`chio-cage` 4, `chio-cli` 5, `chio-guard-sdk` 5, `chio-guard-sdk-macros` 1,
`chio-commerce-order` 1. Every other crate is already at one comment per block.
Five `unsafe fn` declarations (`chio-secret-broker` 3, `chio-guard-sdk` 1,
`chio-secure-ipc` 1) are where `unsafe_op_in_unsafe_fn` adds blocks. Turning the
lint on is a sixteen-comment change, not a campaign.

## U5. Measured, for H7: secret-bearing structs

Eight structs carry a `Zeroizing` field and derive `Clone` or `Serialize`; none
derives `Debug`. Seven derive only `Clone`, which `Zeroizing` tolerates (clones
zeroize on drop): six external-guard configurations holding API keys, and
`DualSignReleaseInput`. One derives `Serialize`: `FrostAuthenticatedDkgPackage`
(`chio-federation-authority/src/frost_ceremony.rs:144`), whose `package_hex:
Zeroizing<String>` sits beside `transport_key_id`, `transport_signature` and an
optional `recipient_participant_id`. That shape is consistent with an
encrypted-for-recipient envelope, which is what a FROST round-2 package must be,
and it is not yet confirmed that `package_hex` holds ciphertext rather than a
plaintext share. Confirming it is H7's first task; until then this is an open
question, not a finding.

## U8. Medium: FROST round-2 DKG packages are authenticated but not confidential as a type

Following U5 to its answer. `chio-federation-authority/src/frost_ceremony.rs:348`
calls `dkg::part2` and, for each recipient, wraps `package.serialize()` in
`FrostAuthenticatedDkgPackage` through `authenticated_package(&context,
FrostDkgRound::Round2, Some(recipient), bytes, transport_key)` (`:356-362`). The
transport key **signs** the package (`transport_signature`); nothing encrypts it.
`package_hex` is `hex::encode(package_bytes)` (`:37`), and the struct derives
`Serialize`.

What a round-2 package is, from the library: frost-core's
`keys::dkg::round2::Package` holds `signing_share: SigningShare` (`dkg.rs:230-246`
in the vendored source). It is the recipient's secret signing share, and
frost-core's documentation requires round-2 packages to travel over a channel that
is both authenticated and confidential.

**What is right.** At rest, the ceremony store keeps the participant's own secret
and each round's output as `EncryptedBlob`s with associated data
(`frost_store/ceremony.rs:24, :42-43`; `schema.rs:28` `secret_ciphertext BLOB NOT
NULL`). The design document states that key shares must not reach the coordinator.
The field is `Zeroizing`, so the author knew it was sensitive in memory. Round-1
packages are public commitments and are correctly plaintext.

**What is missing.** The wire type does not enforce the confidentiality the
protocol requires. Today no route, CLI command or IPC path in this tree serializes
a round-2 package to another participant, so there is no live exposure to report.
The gap is that the first transport someone adds (an operator export file, an HTTP
route, a relay through the coordinator) inherits a plaintext signing share
silently, because the type permits it. This is the design document's mechanism B
in the wrong direction: the struct makes the unsafe state representable.

**Fix.** Encrypt round-2 `package_bytes` to the recipient's transport key inside
`authenticated_package` when `round == Round2`, so `package_hex` carries
ciphertext for round 2 and plaintext only for round 1; the `transport_key_id`
field already identifies the key, and HPKE or X25519 with an AEAD bound to the
same associated data the store uses is the natural choice. Better still, split the
types: `FrostRound1Package` (public, `Serialize`) and `SealedFrostRound2Package`
(ciphertext, `Serialize`), with the plaintext round-2 form never implementing
`Serialize` at all. Add a test that serializes a round-2 package and asserts the
signing-share bytes do not appear in the output. Hardening item H7 now carries this
as its first task.

**Confidence:** high on the code path and the library type, both read directly.
The absence of an in-tree transport was established by search, not proof; a
transport in a companion repository would change the severity to a P1.

## U6. Clean, with the reason recorded: async cancellation across durable writes

Seven `tokio::select!` sites and 29 `tokio::time::timeout` wrappers in TCB
production code; none of the seven `select!` arms awaits a commit, insert,
execute or append in the same block (the only lexical hits were in test files).
Store I/O runs through ten `spawn_blocking` sites, which is the right shape.

The structural reason this is safe is worth writing down so a refactor does not
lose it: `rusqlite::Transaction` rolls back on drop, so a future cancelled before
`commit()` leaves no partial durable state. The exposure that remains is the one
the system already models explicitly: an external effect between commit and
acknowledgement, which is the "unknown outcome" state and is resolved only by
exact durable readback. Cancellation safety here is a property of RAII plus the
existing recovery design, not of care at each site.

## U7. Lane progress, read from git only

`packet/0-gates` has two commits (`edab16cf34 ci(gates): measure assembled
modules in the Rust file hygiene gate`, `19809a63c7 build(profile): keep overflow
checks in the profiles that ship`), both conventional, working tree clean.
`packet/ci-regressions` has no commit yet and five files modified. The shared
target directory is at 2.3G with 259G free.

## What changed in the documents

Hardening spec: H1 and H7 carry the measured figures above, and H7's first task
is U8's fix; H10 records the cross-crate count; H11 (dependency budget for
privileged helpers) is new.
Unrepresentable-defects design: mechanism C states its TCB-wide scope. Dispatch:
Lane K gains H11.
