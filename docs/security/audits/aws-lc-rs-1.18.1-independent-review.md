# AWS-LC remaining Rust API and FFI source audit

Date: 2026-10-04. Auditor: Codex delegated source-review agent.

Source root: `/tmp/arc-security-main-dependencies/third_party/aws-lc-rs-chio`.
Reviewed starting source: tracked files at parent repository commit
`b0dfffb35e5e889d158767e31bfe0d2da1832413`. The implementing parent was making
separate changes during this review. Initial findings refer to the starting
source. The repair follow-up below identifies the later source bytes actually
inspected, rather than implying those repaired bytes retain the defects.

Native source roots used:

- `/home/connor/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-sys-0.45.0/aws-lc`
- `/home/connor/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aws-lc-fips-sys-0.14.2/aws-lc`

The retained `review-progress.md` under
`/tmp/arc-security-launch/output/process-security-20260915/resume-20260921/aws-lc`
was read first. Its prior tests and provenance checks were not rerun or relabeled
as new evidence. This review ran no Cargo builds, tests, native compilation,
sanitizers, or audit-certification commands. The only file written by this agent
is this report.

## Judgment

Do not certify published `aws-lc-rs 1.18.1` as `safe-to-deploy` on this evidence.
In addition to the previously established DES parity defects, this source review
found a production Rust initialization defect in AES key wrapping and cipher
key construction. It also found an unsafe-string contract defect in an unused
private debugging helper. Both were sent promptly to the parent for repair.
The later changes inspected below close those two findings at the Rust source
level. They do not repair the published archive or certify the whole fork.

All assigned Rust production definitions were inspected, with the explicit
coverage below. The native inspection supports the listed wrapper contracts; it
does not constitute an independent whole-package C, assembly, cryptographic,
platform, or deployment qualification. A repaired fork needs complete joined
audit and qualification evidence before any deployment judgment.

## Confirmed production blocker: partially initialized AES_KEY

At the reviewed source, `src/key_wrap.rs:221-229,275-287,330-338,376-388`
allocates `MaybeUninit::<AES_KEY>::uninit()`, invokes native AES key setup, and
then calls `assume_init`. The scope extension found the same pattern at
`src/cipher/key.rs:91-115` for the encryption and decryption schedules.

The generated native bindings define `AES_KEY` with ordinary integer fields:
`rd_key: [u32; 60]` and `rounds: c_uint`. See the sys crate's
`src/x86_64_unknown_linux_gnu_crypto.rs:4641-4646` and the FIPS crate's
corresponding `:4572-4577`. These unused words are fields, not padding.

The native AES setup functions intentionally initialize only the schedule used:

- sys `crypto/fipsmodule/aes/aes.c:39-64` dispatches without clearing the struct.
  Its `aes_nohw.c:941-967` writes 44 words plus `rounds` for AES-128.
  `aes_nohw.c:969-1073` writes 52 words plus `rounds` for AES-192.
- FIPS `crypto/fipsmodule/aes/aes.c:84-109` has the same dispatch contract.
  Its `aes_nohw.c:952-978` likewise leaves 16 integer words unwritten for AES-128.
- The sys x86 AESNI generator `aes/asm/aesni-x86_64.pl:3241-3370` also writes
  the AES-128 round schedule and the round count without filling the unused
  schedule region. This is not solely a portable fallback concern.

Thus successful native return does not satisfy Rust's whole-value initialization
requirement. A safe public AES-128 operation can reach the invalid `assume_init`.
This is a source-established unsoundness; this review has not claimed a runtime
exploit or a sanitizer reproduction. Rust explicitly requires initialization even
for ordinary integer values, excluding padding from that requirement.
[Rust MaybeUninit initialization contract](https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#initialization-invariant)

Minimal repair: use `MaybeUninit::<AES_KEY>::zeroed()` at all six allocation
sites, retaining native return checks. All-zero bits are valid for this struct's
integer fields, and native setup overwrites every field it needs. This repair
does not alter the AES key schedule used by native operations. Useful regression
evidence should observe unused schedule words under native memory checking for
AES-128 and AES-192 and preserve red/green results for original and repaired
source identities. The parent owns implementation and qualification.

The archive comparison independently confirmed `src/key_wrap.rs` was byte-identical
to the published 1.18.1 archive at review time:
`7ae527eeb0cbd2f55b886e92cd47d1567b02a2976ef10fdf742d2382f710a2a6`.
Starting fork `cipher/key.rs` hash:
`53f9e00437ade5250568f04f3bf32438bbe19506f5a49163838141c5a912ba25`.
Published `cipher/key.rs` hash:
`6b6cd11caba316fab7a1c67226f60881b8f8bf27cb37007c3b84a931017b634c`.
The existing DES repair changes that file; both copies retained the AES pattern.

## Confirmed private helper defect: CStr precondition

`src/lib.rs:388-396` creates a zeroed 256-byte array, fills an error string, then
calls `CStr::from_bytes_with_nul_unchecked(&buffer)` over all 256 bytes. Native
`ERR_error_string` writes a terminated string into at most
`ERR_ERROR_STRING_BUF_LEN` bytes, which is 120 in the sys header
`include/openssl/err.h:317-328`; see `crypto/err/err.c:445-459`.
The remainder contains additional zero bytes. This violates the unchecked
constructor's no-interior-NUL precondition.
[Rust CStr safety contract](https://doc.rust-lang.org/std/ffi/struct.CStr.html#method.from_bytes_with_nul_unchecked)

The only located caller is `src/lib.rs:427` inside the test module. The function
is private, unsafe, and otherwise unused; this is not a demonstrated deployed
safe-API exploit. Use the bounded safe `CStr::from_bytes_until_nul(&buffer)`
conversion, handling its result, or another conversion whose preconditions are
actually met.

## Repair follow-up inspected

After the initial review, the parent changed the six AES allocations and the
private error-string conversion. I read the exact working-tree diff and the
current call sites. `cipher/key.rs:94-95` and `key_wrap.rs:223,279,336,384` now
use `MaybeUninit::<AES_KEY>::zeroed()`, with the native return checks retained.
The fields omitted by native schedule setup therefore contain initialized
integer zeroes before `assume_init`. This closes the identified aggregate
initialization flaw for both native backends at all six sites.

`lib.rs:395` now uses the safe `CStr::from_bytes_until_nul(&buffer)` constructor.
The resulting `Result` is only printed with Debug, so an unexpected absence of a
terminator cannot violate a Rust unsafe precondition. This closes the private
helper's string-construction defect.

The reviewed follow-up source identities are:

| File under src/ | SHA-256 |
| --- | --- |
| cipher/key.rs | `6b0187f4ffe3a308ad13657f327d04ee6da3b0f86103f51196bde55ae528ea61` |
| key_wrap.rs | `603b5c4a718618b1af8def45df9ec34c2551c0c644e8cde7c1283e73153ffb8f` |
| lib.rs | `c4bb46b7cd01feaac112c7526f3c18cdfe0f32cf348189a726a451c571200ed7` |

The added `cipher/key.rs:324-332` regression test checks both encryption and
decryption schedules for AES-128 and AES-192, including the unused words. I read
this test but did not execute it. The parent reports a native Memcheck red run
with original allocations (exit 97, 48 uninitialized conditional errors from two
contexts) and a repaired run (exit 0, zero errors). These are explicitly
parent-run results; this report does not independently authenticate their logs
or treat them as a complete package, feature, target, or hosted test campaign.

## Assigned Rust production coverage

Line ranges refer to the starting source. All executable definitions, trait
implementations, macro bodies and algorithm constants within these ranges were
read. Full-line documentation was sometimes omitted from numbered convenience
views; API contracts relevant to the conclusions were read separately. Inline
tests and data fixtures were excluded unless explicitly noted.

| Source file under src/ | Inspected production range | Main reviewed boundary |
| --- | --- | --- |
| cmac.rs | 94-513 | Sealed algorithm selection, key lengths, ownership and clones, concurrency, update/final output bounds, complete-tag verification |
| key_wrap.rs | 35-424 | Sealed KEKs, all four wrap/unwrap methods, native output capacity and return contracts, key drop |
| tls_prf.rs | 28-185 | Sealed digest choices, nonempty secret/output, both seed paths, native lengths, secret drop and conversions |
| kdf.rs | 214-224 | Production module declarations and reexports; remaining definitions are tests |
| kdf/kbkdf.rs | 4-146 | All algorithm factories, identifiers, digest mappings and FFI |
| kdf/sskdf.rs | 4-287 | All digest/HMAC factories, mappings, input and output FFI |
| signature.rs | 286-1188 | Public traits, signature buffer, parsed/unparsed factories and ownership, TypeId casts, every public algorithm constant |
| evp_pkey.rs | 4-579 | Every production definition: parsers, all exports, sign/verify, digest operations, derive, generation, refcount clone and key projections |
| encoding.rs | 6-95 | Generated encoding wrappers, Buffer ownership, redacted Debug, public conversion traits |
| endian.rs | 10-103 | Byte casts, transparent integer wrappers, conversions and array macros |
| error.rs | 8-230 | Error construction, Display/Error and all conversions |
| io/der.rs | 10-200 | Length/tag parsing, nested full consumption, positive/minimal integer rules |
| io/positive.rs | 9-45 | Restricted constructor and nonempty integer projections |
| io.rs | 8-13 | Visibility and reexports |
| iv.rs | 5-84 | Fixed-length construction, RNG, conversions and zeroizing Drop |
| pkcs8.rs | 10-40 | Document ownership, slice exposure and zeroizing Drop |
| fips.rs | 5-169 | Thread-local diagnostic state, service-indicator macros and configuration gates |
| debug.rs | 9-60 | Every formatting macro and hexadecimal formatter |
| hex.rs | 5-67 | All encode/decode helpers, including relaxed decoder |
| unstable.rs | 4-13 | Feature gating and module reexport |
| unstable/signature.rs | 15-83 | Every deprecated type alias and constant |
| lib.rs | 1-7,240-413 | Attributes, module/feature selection, initialization, FIPS/version wrappers, debug helper and sealed trait; feature documentation was also read |
| cbs.rs | 4-13 | Additional parser prerequisite: native borrowed-slice construction |

`key_wrap/tests.rs:1-7` was checked only to confirm its file-level `cfg(test)`
gate despite its unconditional module declaration. `test.rs:1-14,120-122` was
checked only to determine the purpose and public reexports of the hex helpers.
The rest of the testing framework is not counted as reviewed production here.

## Native contracts and findings for the reviewed wrappers

CMAC: sys `crypto/fipsmodule/cmac/cmac.c:17-277` was inspected. Context allocation
is zeroed, cleanup clears CMAC subkeys/scratch, and clone copies into an independent
context. Final writes the configured block size, 16 for AES and 8 for DES-EDE3,
and always sets its output length before successful return. All current Rust
`internal_sign` call sites supply either the 16-byte internal array or a public
`sign_to_buffer` slice checked against the sealed algorithm tag length. Full-tag
verification uses constant-time equality. `internal_sign` itself lacks a local
capacity check; current call sites satisfy the obligation, but adding one would
make its safe internal contract more robust.

CMAC shared-source cloning relies on `EVP_CIPHER_CTX_copy`. Sys
`crypto/fipsmodule/cipher/cipher.c:53-87` copies and duplicates the native private
context without modifying source for the selected CBC algorithms. The selected
descriptors do not set `EVP_CIPH_CUSTOM_COPY`: `e_aes.c:696-707,764-775,832-843`
and `crypto/cipher_extra/e_des.c:81-109`. Mutable operations require exclusive
access or consume the Rust context. The FIPS CMAC file differs from the sys file
only by its leading license, so the reviewed native CMAC logic is the same.

CMAC hygiene observation: `Key::generate` at `cmac.rs:256-260` drops its temporary
key `Vec` without an explicit zeroization on success or error. Native context
cleanup does not clear that earlier Rust allocation. This is a secret-retention
hardening gap, not a demonstrated remote exploit. A `Zeroizing<Vec<u8>>` would
provide the same cleanup discipline as the crate's other secret owners.

Key wrapping: sys `crypto/fipsmodule/aes/key_wrap.c:15-206` was inspected in full.
KW rejects invalid native lengths before writes and writes precisely input plus
or minus eight bytes. Rust checks corresponding output bounds; valid Rust slice
lengths are bounded by `isize::MAX`, so adding eight cannot wrap `usize` on the
supported 32/64-bit targets. KWP checks padding arithmetic overflow and the actual
`max_out` before writing; successful returned lengths stay within that capacity.
The FIPS native file differs only by a leading license, so these checks also
apply there. These capacity conclusions do not cure the AES_KEY initialization
finding above.

Key unwrap failure caveat: `key_wrap.c:95-110` and `170-205` can leave decrypted,
unauthenticated bytes in the caller's output on integrity failure. Rust returns
`Err` and no success slice, but the caller still owns the output allocation.
Neither Rust method documentation nor `include/openssl/aes.h:141-148,166-173`
promises clearing on failure. Therefore this review does not classify it as an
established API-contract violation; applications must use output only on success.
Explicit error-path clearing and documentation would reduce misuse risk. The
temporary stack AES schedules are also not explicitly zeroized by these methods,
although the boxed KEK is zeroized on Drop.

TLS PRF: sys `crypto/fipsmodule/tls/kdf.c:16-132` was inspected. It honors output
length, uses length-delimited label/seeds, bounds each output chunk, cleans A1 and
HMAC contexts, and returns failure without exposing a successful Rust `Secret`.
The FIPS TLS PRF section has the same body after license/include differences.
Rust `Secret` clears on Drop and Debug does not print it. The temporary output
`Vec` in `tls_prf.rs:153-178` is only wrapped in `Secret` on success; a future or
native failure after partial output would drop uncleared Rust bytes. This is a
structural cleanup gap, not a demonstrated failure reachable after partial
output with the currently selected SHA-2 algorithms.

KDF: sys `crypto/fipsmodule/kdf/kbkdf.c:11-101` and `sskdf.c:17-355` were read.
The Rust pointers and size_t lengths reflect actual borrowed slices. Native
KBKDF checks nonempty secret/output, addition overflow and 32-bit counter limits;
SSKDF checks the 2^30 limits and counter bounds. Each native output copy is bounded
by the remaining caller buffer. Internal output blocks are cleansed; failures
after entering the derivation loop cleanse the full output. Failure to create an
SSKDF context before entering the loop can leave the caller's preexisting output
untouched. KBKDF's early error cleanup is safe even before HMAC_CTX_init because
`HMAC_CTX_cleanup` only cleanses flat storage, not uninitialized pointer fields:
sys `hmac.c:270-285`, FIPS `hmac.c:318-333`.

The FIPS KBKDF file is identical. FIPS SSKDF lacks sys's `salt_len > SHRT_MAX`
guard; otherwise the reviewed implementation is the same. HMAC takes a size_t
key length, so this difference is not an observed integer narrowing at the Rust
FFI. No algorithm-correctness proof or side-channel qualification was performed.

EVP ownership/concurrency: native sys `evp.c:36-76`, `evp_ctx.c:51-115,324-385,
458-493`, plus FIPS `evp.c:87-126`, `evp_ctx.c:104-168,506-546` were inspected.
New keys own one reference, contexts acquire/release their key references, failed
key generation frees and nulls a newly allocated output, and Rust clone pairs
one native up_ref with one future native free. Refcounts saturate instead of
wrapping. The sys C11, Windows and locked fallback implementations were read in
full (`crypto/refcount_c11.c:7-56`, `refcount_win.c:6-78`, `refcount_lock.c:11-42`);
their FIPS differences are license-only. Actual platform execution was not tested.

Both backend headers authorize concurrent nonmutating EVP_PKEY use and classify
up_ref and DigestSign/VerifyInit as nonmutating for that purpose. FIPS citations:
`include/openssl/evp.h:85-102,341-358,398-415`. Rust's `as_mut_unsafe_ptr(&self)`
is used for those native APIs or per-call context creation, not to export a safe
public mutation capability. The borrowed get0 projections remain lifetime-bound
to the owning key. These findings support the reviewed Send/Sync declarations;
they do not certify unrelated native methods or arbitrary external system libs.

EVP output sizing: sign/digest-sign query maximum size, allocate that amount and
pass it back as capacity. Derive owns a zeroizing allocation before its fallible
second call. Native headers specify capacity-limited sign/derive behavior:
sys `evp.h:320-339,565-589,697-705`; FIPS has corresponding contracts. Raw export
uses actual slice capacity. The Ed25519, X25519, PQDSA and KEM getter bodies check
capacity before copying: sys `crypto/evp_extra/p_ed25519_asn1.c:76-116`,
`p_x25519_asn1.c:72-111`, `p_pqdsa_asn1.c:21-93`, `p_kem_asn1.c:19-87`.
FIPS Ed25519 and X25519 getter functions are byte-identical, at `:87-127` and
`:83-122`; FIPS PQDSA `:21-92` and KEM `:19-87` were read separately and retain
the same capacity checks. Raw private export returns ordinary Vec storage for
its internal caller to place into a secret owner; no broad zeroization guarantee
for every temporary/copy is asserted here.

EVP parser behavior: Rust rejects null and wrong algorithm types. Native sys
`crypto/evp_extra/evp_asn1.c:71-215` checks complete inner structures but advances
the outer CBS, as documented by the FIPS header `evp.h:252-280`. Rust
`evp_pkey.rs:212-241` does not check remaining outer bytes. Accordingly, these
APIs do not establish exact whole-input DER consumption. This is a documented
native streaming-parser contract and a Rust strictness limitation; no concrete
authorization bypass was demonstrated. An application requiring canonical exact
input consumption must not infer it from successful key parsing alone.

Signature factory: `TypeId` is checked before each internal trait-object pointer
cast. The public algorithm trait is sealed and extends `Any`; untrusted callers
cannot create an arbitrary implementation with forged native algorithm metadata.
Selected curve/digest/padding constants matched their identifiers. Public-key
bytes are copied into an owned box for parsed keys. Cryptographic verification
and key-validation semantics in EC/RSA/Ed25519/PQDSA were assigned to the parent,
not independently re-audited in this report.

Small helpers: DER rejects indefinite/high-tag forms, nonminimal lengths,
negative/empty/nonminimal integer encodings, and trailing bytes in nested values.
The private endian module only instantiates padding-free transparent u32/u64
wrappers for its byte casts. IV and PKCS8 owners zeroize; encoding wrappers
delegate to the previously reviewed Buffer and redact Debug. Hex helpers are
public through the documented testing module: odd nibbles are accepted, the
dirty decoder intentionally filters input, and a u32 counter bounds decoding
above approximately 4 GiB of characters. They are unsuitable as a strict
canonical production parser; no memory-unsafe operation exists in these helpers.

FIPS helpers record diagnostic service status only in FIPS debug builds. They
are not a production algorithm-policy enforcement mechanism. `try_fips_mode`
and `try_fips_cpu_jitter_entropy` return the native status, and `fips_version`
is explicitly a build-time value. The FIPS source `self_check/fips.c:23-35`
shows compile-time mode and entropy indicators; these functions alone do not
establish a certified deployment. Runtime version string conversion uses a
native static string in both `crypto/crypto.c` implementations (sys `:110-125`,
FIPS `:123-138`), which supports the returned static Rust lifetime.

## Extended MaybeUninit scan

Every `MaybeUninit` / `assume_init` occurrence under the fork's `src/**/*.rs`
was located, then the construction and consumption sites were inspected for
the same aggregate validity issue. Besides the six AES allocations:

- `digest/digest_ctx.rs:26-31,61-69`: EVP_MD_CTX_init zeroes the complete object;
  EVP_MD_CTX_copy initializes the destination before copying. Native sys
  `digest.c:30-31,122-187`, FIPS `:83-85,175-240` support that contract.
- `hmac.rs:183-191,301-319`: HMAC_CTX_init clears the entire object;
  HMAC_CTX_copy_ex copies its initialized storage (sys `hmac.c:477-479`).
- `cbb.rs:14-19,39-44`: CBB initialization clears the entire object even on
  allocation failure (sys `bytestring/cbb.c:16-45`, FIPS `:27-56`).
- `cbs.rs:9-12`: native CBS_init writes both struct fields (sys
  `bytestring/cbs.c:23-26`, FIPS `:34-37`).
- `cipher/key.rs:142-151`: fixed-length check plus full 32-byte copy initializes
  the ChaCha key. DES's zero schedules are explicitly zeroed; native DES setup
  writes both words of all 16 subkeys (sys `crypto/des/des.c:332-415`).
- `aead/poly1305.rs:42-74`: opaque state already uses zeroed for this exact
  partial-initialization concern, and native finish promises the full 16-byte tag.
- `cmac.rs:407-433`, `hmac.rs:442-462`, `ec/signature.rs:279-294`,
  `aead/unbound_key.rs:318-336,415-435,454-498,509-535,550-582`, and
  `digest.rs:141-158`: scalar output lengths are used only after native success
  or not read. These have no partially initialized aggregate at assume_init.

This extension does not broaden the original report into a complete re-audit of
all cryptographic logic in those previously reviewed modules.

## Audit-policy recommendation

The published base cannot truthfully receive standard `safe-to-deploy` on this
review. Cargo Vet path enforcement applies audits to original registry bytes,
not to corrected local bytes; a git delta also requires its published base.
[Cargo Vet first-party rules](https://mozilla.github.io/cargo-vet/first-party-code.html)

A non-implying custom `aws-lc-source-reviewed` criterion can truthfully record
review with known findings, provided its definition and audit notes explicitly
say it is not deployment approval. Changing the dependency requirement from
`safe-to-deploy` to that criterion is a weaker Cargo Vet policy by itself.
It becomes defensible only as part of an explicit, mandatory composite approval
system for the separately reviewed first-party fork, not as a way to turn the
existing missing security audit green. Cargo Vet permits custom criteria and
scoped dependency policies; that mechanism does not supply their security
meaning. [Cargo Vet configuration](https://mozilla.github.io/cargo-vet/config.html)

For that composite approach to preserve the intended acceptance boundary:

1. Record the exact published archive, its known defects, and actual review
   coverage honestly. Do not imply the custom criterion grants safe-to-deploy.
2. Separately complete and retain the fork's security review, all necessary
   repairs, and meaningful repair qualification. A matching source hash cannot
   replace missing review of unsafe/native behavior.
3. Bind the exact approved fork bytes to an authenticated upstream archive and
   exact patch reconstruction. Reject missing, extra, substituted or changed
   production files, relevant build/config inputs, and unexpected source origins.
4. Require the fork validation together with Cargo Vet in both required jobs
   and every deployment/release route. Detect registry/unpatched substitution
   and ensure every relevant resolved lock graph and feature configuration is
   covered. Keep native and transitive dependency requirements at safe-to-deploy.
5. Preserve negative/mutation evidence for source drift, unpatched substitution,
   changed graph/feature identity, and omission/bypass of required validation.
   Treat changes to the approved digest, patches, policy or gate as changes
   requiring a fresh security review.
6. Report `cargo vet` alone as checking base review and dependency policy, not as
   authenticating or certifying the path fork. Name the composite fork approval
   separately in human-facing status and documentation.

If these conditions are missing, the custom criterion route is a loophole.
This reviewer does not approve a final policy change or final fork deployment:
the parent must join this bounded review with the other actual coverage and
qualification. The built-in criterion requires enough unsafe and capability
review to reason about realistic untrusted-input behavior; it cannot be inferred
from provenance, hashes, passing tests, or this report's line count alone.
[Cargo Vet built-in criteria](https://mozilla.github.io/cargo-vet/built-in-criteria.html)

## Remaining limits

- No current claim of full-package safe-to-deploy, protected merge readiness,
  whole native-source audit, constant-time machine-code validation, FIPS
  certification, platform runtime qualification, or arbitrary system-library
  correctness is made.
- The inspected repair identities are recorded above. The parent must validate
  the final integrated source and retain the original-source failure evidence
  separately from corrected-source passes.
- Error output preservation, DER trailing-data acceptance, temporary secret
  cleanup and diagnostic-only FIPS state have been made explicit above so they
  cannot disappear behind a blanket clean verdict.
- No audit, exemption, policy record, or production source was written by this
  review agent.
