# Trust-boundary execution

September 27, 2026. Base `00536cc90225bfa707cb64e344effc1f4cdcd2e4`, branch
`packet/3-retention-accounting`, isolated checkout `/tmp/arc-security-launch`.
This batch implements the approved signed-input, verification-result, tenant-read
and FROST plaintext boundaries. The subsequent [sealed ceremony batch](2026-09-27-frost-sealed-ceremony-execution.md) implements FROST transport sealing.

## Implemented boundaries

`UntrustedJsonText<'a>` borrows an owning reader's bounded input, exposes no raw
accessor or serde implementation, and separates three contracts: strict I-JSON,
lossless native signed JSON with full-width integers, and exact canonical bytes.
The old public parser was removed. Receipt, signed export, lineage, manifest,
keyring, broker and response-authority readers use the constrained API. The
closed checkpoint reader and dedicated zeroizing credential parser have explicit
exceptions in the source inventory. Six registered input rules preserve typed
sources while redacting Display and Debug; receipt-store error snapshots retain
the original error through `Arc`.

Portable capability/passport verifier results and governed response operator
evidence now have private fields and read-only accessors. Browser, mobile and C++
consumers were migrated. Constructible quota, event, isolation, approval, budget
and binding projections have record/body names, without old-name aliases. The
[classification](../security/verification-records.md) distinguishes actual
verification results from results supplied by trusted installed ports.

`ReceiptReadContext` cannot be deserialized or have its authority fields mutated.
The authenticated adapter remains responsible for selecting its constructor.
Tenant list and point reads require the exact tenant in SQL and recheck the
signed body's tenant. Point lookup and checkpoint verification share one read
transaction, preserving the existing transparency guards. Invalid tenant strings,
missing context, scope widening and forged projections have typed rejections.
The mutable strictness switch and NULL-row compatibility fallback are removed.
HTTP point lookup retains its admin-only contract; internal kernel provenance
reads are classified separately from user-facing reads.

The SQLite inventory covers 85 tenant tables and 170 statements requiring named
principal contracts, including dynamic predicates and privileged integrity,
recovery and administrative operations. Schema-side comments reference those
contracts without changing executable DDL. There is no bearer-ID class. The new
CI gate checks this inventory, the 18 signed-input constructor sites, remaining
raw decoders in migrated files, sealed fields and the sole production FROST
secret extraction site. Its seven calibration cases exercise actual source
mutations. It is a lexical review gate, not a Rust or SQL authorization proof.

FROST round one and round two use separate types. Round-two plaintext has no
serde implementation, stores secret bytes in `Zeroizing<Vec<u8>>` and redacts
Debug. Only the private encrypted-custody encoder extracts those bytes. It writes
directly into a zeroizing buffer and encrypts immediately, avoiding a plaintext
`serde_json::Value` intermediate. Recovery authenticates ciphertext first, then
rechecks sender, recipient, ceremony, epoch, package digest, transport signature,
FROST encoding and complete recipient coverage. No old plaintext serialization
fallback remains.

Final inline review also found that broker failure evidence prepended its
namespace to full clock/input URNs, producing an invalid wire diagnostic.
Distinct bounded `clock_*` and `signed_json_*` projections now preserve each
reason in ordinary IPC and signed failure receipts. Local typed sources retain
their registered URNs. The regression exercises the actual signed envelope and
receipt verifier and demonstrates rejection of the former invalid spelling.

## Local verification

Raw commands and logs are retained at `/tmp/chio-trust-boundaries-20260927`.
Cargo owners were serialized with locked dependencies, the existing external
target, `umask 022`, two build jobs and one test thread. No subagents or
workspace-wide build, test or lint run was used.

| Boundary | Evidence |
| --- | --- |
| Owner and binding APIs | `check-final.log`: ten selected owners and their tests compiled, including browser/mobile/C++ bindings. |
| Signed JSON, passports, keyring, manifests, FROST ceremony/custody | `focused-tests-3.log`: 60 passing cases before the separate tenant fixture failure described below. |
| Exact-tenant reads | `tenant-final.log`: all five cases pass, including another tenant's exact ID and forged point/list projections. |
| Signed readback, verifier consumers, authority config and broker error evidence | `library-tests-final.log`: 85 cases pass. `broker-final.log` rechecks all four envelope cases after the final assertion strengthening. |
| Unavailable proof/FROST serde implementations | `proof-doc-tests.log`: six compile-fail doctests pass. |
| Portable no-std and lockfile closure | `portable-no-std.log`: core types and portable kernel compile with no default features. Root/fuzz locked offline metadata passes; `docker-final.json` records successful regeneration and a clean mirror check. |
| Source gates | Trust inventory and seven calibrations pass; arithmetic, clock, dependency and file-hygiene caps are unchanged. One strengthened assertion retires an exception, reducing the negative-assertion baseline to 1,282 without changing its expiry. |
| Generated error vocabulary | `codegen-final.log`: regeneration produces identical files. |
| Formatting and graph | Changed Rust sources formatted; AST-only graph update completed. |

The nonempty runtime suites total 150 distinct passing cases. Empty filtered
harnesses add compilation coverage only; reruns are not added to that count.

Earlier failures remain evidence, not passing checks:

- Initial API checks found missing no-std imports, a broker crate alias, verifier
  fixture imports and an existing support file incorrectly discovered as an
  independent integration test. The fixture now lives under `tests/support/`.
- The first runtime run found an outdated keyring error assertion. It now checks
  the structured decode variant and the exact witness-order rejection cause.
- SQL contract comments initially changed canonical DDL strings and caused the
  FROST startup integrity checks to reject. Moving them outside executable Rust
  SQL literals restored the original DDL; all three restart/custody tests pass.
- The corruption fixture initially hit the immutable-receipt trigger. It now
  removes and restores that trigger within one transaction before exercising the
  signed-tenant rejection. Production enforcement was preserved.
- A later compiler pass found one test caller retaining the removed private
  decoder label argument. The caller was migrated. The broker envelope tests
  moved together into an ordinary module when the new regression exceeded the
  existing textual-include cap; no cap or assertion baseline was raised.
- The Docker mirror check found preexisting manifest drift, including missing
  release overflow checks. Regeneration carries the existing workspace policy
  and dependency closure into the container manifest; it does not qualify a
  container image or native package.

## Remaining scope

The broader signed-reader census and full negative runtime matrix across every
tenant table remain open. PostgreSQL is outside this SQLite inventory. The
record classification does not certify all workspace verifiers. FROST step 2 is now implemented in the subsequent
[sealed ceremony batch](2026-09-27-frost-sealed-ceremony-execution.md), with separate
sealing keys, encrypted transport and durable replay handling. Native qualification, sustained fuzzing, scale, independent final
review, hosted CI, integration and release acceptance retain their existing
gates. This is a local implementation checkpoint.
