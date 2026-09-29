# Authority boundary closure

Base: `a3217b9145`, `packet/3-retention-accounting`, `/tmp/arc-security-launch`.
This batch implements the approved four-owner continuation. Local qualification
is recorded below; it does not establish hosted, release or operational acceptance.

## Changes and authority contracts

- Reviewed all 76 baseline reader files in core types, runtime core, secret broker
  and control plane. The registry distinguishes original-byte boundaries from
  parser internals, generated validators, typed conversions and fixture readers.
  It prevents these owners from returning to the unreviewed baseline.
- Migrated 114 inventoried decoder calls to bounded shared readers. Attenuation
  witnesses additionally require exact canonical scopes. JWTs retain their compact
  signature preimage and are bounded before base64 allocation. JWKS and passport
  lifecycle responses use the shared capped peer-stream reader.
- Runtime errors retain JSON, IO, SQLite and clock causes. Attestation, challenge,
  purchase, migration and external-anchor errors preserve parser causes. Security
  ports retain private sources while Display/Debug expose only registered codes.
  Public HTTP/string ports intentionally project redacted errors.
- Runtime admission and swarm readback checks both the indexed identity and the
  retained digest; treaty artifacts check their retained digest. This detects an
  internally consistent replacement under the wrong key as well as payload drift.
- Reviewed the 37 arithmetic entries: 36 bounded/fixture/epoch-floor dispositions
  and one checked advisory-age subtraction. The existing signed advisory validator
  already rejects future timestamps; this change removes a redundant saturation,
  rather than claiming a new future-time exploit was found.
- Replaced 15 production ambient-clock occurrences. Trust-control callers obtain
  a fallible sample before authority or state changes. Failed cluster sampling
  clears local lease availability; optional lag metrics skip unavailable time.
  Budget event identities use UUIDs. The other 36 occurrences are fixtures.
- Audited live proof owners: native flow dispatch already owns private borrowed
  resolver/kernel custody and cannot be deserialized, cloned or retargeted. Added
  it to the seal gate and a field-access compile-fail example. Broker exchange and
  runner authorization remain sealed. Security event verification records remain
  store DTOs; the composition-installed verifier must still authenticate ingress.
- Split cohesive provider/profile-authority helpers and test cases to honor
  existing module caps. No cap increases or new textual include fragments.
- Fixed the arithmetic gate's empty-baseline ratchet and calibrated idempotence.

## Verification ledger

Local qualification passed. Logs, original failures, cancelled invocations and
mutation backups remain in `/tmp/chio-authority-boundaries-20260928/`.

| Boundary | Terminal evidence |
| --- | --- |
| Runtime storage | 64 tests passed, including original JSON, private causes, record substitution, restart and atomic clock refusal. |
| Runtime pheromone policy | 8 tests passed, including future-dated advisory refusal. |
| Core attenuation | 2 tests passed, including matching-hash noncanonical scope rejection. |
| Control-plane readers and recovery | 29 focused tests passed: attestation/JWT, capped peer JSON, native signed-event parsing, correctly signed wrong-policy rejection, expiry and restart/replay recovery. |
| Control-plane clock consumers | 18 issuance, 3 certification and 3 cluster consensus/lease tests passed. |
| External anchors | 12 economic/fiscal and 4 FROST tests passed. |
| Broker boundaries | 4 prepared-connection and 6 SQLite atomic/replay tests passed. |
| Live proof API | Both the valid borrowed-consumer doctest and private-field compile-fail doctest passed. |
| Compiler checks | Owning library/test targets compiled. Strict Clippy passed for all seven affected library packages. Core types passed with default features disabled. |
| Source gates | Trust boundary gate and 18 calibrations, clocks, arithmetic plus calibration, negative assertions, module hygiene and workspace formatting passed. |

That is 153 distinct focused Rust tests and two proof API doctests. Tests using
`current_exe()` ran from stable copied binaries, with `CHIO_CHECKOUT_ROOT` set.
No full-workspace test, hosted CI, publication or activation claim is made.

Four deliberately broken production variants compiled, then failed their
specific regression with an unexpected acceptance (not a build failure):

1. Runtime admission reader parsed through an ordinary `Value`, losing original
   duplicate keys: `original_runtime_json_rejects_ambiguity_with_private_cause`.
2. Runtime SQLite readback omitted its admission-ID comparison while retaining
   digest checking: `sqlite_bundle_readback_binds_digest_and_index_across_restart`.
3. JWT claims used ordinary serde parsing:
   `jwt_original_tokens_are_bounded_unambiguous_and_keep_signed_preimage`.
4. Native event verification omitted the trusted policy-version comparison:
   `trusted_producer_signature_from_an_unconfigured_policy_is_rejected`.

The mutation runner restored all four files byte-for-byte and verified their
hashes. Restored binaries rebuilt successfully; the affected tests, replay-seal
corruption test and attenuation controls all passed again. Mutation results are
in `mutant-results.json`, with individual logs `mutant-{parser,index,jwt,policy}.log`.

The first runtime run had 61 passes and three failures: two regressions exposed
source-chain forwarding through transparent errors, and the replay corruption
case expected the former generic code. Runtime wrappers now preserve their inner
sources, and the corruption test checks the precise parser code for malformed
bytes while retaining every no-repair assertion. The complete 64-test rerun passed.
Compile, formatting and Clippy iterations also retained their original failures.
The first broad source calibration was cancelled because its default mutation
owner became a large generated file; selecting a small production reader brought
the complete 18-case calibration to about 39 seconds. A single-package Cargo
rerun was cancelled after it changed dependency feature unification; subsequent
builds retained the same four-package selection. Neither cancellation counts as
a passing check.

## Remaining scope

The decoder baseline falls from 374 to 298 files. Arithmetic has 85 pending rows
out of 638 historical entries, with 553 classified and 133 marked repaired. The
ambient clock inventory has 142 occurrences. These are inventory counts, not
vulnerability counts. The broad error/proof census beyond these owners, compiler
and secret-ownership enforcement, helper isolation, measured storage performance,
retention/model linkage and exact-candidate delivery remain successor packages in
[the remaining-work queue](2026-09-28-remaining-security-work.md).
