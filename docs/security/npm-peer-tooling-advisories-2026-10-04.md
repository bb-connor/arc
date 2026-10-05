# TypeScript peer-tooling source repairs, 2026-10-04

The PR 1173 candidate replaces the prerequisite's temporary acceptance with
source repairs. The private TypeScript workspace installs authenticated local
Node packages for `braces` and `node-forge`. Their scoped names and `-chio.1`
versions identify modified source; they are not upstream release versions and
are not published packages. All required Expo and React Native peers remain.

The [source inventory](../../supply-chain/npm-tooling-forks.json) binds each
original registry archive, complete reviewed patch, packaged file hash and
resulting archive integrity. `scripts/check-npm-tooling-forks.py` reconstructs
both packages from authenticated registry bytes and checks every selected npm
resolution. It also queries OSV using the original registry identities and
rejects every advisory except the two source repairs identified here. Renaming
a private package therefore does not remove upstream advisory monitoring.

- Braces uses the depth limits and cyclic-parent rejection from
  [upstream PR 72](https://github.com/micromatch/braces/pull/72), pinned at
  `28d440b5dd449dbf1fe6f3506cf94ecca4d02660`. Parsing and all three public AST
  walkers enforce the bound, including caller-supplied ASTs and attempts to
  raise `maxDepth` above the safe maximum.
- Forge uses the nested DigestAlgorithm element-count validation from
  [upstream PR 1152](https://github.com/digitalbazaar/forge/pull/1152), pinned at
  `ceba34402e329f0365134f23fe19898756527d65`. The Node library source is preserved
  apart from that repair. Browser bundles and Flash artifacts are omitted from
  this private Node-only package; stale unpatched bundles are not redistributed.

Both packages retain their original license and attribution. Development
dependencies and lifecycle scripts are omitted from these private artifacts.
The npm overrides reference direct, integrity-locked fixture dependencies, so
every transitive peer-tooling consumer uses the same repair.

The three security controls fail against the original registry packages and
pass against the installed repaired packages: bounded walkers, cyclic ASTs and
extra nested RSA digest fields. Valid RSA signatures and ordinary brace
expansions continue to pass. The pinned upstream RSA suite passes 101 tests
with four upstream pending cases. The complete upstream braces suite has 42
pre-existing Bash compatibility failures; a paired registry/repaired run keeps
the same failure set and introduces none. These historical failures are not
reported as a passing full suite.

The CVE workflow runs source authentication, its substitution controls, live
upstream monitoring and installed-package security regressions before scanning
the normal Python/npm closure. The two temporary advisory suppressions are
removed. The now-unused image-size suppressions are removed as well.

Review of the hosted unfiltered report also found the inherited
`GHSA-866g-f22w-33x8` waiver in the standalone AI SDK peer-test lock. Its claim
that remediation requires AI SDK 6 is obsolete: the
[upstream 3.0.28 release](https://github.com/vercel/ai/releases/tag/@ai-sdk/provider-utils@3.0.28)
backports bounded JSON response reads. The development graph now selects
AI SDK 5.0.210 and `@ai-sdk/provider-utils` 3.0.28, matching the existing workspace
selection within the same major version. That waiver is removed. The package's
published peer range is unchanged; the repository lock qualifies the tested
graph, not consumers' independent dependency selections. Retain the prior
unfiltered finding and require the updated unfiltered scan to be clear.

This repairs the repository's build and qualification tooling. A consumer who
independently installs upstream Expo tooling still selects that upstream
dependency graph. Repository overrides are not propagated into a published
SDK's peers, and this record does not qualify arbitrary mobile deployments.

## Historical prerequisite disposition (superseded)

The remainder records the bounded acceptance used by PR 1168 before these
source repairs. Its suppression guard and expiry are no longer active.

Owner: Chio security maintainers. Review deadline and automatic expiry:
**2026-10-18 00:00 UTC**. This is bounded acceptance for the core dependency
prerequisite, not an upstream vulnerability repair, mobile release qualification,
or evidence that the installed peer packages are safe for arbitrary use.

The accepted IDs are `GHSA-vfj7-8cjw-p6xm` (`braces` 3.0.3) and
`GHSA-86w9-cpqp-85rv` (`node-forge` 1.4.0), including OSV's aliases of those IDs.
The current forge alias set also includes `GHSA-ppp5-5v6c-4jwp`,
`CVE-2026-33894`, and `CVE-2026-85393`; the braces CVE is `CVE-2026-93687`.
The guard's unrelated-advisory probes use distinct `GHSA-grv7-fg5c-xmjg` and
`GHSA-q67f-28xg-22rw` on benign historical version records and keep them blocking.
Current [braces advisory](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) and
[node-forge advisory](https://github.com/advisories/GHSA-86w9-cpqp-85rv) have no
published patched version. Registry checks on 2026-10-04 found that current
Metro and Expo consumers still require these packages. No replacement fork,
package-wide suppression, or change to the mobile SDK's required peers was made.

## Exact scope and installed graph

Only `sdks/typescript/package-lock.json` is covered. Its private npm workspace
installs the mobile package's required Expo and React Native peers. Both affected
records are `peer: true`, not `dev: true`. They remain present on disk in those
peer installations, including consumers' installations where these peers are
required. Absence from a Chio tarball does not mean the dependencies disappear.

The inspected incoming dependency chains are:

| Locked consumer | Affected dependency path |
| --- | --- |
| Expo 57.0.2 -> `@expo/cli` 57.0.4 | `@expo/metro-file-map` 57.0.0 -> `micromatch` 4.0.8 -> `braces` 3.0.3 |
| `@expo/metro` 56.0.0 or Metro 0.84.4 | `metro-file-map` 0.84.4 -> `micromatch` 4.0.8 -> `braces` 3.0.3 |
| Expo 57.0.2 -> `@expo/cli` 57.0.4 | `node-forge` 1.4.0, directly and through `@expo/code-signing-certificates` 0.0.6 |

`scripts/tests/osv-peer-tooling-scope.test.py` rejects another same-directory
lockfile, changed affected versions or peer status, and changed inspected
incoming parent versions or edges. It uses the real scanner and benign lock
records to prove that both advisories still block in a sibling lock and a child
lock, that unrelated advisories on each package remain blocking, and that
expiration restores blocking in the accepted directory. The CVE
workflow runs this guard before its full scan and uses directory-local discovery,
without a global `--config` override.

## Reachability and shipping boundary

The inspected source locations below are relative to `sdks/typescript/` and its
installed `node_modules`, with versions fixed by the lockfile.

- Both `metro-file-map/src/watchers/common.js:23` and
  `@expo/metro-file-map/build/watchers/common.js:27` call `micromatch.some`.
  `micromatch/index.js:264` implements that method with `picomatch`, without
  invoking the affected braces walkers. The braces calls are in other methods
  (`parse`, `braces`, and `braceExpand`), unused by those inspected consumers.
  Watch patterns come from developer configuration plus fixed package and health
  check patterns (`metro-file-map/src/Watcher.js:177` and
  `@expo/metro-file-map/build/Watcher.js:150`). File names are candidate strings,
  not glob programs.
- `@expo/code-signing-certificates/build/main.js:157` verifies a configured
  self-signed certificate and then checks that its public key matches the local
  private key. `main.js:200` verifies a signature that the same helper has just
  generated. Expo CLI's `build/src/utils/codesigning.js:298` loads the configured
  certificate and private key from local files. Its iOS code-signing helper at
  `build/src/run/ios/codeSigning/Security.js:70` parses a certificate; it does not
  create a Chio trust decision. The vulnerable forge verification primitive is
  reachable in tooling, but the inspected paths do not expose it to arbitrary
  attacker-supplied Chio runtime messages or certificates.
- The packed Chio mobile JavaScript exports (`build/src/index.js`) only forward
  to `build/src/NativeChio.js`, which imports `expo-modules-core` and resolves the
  native `Chio` module. They never call Expo CLI, Metro, `node-forge`, or `braces`.
  The separate Expo plugin uses `@expo/config-plugins` to modify native project
  configuration. The checked-in iOS and Android `Chio` modules currently fail
  closed with `ChioBindingUnavailable`; this review does not assert implemented
  native verification.

After the publishable workspace build, `npm pack --ignore-scripts --workspace
@chio-protocol/mobile` produced a 22-file tarball with no bundled dependencies,
`node_modules`, or package lock. Its SHA-256 was
`f0f8a4291b76ab89c1f76ebb36375dd445e296a3b7d466c1037567078cfe8131`.
Both the JavaScript entry points and native unavailable bindings were inspected
inside that artifact. This is a packaging boundary, not a waiver for using the
installed Expo/Metro packages in another application or trust context.

## Remediation debt and re-review triggers

The owner must remove each exception when a compatible upstream release fixes
or removes the affected dependency, and refresh locks and qualification. Expiry
must not be extended without a new review. Any affected-version change, inspected
parent-chain change, new same-directory lock, SDK export importing this tooling,
or use accepting untrusted glob patterns, messages, or certificates requires
re-review before this disposition may be reused. Mobile product activation also
requires its own implemented native binding and release evidence.

The unrelated `image-size` exceptions were moved unchanged in advisory scope to
the TypeScript workspace directory, and the existing `@ai-sdk/provider-utils`
exception to `sdks/typescript/packages/ai-sdk/`. The obsolete sharp exception was
removed because the candidate resolves sharp 0.35.4. Rust advisory gates are
unaffected. Raw unfiltered and effective OSV results must both be retained with
qualification evidence: an effective zero-finding result includes these accepted
debts and must never be reported as all upstream vulnerabilities being fixed.
