# TypeScript peer-tooling advisory disposition, 2026-10-04

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

## Foundation composition re-review

The foundation uses Metro and metro-file-map 0.84.5 plus `@expo/metro` 56.0.2.
The prerequisite used 0.84.4 and 56.0.0. The parent-inventory guard correctly
rejected reuse of the earlier graph. The new graph also contains nested copies
of Metro and metro-file-map beneath `@expo/metro`; all incoming edges are now
explicit in `REVIEWED_PARENTS`.

Both versions of these three packages were downloaded from the lockfile's npm
archive URLs and verified against their SHA-512 integrity records before
comparison. Every metro-file-map JavaScript file is byte-identical across the
change. Its only changed file is package metadata. The inspected watcher still
calls `micromatch.some`, and the affected braces path is unchanged. Metro's
JavaScript delta replaces its image-size dependency with local image parsers;
the Expo wrapper adds the corresponding forwarding module. Neither change adds
a braces or node-forge consumer. The locked micromatch, braces, Expo CLI,
code-signing certificates, node-forge and Expo records remain identical to the
landed prerequisite. This re-review covers these advisory paths, not a blanket
audit of the new image parsers or mobile product acceptance.

The two advisory IDs, affected versions, directory scope and October 18 expiry
remain unchanged. The archive integrity records, source deltas and repeated
scope-guard evidence are retained with the foundation review repair bundle.
