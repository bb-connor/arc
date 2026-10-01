# Guard and security reader qualification

Source base: `90e8f0683b251b49cccbaa6d94d554c53eb88932`. The owning local commit
contains this record and the final source hashes. The batch began September 30;
final consumer qualification and closeout continued October 1.

All **33 pinned readers** have contracts in
[reviewed-readers.json](reviewed-readers.json). Supporting owners are recorded
separately in [supporting-owners.json](supporting-owners.json). The baseline falls
from 131 to **98 workspace files**, with zero guard, security, trust, protocol or
CLI baseline files. These counts measure review debt, not vulnerabilities.

## Terminal evidence

- [Package campaign 4](qualification-4.log) ran all 12 selected packages with
  registry `marketplace` and the default WASM backend. Its terminal exit is
  **101**, with six failures confined to the bundled embedding input in
  `chio-guards --test cua_guards`; every other target passed. This campaign is
  not relabeled green.
- The corrected unsigned-document parser passes its
  [core numeric/duplicate control](unsigned-document-control.log), including
  continued rejection under the unchanged signed and external numeric profiles.
  The complete [guard package rerun](guards-final.log) then passes **556 tests**,
  with two ignored doctests and no failures.
- [Test summary](test-summary.json) replaces all guard-package results from
  campaign 4 with that complete rerun and adds the new core control. Accepted
  results total **1,445 harness passes, zero failures, 11 ignored**, across
  **106 test binaries and 12 doctest groups**. The core command deliberately
  filters 409 unrelated tests. Twelve Go/Python cases in the harness pass count
  return early because their built SDK WASM artifacts are absent; those are
  **not** SDK runtime qualification.
- [CLI and optional WASM fuzz consumer compile](cli-consumers.log):
  `cargo check --locked --offline -p chio-cli --tests --features
  iroh,chio-wasm-guards/fuzz` terminates with exit zero. This compiles the new
  error mappings and final parser API; it is not CLI or fuzz execution.
- [Trust inventory](trust-check-final.log), [file hygiene](hygiene-final.log),
  [negative assertions](negative-final.log), [wire schemas](wire-check.log) and
  [changed-file formatting](format-final.log) pass. No limits or exceptions were
  raised. The negative-assertion ratchet remains 1,257 assertions at 1,175 sites.
- [Qualification metadata](qualification.json), [source hashes](source-hashes.json)
  and [test-binary hashes](binary-hashes.json) identify the final source and
  accepted local evidence. The metadata records which final edits were covered
  by the focused rerun or consumer compilation. Two test modules were moved
  intact to their owners' ends after execution; no test bodies changed.
- [Independent review](review.md): one read-only reviewer, no delegated
  implementation and no claimed second independent review of the fixes.

Ignored cases are the native x86_64 seccomp compiler-boundary case, the
Docker-dependent Zot integration, six TypeScript WASM cases and three doctests.
The missing Go/Python artifacts produce separate early returns described above.
Live provider and alternate-backend interoperability were not exercised.

## Retained failed attempts

| Attempt | Terminal result and remediation |
| --- | --- |
| [Qualification 1](qualification-1.log) | Compile failure from the initial bounded-vector import; corrected to the actual `ports` owner. |
| [Qualification 2](qualification-2.log) | Compile failure from passing an untrusted descriptor string where the validator requires the static expected media type; corrected at the download helper boundary. |
| [Qualification 3](qualification-3.log) | Five targets failed: stale unknown-VirusTotal/error assertions, the registry's flattened Sigstore parser cause, and overly strict embedding float input. Typed causes, file-path context, explicit denial semantics and test contracts were corrected. |
| [Qualification 4](qualification-4.log) | Six bundled embedding cases exposed valid `0.10`-style decimals still rejected by the signed numeric contract. Added the unsigned document profile without changing signed/external parsing; core control and complete guard rerun pass. |

Each command has a same-name JSON record with command, environment, duration and
terminal exit status. Failed logs are preserved verbatim. Raw command logs are
excluded from source/documentation whitespace checks.

## Acceptance boundary and next work

This is local source/package qualification. Existing sandbox, keyring,
quarantine, decoy and security-type constraints were reviewed and retained where
sound. New parser checks do not replace authentication, signatures, replay,
quorum, policy or live admission. No single all-green combined 12-package run,
workspace clippy, full-workspace campaign, hosted CI, native enforcement, M5 or
release acceptance is claimed.

File helpers reject final symlinks on Unix; parent-directory custody and atomic
cache/blocklist publication remain distinct work. Broader semantic error-source
migration and cryptographic/live-provider qualification remain separate. No
push, merge, publication or activation occurred.

Next: all [31 platform readers](next-readers.json), covering HTTP authority,
transaction passports, finding ingress/workers/PostgreSQL state, commerce,
enterprise exports, web interoperability and trust-market context. The other
67 baseline readers and non-reader roadmap gates remain queued.
