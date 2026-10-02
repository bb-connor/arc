# Funded work and security integration evidence

Combined source: `71e5cbc3bf7b08f477ed0e0361f2cca0c36eaea3`, with security parent
`491f585e9013dcb6335589c82d00ac219efbf0a6` and funded parent
`7755d3762baa5e0fda0d171835a9000c26de9033`. The separate active security worktree
and its uncommitted changes were not used. No shared branch was published.

## Evidence boundaries

| Snapshot | Binary SHA-256 | Executed boundary |
| --- | --- | --- |
| v1 | `58635df3aabb84a0a3a55fd6b0f84aff12df3fd5f0b3090a89b08d8ccb14e2aa` | Earlier standalone/native and Python checks; superseded for lifecycle by v2 |
| v2 | `71d3d0c43134ceea39660c48ec1e8a6d90aa7b49e38ed3f11c3d96e69efde1d5` | 95 native tests including six opted-in owned-chain cases; 20 selected process scenarios; 38 independent-Python checker tests |
| v3 | `919d5f4bad46f318f4e505e0377ee94f751a35a218c4713c1af58b06a1cdcfdf` | Final source: strict Clippy, four peer unit tests and authenticated peer payout/refund |

The compressed source manifests preserve complete original input hashes.
`integration-commit.json` ties v3 to the committed tree. The sole v2-to-v3 source
change is `h.field.equiv(*n)` to `h.field.equiv(n)` in the HTTPS header check;
`v2-to-final.patch` and the per-file hashes retain it. The full 95-test and
20-scenario runs are v2 evidence, not silently relabeled v3 executions.

The 20 process scenarios are peer payment/refund (2), isolated bilateral
payment/refund (2), earned-child crashes (4), refund resolution (7), and
execution/custody crashes (5). Python unittest reports count test methods;
several methods execute multiple explicitly selected scenarios. The source
harness and command records preserve that distinction.

Public v2 artifacts are under `public-v2/`; the final peer rerun is under
`public-v3-peer/`. The copied source index uses its original `public/` prefix
for v2; that prefix maps to `public-v2/` here. Binding reports reconstruct
agreement-body digests, original native identities, rail outcomes and unknown
parent terminals. They are derived summaries; the signed source artifacts are
retained alongside them. All roles use author-controlled local infrastructure
and mock assets.

## Integration findings

The merge probe identified 21 conflicts. Resolution preserved current checked
clocks, receiver-owned admission, raw JSON validation, fallible DPoP handling,
bounded counters and durable recovery semantics. The standalone example lock
was regenerated for the combined dependency graph and used locked/offline.

A real process failure exposed delayed-attestation enrollment: the old code
validated independently signed standing at the earlier governance-draft time.
The deterministic regression first fails with stale standing, then passes when
historical custody uses the signed observation time while fresh enrollment
still checks current standing. Future-standing rejection remains tested. An
equivalent rustls hostname-error diagnostic was added to the negative transport
harness without accepting a successful connection or any output artifact.

All failed build, test and lint attempts remain in their original logs. The
initial strict Clippy failure is superseded by `standalone-clippy-retry`, not
deleted. Format and schema checks passed in their recorded runs.

## Remaining release gates

This evidence qualifies the specified research boundaries only. Formal-mirror
anchors still refer to moved/deleted symbols, the broader proof-coverage
mapping is stale, and inherited or combined files exceed Rust hygiene caps.
Raw whitespace checks also report incoming historical evidence, CRLF fixtures
and prior-document formatting. None was rewritten just to make a gate green.
Full combined-workspace and security inventories, exact-source hosted CI,
off-host operator deployment, custody capacity and independent operation
remain unqualified. The paper does not label this candidate a security release.

The command JSON next to each log gives argv, environment, source checkout,
timing and terminal exit status. Use those records with the pinned checkout
to reproduce the selected lane; the original `/tmp` paths are provenance,
not mandatory installation paths. Install the repository's frozen Node and
Python dependencies, choose a fresh Cargo target and set `CHIO_CHECKOUT_ROOT`
to the integrated checkout before repeating native suites.
