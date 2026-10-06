# iroh-blobs 0.103.0 to 0.103.1 source delta audit

Date: 2026-10-06. Auditor: Codex, inline source review for PR #1173.

## Source custody

Both published archives match the live crates.io registry checksums:

| Version | Archive SHA-256 | Upstream commit |
| --- | --- | --- |
| 0.103.0 | `5be50b0e2d0a9ba65cee4e0dfb708b3704e02ad12bd4c14c6307e94245943126` | `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc` |
| 0.103.1 | `a3148ad01585eb6b7cfb641e4100564f4f56db644f4cbed8c10ab2478663161f` | `7a4c53a45ecd2bbbb5dd86b3639271004ae89d39` |

The registry published the replacement at 07:35 UTC and yanked the old version
at 07:39 UTC on October 6. The upstream API confirms the replacement commit is
the `0.103.1` release. Archive verification, full delta, and registry observation
are retained in the PR qualification evidence.

Primary source: [request-mode repair](https://github.com/n0-computer/iroh-blobs/pull/270)
and [replacement release commit](https://github.com/n0-computer/iroh-blobs/commit/7a4c53a45ecd2bbbb5dd86b3639271004ae89d39).

## Reviewed changes

I read all twelve changed release files and the surrounding request selection,
provider dispatch, hash construction, filesystem actor startup and termination.
The changed files are `.cargo_vcs_info.json`, `CHANGELOG.md`, both manifests,
`Cargo.lock`, two examples, `src/hashseq.rs`, `src/provider.rs`,
`src/provider/events.rs`, `src/store/fs/meta.rs`, and `src/tests.rs`.

The significant repair is in `EventSender::request`. The old code selects
`mask.get` for every request. A private `RequestKind` trait now selects `get`,
`get_many`, or `push` for the corresponding typed request. Observe requests map
their three modes explicitly. The existing `RequestMode::Disabled` branch returns
`ProgressError::Permission` before dispatch. This restores the default and
`ALL_READONLY` masks' explicit prohibition on pushes. Notification,
interception, progress, throttling and channel error handling otherwise retain
their existing branches. The trait and request helper remain crate-private.

The limit example now explicitly disables get-many requests, which its single
hash interceptor does not authorize. The random-store example and permissive
push test explicitly opt into pushes. Two upstream regressions check unsolicited
push rejection. These changes agree with the request-type repair.

`handle_stream` moves its existing dispatcher into a private function and logs
returned errors locally before returning the same result. The metadata actor
moves its existing loop into `run_inner`, logs its error and exits. Its callers
already discard the spawned result. Transaction logic, command ordering and
startup errors do not change. Diagnostic error text must still be treated as
local operator data.

`HashSeq::iter` replaces checked 32-byte chunk conversion with the safe
`as_chunks::<32>` API. Its constructor requires a multiple-of-32 length, and
both implementations iterate the same full chunks in order. There is no new
unsafe operation, alignment assumption, ownership transfer or hashing change.
The retained Rust requirement is 1.91, below this workspace's 1.95 requirement.

The only dependency requirement change is build-helper `cfg_aliases` from
`0.2.1` to `0.2.2`, reviewed separately. The release's standalone lock refresh
does not authorize unrelated production lock upgrades.

## Judgment and acceptance boundary

The reviewed delta supports `safe-to-deploy` conditional on the retained
`0.103.0` base acceptance. That base is an existing explicit exemption; this
review does not convert it into a full source audit. The legacy fallback when
an interception mode has no event client is unchanged. Applications must still
provide their intended endpoint identity gate, resource bounds and access
policy; this delta establishes the request mask repair.

Acceptance requires old-versus-new real peer/store regressions through Chio's
production catch-up protocol, retained legitimate transfers, complete affected
crate tests, strict Clippy, authenticated locked resolutions, all six audit graphs,
and the enforced deny policy. Results are recorded in the review qualification
package, without adding an exemption or suppressing the yanked-version error.

The actual gated, two-peer Chio regressions reproduce two forbidden-push failures
and one permitted-push success against `0.103.0`. All three pass against `0.103.1`.
Each mode also fetches and verifies two fresh signed roots over the same admitted
connection. Receiving-store inspection establishes push rejection during the
bounded observation interval; the push protocol itself does not acknowledge
remote authorization. The enabled-push control confirms that the fixture can
observe a completed transfer. The first fixture run fails redundant shutdown
after successful transfers and is retained separately from behavioral evidence.
