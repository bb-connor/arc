# Chio Roadmap — Continue From 189/266 Paused State

Paste this into a fresh Claude Code session at the repo root
(`/Users/connor/Medica/backbay/standalone/arc/`). You are picking up
where the prior orchestrator paused. Read this in full before acting.

---

## 1. Where you are

- `origin/project/roadmap-04-25-2026` HEAD: 189 of 266 tickets merged.
- Open PRs: 0.
- Ready unblocked tickets (deps merged, no scope issues): 0.
- Blocked tickets needing scope/API decisions: 13 (enumerated in §4).
- Last merged PR: #224 (`M10.P2.5.T1`).

The prior orchestrator paused at "first clean stop point" because every
remaining pending ticket either has an undersized `owner_glob`, a
missing soft-dep, or a structural design question that the YAML doesn't
resolve.

**Your job: unblock the 13. Make judgment calls. Keep shipping.**

## 2. Authorization (the user said: "keep pushing autonomously")

The prior session was conservative about expanding `owner_glob`. The
user has explicitly upgraded that authority for this run.

### You may, without further confirmation:

- **Expand `owner_glob`** when the milestone doc clearly anticipates
  the path. Document the expansion in the PR body under
  `## Scope expansion` with a one-line citation (milestone-doc
  filename + line range).
- **Add an external crate dep** when the milestone doc names the
  primitive (e.g. AEAD, content-bundle store) and the dep is in the
  same family the workspace already uses (RustCrypto family,
  `tokio` ecosystem, `serde` ecosystem). Pin to a workspace-stable
  version. Note the dep + rationale in `## Dependency added`.
- **Narrow a gate-check** when the canonical command exercises code
  that's outside the ticket's true scope (the M05.P1.T6 case below
  is the canonical example). Substitute a tighter `cargo test -p
  <crate> --test <suite>` invocation that exercises the same contract
  without dragging in unrelated work. Note in `## Gate-check adapted`.
- **Land a small predecessor crate change** when a ticket's soft-dep
  mentions an existing crate's hook that turns out not to exist. The
  fix lives in the dependent ticket's PR; document under
  `## Predecessor change`.
- **Admin-merge** every PR via `gh pr merge <N> --repo bb-connor/arc
  --squash --admin --delete-branch`. CI billing remains exhausted;
  PR #224 and earlier all merged this way.
- **Rebase + force-with-lease** to resolve `Cargo.lock` and workspace
  `Cargo.toml` `[workspace] members` conflicts. For added/added
  files (`wit/`, fixtures), `git checkout --ours` during rebase to
  prefer the upstream-merged version.

### You must still halt for:

- **Cross-doc invariant violations** (touching frozen kernel paths
  outside M05; touching `chio:guard@0.2.0` `wit/` outside M06;
  touching `chio-attest-verify` outside M09).
- **Forbidden actions** (table 10 row F: bumping crate versions
  minor/major, dropping/`#[ignore]`-ing passing tests, adding
  `#[allow(clippy::...)]`, force-pushing shared commits, editing
  `releases.toml`).
- **Workspace one-liner failure** post-merge.
- **Three consecutive executor failures** on the same ticket.
- **Genuinely ambiguous design questions** the milestone doc doesn't
  resolve.

For halts, post a chat message and continue scheduling other unblocked
work — halts are per-ticket.

## 3. Workflow per iteration

1. Compute the READY set (the Python recipe in
   `.planning/trajectory/HANDOFF-PROMPT.md` §4 still applies).
2. For any of the 13 blockers in §4 below, apply the prescribed
   unblock and re-add to the schedulable set.
3. Schedule 4-8 executors in one parallel batch (one Agent tool call
   per ticket, all in one message, all `run_in_background: true`).
4. Admin-merge each PR as it lands. Resolve conflicts inline (§2).
5. Loop.

## 4. The 13 blockers, with prescribed unblocks

When you spawn the executor for each, paste the unblock block into the
prompt's `## Source-of-truth references` and `## Task` sections so the
executor doesn't re-discover the issue.

### 4.1 M10.P1.T7 — BLOB-encrypted spool persistence

**Block**: needs AEAD choice + `chio-store-sqlite` scope expansion.

**Unblock**:
- AEAD primitive: **`chacha20poly1305`** (workspace dep,
  `chacha20poly1305 = "0.10"` — RustCrypto family, matches workspace
  conventions; alternative `aes-gcm` rejected for portability).
- Expand owner_glob to include:
  - `crates/chio-store-sqlite/src/lib.rs`
  - `crates/chio-store-sqlite/src/encrypted_blob.rs` (new)
  - workspace `Cargo.toml`
- API to land in `chio-store-sqlite`:
  ```rust
  pub struct TenantKey([u8; 32]);
  pub struct EncryptedBlob { ciphertext: Vec<u8>, nonce: [u8; 12] }
  pub fn encrypt_blob(tenant_key: &TenantKey, plaintext: &[u8]) -> EncryptedBlob;
  pub fn decrypt_blob(tenant_key: &TenantKey, blob: &EncryptedBlob) -> Result<Vec<u8>, DecryptError>;
  pub fn write_encrypted_blob(&self, tenant_id: &TenantId, key: &TenantKey, payload: &[u8]) -> Result<BlobHandle, _>;
  pub fn read_encrypted_blob(&self, handle: &BlobHandle, key: &TenantKey) -> Result<Vec<u8>, _>;
  ```
- Then in `chio-tee/src/persist.rs`, consume the hook per the original
  ticket spec.
- Citation: `.planning/trajectory/10-tee-replay-harness.md` line 594
  ("chio-store-sqlite tenant-key BLOB encryption hook").

### 4.2 M04.P6.T2 — anchored-root differential test

**Block**: owner_glob missing the integration-test wiring path.

**Unblock**: expand owner_glob to include
`formal/diff-tests/tests/anchored_root.rs` AND
`formal/diff-tests/Cargo.toml` (cargo test-target wiring). The doc at
`.planning/trajectory/04-deterministic-replay.md` Phase 6 names the
diff-tests crate as the harness host.

### 4.3 M05.P1.T6 — update in-tree callers to async path

**Block**: workspace gate-check pulls in governed call-chain ordering
tests outside T6's scope.

**Unblock**: narrow the gate from `cargo test -p chio-kernel --quiet`
(full-suite) to:
```
cargo test -p chio-kernel --test receipt_signing_async \
  && cargo test -p chio-kernel --lib evaluator:: \
  && cargo build -p chio-kernel
```
Document the substitution in PR body. The full-suite gate runs at the
M05 P1 sub-wave-gate (after T7) per
`.planning/trajectory/05-async-kernel-real.md` Phase 1 finalization.

### 4.4 M06.P1.T3 — bundle-handle resource + fetch-blob host call

**Block**: missing content-bundle/blob store soft-dep.

**Unblock**: land a minimal in-process content-bundle store inside
`crates/chio-wasm-guards/src/bundle_store.rs` (expand owner_glob).
Surface:
```rust
pub trait BundleStore: Send + Sync {
    fn fetch_blob(&self, sha256: &[u8; 32]) -> Result<Vec<u8>, BundleError>;
}
pub struct InMemoryBundleStore { /* HashMap<[u8;32], Vec<u8>> */ }
```
The OCI-backed `BundleStore` impl lands later in M06.P2 (registry
phase). T3 only needs the trait + in-memory impl + the `fetch-blob`
host-call wiring per `06-wasm-guard-platform.md` Phase 1 T3.

### 4.5 M07.P2.T4.a — OpenAI SSE transport scaffold

**Block**: needs `crates/chio-openai/src/lib.rs` in scope.

**Unblock**: expand owner_glob to include `crates/chio-openai/src/lib.rs`
(declare the `streaming` module) and `crates/chio-openai/src/streaming/mod.rs`.

### 4.6 M07.P3.T4 — Anthropic server_tools manifest extension

**Block**: owner_glob too narrow for real wiring.

**Unblock**: expand to include `crates/chio-manifest/src/lib.rs` (or
the equivalent surface — find via `rg -l 'server_tools' crates/`)
**plus** the chio-anthropic-tools-adapter consumer wiring at
`crates/chio-anthropic-tools-adapter/src/manifest.rs` (new).

### 4.7 M07.P4.T4 — Bedrock IAM principal disambiguation

**Block**: owner_glob too narrow.

**Unblock**: expand to include `crates/chio-bedrock-converse-adapter/src/iam_principals.rs`
(new) AND `config/iam_principals.toml` (the signed config file the
ticket spec names).

### 4.8 M10.P2.T3 — diff renderer

**Block**: owner_glob too narrow for real wiring.

**Unblock**: expand to include `crates/chio-cli/src/cli/replay/diff.rs`
(new) AND a touch on `crates/chio-cli/src/cli/replay/execute.rs`
(landed in PR for M10.P2.T2; T3 hooks the diff renderer into the
report generator).

### 4.9 M10.P2.5.T2 — chio replay --bless --into

**Block**: owner_glob too narrow.

**Unblock**: expand to include `crates/chio-cli/src/cli/replay/bless.rs`
(new) plus the existing `crates/chio-cli/src/cli/replay/traffic.rs`
(touch the dispatch). Per
`.planning/trajectory/10-tee-replay-harness.md` Phase 2.5 T2.

### 4.10-4.12 M08.P2.T2 / T3 / T4 — workers/edge/deno scaffolds

**Block**: gate-check `bun run --filter ...` requires repo-root
`package.json` + `bun.lock` updates.

**Unblock**: expand each ticket's owner_glob to include:
- repo-root `package.json` (only the `workspaces` array — append the
  new package path)
- `bun.lock` (regenerated by `bun install`)

Schedule T2/T3/T4 sequentially (NOT in parallel — they all touch
`bun.lock` and root `package.json`).

### 4.13 M07.P4.T6 — cross-provider verdict-equality demo

**Block**: depends on unresolved OpenAI streaming alias issue.

**Unblock**: this ticket truly depends on M07.P2.T4.a/b landing
(streaming state machine in `chio-openai`). Defer scheduling until
M07.P2.T4.b (the streaming wire-up) is merged. If M07.P2.T4.a is
unblocked per §4.5, T4.b becomes ready next; T6 then becomes ready
after both. **No standalone unblock — schedule order is the unblock.**

## 5. Scheduling order recommendation

Pick this order to maximize parallel throughput while serializing
shared-path edits:

**Wave A (parallel, no shared paths):**
- M04.P6.T2 (formal/diff-tests)
- M05.P1.T6 (chio-kernel internals)
- M06.P1.T3 (chio-wasm-guards bundle store)
- M07.P2.T4.a (chio-openai streaming scaffold)
- M07.P3.T4 (chio-manifest + anthropic adapter)
- M10.P2.T3 (chio-cli diff renderer)

**Wave B (after Wave A merges, serialized for workspace Cargo.toml):**
- M10.P1.T7 (adds chacha20poly1305 to workspace; expands store-sqlite)

**Wave C (serialized for bun.lock):**
- M08.P2.T2 → T3 → T4 (workers, edge, deno — one at a time)

**Wave D (parallel after their deps land):**
- M07.P4.T4
- M10.P2.5.T2

**Wave E (after Wave A's M07.P2.T4.a + the follow-on T4.b merges):**
- M07.P4.T6

After each wave merges, recompute READY — many downstream tickets in
M04/M05/M06/M07/M08/M10 will unblock.

## 6. Executor prompt template (reuse from prior session)

```
Execute ticket **<TICKET_ID>** for Chio at /Users/connor/Medica/backbay/standalone/arc/.
End-to-end: worktree → implement → gate-check → push → open PR.

## Spec
<paste YAML from .planning/trajectory/tickets/<MILESTONE>/<PHASE>.yml>

## Scope expansion (authorized this run)
<paste the unblock block from CONTINUE-PROMPT.md §4 for this ticket>

## Source-of-truth references
- Milestone doc: <path> Phase N Task M
- Citations for scope expansion authority: CONTINUE-PROMPT.md §2
- House rules: no em-dashes (U+2014), unwrap_used/expect_used clippy-banned, conventional commits

## Worktree
git worktree add /tmp/arc-m<NN>p<P>-t<T> -b <worktree_branch> origin/project/roadmap-04-25-2026
cd /tmp/arc-m<NN>p<P>-t<T>

## Task
<numbered steps>

## Gate check
<from YAML, possibly adapted per §2/§4>

## Commit + push + PR
- Subject: <conventional-commit prefix>(<scope>): <imperative summary> [<TICKET_ID>]
- gh pr create --base project/roadmap-04-25-2026 --repo bb-connor/arc \
    --title "<title> [<TICKET_ID>]" --body "<heredoc>"
- Body sections (in order):
  ## Summary
  ## Scope expansion        (cite milestone doc lines)
  ## Dependency added       (if applicable)
  ## Gate-check adapted     (if applicable)
  ## Gate-check output      (verbatim)
  ## Test count             (vs baseline if applicable)
  ## Em-dash scan           (verbatim)
  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>

## Report back
PR URL/number, branch + SHA, gate-check output, scope-expansion summary, deviations.

Self-contained brief. Begin.
```

Spawn with `subagent_type: gsd-executor` and `run_in_background: true`.

## 7. Reporting cadence

- **On each batch dispatch**: one-line "launched N agents: M04.P6.T2, M05.P1.T6, ...".
- **On each merge**: silent unless wave-gate close.
- **At every ~10 PRs merged this run**: brief progress (merged count, in-flight count).
- **On halt**: full halt message per §2.

## 8. Completion criteria

- All 266 tickets in `.planning/trajectory/tickets/` show `merged`
  status (via the recipe in `HANDOFF-PROMPT.md` §4).
- Workspace one-liner is green on `origin/project/roadmap-04-25-2026`:
  ```
  cargo build --workspace && cargo test --workspace \
    && cargo clippy --workspace -- -D warnings \
    && cargo fmt --all -- --check
  ```
- Post a final summary in chat: total merged this run, halts encountered,
  scope expansions performed (one-line per), any deferrals flagged for
  follow-up.

## 9. Local working tree note

The user notes the working tree at `/Users/connor/Medica/backbay/standalone/arc/`
contains pre-existing untracked trajectory/catalog files plus
`target-m07p3-t3/`. Leave them. They are not yours.

The 13 blocker analysis above (and your prior pause) lives in chat
context, not on disk. This document is your durable handover.

---

End of continue prompt. You are clear to begin.
