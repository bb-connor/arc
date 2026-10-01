# Guard and security reader execution

Base: `90e8f0683b251b49cccbaa6d94d554c53eb88932`, isolated branch
`packet/3-retention-accounting`, checkout `/tmp/arc-security-launch`.
Scope: all 33 paths pinned by the preceding trust batch, plus shared owners and
direct consumers. This continues remaining-work item 2 and mechanisms B/C.

## Delivered contracts

1. **Guard decisions and loading.** All six external providers validate bounded
   original responses before typed projection; threat-intel argument and cache
   readers share their original native JSON gate. Missing verdict fields cannot
   silently become Allow. Explicit Vertex blocks deny below the probability
   threshold; Safe Browsing's valid empty no-match response remains supported.
   Original JSON causes are retained with redacted diagnostics.
2. **Registry and WASM custody.** OCI downloads enforce bounds in transport,
   preflight aggregate and per-descriptor size, and check exact hashes. Cache,
   embedding and WASM files use bounded regular reads with Unix final-symlink
   rejection. Manifests, sidecars, blocklists and canaries validate original
   documents. Canonical blocklist state and bounded unsigned embedding floats are
   preserved. Malformed structured guest denial JSON is no longer reinterpreted.
3. **Security execution, recovery and types.** Existing bounded canonical and
   authenticated sandbox, keyring, quarantine and decoy readers have explicit
   dispositions. Temporal rules now use original bounded native JSON. Persisted
   and live Unix decoy paths share a 4096-byte maximum. `BoundedVec` rejects
   overflow without constructing another element; native full-width integers
   and the existing validated identifier/label/grant contracts remain intact.
4. **Review and accounting.** One independent read-only review identified two
   material gaps, both fixed with production-linked controls. All 33 pinned
   paths are recorded, reducing the workspace baseline from 131 to 98. Guard,
   security, trust, protocol and CLI baseline counts are zero. Counts measure
   semantic review debt, not vulnerabilities or threat closure.

The [plan](../superpowers/plans/2026-09-30-guard-security-readers.md),
[per-reader dispositions](artifacts/2026-09-30-guard-security-readers/reviewed-readers.json),
[supporting contracts](artifacts/2026-09-30-guard-security-readers/supporting-owners.json)
and [review resolutions](artifacts/2026-09-30-guard-security-readers/review.md)
provide the detailed ownership record.

## Qualification and limits

The [evidence record](artifacts/2026-09-30-guard-security-readers/README.md)
contains terminal commands, failed attempts, final test counts, source/binary
hashes and consumer compilation. This is local scoped qualification. Parsing
never substitutes for signatures, replay, issuer/policy checks or live admission.
Full-width native integers are not narrowed into the external signing profile.

There is no new compatibility decoder or fallback. Removed OCI download settings
are not retained as no-op configuration. Cargo.lock adds existing workspace
core-types/libc dependency edges without upgrading package versions.

Broader mechanism C semantic errors, ancestor filesystem custody and atomic
publication, optional SDK/backend/device matrices, native enforcement, hosted
exact-candidate CI, supply-chain audits, M5 and release acceptance remain separate.
The worktree and unrelated `output/` are preserved. No push, merge, publication
or activation.

## Next implementation batch

Execute all **31 platform readers** pinned in
[next-readers.json](artifacts/2026-09-30-guard-security-readers/next-readers.json):

- HTTP authority/compliance/emergency/plan inputs and transaction-passport
  evidence graphs, runtime security and verifier policy.
- Hosted finding ingress, worker protocols/execution and PostgreSQL catalog,
  checkpoint, HTTP and replication readers.
- Commerce orders/mandates/settlement/replay, enterprise exports, agent web
  interoperability and trust-market context.

Validate each original bounded document before projection or durable state use,
retain native error causes, preserve authentication/replay ownership, and repair
specific authority or lifecycle gaps found in those owners. Qualify focused
packages and direct consumers, then update the remaining queue. The other
67 baseline files and non-reader roadmap gates remain explicit follow-up work.
