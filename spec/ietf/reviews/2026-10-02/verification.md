# Verification of the release-target draft

Document and publication verification completed on October 2, 2026. The first table records local document checks; production verification is recorded separately below.

| Check | Result |
|---|---|
| RFCXML, prepped XML, text, and PDF generation | Passed; no writer warnings or errors. |
| `make -C spec/ietf check` | Passed, exit 0. |
| Generated example/vector tests | 79 passed. |
| Build-gate tests | 8 passed. |
| Regeneration equivalence | XML/text exact; prepped XML normalized preparation timestamp; extracted PDF text exact. |
| idnits submission mode | 0 errors, 0 warnings, 0 comments. |
| Plain-text column width | At most 72 columns. |
| Existing examples against newer security source corpus | Passed without changes to generated appendices. |
| Independent source protocol fixtures | 38 of 38 expectations passed. |
| Additional schema and signing-input assertions | 13 passed; 51 total assertions. |
| Source anchors | No duplicate anchors or unresolved source cross-references. |
| Public draft hygiene | No private repository links, internal code paths, restored About note, agentproto assignment, or em dashes. |
| `git diff --check` | Passed. |
| Rendered PDF | 129 pages; no extracted word extends outside its page. |
| Visual review | All 129 pages inspected in contact sheets; pages 1, 14, 24, 39, 48, 58, 77, 88, 102, and 108 inspected at 1400-pixel height. No observed clipping, table overlap, missing glyphs, or broken figures. |

[Build log](build.log) and [check log](check.log) retain terminal output. [Artifact digests](artifact-digests.json) bind the reviewed source and renderings. [Wire results](wire-verification.json) record every independent assertion. [Normative inventory](normative-inventory.json) contains 227 BCP 14-bearing blocks and 591 keyword occurrences; 118 blocks retain previously reviewed wording, 21 cover source wire updates, 78 contain release requirements, and 10 are classified under external standards.

## Reproduction

From the document worktree:

```sh
PATH=/opt/homebrew/lib/ruby/gems/4.0.0/bin:$PATH make -C spec/ietf
PATH=/opt/homebrew/lib/ruby/gems/4.0.0/bin:$PATH make -C spec/ietf check
```

With the selected security source checked out separately at the revision pinned in `source-manifest.json`:

```sh
python3 spec/ietf/tools/render_vectors.py \
  --vectors "$CHIO_REVIEW_SOURCE/tests/bindings/vectors" \
  --out spec/ietf/generated --check

python3 spec/ietf/reviews/2026-10-02/verify_wire_review.py \
  "$CHIO_REVIEW_SOURCE"
```

The latter script requires `jsonschema`, `referencing`, and `cryptography`. It checks all positive and negative protocol-primitives fixture expectations, exact-argument intent closure, argument-digest substitution, operation-nonce preimage separation, and pending-result nonce exclusion. It uses a deterministic test-only Ed25519 key and the document's independent canonicalizer. Fixture signatures with placeholder material are not represented as cryptographically valid runtime evidence.

The wire checks do not run the Rust kernel. They do not prove durable admission, confinement, deployment behavior, or completed roadmap qualification. No full workspace Cargo run or Datatracker action was performed by this document review. Site checks and deployment are recorded separately as publication evidence. The release reconciliation items remain in the review report for the actual completed implementation.

## Public package

The reviewed prose and all five source/rendering inputs match the public source package at `5f63e6e4e5284c182e9c94e56208c9a829e31a7e`, branch `docs/ietf-production-profile-20261002` in the public Chio repository. Public review and submission summaries replace internal provenance links in that package. The internal review source was refreshed to `df9f1791b3` and all 51 independent assertions were repeated successfully.

The second pass also inspected PDF pages 54, 77, 81, 93, and 100 at 1300-pixel height after regeneration. No clipping or overlapping content was observed.

## Site publication

[Site PR 221](https://github.com/backbay-labs/chio-world/pull/221) merged as `55b3243e5213831a28e2d0531a761dc5f7005af2`. Its tree exactly matches the tested branch at `72b58f02c105c647920795886510e428b8757272`. Vercel production deployment `dpl_95YRf4EPm7LeuQmuZQnRaHQQToDC` is READY at that merge commit, with both Chio domains and their `www` aliases attached. The public source package is published on its named branch and pinned immutably by the site; this record does not claim a merge into the public source repository's main branch.

Local site verification passed 3,338 unit tests (one existing skip), TypeScript, the production build, 21 generated datasets, 543 snippets, CLI source comparison, and 431 historical transcript integrity checks. A reviewed compatibility certificate preserves the existing transcript capture; these transcripts were not recaptured. All 34 production-build browser checks passed, covering responsive layout, source and paragraph anchors, keyboard and touch behavior, citations, downloads, JavaScript-disabled reading, and zero desktop/mobile axe violations.

After deployment, 16 HTTP checks verified the reader and byte-identical TXT/XML/PDF downloads across all four public hostnames. Six browser checks against production passed, including source anchors, mobile deep links, mobile accessibility, and all three download hashes. No error entries were returned in the sampled ten-minute production log window.

The search publisher changed only this draft: 13 new and 72 changed chunks received embeddings. The resulting index revision is `7a4e35a0ec6cabb13c3ecdb5274695f0af283f6e17c6315e61ad4b550d2c2df6`, with 8,112 of 8,112 chunks embedded. A post-publication comparison found all 156 draft chunks unchanged and no missing embeddings. Four live queries across both public domains returned the revised lifecycle and signing-key sections using hybrid keyword/semantic retrieval.

Repository-wide prose, page, and source-reference audits reproduced the base's existing findings, with none added. GitHub Actions jobs could not start because GitHub reported an account billing/spending restriction. Hosted CI is therefore not recorded as passing; the local checks and successful Vercel builds are separate evidence. The search client emitted an existing future PostgreSQL `sslmode` compatibility warning, without any TLS configuration change. Vercel inspection used CLI 62.1.0, while the global installation remains 60.1.3.

The shared checkouts' snapshotted tracked changes were preserved (459 site files and five source files). No runtime implementation or Datatracker submission was performed. [Publication results](publication-verification.json), [live artifact checks](production-artifact-verification.json), and [live search checks](production-search-verification.json) retain the exact release evidence.
