# Verification of the release-target draft

All results below are local document-review results from October 2, 2026.

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
| Rendered PDF | 128 pages; no extracted word extends outside its page. |
| Visual review | All 128 pages inspected in contact sheets; pages 1, 14, 24, 39, 48, 58, 77, 88, 102, and 108 inspected at 1400-pixel height. No observed clipping, table overlap, missing glyphs, or broken figures. |

[Build log](build.log) and [check log](check.log) retain terminal output. [Artifact digests](artifact-digests.json) bind the reviewed source and renderings. [Wire results](wire-verification.json) record every independent assertion. [Normative inventory](normative-inventory.json) contains 221 BCP 14-bearing blocks and 570 keyword occurrences; 123 blocks retain previously reviewed wording, 20 cover source wire updates, 69 contain release requirements, and 9 are classified under external standards.

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

The wire checks do not run the Rust kernel. They do not prove durable admission, confinement, deployment behavior, or completed roadmap qualification. No full workspace Cargo run, hosted CI run, website deployment, or Datatracker action was performed by this document review. The release reconciliation items remain in the review report for the actual completed implementation.
