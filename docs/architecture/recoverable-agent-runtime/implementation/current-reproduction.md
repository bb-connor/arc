# Current source correspondence and evidence reproduction

The current implementation is unqualified. A command declaration, source
locator or locally closed finding does not establish a current native, provider,
Linux, formal, hosted or release qualification result.

The original coverage records remain at [authority coverage](p1/requirements-coverage.json),
[knowledge coverage](p4/requirements-coverage.json) and
[product coverage](p6/requirements-coverage.json). Their original paths, symbols,
source hashes and execution claims remain historical.

The additive overlay is retained at
`target/current-review-followup/qualification-evidence-review/source-anchor-and-claim-correspondence-20261008T002646.344452Z/current-overlay/overlay.json`.
It identifies each original JSON pointer and its current source locator/hash:

| Original finding | Captured locator scope |
|---|---|
| C1-08 | All 160 authority-coverage locator occurrences. |
| E-knowledge-15 | All 55 knowledge-coverage locator occurrences. |
| G-product-07 | All 28 product-coverage locator occurrences, including the nine stale name/path occurrences. |
| H-SDK-13 | Shared product locators, current command declarations and the separate historical-package reproduction limits below. |

There are 243 unique historical pointers and 51 current containing-source
files. The capture resolved every locator without source drift. Of those
references, 178 point into a containing file whose bytes differ from the earlier
overlay. This is a file-hash observation, not proof that 178 function bodies
changed or that a historical behavioral result still applies. Acceptance-test
locators identify lexical Rust definitions or Python AST definitions; they do
not establish build membership or a passing execution.

The local review reader rejects changed source pins, substituted original or
current locators, missing required rows and a borrowed current qualification
flag. Its exact retained commands and controls are beside the overlay. These
development artifacts are not a public release package or a replacement for
the current qualification auditor.

From the checkout root, list the current gate declarations:

```sh
python3 -I -B scripts/verify-recovery-qualification.py --catalog
```

The captured invocation declared 32 commands and executed none of those gates.
Use the emitted current paths and complete command arguments for a new
candidate. Historical `catalog.py` retains its original 33 commands, including
renamed paths, and is not imported by the current auditor. Listing a command or
resolving its source path does not replace executing it on an identified subject.

The following current reader inspects retained package bytes without loading
the archived auditor's Python code:

```sh
python3 -I -B scripts/verify-recovery-qualification.py \
  --historical-package docs/architecture/recoverable-agent-runtime/implementation/p5 \
  --expected-seal-sha256 95f97066981d3d7daf91bee2557e47f94b149c290f1c62f9bbc5a76f62f766f7 \
  --source-root "$PWD"
python3 -I -B scripts/verify-recovery-qualification.py \
  --historical-package docs/architecture/recoverable-agent-runtime/implementation/p6 \
  --expected-seal-sha256 3130ce6c7f29e9ab4294617ce32aa66afe8aec8e4741693c1a47086c7603d173 \
  --source-root "$PWD"
```

The captured P5 command verified 264 retained artifacts and returned
`current_qualified: false`; its 643-source historical inventory differs from
the current source. The captured P6 command refused at
`qualification.historical_artifact_inventory`. Its published tree includes
the additive [redaction note](p6/evidence/REDACTIONS.md). A separate exact
readback confirmed all 5,099 declared files are present and identified the two
documented digest changes:

| Published metadata | Original SHA-256 | Published SHA-256 |
|---|---|---|
| `owned-resource-cleanup.json` | `186b163c5e2fc76ef636780db440ab95b20535d5a475eeca5365dc4672c35c74` | `edab34ee4f0ef7afd4292781ce39a518e5918a3c4cc0b9a233c7482c2216faa3` |
| `matched-linux-performance/host-metadata.json` | `4cdd37517d7a4989e8a2ae6dec91b01a37be288678fc8a5297386db0b0199ae8` | `191e59a184f01394234172b11679ce899ba8dfa22176486996dd2aed1ce84d6b` |

The published redactions and original seal remain intact. They are not a
currently passing original-byte package audit. The redaction note records that
the unredacted originals are retained outside the repository. Reproducing the
original sealed package requires those exact originals and its exact sealed
source. Neither this overlay nor the source correspondence reconstructs them.
The [historical reproduction instructions](p6/REPRODUCE.md) remain unchanged.

A new qualification record must carry its actual source inventory, original
execution/profile evidence and an independently supplied seal. Check that new
record with the current auditor's `--record`, `--root`, `--source-root` and
`--expected-seal-sha256` arguments. Missing dimensions, mismatched current
sources and unsupported completion claims are required refusals. Any affected
reader repair must pass its owning controls on the installed source before
acceptance. The current per-ID review
overlay at `target/recovery-pr/current-review-followup/current-reviewed-dispositions.json`
tracks locally accepted dispositions and remaining checks; it carries no
whole-source qualification or compiled-closure claim.
