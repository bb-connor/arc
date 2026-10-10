# Historical recovery packages

These packages describe earlier experimental source. They do not qualify the
current runtime. The current verdict is in [STATUS.md](../STATUS.md), and the
maintained implementation follows [the storage support policy](../storage-support.md).

The content-addressed [archive](a6ac2b0a3a28ff27cfee3647037cc35db423a74ed781ed40569a2b1c1b493d6d.tar.gz) preserves **5,924 files**
from commit `4b9229dca4329141ba3c929264ef71aee12e37c6` at their original repository paths.
Every archived byte was checked against its Git blob before packaging. A fresh
reconstruction was compared byte for byte and mode for mode before the expanded
tracked copies were removed. `MANIFEST.json` inside the archive lists each path,
Git blob, SHA-256 digest, size and executable mode. [index.json](index.json) binds
the complete archive. Neither failed attempts nor historical seals were changed.
The published redactions and their original notes remain inside the archive.

## Retrieve without executing historical code

From the repository root, verify the archive and extract into a fresh directory:

```sh
(cd docs/architecture/recoverable-agent-runtime/implementation/history && shasum -a 256 -c SHA256SUMS)
mkdir target/recovery-history
tar -xzf docs/architecture/recoverable-agent-runtime/implementation/history/a6ac2b0a3a28ff27cfee3647037cc35db423a74ed781ed40569a2b1c1b493d6d.tar.gz -C target/recovery-history
```

The restored package roots are under
`target/recovery-history/docs/architecture/recoverable-agent-runtime/implementation/`.
All old relative paths and links resolve within that reconstructed tree.
Use the maintained auditor for read-only historical byte checks:

```sh
python3 -B scripts/verify-recovery-qualification.py --historical-package target/recovery-history/docs/architecture/recoverable-agent-runtime/implementation/p5
```

The historical product package intentionally retains the original seal alongside
two subsequently published redactions. Its original package-integrity check can
therefore refuse those two artifacts. Archive integrity verifies the preserved
published bytes; it does not rewrite that seal or turn refusal into qualification.
The exact note is `p6/evidence/REDACTIONS.md` in the reconstructed tree.

## Package paths

| Phase | Original root within the repository | Contents |
|---|---|---|
| P0 | `docs/architecture/recoverable-agent-runtime/implementation/p0` | Original plans, coverage, reviews, manifests and evidence. |
| P1 | `docs/architecture/recoverable-agent-runtime/implementation/p1` | Original plans, coverage, reviews, manifests and evidence. |
| P2 | `docs/architecture/recoverable-agent-runtime/implementation/p2` | Original plans, coverage, reviews, manifests and evidence. |
| P3 | `docs/architecture/recoverable-agent-runtime/implementation/p3` | Original plans, coverage, reviews, manifests and evidence. |
| P4 | `docs/architecture/recoverable-agent-runtime/implementation/p4` | Original plans, coverage, reviews, manifests and evidence. |
| P5 | `docs/architecture/recoverable-agent-runtime/implementation/p5` | Original plans, coverage, reviews, manifests and evidence. |
| P6 | `docs/architecture/recoverable-agent-runtime/implementation/p6` | Original plans, coverage, reviews, manifests and evidence. |

Historical scripts are retained as evidence. They are not imported by the
maintained runtime or current qualification auditor. Original review-register
locators keep their original spelling and can be resolved in the reconstruction.
