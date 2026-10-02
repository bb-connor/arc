# Receiver-Owned Bilateral Admission

LaTeX source and reproducibility materials for "Receiver-Owned Bilateral
Admission for Cross-Organization Agent Tool Calls," targeting USENIX Security
2027 (submission cycle to be confirmed).

The USENIX submission build is:

```sh
make submit-check
```

The gate performs the complete LaTeX and BibTeX build, checks references and
citations, and enforces the 13-body-page limit. `paper-usenix.tex` is the
submission source; `paper.tex` is the ACM-style fallback.

The paper's formal and empirical evidence is pinned in
`supplementary/artifact-manifest.json`. From the repository root, validate the
manifest and independently rebuild its Lean archive with:

```sh
bash scripts/check-programmable-sovereignty-artifact.sh
```

For proofs, focused tests, experiments, and the PDF in one pass:

```sh
bash scripts/check-programmable-sovereignty-artifact.sh --full
```

## Provenance

Every number in the paper is read from `bench/results/*-inline.tex`, which
`bench/run-bilateral-admission.sh` and `bench/run-replay-corpus.sh` write.
The benchmark also records the host identity in
`bench/results/bilateral-admission-environment.json`; the paper reads the
host identity through macros generated from that file, and the claim ledger's
measurement block is regenerated from `bench/results/bilateral-admission.json`
by the same script.

Provenance has a two-commit shape. Result files carry the commit at which
they were produced; the artifact manifest is committed afterwards and pins a
later source commit. The manifest proves that the benchmark input tree (the
crates, examples, specs, scripts, and toolchain files the benchmark depends
on) is byte-identical between the producer commit and the pinned source
commit, so the two commits describe the same code. The Rust toolchain is
pinned by `rust-toolchain.toml`; `Cargo.lock` and `rust-toolchain.toml` are
recorded in the manifest informationally rather than hash-pinned, so a
dependency or compiler bump does not by itself invalidate the artifact.

`CLAIM_LEDGER.md` maps each result to its evidence and limits. Lean proves the
finite-domain checker theorem. The Rust evidence is differential testing, and
two configured keys do not establish two independent organizations.
