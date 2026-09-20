# ignore 0.4.32 source review and repair

September 20, 2026. Confidence is high for the reproduced filtering defects,
the two production repairs and the package tests. This is direct source
review by the executing agent, not independent certification.

## Source identity and scope

The verified registry archive SHA-256 is
`0b17771570a2b94107741a7b033f19132c2eee21d59d21b24d2ced26500bd66e`.
The packaged VCS record names BurntSushi/ripgrep commit
`5ed408e17eccfc59bcec48f584feece902873e54`, directory `crates/ignore`.
The inventory records all 22 original regular files and retains both licenses.

Reviewed both manifests and all production modules: error and match types,
Gitignore parsing and matching, overrides, type filters and their default
table, path helpers, parent/directory rule loading, incremental matching,
serial traversal and the parallel work queue. The package has no build script,
unsafe Rust, process execution or network access. Its production filesystem
operations read paths, metadata, ignore files and Git configuration. Filesystem
creation and deletion found in the source belong to test fixtures.

Chio's only direct dependency API use is in nono's rollback exclusion module:
it builds a root Gitignore matcher and queries it after other exclusion rules.
That module discards `add` errors and falls back to no Gitignore matcher if
construction fails. The current Chio confinement entrypoint does not invoke
that rollback module, `WalkBuilder` or incremental matching. New rollback
integration needs its own error-handling and coverage review.

## Reproduced defects

1. With both `max_filesize` and `filter_entry` configured, the serial walker
   returns the size decision before evaluating the custom predicate. A small
   file explicitly rejected by the predicate is returned. The parallel walker
   correctly applies both filters. The regression retains a permitted small
   file and rejects both a predicate-denied file and an oversized file.
2. On Unix, the basename helper treats any path ending in a dot as though its
   final component were dot or dot-dot. Consequently `.hidden.` and `.hidden..`
   escape hidden-file filtering. Both ordinary visible names ending in dots
   and actual dot components must remain distinguishable.

The original package passes its upstream suite but fails these two additional
assertions. The other five new boundary cases pass on the original bytes.
These are dependency file-selection defects. The review found no current Chio
confinement path to either defective function.

## Selected repair

`third_party/ignore-chio` retains the complete package and changes exactly two
production hunks. The serial walker only returns early for an oversized file,
then evaluates the predicate for remaining files. The Unix helper recognizes
actual dot/dot-dot components without dropping other names ending in dots.
No original test assertion changes.

Eighteen original files remain byte-identical. The other four are the two
production files, the unpublished standalone-test manifest and its lockfile.
The new files are the patch inventory and regression target. The root, fuzz
and generated Docker graphs select this local source. Their lock changes only
remove the registry source and checksum for ignore 0.4.32; all other versions
and dependency edges remain unchanged.

The original registry release receives no `safe-to-deploy` audit. The selected
fork is locally maintained source, using the existing policy for owned repairs.
No criterion, exemption or imported trust authority is weakened. Cargo-vet
still reports four missing deployment audits: the three AWS-LC packages and
regress 0.11.1.

## Verification

Rust 1.94.1 on macOS arm64, all features, one Cargo job and serial tests:

- Original upstream: 187 tests and seven documentation checks pass.
- Original new probes: five pass and two fail with the defects above.
- Selected repair: all 187 original tests, seven new tests and seven
  documentation checks pass. There are no ignored cases.
- Locked offline root and fuzz metadata resolve the selected source; generated
  Docker metadata retains the same dependency selection.

The probes also exercise partial malformed-rule errors, negation, anchored and
directory-only rules, escaped literals, serial/parallel/incremental agreement,
parent pruning, lexical normalization, cached rule updates, optional symlink
descent and loop errors. The companion boundary file matches the fork's test
target byte for byte.

The original source fails strict Clippy with 70 library diagnostics. Ordinary
all-target Clippy exits successfully with warnings on both sources: 121 unique
diagnostic locations originally and 118 after repair. The remaining warnings
are retained, not suppressed. This is not a strict upstream Clippy pass. The
first-party workspace's strict Clippy gate remains separate.

## API boundaries that remain

- Ignore rules select files; they do not authorize access. Explicit walk roots
  bypass ordinary selection filters, and caller-supplied custom ignore paths
  can name files outside the root.
- Ignore-file loading can partially succeed. Callers needing complete rules
  must inspect returned errors and directory-entry errors. Global rule loading
  also consults Git environment/configuration and can log and ignore errors.
- Glob matching and lexical normalization do not prove filesystem containment.
  Following a symlink can intentionally leave the starting tree. Metadata and
  later file access are subject to races; no descriptor-based boundary is
  provided by this package.
- Incremental matchers cache loaded rules. A fresh matcher is needed to observe
  changes. Their input must satisfy the documented root-relative, no-parent-
  component contract. A non-match is not authorization.
- Rule files, directory breadth, cached directories and matching work have no
  complete resource budget here. Parallel walking buffers directory entries.
  Size filtering uses metadata and does not bound a subsequent read.

Evidence is retained in the primary checkout under
`output/process-security-20260915/ignore-audit-eb040d592/`, including exact
archive/source inventory, original failures, terminal results, diagnostics,
production diff, source comparison and selected dependency metadata.

The active foundation and x86 cage runs at `eb040d592` predate this selection.
They do not qualify the new graph. Its Cargo.lock SHA-256 is
`51af2e7dd4292a31f917b650c46c26a70cc263ac324cbe90fadbf742a8c7a8d0`;
image inputs are aligned to that value, with fresh combined qualification and
image validation still required.
