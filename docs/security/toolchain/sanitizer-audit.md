# Sanitizer audit

What runs under which sanitizer today, what was measured to run, and what
breaks. Measured on `packet/k-gates` at base `07e963e8f5` on 2026-09-26, on
an aarch64 Linux host with `nightly-2026-02-07` (`rust-src` installed for the
`-Zbuild-std` rows). Every table row names the command it came from so it can
be re-run; a row without a command is not evidence.

## What the workflows run today

Five workflow files mention sanitizers. Four run one, and it is always
AddressSanitizer through libFuzzer.

| Sanitizer | Workflow, job | Trigger | What it instruments | Last green run (2026-09-26) |
| --- | --- | --- | --- | --- |
| ASan | `fuzz.yml`, `fuzz-scheduled (<target>)` | nightly 03:23 UTC, dispatch | 28 libFuzzer targets in `fuzz/`, `cargo +nightly fuzz build --sanitizer address`, 1800 s each | **2026-05-04, run 25294881298, by dispatch**. Every scheduled run since at least 2026-09-21 ended `failure` or `cancelled` |
| ASan | `cflite_pr.yml` | pull request | ClusterFuzzLite, `sanitizer: address`, code-change mode, 60 s per changed target | 2026-09-26, run 36213772460 |
| ASan | `cflite_batch.yml` | schedule | ClusterFuzzLite batch, `sanitizer: address` | 2026-09-26, run 36227311613 |
| none | `dudect.yml` | schedule | a comment mentions sanitizers; the workflow runs none | n/a |
| TSan | none | | | |
| MSan | none | | | |
| LSan | none | | | |

Commands: `grep -lE 'sanitizer|Zsanitizer' .github/workflows/*.yml`;
`gh run list --workflow <file> --status success --limit 1`;
`gh run list --workflow fuzz.yml --limit 6`.

The nightly ASan matrix is not green and has not been for months. In run
35976155678 (2026-09-24) the jobs `fuzz-scheduled (fuzz_policy_parse_compile)`
and `fuzz-scheduled (fuzz_sql_parser)` fail in the step `Run fuzz target
(ASan, max_total_time = 1800s)`, and the matrix cancels the other 26 targets
when they do (`gh run view 35976155678 --json jobs`). Whether those two
failures are crashes, sanitizer reports or timeouts was not extracted here;
they belong to the fuzz owner, with the run IDs above as the starting point.
Until they are dispositioned, the only scheduled sanitizer lane in the
repository reports nothing to anyone.

UBSan does not appear because it is not a rustc sanitizer: Rust has no
undefined-behaviour sanitizer, and the C in the `-sys` crates (SQLite through
`libsqlite3-sys`, `aws-lc-sys`) is compiled by `cc` with flags `RUSTFLAGS`
does not reach. Undefined behaviour in Rust is Miri's job; see the Miri crate
list beside this document.

No sanitizer runs on any test suite. TSan on the concurrent code the loom
models cover (the store writer, the broker service, the scheduler worker) is
the gap the hardening spec expected, and it is confirmed.

## What was measured to run

Unit tests (`--lib`) of one crate per row, on `aarch64-unknown-linux-gnu`
with `--target` set so the sanitizer flags reach only target artifacts.
Wall time includes compilation in a cold, isolated target directory.

| Crate | ASan | LSan | TSan | MSan |
| --- | --- | --- | --- | --- |
| `chio-security-types` (20 tests) | 20 passed, 33 s | 20 passed, 33 s | 20 passed, 55 s, `-Zbuild-std` | 20 passed, 69 s, `-Zbuild-std` |
| `chio-bounded` (9 tests, `cfg(loom)` crate) | 9 passed, 15 s | | 9 passed, 35 s, `-Zbuild-std` | |
| `chio-supervisor` (20 tests, `cfg(loom)` crate) | 20 passed, 13 s | | 20 passed, 14 s, `-Zbuild-std` | |
| `chio-keyring` (7 tests, links SQLite through `rusqlite`) | 7 passed, 40 s | | 7 passed, 42 s, `-Zbuild-std` | |

Commands, from the workspace root with `CARGO_TARGET_DIR` set to a directory
used for nothing else:

```
RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-02-07 test -p <crate> --lib --target aarch64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=leak"    cargo +nightly-2026-02-07 test -p <crate> --lib --target aarch64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=thread"  cargo +nightly-2026-02-07 test -Zbuild-std -p <crate> --lib --target aarch64-unknown-linux-gnu
RUSTFLAGS="-Zsanitizer=memory"  cargo +nightly-2026-02-07 test -Zbuild-std -p <crate> --lib --target aarch64-unknown-linux-gnu
```

## What breaks, and why

**TSan and MSan without `-Zbuild-std`.** This nightly enforces the sanitizer
ABI check: with the prebuilt standard library the build stops in the first
dependency with

```
error: mixing `-Zsanitizer` will cause an ABI mismatch in crate `stable_deref_trait`
  = note: `-Zsanitizer=thread` in this crate is incompatible with unset `-Zsanitizer` in dependency `core`
```

ASan and LSan do not change the ABI and link against the prebuilt library.
TSan and MSan must rebuild `core`, `alloc` and `std` instrumented, which is
what `-Zbuild-std` does and why those rows carry it and cost more.

**Uninstrumented C under TSan.** `chio-keyring` links SQLite compiled by `cc`
without `-fsanitize=thread`. Its seven unit tests pass under TSan with no
report, because TSan instruments the Rust side of every call and treats the C
side as opaque: races inside SQLite are invisible, races on Rust state around
the calls are not. That is a limitation to state next to any TSan result on a
store crate, not a reason to skip the measurement.

**A separate target directory is not optional.** Sanitizer `RUSTFLAGS` change
every artifact's fingerprint. Run against a shared target directory they
evict the whole cache for every other user of it.

## Decision

Enough passes to add a lane: `sanitizers.yml`, nightly, advisory, pinned to
`nightly-2026-02-07`, running ASan on the prebuilt library and TSan with
`-Zbuild-std` over the crate list measured above, each job time-boxed. It
starts with the four measured crates. The store and the broker are the
crates the spec wants under TSan most; neither completed its box (below),
and each joins the lane's list when a run on a warm instrumented cache is
green.

The lane is registered nowhere until it has history; adding a `[gates.*]`
entry is a `releases.toml` change for its owners once the job name is stable.

## Measurements that did not complete

Both ran with `-Zbuild-std` in a cold instrumented target directory on a host
whose load average sat between 8 and 21. Neither is a result; each is a
statement of what the box was not long enough for.

| Crate | TSan | Notes |
| --- | --- | --- |
| `chio-store-sqlite` (1,705 unit tests, SQLite linked uninstrumented) | did not complete: the 2,400 s box expired during the instrumented build of the standard library and the store's dependencies, before any test ran; no report, no result | `RUST_TEST_THREADS=1`; needs a warm instrumented cache or a box of an hour or more, measured on an idle host |
| `chio-secret-broker` (180 unit tests) | did not complete: stopped after 274 s while still compiling its dependencies (chio-kernel among them) under instrumentation; no test ran, no result | `RUST_TEST_THREADS=1`; the same warm-cache or longer-box condition as the store |

## Red on mutation

A scratch crate whose one test reads one byte past a heap allocation through
`pointer.add(len)`, built with `RUSTFLAGS=-Zsanitizer=address` on the same
nightly and target, fails with `ERROR: AddressSanitizer: heap-buffer-overflow`
naming the read; the process exits non-zero and `cargo test` reports the
failure. The lane runs the listed crates with exactly that command, so the
same defect in a listed crate's test fails the lane the same way.
