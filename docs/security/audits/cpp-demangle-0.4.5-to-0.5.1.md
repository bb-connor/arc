# cpp_demangle 0.4.5 to 0.5.1 source audit

Date: 2026-10-04. Auditor: Codex delegated source-review agent.

## Judgment

The exact `0.4.5 -> 0.5.1` delta preserves the reviewed security properties
conditional on the retained base acceptance. I support a delta audit with that
meaning. This is based on reading every changed file and the surrounding parser,
formatter, ownership, recursion and build-script behavior described below, not
merely counting unchanged unsafe blocks or relying on another organization's
certificate.

This is not a full `safe-to-deploy` certificate for either version. The existing
`0.4.5` exemption remains baseline audit debt. In particular, an undocumented
layout assumption and the legacy parser resource concerns below remain. A
delta attached to that exemption cannot truthfully be reported as completing
the full source audit or removing the exemption debt. I wrote no audit,
exemption, policy, lockfile, or production source entries and ran no builds,
tests, fuzzers, or runtime demonstrations.

Cargo Vet defines a delta as preserving a criterion between versions, and
requires enough context to establish preservation. It does not turn the base
into a completed full audit. The existing local policy was read at
`/tmp/arc-security-main-dependencies/supply-chain/config.toml:883-885` and
contains the `0.4.5` safe-to-deploy exemption.
[Cargo Vet delta semantics](https://mozilla.github.io/cargo-vet/audit-entries.html)

## Source identity

Both source trees were read under
`$LOCAL_TOOL_PATH`.
Every regular file in each cached published archive was compared byte for byte
with its corresponding extracted tree: 22 files per version, zero mismatches.

| Artifact | SHA-256 |
| --- | --- |
| cpp_demangle-0.4.5.crate | `f2bb79cb74d735044c972aae58ed0aaa9a837e85b01106a54c39e42e97f62253` |
| cpp_demangle-0.5.1.crate | `0667304c32ea56cb4cd6d2d7c0cfe9a2f8041229db8c033af7f8d69492429def` |
| 0.5.1/src/ast.rs | `b2695a4af971a7787aa85b23164c5ef628b28ce1f154cda8d3cd062a6efaefa1` |
| 0.5.1/src/lib.rs | `2c7523a7747e29579f40bb622e30fb469014901f46f4e782656f45aeda613e32` |
| 0.5.1/build.rs | `080e47720ec5aecec9bbbcbc4155f609c69db510b1a880fdc9a0deb90ee59f77` |

The 0.5.1 archive hash matches the workspace lockfile entry at the time read.
The VCS metadata changed from `1e679dd1979e1d323de26f81535dd9566263174c`
to `6fc3a53ba2ae11bdcf470ed44058a233af517160`; this metadata is descriptive,
not an independent authenticated Git history review.

The parent reported a Bytecode Alliance delta from 0.4.3 to 0.5.1. I did not use
that report as a substitute for this exact 0.4.5 delta review or independently
authenticate that imported entry here.

## Actual coverage

Every hunk of all 12 changed files was read: `.cargo_vcs_info.json`,
`CHANGELOG.md`, `Cargo.lock`, `Cargo.toml`, `Cargo.toml.orig`, `README.md`,
`build.rs`, both examples, `src/ast.rs`, `src/lib.rs`, and `src/subs.rs`.
This includes changed inline test source, although no tests were executed.

Additional complete production-file reads in 0.5.1:

- `build.rs:1-309` and `src/lib.rs:1-443`.
- `src/index_str.rs:1-173`, `src/subs.rs:1-173`, `src/logging.rs:1-17`, and
  `src/error.rs:1-124` (the small inline size test was also visible).
- `src/bin/afl_runner.rs:1-9`, plus the normalized and original manifests.

AST review covered both unsafe operations and their construction/use context,
not the complete 8,395-line production AST implementation. Principal focused
reads were the following 0.5.1 ranges:

| Range in src/ast.rs | Reviewed boundary |
| --- | --- |
| 1-1520 | Parse and demangle contexts, RAII depth accounting, scope resolution, output sink, inner stack, unsafe newtypes, handle/vocabulary macros, root parse and encoding entry |
| 1580-1618,1780-1895,1940-2514 | Clone suffix progress; name, nested-name and prefix construction; leaf lookup; compatibility change context |
| 2516-2752,2770-3030 | Unqualified names, declared lengths, identifiers, ABI tags and numeric wrappers |
| 3090-3220,3310-3490 | Operator parsing/formatting, cast barrier and constructor parsing |
| 3628-3888 | Type dispatch, qualifier progress guard, template lookahead, insertion and pointer/reference recursion |
| 4280-4323,4655-4688,4886-4912 | Parametric type bounds, nonempty argument-list invariant and unnamed type numeric handling |
| 5290-5570,5590-5643 | Template/function parameter arithmetic, references, template vectors and argument parsing |
| 5908-6365,6490-6598 | Changed expression dispatch and formatter, list progress and established analogous list operations |
| 6600-6690,7348-7385,7580-7655 | Unresolved-name consumption, discriminators and substitution index validation |
| 8020-8120,8180-8395 | Resource-name bounds, complete new fold expressions, repetition helpers, consume and numeric UTF-8 conversion |

Some additional unchanged AST fragments were inspected through search context;
they are not promoted to full-file coverage. Unchanged AST sections, the whole
existing test corpus, optional AFL's dependency implementation and downstream
deployment routes were not comprehensively audited here.

## Delta reasoning

API error handling: `lib.rs:252-314` replaces the `Display` implementation with
an explicit fallible default-options demangle method and renames the existing
options method. The old `Display` also built an intermediate String; this
change does not introduce that allocation pattern. It removes the path where a
semantic formatting error can reach formatting machinery expecting errors only
from its writer. The underlying context construction, input ownership and
`structured_demangle` behavior are unchanged. `Symbol::new` still rejects
trailing input; the separately named tail API deliberately returns it.

New fold expressions: `ast.rs:6070-6081,8182-8289` consume their prefix and
operator before each operand parse, require a binary operator, own each operand
in a Box, propagate parse/write errors and enter the same depth guards as
existing expressions. The binary variants visit each stored operand once.
The `fL` lookahead uses Option-aware byte inspection and preserves the existing
function-parameter alternative when the next byte is numeric. No unchecked
access, native operation, new recursive bypass or independent output expansion
mechanism was introduced by these branches.

Initializer lists: `ast.rs:5961-5965,6337-6348` replace one boxed expression with
a vector supporting zero or more expressions. Each successful Expression parse
consumes an operator, a delimiter, a numeric/reference token, or a nonempty name;
the repeat ends on failure and then requires the closing `E`. The same helper
and expression parser already implement call arguments and conversion lists at
`:5934-5958`, and new/delete arguments at `:6142-6205`. The added list retains
depth/error handling and introduces width proportional to consumed expressions,
not a new count-driven allocation or non-consuming success case.

Compatibility parsing: the prefix merge at `:2338-2370` retains the prior
progress requirement, handles absent `current` without unwrap, and consumes `M`
only after checking that exact byte. Accepting LocalSourceName in a data-member
prefix carries the same owned SourceName and checked input offsets. Optional
`on` at `:2554-2559` is removed through bounded `consume` and otherwise leaves
input intact. The conversion-template lookahead at `:3772-3785` operates on a
cloned substitution table, preserves TooMuchRecursion propagation and falls
back without committing trial substitutions. The cast/conversion barrier at
`:3177-3189` uses the existing RAII stack swap, including restoration on error.
These changes broaden C++ presentation compatibility; this library does not
validate authorization identities or execute the represented C++ expressions.

Build and dependency changes: the build script generates test source beneath
OUT_DIR from package-local fixtures, with no network, child process or native
build. Both published packages exclude `in/**` and `tests/**`; both generators
return before creating output if those directories are absent. The changed
generated tests use the fallible demangle API. Optional AFL changes from 0.15
to 0.16, so a graph enabling that dependency still needs its own dependency audit;
it is absent from the workspace cpp_demangle lock entry inspected. The normal
library dependency remains cfg-if. Other changes are metadata, examples,
release notes or a Debug spacing correction.

## Existing unsafe and parser boundaries

The crate denies unsafe code globally and locally allows only two operations.
At `ast.rs:8346-8395`, parse_number receives only bases 10 or 36 at current
call sites. The digit scan admits ASCII digits or uppercase ASCII letters, so
the selected bytes passed to `str::from_utf8_unchecked` are valid UTF-8.
The count comes from iteration over the same slice; signed magnitude is parsed
as a nonnegative isize before negation. The conversion rejects magnitude
overflow and leading zeros. This operation and its prerequisites are unchanged.
[Rust char digit contract](https://doc.rust-lang.org/std/primitive.char.html#method.is_digit)

The other operation, `reference_newtype` at `ast.rs:911-964`, remains a layout
proof gap in both versions. It casts immutable references to Vec and slice
wrappers without `repr(transparent)`. Lifetimes and shared access prevent
ownership transfer or conflicting mutation, but do not independently establish
wrapper size, alignment, field offset or DST layout. The Rust language only
provides minimal repr(Rust) guarantees; transparent representation supplies the
matching single-field layout. Adding `#[repr(transparent)]` to the generated
struct is the direct robustness repair. This review observed no pinned-compiler
layout mismatch, miscompilation or exploit, and did not run a layout test.
It must not be described as a demonstrated current-toolchain memory corruption.
[Rust layout guarantees](https://doc.rust-lang.org/reference/type-layout.html#the-rust-representation)
[Transparent representation](https://doc.rust-lang.org/reference/type-layout.html#the-transparent-representation)

Unchanged parser limits and concerns:

- Parse/demangle recursion defaults remain 96/128, with RAII decrement on all
  returns. Caller-selected very high limits deliberately permit deeper stacks.
  These guards are depth bounds, not total work or output-byte bounds.
- `TemplateParam::parse` at `ast.rs:5298-5304` accepts a nonnegative isize and
  computes `number + 1` before converting to usize. The source therefore has
  a checked-arithmetic panic boundary at isize::MAX. A candidate 64-bit input is
  `T9223372036854775807_`; no runtime execution was performed here. With wrapping
  release arithmetic, later safe reference lookup rejects an unavailable index.
  The exact same addition exists at line 5300 in 0.4.5.
- Iterative PrefixHandle parsing can produce long chains without accumulating
  parse depth. `Encoding::demangle` calls `name.get_leaf_name` at line 1492;
  constructor/operator leaf absence can recurse through prefix handles and
  `Prefix::get_leaf_name` without a depth guard at `:2387-2398`. A candidate
  stress family is `_ZN1a` followed by many `C1` tokens and `Ev`. This is a
  source-grounded potential stack-exhaustion path requiring bounded reproduction,
  not a claimed reproduced crash. The same construction and unguarded leaf walk
  exist in 0.4.5, including before the prefix compatibility change.
- Input slices and reference lookups use checked Rust indexing/get, and native
  FFI is absent. Some internal methods can panic on invalid manually constructed
  AST state. Output String size and total formatting work are not capped.
  `structured_demangle` can use a caller-bounded writer; the ordinary demangle
  API allocates output. These are not blanket denial-of-service guarantees.
- The logging feature prints input symbols and parser state to stdout. Its
  feature gate and behavior are unchanged. It should be treated as diagnostic
  output, not as confidential symbol handling.

The inspected downstream `wasmtime-environ-48.0.5/src/demangling.rs:1-30` uses
the fallible Symbol API and allocates the complete demangled String before
writing it, falling back to the original name on a returned error. This limited
call-site read does not establish that panic, stack exhaustion or output growth
are isolated by every downstream caller.

## Acceptance boundary

The reviewed delta can extend the existing explicit exemption-backed chain
without introducing a new exemption or claiming a full base certificate. Its
notes should retain the unchanged layout assumption and legacy resource debt.
The exact release tests and Cargo Vet graph verification remain the parent's
responsibility. If the intended gate instead requires every package to have a
genuine complete safe-to-deploy source audit, this delta-plus-exemption route
does not satisfy that stronger gate; the baseline review and concerns still
need resolution.
