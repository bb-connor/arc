# cfg_aliases 0.2.1 to 0.2.2 source delta audit

Date: 2026-10-06. Auditor: Codex, inline source review for PR #1173.

## Source custody

The published archives match the live registry checksums:

| Version | Archive SHA-256 | Upstream commit |
| --- | --- | --- |
| 0.2.1 | `613afe47fcd5fac7ccf1db93babcb082c5994d996f20b8b159f2ad1658eb5724` | `3d55ba79872b61265a7176110a5200df0c9d9e54` |
| 0.2.2 | `f079e83a288787bcd14a6aea84cee5c87a67c5a3e660c30f557a3d24761b3527` | `e069ce61e00fee423ac1dbe6a897f228f1774716` |

## Reviewed changes

I read all six changed files and the macro's configuration lookup, recursive
parser, expression emission and public entry point. Cargo metadata identifies
the library and existing integration test explicitly, with no build script or
dependencies. A standalone single-package lock is added. Remaining changes are
version metadata and documentation corrections.

The executable delta removes three trailing semicolons from recursive macro
expansions in `@parser_clause`. The parser still consumes one token or comma per
recursive step, groups the same clauses and emits the same `all`, `any` and
`not` boolean expressions. Removing the semicolons preserves the expression
value and avoids expression-position macro rejection by the current compiler.
No matching rule, configuration condition or alias name changes.

The unchanged helpers read Cargo configuration and profile environment variables
and the macro prints Cargo's configuration directives. Inputs are trusted build
script tokens. No filesystem, network, subprocess, FFI or unsafe operation is
introduced. Invalid or recursively defined trusted aliases can still fail
compilation; this is not a runtime policy or an untrusted policy parser.

## Judgment and acceptance boundary

The delta supports `safe-to-deploy` on top of the retained imported audit chain:
Embark's `0.1.1` source audit and Mozilla's `0.1.1 -> 0.2.1` delta. This records
a review of the changed source rather than a new exemption or an assertion that
an unchanged unsafe-token count constitutes an audit.

Acceptance requires the replacement's actual integration tests and doctests,
affected locked builds and strict Clippy, and Cargo Vet verification of the
resulting production and research graphs. The PR qualification evidence records
those terminal results separately from this source judgment.

The authenticated `0.2.2` archive passes its actual integration test and seven
doctests under the workspace toolchain. One upstream doctest remains ignored;
it is not counted as execution. Both locked commands exit zero and leave the
extracted source inventory unchanged. Graph and consumer acceptance remain
separate requirements.
