# Independent review and author corrections

Reviewed source base: `14ce46a3edbf75c27162d2c13c1dce07b919b070`, plus the frozen
working tree recorded in the local archive's `review-source.json`, `review.diff`
and `review-files.txt`. One independent reviewer inspected production code, new
files, tests, plan and design. It ran no Cargo graph and made no edits.

The original verdict was **not ready for acceptance**, with four Important
findings and no Critical or Minor findings. The author owns the corrections and
verification below; there was no second independent review.

| Finding | Reproducing evidence | Correction |
| --- | --- | --- |
| SQLite storage-class confusion could extend an expired lease | `review-storage-class-red`: expired protected write succeeded after TEXT expiry corruption | Require INTEGER storage for every persisted time/fence operand; 13 write-fence controls and 104 existing owner tests pass |
| Nested routers skipped preflight because MatchedPath includes outer prefixes | `review-nested-route-red`: nested honest signed request succeeded, duplicate body incorrectly returned 200 | Strip framework-owned NestedPath before contract selection; nested/parameterized actual-router control passes |
| Middleware text anywhere in a builder did not prove that it wrapped later routes | `review-census-red`: misplaced layer and added literal route alias were accepted | Pin reviewed builder bodies, including order, merges and literal paths, alongside actual method/path/mode bindings |
| Ordinary module and reader-type aliases erased census consumers | `review-census-red`: module reexport and UntrustedJsonText import aliases lost owners/callers | Resolve reader-type imports and proven source-module aliases before free-function resolution |

The alias fix first exposed recursive glob expansion and module/function namespace
confusion in the whole corpus. Separate synthetic controls reproduced both
scanner failures. The final resolver rewrites only proven module aliases and
retains cycle detection; 23 ingress calibration cases and the complete source
gate pass. Initial recursion errors, the diagnostic run and a stale reader-hash
failure remain failed attempts in the qualification manifest.

## Review boundaries and rulings

- Whole-database rollback and unrestricted database mutation authority remain
  outside this packet. Malformed persisted storage classes still fail closed.
- Explicit-time scheduler/acquisition APIs remain trusted orchestration entry
  points. Protected writes independently observe store-owned time after locking.
- Handler authentication and signature correctness remain their owners'
  responsibilities. Representative actual-router controls do not requalify every
  handler or remote fan-out.
- Hosted CI, release, deployment and complete workspace health were not judged.
  Root owns the terminal local qualification records and publication check.

Later fixture repairs initialize the injected clock before opening an authority
store, put six legacy authority fixtures in private directories, preserve typed
SQLite rejection provenance, and give the unsigned simulation fixture its required
subject filter. These are author-verified test corrections, not an independent
review of new production behavior. No lint allowance, ignore, timeout or debt
baseline was expanded.
