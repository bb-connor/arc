# Independent specification review

Date: 2026-10-07. Scope: proposed numbered specifications, schema/example contracts,
phase plans and the bounded runner example. This is not a runtime security audit.
Review was performed independently from drafting using the Superpowers review
workflow. Source assertions were checked against the identified native/Pi and
Omarchy trees where relevant.

Disposition: all identified P2 issues addressed and re-reviewed; no remaining
P0/P1/P2 findings reported in that scope. Confidence: high in those corrections.
Final document validation is recorded [separately](validation.md).

| Finding | Why it mattered | Resolution and re-review |
| --- | --- | --- |
| Native identifiers forced to UUID versions 1-5 | Resource operation IDs are SHA-256 and native approvals can use UUIDv7 or explicit strings | Owner-bound native operation references; native proposal/decision/review IDs preserved; UUIDv7 positive fixture |
| Start summary lacked admission binding | Enrollment selection/provider/limits could change after user review | scope.get plus required scope_revision/reviewed_scope_digest, atomic reservation comparison and race acceptance |
| Stop and health shapes omitted required observations | UI could not distinguish stopped guest from unknown native admission or stale lock state | Explicit independent stop dimensions, timestamped health/session states and hello build identities |
| Filtered events conflicted with global sequence checks | Another task's event would create a false gap | Unfiltered v1 global journal; filtering only in presentation; interleaved-task case |
| Active snapshot floors could defeat hard history caps | A flood within the snapshot TTL could make legal trimming impossible | Early snapshot invalidation with cursor_expired before trimming at either hard bound |
| Qualification runner trusted wrapper exit | A child could close output pipes and survive while wrapper exited 0 | Always observe/clean the owned fixture group, separate wrapper_reaped/descendants_absent, reject unexpected descendants and require cgroups for group-escaping commands |
| Result shape could exceed wire bound | A valid 200-row page or escaped summary could exceed 64 KiB | Byte-aware page reduction, indivisible-response refusal and encoded-bound cases |

The runner finding was independently reproduced by extracting the original plan
sample and launching a controlled child that closed stdout/stderr. The revised
sample was extracted and tested: the closed-pipe survivor case now fails while
cleanup succeeds; the clean positive remains successful. Eight focused local
component tests passed on macOS arm64. This validates the example's bounded
fixture behavior only, not the future Linux cgroup executor or Omarchy profile.

Reviewed sample source SHA-256:
`2afe6697a1c8b79a0c100078fd01d2e61d0dacc12bba25c0f2ae3b9c3c609dcd`.

Remaining work is intentional and visible: the runtime prerequisite register,
profile-specific applicability closure, actual Linux/native/provider acceptance,
clean installation and release publication. These are not hidden behind a green
document validator or synthetic examples.
