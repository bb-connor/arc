# Work source boundaries

The [source manifest](SOURCES.json) and [integration inventory](INTEGRATION.md) pin the inspected source. Their conclusions are source-level boundaries, not executed-test or release claims.

| Capability | Inspected main | Required integration |
| --- | --- | --- |
| Native execution and process identity | Durable admission, retained requests/nonces, `ProcessRuntime::invoke_known_only` | Complete Work request custody and scoped original-operation adapter |
| Serving ownership | `SqliteAuthorityStore` fences, integrity and global commits | Qualified D1/S1 factories and one v1 schema per store |
| Capability signing | `SqliteCapabilityAuthority` issues fresh UUID-bound tokens | Original Work issuance-ID intent and exact-body readback |
| D1 delegation | Absent | Work-substrate source from #1173, then serving-owner qualification |
| S1 graph | Fixed bundles and pure minting/verifiers | Additive source from #1173, retained unsigned drafts, commit-before-publication and original-success readback |
| Working terms | Verified manifests and native treaty admission | Audience-scoped catalogs; semantic generations after REC |
| Acceptance | Native receipts; no generic Work evaluator/projector | Exact evaluator/procedure/producer/artifact mapping, ordinary charged evaluation |
| Semantic/knowledge recovery | Absent | Actual #1179 reservation/origin/authority, semantic, knowledge and confined-return owners |
| Public developer API | No Work feature, WorkClient or WorkService | Strict closed v1 contracts, authenticated host composition, installed SDK transport |

The source inventory records all 16 request fields, distinct digest domains, current and proposed resource limits, manifest dependency edges and the W1.3-W1.6 a/b split. It exposes missing issuers and custody paths instead of treating proposal names as constructors. Joined-source runtime baselines remain pending until the required substrate and recovery owners land.
