# Summary 96-01

Made portable passport lifecycle truth explicit and freshness-aware instead of
leaving stale lifecycle state implicit in client-side TTL handling.

ARC now recognizes `stale` as a first-class fail-closed lifecycle state,
requires `updated_at` on persisted and resolved lifecycle records, and denies
portable issuance when operator lifecycle truth is over-aged or contradictory.
