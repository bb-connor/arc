# Recovery selection without terminal-history scans (F040)

Use the existing live-operation and quarantined-deferral indexes for both
`recovery/page.rs::read_snapshot` and the bounded legacy tail probe. The SQL
limit and cursor continuation already exist on main; preserve them.

1. Run the preserved page-work and sweep tests plus the new legacy tail-work
   test against current source. Retain genuine VM-step failures separately
   from fixture or compilation errors.
2. Port `ed40f4290` into the shared reader and apply the same candidate identity
   selection to the legacy tail probe. Keep exact row validation before skips,
   fencing, clock checks, the 256-candidate legacy budget, and read-only behavior.
3. Run focused history/legacy recovery controls, caller-share index controls,
   strict store Clippy and formatting. Obtain Claude review and publish a
   separate PR on actual main.

No schema migration is needed. The candidate union still enumerates live and
quarantined identities; this removes growth from ordinary terminal history,
without claiming SQL work proportional to the returned page size.
