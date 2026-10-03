### Task 3: Authenticated archive queries and exports

Files: SQLite retained read module, query helper and evidence export; tests.
Interfaces: retained snapshot supplies pinned live/archive connections and trusted
watermark; bounded query returns original sequence cursors and authorized scope.

- [ ] Reproduce archived receipt omission in query/export. Expected: RED.
- [ ] Implement retained pagination, prefix limits, complete child/tool export and
  original inclusion proofs using authenticated snapshots; refuse legacy omissions.
- [ ] Test mixed live/archive pagination, tenant isolation, restart, missing and
  corrupted archives, uncommitted archive tails, and proof validation. Expected: pass.
