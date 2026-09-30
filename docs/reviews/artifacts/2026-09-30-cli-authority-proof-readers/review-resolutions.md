# Whole-batch review resolutions

One independent reviewer reviewed the uncommitted implementation against
`943482d2cb82a1cf466584b47aee6b509c921d90`. No implementation subagents were used.
The reviewer did not run builds or change files. Findings and dispositions:

1. **Catalog deletion escape:** catalog identifiers now accept bounded ASCII
   names only, reject duplicates including case aliases, and cannot supply an
   absolute or relative path. The effect owner also rejects symlink/non-directory
   parents and destinations before removal. Negative traversal and positive-name
   controls cover the owner.
2. **Commerce allocation amplification:** required artifacts, optional protocol
   payloads and receipts use one bundle budget. Every retained duplicate charges
   bytes. Receipt candidates are read once, schema/digest checked and indexed;
   repeated references cannot trigger unbounded rescanning. A repeated-reference
   control rejects above the budget and accepts the exact byte boundary.
3. **Certificate session omission:** SQL filters exact signed ACP/session-context
   metadata, independent of synthetic or real capability IDs. A valid signed
   receipt with a real capability ID is selected only for its exact session.
4. **Read-only issuer-key creation:** metadata uses existing private custody;
   a missing-seed control asserts that no file is created.
5. **Assembly copy before limit:** policy bytes are captured and parsed before
   output creation, then those captured bytes are written.
6. **Settlement RPC substitution:** protocol, exact request ID and exclusive
   result/error shape are checked before projecting independent chain evidence.
7. **Secret-buffer reallocations:** private custody uses one fixed-capacity
   zeroizing allocation, including error paths. It never grows after receiving
   secrets. Existing/private/mode/link/size controls cover the public helper.
8. **Explanation temporary paths:** evidence readers consume the captured
   passport; only final display paths are remapped to the original input root.
   A source-substitution control proves presentation never rereads the original.
9. **Windows synchronization regression:** directory fsync remains Unix-only;
   regular files sync everywhere. No Windows execution is claimed here.

Integration qualification additionally repaired the CLI's loss of safe public
proof-rejection details. Static diagnostics and registered categories preserve
integrity/schema exit codes, with original native errors retained as local
sources. Selected commerce/risk/runtime/family adapters additionally retain concrete
native errors through proof-room. Tests assert public redaction and source identity. No raw parser or
schema-validation text is copied to public output.

The final checks are pinned in README.md. Hostile concurrent ancestor mutation,
downstream cryptography, unrelated delegated loaders and hosted/M5 qualification
were outside this review. This record does not claim a second independent review
of the repairs.
