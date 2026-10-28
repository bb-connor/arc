# Runtime source qualification v1

An operation-owned runtime source is a configured artifact and trust-floor backend bound to a provisioned destination authority. Qualification records the source ID, runtime authority ID, destination authority ID, and the device, inode and single-link identity of the opened SQLite database. The descriptor uses canonical JSON and a domain-separated digest. A descriptor alone does not authorize a claim: the configured source must verify its persisted binding against the live opened file.

The source binding is immutable. Installation in the destination is fenced and committed to its authority log. Runtime claims retain their operation, request, grant, resource and recovery-lease bindings. The source contains no standalone consumed-lease or continuation markers.

Only an empty unstamped source database may initialize. Existing databases must have the exact v1 catalog. Missing, modified, retired or unknown schema objects refuse without schema adoption. Source qualification is checked before changing journal mode.

Device or inode changes refuse, including copies, restored backups, replacement files and remounts that change physical identity. Hard-linked sources refuse. Physical qualification failures report `runtime_source_qualification_invalid`. Moving or copying an already qualified database does not requalify it.

The destination operator may call `SqliteAdmissionOperationStore::requalify_runtime_source` with the exact prior record, unused source and runtime authority IDs, a separately configured source, the current mutation fence and trusted time. The source is qualified outside destination locks under installation exclusion. The destination transaction appends an immutable supersession record and installs the new qualification with two global commits. A stale fence, changed prior record, reused identity or failed source callback leaves destination history unchanged. An identical retry verifies the retained replacement; a different replacement refuses.

The destination limit is 128 active sources. Superseded records remain immutable and globally verifiable but no longer consume active capacity. Their bindings cannot authorize fresh claims or dispatch; retained claim history and release remain valid. Supersession never deletes prior authority, rewrites historical evidence or reuses an old source binding.

Physical qualification does not detect restoring an older valid database image in place while preserving its physical identity. Requalification provisions a fresh source; it does not establish content rollback detection for the prior source. A content rollback claim requires an independently retained monotonic authority checkpoint.

The installation exclusion guard is shared with other authority-source families. Its migration-era method name is tracked by SOURCE-INSTALLATION-GUARD-NAME; the exclusion remains required during source callbacks.

The runtime harness installs a qualified SQLite source before invoking the kernel.
Its admission artifact is the signed kernel receipt, including a denial receipt.
Step and proof-source records bind `toolReceiptSha256`; the
separate cross-boundary treaty admission report retains its own report digest.
