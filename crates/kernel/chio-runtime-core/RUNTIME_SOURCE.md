# Runtime source qualification v1

An operation-owned runtime source is a configured artifact and trust-floor backend bound to a provisioned destination authority. Qualification records the source ID, runtime authority ID, destination authority ID, and the device, inode and single-link identity of the opened SQLite database. The descriptor uses canonical JSON and a domain-separated digest. A descriptor alone does not authorize a claim: the configured source must verify its persisted binding against the live opened file.

The source binding is immutable. Installation in the destination is fenced and committed to its authority log. Runtime claims retain their operation, request, grant, resource and recovery-lease bindings. The source contains no standalone consumed-lease or continuation markers.

Only an empty unstamped source database may initialize. Existing databases must have the exact v1 catalog. Missing, modified, retired or unknown schema objects refuse without schema adoption. Source qualification is checked before changing journal mode.

Device or inode changes refuse, including copied databases, restored backups, replacement files and remounts that change physical identity. Hard-linked sources refuse. Physical qualification failures report `runtime_source_qualification_invalid`. The current interface cannot supersede an installed qualification or reuse its source or runtime authority IDs. The destination limit is 128 installed records, with no reclamation. Replacement requires independently provisioned new source and runtime authority IDs. An exhausted destination requires a new provisioned authority. Operators must not treat moving or copying a qualified database as supported recovery.

Operator requalification is tracked as RUNTIME-SOURCE-REQUALIFY. Its required design appends a fenced superseded record and creates a new source record without deleting history; only non-superseded records will count toward the active-source limit. That interface is not implemented by this contract.

The installation exclusion guard is shared with other authority-source families. Its migration-era method name is tracked by SOURCE-INSTALLATION-GUARD-NAME; the exclusion remains required during source callbacks.

The runtime harness installs a qualified SQLite source before invoking the kernel.
Its admission artifact is the signed kernel receipt, including a denial receipt.
Workflow, step and proof-source records bind `admissionReceiptSha256`; the
separate cross-boundary treaty admission report retains its own report digest.
