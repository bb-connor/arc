# Evidence redactions

Two retained evidence files were redacted before publication in this
public repository. Oracle Cloud resource identifiers (OCIDs), bastion
client allowlist addresses and the tenancy-specific availability-domain
prefix were replaced with stable placeholders. Each distinct original
value maps to one placeholder within these files, so records that named
the same resource still agree. No other bytes changed.

| File | Original sha256 | Published sha256 |
|---|---|---|
| `owned-resource-cleanup.json` | `186b163c5e2fc76ef636780db440ab95b20535d5a475eeca5365dc4672c35c74` | `edab34ee4f0ef7afd4292781ce39a518e5918a3c4cc0b9a233c7482c2216faa3` |
| `matched-linux-performance/host-metadata.json` | `4cdd37517d7a4989e8a2ae6dec91b01a37be288678fc8a5297386db0b0199ae8` | `191e59a184f01394234172b11679ce899ba8dfa22176486996dd2aed1ce84d6b` |

Historical package records and auditors bind the original hashes, so a
package audit reports these two files as altered. The unredacted
originals are retained outside the repository.
