# Execution-evidence review closeout

The initial kernel/store, funded integration and independent Python reviews are
retained alongside this record. Those reviews describe earlier working snapshots.
After the user stopped sub-agent work, the primary agent completed integration,
source review, corrections and qualification. No later delegated review is claimed.
The containing manifest identifies the final source objects and successful checks.

| Initial finding or qualification gap | Final handling |
| --- | --- |
| Invalid execution signer standing could mint a negative financial decision | Execution-profile decisions require an accepted evidence assessment before either financial verdict. Signed invalid/revoked status tests cover fresh decisions and replay. |
| Current-time validation blocked an earned decision after Finding expiry | Fresh claims validate at the present time; retained decisions re-derive the exact assessment at its original evaluation time. A real-time expiry test covers replay and payment preparation. |
| Source-hash auditing exported evidence and reacquired a finalizer lease on a resolution handle | The audit reads only the retained raw source. The regression checks unchanged authority commits and successful original refund resolution; all owned scenarios are rerun after rebuilding. |
| Python could accept backdated artifacts after signer revocation | Every non-null revocation rejects for this profile, across governance, production and checkpoint standing. |
| Python authority-role collisions diverged from Rust | The Rust profile's complete collision matrix is mirrored and tested with valid signatures. Provider and its native kernel remain the explicitly supported shared role. |
| A provider could substitute the allocation in the public witness | A separately supplied allocation pin is required. The checker reports pin verification and explicitly does not derive or verify EVM funding. |
| Blank Finding policy text differed across languages | Nonblank fields follow the Rust Finding policy contract; execution-core identifiers retain their separate byte/NUL rules. |
| Kernel tests lacked callback source/fence mutations | Signer callbacks that change retained requests or live fencing reject before evidence publication. Reentry, panic, expiry, replacement and crypto-floor tests remain. |
| Storage tests lacked self-consistent replacement and whole-database rollback | The native integration test covers deletion, recomputed canonical replacement and restoring the pre-projection database while preserving the newer external anchor. All three reject. |
| Unsupported source profiles needed explicit coverage | Native denial, security-release and federation fixtures reject execution export. The source validator restricts this first profile to complete native Value returns. |

Actual Rust-produced public evidence exposed two independent-verifier integration
details: the original native action also commits the bilateral capture-waiver
argument, and the Finding checkpoint reference is the pinned log id plus sequence.
Python now checks those commitments, including the original policy hash, and
rejects signed substitutions. It makes no independent financial-waiver claim.

The separately pinned checkpoint cannot use the native receipt store's same-signer
checkpoint path. Integration preserves that existing rule and uses the existing
checkpoint builder with immutable first-checkpoint custody in the original funding
journal. This is a one-allocation, one-leaf local log; no general multi-allocation
log or independent administration is implied.

Final test corrections preserve the intended production checks. The execution
Finding fixture no longer supplies stale collateral and recipe artifacts bound
to its predecessor profile. SQL-only fixtures now supply the complete parent
rows and composite keys required by foreign-key enforcement. Real native SQLite
migration and rollback tests remain separate from those schema-only fixtures.

No unresolved production defect was established in this reviewed scope. Local
qualification does not replace external review, remote CI, release qualification,
independent operators, public-chain finality, or a new formal proof.
