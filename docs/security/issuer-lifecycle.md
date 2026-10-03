# Capability issuer lifecycle

A receipt signer attests decisions. It is a capability issuer only when the kernel
explicitly configures it as a local authority or CA pin. An approval signer also
requires a separate approver roster. Reusing a key across those roles is an
explicit deployment choice, not an implication of possession.

## Live authority and historical evidence

SQLite authority schema 3 retains every public issuer in its history. Current
admission reads a separate live projection under the authority transaction:

- Active: the current custodian may issue and verify capabilities.
- Verification-only: previously issued capabilities can verify until the
  exclusive `verifyUntil` deadline. `issuedAt` must be at most `issueUntil`.
  Capability times are whole Unix seconds, so the issuance cutoff includes the
  rotation second. A compromised old key can backdate within that period; use
  revocation or recovery when compromise is suspected.
- Retired: a historical issuer no longer grants live authority.
- Revoked: a historical issuer is explicitly compromised or withdrawn. It cannot
  be retired, reactivated or used as a successor.

Rotation defaults to at most 3,600 seconds of overlap. A caller can choose a
shorter deadline, including immediate expiry. Expired keys remain in public
history; checking an old receipt signature never turns them into capability
issuers. Store errors or unavailable/regressing time grant no issuer trust. A
durable observed-time floor prevents a restart with earlier time from reopening
an expired window.

Full and portable kernel admission both check the managed issuer lifecycle before
resolving trusted keys. A static CA pin cannot override a managed issuer's cutoff,
deadline, retirement or revocation. Remote-authority admission refreshes current
state even when its diagnostic cache is fresh; an unavailable refresh denies.

Retained keyring hosts resolve the authenticated key log and owned clock again on
each admission. Key-log transitions use milliseconds while capability issuance
uses seconds. For that backend, an old issuer's token must predate the entire
deactivation second, since its timestamp cannot establish ordering within that
second. This conservative cutoff differs from SQLite's explicitly whole-second
rotation contract. Historical witnessed signature evidence remains separately
verifiable and cannot restore live authority.

## Signed state and recovery

Version 2 transitions bind the stream ID, immutable anchor digest, predecessor
commitment, next generation, transition time, operation and complete issuer-state
digest. A current-head signature authorizes rotation, retirement and revocation.
Retirement and revocation target historical keys. Remove the current head through
an atomic successor transition rather than leaving a headless stream.

An optional independent recovery key is pinned when the stream is initialized.
Only that root may authorize recovery. Recovery generates a fresh local issuer,
revokes every prior issuer and commits the public transition with the new local
seed in one transaction. Replication copies public state and signatures, never a
seed. A follower therefore cannot begin issuing merely by receiving a recovery
transition. Private custody transfer is a separate operator procedure.

Use the local `chio federation authority` commands while the affected service is
stopped or under its established exclusive maintenance procedure:

```text
chio federation authority replication-init --database PRIVATE/authority.db --stream-id CLUSTER --out anchor.json --recovery-public-key ROOT_HEX
chio federation authority issuer-rotate --database PRIVATE/authority.db --verify-until UNIX_SECONDS
chio federation authority issuer-retire --database PRIVATE/authority.db --public-key OLD_ISSUER_HEX
chio federation authority issuer-revoke --database PRIVATE/authority.db --public-key OLD_ISSUER_HEX
chio federation authority issuer-recover --database PRIVATE/authority.db --recovery-key-file PRIVATE/recovery-key.json
```

Provision the recovery key through the existing private authority-key format and
custody procedure. `replication-init` publishes only its public key. Retire,
revoke and recover require a pinned stream. Local unpinned rotation still uses the
bounded overlap but does not establish peer trust. Distribute the public anchor
and its digest through independent authenticated operator channels before pinning
followers. An HTTP service token cannot replace a pin or authorize a transition.

## Migration and bounded history

Legacy v1 checkpoint and rotation bytes retain their canonical commitments. The
legacy head remains active; older keys receive a conservative verification window
ending at most one hour after their successor activation. The first v2 operation
materializes that lifecycle in the signed history. A v1 operation cannot follow a
v2 state and old envelopes cannot roll back a committed v2 prefix.

The chain limit remains 1,024 transitions and 4,096 retained keys. Before reaching
the transition limit, plan an explicit offline recheckpoint: record the accepted
state and commitment, provision a new stream from independently authenticated
state, and redistribute its pin to every consumer under the deployment's recovery
procedure. Existing anchors cannot be changed in place. Do not delete replication
rows, copy a follower seed over the issuer, or silently repin a running consumer to
make an error disappear. Recheckpointing and safe custody handover are operator
acceptance work, not automatically performed by this implementation.

Follow [private SQLite custody](authority-sqlite-custody.md) before reopening an
older database. Schema 3 prevents an older binary from opening the new authority
store as though all historical issuers remained active. Linux custody is locally
qualified; other platforms refuse before creating seed-bearing files.
