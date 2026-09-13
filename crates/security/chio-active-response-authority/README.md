# Chio active-response authority

This crate provides the Linux process boundary for pre-admitted active
response. It does not mint policy, capabilities, approvals, or governance
artifacts online. Operators review a closed canonical bundle offline, build a
new immutable SQLite snapshot, and restart the daemon with the new deployment
and store digests.

At startup the daemon loads the complete canonical
`chio.active-defense.deployment-config.v1`, validates its normalized digest and
broker/authority role separation, validates the complete SQLite image,
recomputes its logical digest, and decodes all records into an immutable
in-memory snapshot. A standalone response-authority runtime subset is not a
valid daemon config. Authorization decisions never consult mutable database
state after startup. The retained read-only database connection exists only
for exact file-custody and health revalidation.

The daemon accepts only one pinned broker process over a mode `0600` Unix
socket. Protocol v2 signs the exact deployment and store digest in every
request and response. Policy selection keys bind the complete evidence ID,
correlated finding body, and batch binding. Artifact keys bind the complete
response-plan authorization body and admission artifact reference.

Private signing material is accepted only through `--signing-key-fd`. The
descriptor must be transferred exclusively by the launcher, owned by the
configured service UID, and contain exactly 32 bytes. Key paths and key
environment variables are intentionally unsupported.

Plan, build, and validate operator artifacts with:

```text
chio security authority-store digest --input BUNDLE
chio security authority-deployment digest --input DEPLOYMENT-DRAFT
chio security authority-store build --input BUNDLE --output STORE --manifest MANIFEST
chio security authority-deployment validate --input DEPLOYMENT
```

The store digest excludes the deployment digest by design. Operators first
compute the content digest from a reviewed bundle whose deployment digest may
be zero, bind that content digest into a deployment draft, compute the
deployment digest, populate both deployment digest fields, validate the final
deployment, and only then build the pinned store.

The runtime stays dark until the rollout gates in
`docs/security/active-defense-rollout.md` are satisfied. Its existence is not
authorization for public traffic, dynamic governance, permanent automatic
revocation, or receipt correlation.
