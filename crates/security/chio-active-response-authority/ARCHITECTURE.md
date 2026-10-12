# chio-active-response-authority architecture

## Responsibility and boundary

This crate owns the pre-admitted active-response authority service, its static
deployment checks, and its reviewed SQLite store builder. The service returns
stored policy selections or admission-artifact drafts for exact input matches.
The broker and kernel retain capability verification, governed approval,
dispatch admission, and effect execution responsibilities.

The public library exports `AuthorityRuntimeConfig`, combined deployment
configuration, validation, store bundles and manifests, lookup-key helpers,
`AuthorityStore`, `PreAdmittedAuthorityHandler`, and `AuthorityDaemonRuntime`.
Runtime and store exports are gated to Unix; daemon construction and serving
require Linux. Signal-handler installation is exported only on Linux.
The crate declares no Cargo features.

## Structure

| Module | Responsibility |
| --- | --- |
| `config` | Runtime/combined schemas, deployment digest, execution profile, paths, and config-file custody. |
| `store` | Canonical records, logical digest, private SQLite creation, verified lookup maps, and mode-bound handler. |
| `runtime` | Signing-key custody, authenticated listener, protocol server, bounded workers, and shutdown. |
| `shutdown` | Standalone daemon ownership of SIGINT/SIGTERM handlers. |
| `bin/chio-active-response-authorityd` | Required argument parsing, process hardening, descriptor adoption, and serving. |

`AuthorityError` distinguishes untrusted JSON, configuration, custody, store,
invariant, runtime, and missing pre-admission failures. The handler maps missing
records or mode mismatches to a permanent `active_response.not_pre_admitted`
rejection; other store failures become fatal integrity errors.

## Data and control flow

Operators supply an `AuthorityStoreBundle` containing nonempty policy and
artifact inventories. `compute_authority_store_digest()` prepares validated,
key-sorted logical records and hashes their canonical image with the authority
identity. The deployment digest is excluded from this content digest.
`ActiveDefenseDeploymentConfig::compute_deployment_digest()` zeroes both nested
and outer deployment digest fields before hashing the normalized configuration.
This allows the store content digest to be bound into the deployment first.

`build_authority_store()` requires the final nonzero deployment digest and
distinct absolute output paths. It creates new private database and manifest
files, writes the strict SQLite tables and canonical manifest, syncs and
revalidates file identities, then reopens and health-checks the store before
disarming cleanup guards. A failed build removes only its retained output inode.

Daemon startup loads the complete combined deployment through
`load_runtime_config()`. It validates the configuration digest, broker process
and key bindings, receipt signer separation, and privileged path inventory.
The returned authority projection is then checked against the current process.
The daemon adopts the inherited key descriptor, verifies its custody and public
identity, opens the store against configured deployment/store digests, and binds
an authenticated Unix listener with the expected client peer.

`AuthorityStore::open()` decodes validated rows into private `BTreeMap` values.
`select_policy()` and `load_artifacts()` read these startup maps and compare the
complete requested records before returning clones. `health()` separately
rechecks the retained connection, file identity, schema, rows, and logical digest.
Subsequent database writes cannot add new entries to the lookup maps.

## Trust and invariants

Runtime schema v2 requires explicit live/dry-run mode, nonzero pinned digests,
distinct nonzero process IDs, matching service UID, and separate client and
authority keys. Deadlines are 1-30,000 ms, permitted clock skew is 1-30 seconds,
replay capacity is 1-65,536, workers are 1-64, and queue capacity lies between
the worker count and 1,024. Combined deployment validation additionally binds
the broker identities, receipt signer, and distinct privileged paths.

The deployment loader requires an absolute path and a nonempty regular file
of at most 1 MiB. It reads through a 1 MiB plus one-byte limit and detects size
changes. On Unix it opens with `O_NOFOLLOW` and requires the configured UID,
one link, and no group/other permissions. Canonical decoding rejects ambiguous
or noncanonical authoritative JSON.

Store opening uses SQLite read-only and no-follow flags and compares the actual
opened database's device/inode/link identity. Files must be private regular
files owned by the trusted service UID, with one link and size at most 1 GiB.
Startup checks include SQLite integrity, exact table schema, metadata,
canonical rows, record counts, lookup keys, and the logical image digest.
Each table scan admits at most 65,536 records, and each decoded payload is
limited to 1 MiB. SQLite materializes a payload before its size check.

Selection keys include evidence ID, complete correlated finding body, and batch
binding. Artifact keys include the complete `ResponsePlan` and artifact
reference. The artifact validator separately binds the draft's action, tenant,
plan hash, authority, submission proof, governed intent, payload digest, and
time window using the plan's compact `authorization_body()`. These checks
establish record consistency; downstream admission verifies authorization.

`PreAdmittedAuthorityHandler` checks execution mode before returning artifacts
and after selecting a policy. A dry-run deployment requires a simulator with
the deployment digest and configured receipt signer when constructing its
host execution profile. A live profile accepts no simulator. Matching a mode
does not grant a capability or approval.

The inherited key file must contain exactly 32 bytes; the reader rewinds it
and rejects trailing bytes. Runtime workers use a bounded queue. A full queue
closes the accepted stream, and fatal worker/server failures stop serving.
Shutdown stops acceptance, discards queued work, and joins in-flight workers
under their existing protocol deadlines. Library hosts supply a stop flag;
the standalone binary installs its signal policy before startup.

## Dependencies

`chio-control-plane` supplies artifact validators and the signed authority
protocol server. `chio-secure-ipc` supplies peer authentication, listeners,
descriptor custody, and process hardening. `chio-core` supplies canonical JSON
and Ed25519 signing. `chio-security-types` supplies execution modes, bindings,
plans, identifiers, and digests.

`rusqlite` persists reviewed snapshots, and `chio-sqlite-file-identity` checks
the database file actually opened by SQLite. SHA-256 commits logical store and
deployment images. `libc`, `rustix`, and `nix` support Unix/Linux custody and
process operations; `zeroize` clears the temporary signing seed.

## Verification

`config/tests.rs` checks combined process/path/key binding, exact deployment
digest vectors, required execution mode, mode substitution, simulator mismatch,
standalone projection rejection, and combined-deployment loader revalidation.
`store/tests.rs` checks logical digest order, canonical metadata/rows, invalid
bundle rejection before output creation, startup-map isolation from later
writes, and cleanup preservation of replacement inodes.

`runtime.rs` contains Linux process tests for authenticated daemon health,
unauthorized clients, worker panic termination, queued/in-flight shutdown,
and exact key-file length despite inherited offsets.
Run `cargo test -p chio-active-response-authority --lib` on Linux for these tests.
The README sample exercises static runtime validation without file or socket
operations; it does not perform daemon startup or broker/kernel admission.
