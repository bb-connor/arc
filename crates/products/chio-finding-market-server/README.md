# chio-finding-market-server

Runs the authenticated PostgreSQL finding market's loopback HTTP listener.
The executable loads a hosted operator profile, checks runtime credentials,
and builds the authentication and request boundaries from
`chio-finding-hosted-edge`. It also provides replication freshness checks.

## Usage

This offline rejection example verifies that the profile path must be
absolute before any file or database I/O. Run from the workspace root.

```sh
if diagnostic=$(cargo run --locked -p chio-finding-market-server --quiet -- --profile profile.json 2>&1); then
  exit 1
fi
test "$diagnostic" = 'hosted server profile is invalid: profile path must be absolute'
```

Normal startup uses `chio-finding-market-server --profile
/absolute/path/hosted-profile.json`. Supply a canonical JSON profile owned by
the process user, with no group or other permissions, and at most 4 MiB.
The profile must choose a trusted proxy edge and a loopback listener.
The proxy provides the external HTTPS boundary.

Set the runtime database URL, trusted proxy token, and API-key pepper in the
environment variables named by the profile. Provide the database CA file and
set `CHIO_FINDING_DEPLOYED_CANDIDATE_SHA` and
`CHIO_FINDING_DEPLOYED_ARTIFACT_SHA256` to the profile's release identities.

`--replication-check-once` runs one check round and exits, writing signed checks
to PostgreSQL. It requires the profile's replicator URL and AuthorityStatus
remote signer credentials. `--replication-check-interval-secs` accepts 5 through
20 for continuous checks and conflicts with the one-shot flag.

## Guarantees

- `read_profile` opens a private regular file without following its final
  symlink, caps the read, checks the retained length, and requires canonical JSON.
- `run` calls `FindingHostedProfile::validate`, requires a trusted proxy, and
  enforces loopback binding for the HTTP serving path.
- `deployed_release_identity` rejects candidate or artifact digest drift before
  the listener starts. HTTP requests receive configured limits of 4 MiB per
  body and 1024 concurrent requests through `HostedHttpServerState`.
- `write_replication_check` requires writable PostgreSQL authority and the
  expected configuration revision before appending a signed freshness check.

SIGINT or SIGTERM triggers the listener's shutdown future. Errors return a
failing exit code; replication loops stop after repeated complete round failures.

## Status

This unpublished Unix binary implements listener startup and replication checks.
Unit tests cover profile-file gates, release binding, writable authority modes,
and concurrent tenant rounds. Deployment acceptance requires the configured
proxy, PostgreSQL roles and schema, remote custody, and external route checks.

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [Hosted edge](../../platform/chio-finding-hosted-edge/README.md)
- [Migrator](../chio-finding-market-migrator/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
