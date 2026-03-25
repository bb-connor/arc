# PACT Certify Guide

`PACT Certify` is the certification layer that turns a conformance evidence
corpus into a signed pass/fail artifact, then publishes or resolves that
artifact through a fail-closed registry when operators need a stable status
surface.

The current surface is intentionally narrow but now covers the operator loop:

- it evaluates an explicit conformance scenario/result corpus
- it applies one fail-closed criteria profile, `conformance-all-pass-v1`
- it signs the resulting artifact with an operator-controlled Ed25519 key
- it can verify a signed artifact locally
- it can publish, list, get, resolve, and revoke signed artifacts in a local
  or trust-control-backed registry

This is still not a public certification marketplace or discovery network.

## Command

```bash
pact certify check \
  --scenarios-dir tests/conformance/scenarios/wave1 \
  --results-dir target/release-qualification/conformance/wave1/results \
  --output target/release-qualification/conformance/wave1/certification.json \
  --report-output target/release-qualification/conformance/wave1/certification-report.md \
  --tool-server-id demo-server \
  --tool-server-name "Demo Server" \
  --signing-seed-file .pact/certify-ed25519.seed
```

Verify one artifact:

```bash
pact certify verify \
  --input target/release-qualification/conformance/wave1/certification.json
```

Publish into a local registry:

```bash
pact certify registry publish \
  --input target/release-qualification/conformance/wave1/certification.json \
  --certification-registry-file .pact/certifications.json
```

Resolve the current certification state for one tool server:

```bash
pact certify registry resolve \
  --tool-server-id demo-server \
  --certification-registry-file .pact/certifications.json
```

Use the trust-control service instead of a local file:

```bash
pact --control-url http://127.0.0.1:8940 \
  --control-token "$PACT_CONTROL_TOKEN" \
  certify registry list
```

## Criteria Profile

`conformance-all-pass-v1` passes only when all of the following are true:

- the scenario corpus is non-empty
- the result corpus is non-empty
- every result maps to a declared scenario
- every declared scenario has at least one result
- every declared scenario has `expected: "pass"`
- every observed result is `pass`

The command fails closed at the verdict layer:

- `fail`, `unsupported`, `skipped`, and `xfail` all block certification
- unknown-scenario results block certification
- partial coverage blocks certification

## Artifact Shape

The generated JSON artifact contains:

- the stable schema ID: `pact.certify.check.v1`
- the target tool-server identity
- the criteria profile used
- a pass/fail verdict
- summary counts across the evaluated corpus
- explicit findings for partial coverage, unknown scenarios, and non-pass results
- normalized SHA-256 digests of the loaded scenarios, results, and generated report
- the signer's public key and the Ed25519 signature over the canonical JSON body

The artifact is portable: a verifier only needs the body, signature, and public
key to validate integrity.

## Registry Model

The registry stores the signed certification artifact as the immutable payload
and derives a stable `artifactId` from the canonical SHA-256 digest of the full
signed JSON.

Each registry entry tracks:

- `artifactId`
- `artifactSha256`
- `toolServerId` and optional `toolServerName`
- `verdict`
- `checkedAt`
- `publishedAt`
- `status`: `active`, `superseded`, or `revoked`
- optional `supersededBy`
- optional `revokedAt` and `revokedReason`

Publishing a new artifact for the same `toolServerId` automatically supersedes
the previously active artifact. Revocation is explicit and does not silently
reactivate older entries.

`resolve` returns one operator-facing state for a tool server:

- `active`: a current published artifact exists
- `revoked`: no active artifact exists and the latest relevant entry is revoked
- `superseded`: no active artifact exists and only superseded history remains
- `not-found`: the registry has no artifact for that tool server

## Signing Model

Use a dedicated seed file for certification signing. The command will create it
on first use if it does not already exist.

Treat that file as an operator trust root:

- keep it out of source control
- restrict it to the certification operator
- rotate it deliberately, not per run

If you expose registry operations through `pact trust serve`, configure a
dedicated `--certification-registry-file` on that service and keep the bearer
token explicit with `--service-token`.

## Relationship To Release Qualification

`PACT Certify` is built on top of the existing conformance and qualification
pipeline. A typical flow is:

1. run `./scripts/qualify-release.sh`
2. inspect the generated compatibility report and raw results
3. run `pact certify check` against the selected wave corpus
4. optionally run `pact certify verify` as a local integrity gate
5. publish the signed artifact into the local or remote certification registry
6. use `pact certify registry resolve` to surface the current operator-facing
   status for that tool server
