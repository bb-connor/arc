# Independent clock, contract and consumer review

Reviewed the working source against base `491f585e9013dcb6335589c82d00ac219efbf0a6`,
including new helpers and excluding unrelated output. This fresh read-only review
ran no Cargo graph and made no hosted qualification claim.

## Original findings

No Critical findings. Two Important issues remained in the reviewed snapshot:

1. Reputation issuance sampled host time inside the scorer and opened stores
   without the supplied clock. With an old injected epoch and short temporal
   decay, signed denial evidence could disappear from scoring and permit a higher
   issuance tier. Thread the authority clock through scoring and its stores.
2. Direct remote issuance sent the mutating RPC before reading the owner clock.
   A caller could mint remotely with an already-unavailable clock, then receive
   an error during response validation. Probe before RPC and retain the later
   response-time check.

One Minor: the lexical clock scanner missed `SELECT unixepoch(\"now\")`
in an escaped Rust string. The resulting SQLite statement reads ambient time.

A missing new aggregate-validator argument was also identified and corrected
during review. Compilation and hosted acceptance remain the implementer's gates.

## Independent checks and limits

The current trust-boundary scan returned no errors; consumer CI inventory passed.
A stronger inventory-only promotion control rejected all 38 baseline readers
without source evidence. Seven other baseline readers already contained valid
source witnesses, so their promotion was legitimately source-supported.
Native aliases, function references, SQL defaults and local decoder aliases were
examined. Supported native convenience constructors, process-local clock fences,
post-commit health failures and declared lexical/dataflow limits were considered
and were not additional findings.

Original verdict: resolve both Important findings before claiming closure.
Broader clock debt and ingress coverage remain outside this batch.

## Root fix pass

The reputation control reproduced the old-epoch permission error. The repaired
policy context carries the same authority clock through scoring and both stores.
The remote control observed one actual loopback issuance request before the fix;
the implementation now probes before RPC and retains the response-time sample.
The escaped-SQL control failed on the old scanner and passed after repair; the
immutable base census reproduced byte-for-byte. Terminal Rust verification is
recorded in the batch qualification artifact.

## CI-only follow-up after the hosted timeout

The same reviewer examined the six-file workflow split at `9a7892297669` against
`88464cc1d8`. All 15 installed-consumer steps, the worker/comparison jobs and the
host acceptance commands were preserved as parsed YAML. The existing required
check name now requires success from all four dependency jobs.

One additional Important issue was found: the pinned download action places an
ID-selected artifact under a named subdirectory unless `merge-multiple` is set.
The restore script expected the archive at the download root. This follows from
the [pinned action source](https://github.com/actions/download-artifact/blob/d3f86a106a0bac45b974a628896c90dbdf5c8093/src/download-artifact.ts#L162).
The first transfer fixture assumed a flat path and therefore missed the failure.

The root reproduced the missing archive by modeling that path selection, then
set `merge-multiple: true` while retaining the exact artifact ID and producer
SHA-256. The reviewer checked the two-file correction and independently reran
its three passing controls. The finding is resolved, with no remaining finding
in the bounded CI follow-up. This was not a second broad Rust review, Cargo run
or hosted qualification.
