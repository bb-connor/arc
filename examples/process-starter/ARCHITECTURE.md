# Packaged process starter

## Ownership and public surface

The starter consumes the existing Chio CLI and authenticated worker protocol.
It adds no authorization, dispatch or replay implementation. Its public surface
is `run.py --state <directory>`, with an optional deliberate worker interruption.
The Python producer owns the sample message. The Node consumer owns bounded
arithmetic over the guarded mailbox result and its application checkpoint.
The Rust host owns the process tree, attenuated capabilities, worker credentials,
durable admission, mailbox persistence and restart attempts.

`scripts/qualify-process-packages.py` builds the wheel, source distribution and
npm tarball. It copies the supplied host binary and application into an external
directory. `run.py` installs the packages into a new private environment using
offline installers, then initializes and runs the native host. The package
manifest pins the copied artifacts to prevent accidental changes during resume.

## Trust and recovery boundary

Application code, local package artifacts and the native executable are trusted
operator inputs. The hash manifest is unsigned and does not establish release
provenance. Workers receive credentials through private standard input. Public
evidence includes original receipt text and the key pinned at initialization,
but excludes host databases, signing keys and worker credentials.

The workers share an operating-system user and are not sandboxed. Capabilities
restrict mediated tool operations, not arbitrary direct filesystem access.
Receipt verification checks signatures and action parameter hashes. It does
not certify the arithmetic result or prove a complete receipt log. The known
send uses one stable operation key across restart attempts, preserving its
original signed result. Unknown outcomes remain governed by the host's
fail-closed admission contract.

## Verification

Qualification checks that both runtime imports come from installed package
artifacts outside the checkout. It exercises a committed Python handoff,
automatic restart, Node consumption, checkpointing, acknowledgment and two
scope denials. A read-only mailbox database oracle confirms one lifetime
message and an empty pending queue. Repeating a completed run retains worker
output modification times, attempt counts and receipt bytes. The same protocol
tests run against the installed wheel, npm tarball and a wheel rebuilt from
the source distribution. Artifact drift is rejected before the host starts.
