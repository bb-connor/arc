# Hosts, setup and confined return boundaries

Subject: the pinned snapshot. This is source inspection only.

## Thin host adapters are required integration surfaces

The LangGraph node is twenty lines and delegates to `RecoveryHostSession`.
The CrewAI tool also delegates to that session, disables tool caching and
accepts a closed choice rather than effect instructions. Neither contains an
alternative recovery effect implementation. Keep their framework-specific
adaptation and consolidate common transport behavior in the existing shared
session/client, not another adapter layer.

`RecoveryHostSession` owns exact command bytes, a per-session action budget and
late request/cleanup tasks. Its synchronous worker supports CrewAI's event-loop
boundary; the async path supports LangGraph. Sharing the underlying admitted
operation is already implemented. Removing the worker because an async method
also exists would lose synchronous host behavior and interruption ownership.

`RecoveryClient` routes commands, review, explanations, settlement, reports,
policy proposals and setup to the native host. It disables redirects and ambient
proxy configuration and does not add retries. Framework output is a closed
status projection; credentials and raw native results stay out of saved state.
Keep the meaningful public tests for unknown results, repeat command identity,
native refusal, bounded waits and exception-text redaction. Those are not
redundant with Rust's persistence tests.

## Setup is acceptance, not another runtime

`recovery/setup.rs` composes the existing `RecoveryRuntime`, serving Store,
knowledge mediator and an operator signer. It invokes the same benign command,
obtains a signed denial through the Kernel and then requires a changed serving
fence before qualification. Restart replay uses the original native result.
Keep those actual operations and the Store verification of their evidence.

The optional knowledge field in `RecoverySetupHost` is rejected immediately
when missing (`:68`, `:125`). A nonoptional `Arc<NativeKnowledgeRuntime>` in the
host composition would express the supported state more cleanly. This is a
public API change, not a runtime correctness fix. Retain an explicit error at
untrusted/configuration decoding boundaries, and check constructors outside the
reviewed source before changing the signature.

## Confined execution reuses the existing cage

`confinement/execution.rs:91` checks the selected compiled cage: blocked network,
default filesystem denial, `NativeMinimalV1`, fixed environment, one executable,
closed descriptor purposes and provider disabled. `:167` calls the existing
`chio_cage::prepare_launch`; `:179` calls `launch_prepared`. This is host custody
around the cage, not a second sandbox implementation.

The reviewed profile has an eight-byte value channel and separately bounded
private diagnostics. Channel readers share an absolute deadline. The stage
path rechecks audience after blocking reads and exit observations, discards
diagnostic contents, and stages the return through native and Process owners.
It does not qualify arbitrary model/provider/stream features. The profile's
disabled channels must remain disabled unless separately implemented and tested.

The apparent repeated checks around channel joins and first-byte delivery are
required time-of-use checks. Keep them. Likewise, `PreparedConfinedReturn` owns
private bytes without `Clone` or a getter; `ConfinedDeliveryError` retains the
actual sink outcome across acknowledgment failure. Its reconciliation method
records that outcome and does not deliver again. Do not replace either with a
serializable descriptive record that callers can manufacture.

`ProcessArtifactBroker::begin_verified_confined_delivery` obtains a Kernel proof
before the Process transaction orders delivery against cancellation. These two
steps own different databases and are not duplicate authorization checks.

No cage/controller execution, Linux acceptance or live-provider campaign was
performed. Store confinement internals and the existing cage implementation
have not received a complete line-by-line review in this architecture pass.
