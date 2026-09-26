# Design: making the recurring defect class unrepresentable

Pass 5 of the September 26 review lineage. Unlike passes 1 to 4, this is a design
document, not a hunt. Reviewed candidate: `3cd73631a18a6ec169b1e1a5bbd3ebe8bcb00130`
on draft [PR #1160](https://github.com/bb-connor/arc/pull/1160).

Companions: the [security engineering standard](../../security/engineering-standard.md),
the [engineering excellence addendum](../plans/2026-09-26-security-engineering-excellence.md),
and the four prior reviews
([Q](../../reviews/2026-09-26-security-code-quality-review.md),
[R](../../reviews/2026-09-26-security-code-quality-review-pass-2.md),
[P](../../reviews/2026-09-26-security-performance-review-pass-3.md),
[S](../../reviews/2026-09-26-security-review-pass-4.md)). The
[pass 6 validation](../../reviews/2026-09-26-review-validation-pass-6.md) re-verified
the numbers this document relies on.

## The one defect, stated once

Eight findings across four passes have the same shape:

> A correct primitive exists. Correctness depends on a convention about where it is
> called. The convention is enforced by memory.

| Finding | Primitive | Convention |
| --- | --- | --- |
| Q2 | `ResponseExecutionBinding::validate()` | remember to call it after deserializing |
| Q3 | `require_execution_mode(Live)` | remember to call it on every live path (5 sites today) |
| Q4 | signature coverage of `execution` | remember that this is what blocks strip-to-legacy |
| R1 | eight guard comparisons before `u64` subtraction | remember to guard the ninth |
| R2 | `StateMachineError::Shape(#[from] ResponseShapeError)` | remember to use `?` instead of `map_err(\|_\| InvalidDispatch)` |
| R4 | `pub const RESPONSE_AFFECTED_SET_DOMAIN` | remember to import it rather than redeclare the bytes |
| S2 | `canonical_json_bytes_from_str` (strict) | remember which entry point untrusted text requires |
| S3 | unguessable identifiers | remember which tables rely on that instead of a tenant predicate |

Hunting instances has diminishing returns. The design below makes each row a
compile error or a gate failure instead of a review comment.

## Two new findings from this pass

Designing the types required measuring how the codebase already uses them.

### T1. The `Verified*` prefix is a type guarantee in 116 places and a naming convention in 45

169 named-field structs are called `Verified*`, `Authorized*`, `Admitted*` or
`Validated*` in production code. Field visibility:

| Fields | Count | Meaning |
| --- | --- | --- |
| all private | 116 | constructible only through the module's constructor: a real token |
| all `pub(crate)` or crate-mixed | 4 | constructible by literal anywhere in the crate |
| all `pub` | **45** | constructible by literal anywhere in the workspace |
| mixed | 3 | |

**18 of the 45 all-`pub` types live in TCB crates**, including `VerifiedCapability`
(`chio-kernel-core/src/capability_verify.rs`, 7 fields, the result of capability
verification), `VerifiedPassport`, `VerifiedSecurityEvent`,
`VerifiedActiveResponseOperatorCapability`, `VerifiedApprovalSetBody` (12 fields),
`VerifiedSupplementalQuotaClaim` (18 fields) and `AuthorizedBudgetHold`.

**Four of those also derive `Deserialize`:** `VerifiedCapabilityJson`,
`VerifiedSecurityEvent`, `VerifiedApprovalSetBody`, `VerifiedIsolationEvidence`. A
wire payload can therefore *assert* that it is verified, and the type system will
agree.

A nuance that keeps this honest: an all-`pub` `Verified*` struct is a hole only if a
downstream consumer accepts the type as proof. Where it is a plain data carrier
returned from a verifier and every consumer re-checks, it is a naming smell. That
distinction cannot be settled by inspection for 45 types, which is the point; the
four `Deserialize` cases are the sharp edge regardless, because deserialization is
a constructor the module does not control.

Standard rule 2.2 called this pattern "used well across the reviewed paths and the
single strongest thing about the current design." That was 70 percent true. The
rule has been qualified.

### T2. Two error-code registries, and the security TCB uses the unregistered one

`crates/core/chio-errors` is a spec-driven URN registry: 114 `ErrorCodeSpec`
constants generated from `spec/`, with `Domain`, `Severity` and `Code`. The security
port layer does not use it. `chio-security-types` declares its own
`ErrorCode(String)` with five ad-hoc values (`store.unavailable`, `store.conflict`,
`store.invalid_data`, `store.integrity_failure`, `invalid.identifier`) and has no
dependency on `chio-errors`. `PortError { kind, code }` therefore carries a code that
exists in no registry, and the response path's `StateMachineError` carries none at
all.

This matters for mechanism C: a structured rejection is only as useful as the
registry it maps onto.

## The three mechanisms

Each mechanism is a contract plus a sketch in the house idiom already present in
`Digest32` and `CanonicalBody` (private field, `#[must_use]` constructor,
`#[serde(transparent)]` or `try_from`, accessors only). Nothing here introduces a
new idiom; it applies the existing one where it was skipped.

### Mechanism A: evidence tokens

**Contract.** A check produces a value; the operation consumes the value. The
value has private fields, no `Default`, no `From<Unverified>`, no `Deserialize`, and
exactly one constructor, which *is* the check. Accessors are read-only. The
compiler then rejects the operation without the check.

**Sketch: the five mode-check sites become one constructor.**

```rust
/// A response plan whose execution mode has been checked for a specific
/// commit mode. The kernel admission and quarantine dispatch entry points
/// accept this type and nothing else.
#[derive(Debug)]
pub struct LiveAuthorizedPlan {
    plan: ResponsePlan,
    commit_mode: ResponseDispatchCommitMode,
}

impl LiveAuthorizedPlan {
    pub fn authorize(
        plan: ResponsePlan,
        commit_mode: ResponseDispatchCommitMode,
    ) -> Result<Self, DispatchRejection> {
        match (&plan.provenance, commit_mode) {
            (PlanProvenance::Bound(binding), _) if binding.mode() == ResponseExecutionMode::Live => {}
            (PlanProvenance::Bound(binding), _) => {
                return Err(DispatchRejection::ExecutionMode { observed: binding.mode() });
            }
            (PlanProvenance::Legacy, ResponseDispatchCommitMode::Fresh) => {
                return Err(DispatchRejection::LegacyPlanFreshDispatch);
            }
            (PlanProvenance::Legacy, _resume) => {
                // Historical recovery only; retirement condition per correction 1C.
            }
        }
        Ok(Self { plan, commit_mode })
    }

    #[must_use]
    pub fn plan(&self) -> &ResponsePlan {
        &self.plan
    }

    #[must_use]
    pub fn commit_mode(&self) -> ResponseDispatchCommitMode {
        self.commit_mode
    }
}
```

`prepare_response_dispatch` and both kernel admission entry points change their
parameter from `ResponsePlan` to `LiveAuthorizedPlan`. The inverse rule at
`state_machine.rs:687` disappears because the rule exists once. A sixth live path
that forgets the check does not compile.

**Sketch: retrofitting a hollow `Verified*` type.** For a type that must cross the
wire, the wire form is by definition unverified, so it gets a different name:

```rust
/// Signed security event as received. Not yet verified.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSecurityEvent { /* pub fields are fine here: nothing trusts them */ }

/// A security event whose signature, schema and binding have been verified.
/// Not `Deserialize`: the only way to obtain one is `SignedSecurityEvent::verify`.
#[derive(Debug, Clone)]
pub struct VerifiedSecurityEvent {
    event: SecurityEventBody,
    verifier: VerifierId,
}

impl SignedSecurityEvent {
    pub fn verify(self, trust: &TrustRoots) -> Result<VerifiedSecurityEvent, EventRejection> { /* ... */ }
}
```

The 45 all-`pub` types are migrated on this shape when touched, the 4 `Deserialize`
ones first.

### Mechanism B: constrained values

**Contract.** The value cannot exist in an invalid state. Validating constructor;
`#[serde(try_from = "...Wire")]` so deserialization is the validation; no `Deref`
to the raw representation; at most one named exit to the raw form, for storage or
wire, and that exit is greppable.

**Sketch: untrusted text (S2).**

```rust
/// JSON text whose bytes originated outside this process. The only path from
/// here to canonical bytes is the strict parser; the permissive typed-value
/// canonicalizer is unreachable without `into_raw_for_storage`, which is gated.
#[derive(Debug)]
pub struct UntrustedJsonText(Box<str>);

impl UntrustedJsonText {
    pub fn from_wire(bytes: &[u8], bound: usize) -> Result<Self, WireError> {
        if bytes.len() > bound { return Err(WireError::TooLarge { bytes: bytes.len(), bound }); }
        let text = core::str::from_utf8(bytes).map_err(|_| WireError::NotUtf8)?;
        Ok(Self(text.into()))
    }

    pub fn canonicalize(&self) -> Result<CanonicalBody, CanonicalError> {
        canonical_json_bytes_from_str(&self.0).and_then(CanonicalBody::new)
    }

    /// Named exit. Listed in the escape-hatch gate.
    #[must_use]
    pub fn into_raw_for_storage(self) -> Box<str> {
        self.0
    }
}
// Deliberately absent: Deref<Target = str>, AsRef<str>, Display, From<String>.
```

**Sketch: an accounting quantity (R1).**

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct ExposureUnits(u64);

impl ExposureUnits {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(MAX_EXPOSURE_UNITS);

    pub fn new(units: u64) -> Result<Self, BudgetStoreError> {
        (units <= MAX_EXPOSURE_UNITS).then_some(Self(units))
            .ok_or(BudgetStoreError::ExposureOutOfRange { units })
    }

    pub fn try_sub(self, other: Self) -> Result<Self, BudgetStoreError> {
        self.0.checked_sub(other.0).map(Self)
            .ok_or(BudgetStoreError::ExposureUnderflow { have: self, take: other })
    }

    pub fn try_add(self, other: Self) -> Result<Self, BudgetStoreError> {
        self.0.checked_add(other.0).filter(|v| *v <= MAX_EXPOSURE_UNITS).map(Self)
            .ok_or(BudgetStoreError::ExposureOverflow { have: self, add: other })
    }

    /// Named exit for SQL binding. Listed in the escape-hatch gate.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}
// Deliberately absent: impl Sub, impl Add, Deref<Target = u64>.
```

The four implementations of the release invariant (in-memory store, SQLite store,
composite transitions, formal models) collapse into calls to `try_sub`, and the
`overflow-checks` backstop from Packet 0.2 becomes the second line rather than the
first. The SQL `>= ?` predicate stays as the third.

**Sketch: domain separation as a closed enum (R4).**

```rust
/// Every signature and hash domain in the workspace. One declaration per
/// payload type; the byte string appears exactly once, here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Domain {
    ResponseEffect,
    ResponseRequest,
    ResponseTransition,
    ResponseAffectedSet,
    KeyLogArtifactTimeAnchor,
    // ... 232 variants after deduplication
}

impl Domain {
    #[must_use]
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::ResponseEffect => b"chio.response-effect.v1\0",
            Self::ResponseRequest => b"chio.response-request.v1\0",
            // ...
        }
    }
}

#[cfg(test)]
mod domain_registry_tests {
    // Every `bytes()` value is distinct and matches `chio.<area>.<payload>.v<N>\0`.
    // A duplicate or a malformed shape is a test failure, not a grep.
}
```

The eight duplicated declarations become one variant each. Producer and verifier
cannot disagree about a domain because there is nothing to disagree with. The
`PLACEHOLDER-SIGNATURE-OVERRIDE-IN-PRODUCTION` value becomes a `#[cfg(test)]`
variant or is deleted.

### Mechanism C: structured rejection

**Contract.** Every denial names the rule that fired and keeps its cause. One
variant per rule, or one variant carrying a closed discriminant. Inner errors are
preserved through `#[source]` (`thiserror`'s `#[from]`), never `map_err(|_| ...)`.
Every variant maps to a registered code.

**Sketch.**

```rust
/// Why a response dispatch was refused. One variant per rule, so a test, a
/// receipt and an operator can each tell which rule fired.
#[derive(Debug, thiserror::Error)]
pub enum DispatchRejection {
    #[error("plan execution mode is {observed:?}; live dispatch requires Live")]
    ExecutionMode { observed: ResponseExecutionMode },
    #[error("legacy plan cannot acquire fresh dispatch authority")]
    LegacyPlanFreshDispatch,
    #[error("authorization capability digest does not match the plan")]
    CapabilityDigestMismatch,
    #[error("executor authority generation must be nonzero")]
    ZeroExecutorGeneration,
    #[error("authorized at {authorized_at:?}, outside plan window [{created_at:?}, {expires_at:?})")]
    AuthorizationOutsideWindow { authorized_at: UnixMillis, created_at: UnixMillis, expires_at: UnixMillis },
    #[error("initial lease is outside the plan window")]
    LeaseOutsideWindow,
    #[error("approval requirement does not match the commit mode")]
    ApprovalCommitModeMismatch,
    #[error("resume requires a governed approval")]
    ResumeRequiresGovernedApproval,
    #[error("snapshot has no execution dispatch or already carries an authorization hash")]
    SnapshotNotDispatchable,
    #[error(transparent)]
    Binding(#[from] ResponseShapeError),
}

impl DispatchRejection {
    /// The registered code, so receipts and logs carry a stable identifier.
    #[must_use]
    pub const fn code(&self) -> &'static chio_errors::ErrorCodeSpec { /* ... */ }
}

// In StateMachineError:
//     #[error(transparent)]
//     InvalidDispatch(#[from] DispatchRejection),
```

The six `InvalidDispatch` return sites in `state_machine.rs` (`:685`, `:687`,
`:696`, `:707`, `:715`, `:878`) map onto these variants; the `||` at `:689-696`
splits into its six conditions. `StateMachineError::Shape(#[from]
ResponseShapeError)` already exists, which means the new mode check could have
written `?` and kept the cause; it wrote `.map_err(|_| InvalidDispatch)` and lost
it. The mechanism makes the lossy form the harder one to type.

Negative tests then assert
`matches!(err, StateMachineError::InvalidDispatch(DispatchRejection::ExecutionMode { .. }))`
and mean something. Packet 4's fuzz oracles assert which boundary refused.

**Registry.** `PortError` should carry `chio_errors::Code` and the five ad-hoc
`chio_security_types::ErrorCode` strings should be registered in `spec/` and
generated like the other 114. Two registries will drift; one cannot.

## Mechanism D, cross-cutting: the escape-hatch gate

Every type above needs at most one unchecked path, for tests, migration or storage
readback: `for_test`, `from_stored`, `into_raw_for_storage`, `get`. Today the
workspace has seven such functions in `core`, `security` and `kernel`
(`for_test` x2, `from_raw`, `from_trusted_selection`, `from_trusted_context`, and
two Kani `assume_*` helpers). That surface is small enough to enumerate.

A gate, shaped like the hygiene gate with its ratchet and self-test, lists the
allowed escape hatches by path and name and fails on a new one. The mechanisms
above convert "remember to call X" into "the compiler rejects, and the one escape
is greppable and reviewed."

## What this design does not cover, on purpose

- **OS boundaries.** Fork safety in `pre_exec`, seccomp argument constraints and
  Landlock rules are correct by careful construction and cannot be typed. The
  standard protects them with comments (rules 9.4, 9.5) and native probes
  (correction 2A). The pass 6 validation found the seccomp helper already rejects
  an unknown constraint key at launch, which is the right place for that check.
- **Gates and profiles.** Q1 (`include!` blind spot) and R1's profile half are
  tooling, not types. Packet 0 owns them.
- **Measurement.** P2 is a benchmark gap. No type fixes it.
- **Lock policy.** S1 is a decision about panic containment, applied uniformly.
  Packet 10.1 owns it and it is coupled to Packet 0.2.

## Migration order

Ordered by what unblocks what, then by blast radius.

1. **Mechanism C for the response path** (correction 1D). Prerequisite for testing
   A and B strongly. Also register the five ad-hoc port codes.
2. **Mechanism A for the five mode-check sites** (correction 1B), then for the four
   `Deserialize` hollow `Verified*` types in `chio-security-types` and
   `chio-core-types`, which are the forgeable-from-wire cases.
3. **Mechanism B, `Domain` enum** (correction 1E generalized). Zero behavior
   change, provably byte-identical, removes the eight duplicates and the
   placeholder in one commit.
4. **Mechanism B, `ExposureUnits`** (Packet 8). Money path; sequenced after
   Packet 0.2's `overflow-checks` backstop is in place.
5. **Mechanism B, `UntrustedJsonText`** (Packet 10.2), one boundary at a time,
   starting with the signed simulation report because it is new.
6. **Mechanism D gate** as soon as the first A/B type lands, so escape hatches are
   counted from the start.
7. **Remaining 14 TCB hollow `Verified*` types** as their modules are touched by
   Packet 7.

## Acceptance

- A `compile_fail` test per mechanism A type proving the literal does not compile
  and the operation does not accept the unverified form.
- A `try_from` rejection test per mechanism B type proving an invalid payload does
  not deserialize.
- Negative tests on the response path assert a `DispatchRejection` variant, and
  the mutation check from standard rule 10.2 confirms each fails for the named
  reason.
- The escape-hatch gate passes on its allowlist and fails on its violating
  fixture.
- Count of all-`pub` `Verified*`/`Authorized*` types in TCB crates: 18 today, 0 at
  exit. Count of all-`pub` types that also derive `Deserialize`: 4 today, 0 at
  exit.
- One error-code registry.
