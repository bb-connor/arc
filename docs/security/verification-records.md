# Verification results and records

In-process evidence has private fields and no deserializer. A wire record can
describe a decision, but decoding it cannot recreate the evidence that admitted
that decision. This distinction applies at the consuming boundary, not just to
the name of a struct.

| Type | Classification | Owning check / consumer |
| --- | --- | --- |
| `VerifiedCapability` | Sealed verifier result | `chio-kernel-core::capability_verify`; issuer, signature and time checks. Scope/request, revocation and stateful admission remain separate checks. |
| `VerifiedPassport` | Sealed verifier result | `chio-kernel-core::passport_verify`; envelope, trusted issuer, signature and validity checks. |
| `VerifiedActiveResponseOperatorCapability` | Sealed admission result | Governed active-response admission; request capability verification and durable admission run before construction. |
| `ReceiptReadContext` | Sealed adapter-issued read context | Trusted service/local adapter selects a constructor after authentication; no request deserializer or writable authority fields. This is an explicit composition contract, not an independently signed credential. |
| `SupplementalQuotaVerificationRecord` | Trusted-port record | The installed supplemental verifier returns it directly to the kernel, which rechecks bindings and constructs private `KernelVerifiedSupplementalQuotaClaim`. |
| `SecurityEventVerificationRecord` | Trusted-port / durable projection | `VerifiedSecurityEventIngress` calls its installed `SecurityEventVerifierPort` before store admission. Native verification checks tenant/producer trust, canonical body, signature and time. Persisted recovery is store-owned. |
| `IsolationVerificationRecord` | Trusted-port record | Flow-state rotation invokes the installed isolation verifier. Request callers do not supply its result as proof. |
| `ApprovalSetBody` | Serializable signed artifact body | Kernel approval verification checks members, signatures and bindings before constructing private admission/reservation evidence. |
| `BudgetHoldAuthorizationRecord` | Budget-store decision record | Only the immediate result of the installed store's authorize-hold operation reaches kernel budget admission. |
| `CapabilityVerificationJson` / mobile `CapabilityVerificationRecord` | Browser / FFI projection | Output serialization of the sealed portable result. There is no conversion back to `VerifiedCapability`. |

The old record names were removed from source APIs without aliases. Existing
wire fields retain their meaning; no new input path trusts their names.

The source gate pins the sealed declarations and the migrated input owners.
Compile-fail doctests enforce unavailable serde implementations. Neither this
inventory nor a private field proves that every verifier in the workspace is
correct; the owning negative tests still establish the checks performed before
construction.
