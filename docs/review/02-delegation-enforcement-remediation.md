# Delegation Enforcement Remediation

## Problem

CHIO currently presents delegation attenuation, delegation-chain validity, and revocation completeness as runtime properties, but the kernel admission path does not actually enforce them as first-class acceptance conditions.

Today, the main tool-call path verifies:

- the leaf capability signature
- the leaf time bounds
- revocation for the leaf capability ID plus the capability IDs named in the presented `delegation_chain`
- subject binding
- scope matching for the requested action

The hot path does **not** currently require:

- full structural validation of the presented delegation chain
- runtime enforcement that each hop is a valid attenuation of its parent
- resolution of the actual parent capabilities referenced by the chain
- cryptographic binding between each delegation link and the concrete child capability being executed
- proof that the presented chain is complete rather than truncated
- revocation checks for delegation edges as first-class objects

That gap shows up directly in the code:

- `evaluate_tool_call` and the nested-flow bridge path do not call `validate_delegation_chain` or `validate_attenuation`; they only verify the leaf token and then proceed to scope/budget evaluation: `crates/arc-kernel/src/lib.rs:1865-1945` and `crates/arc-kernel/src/lib.rs:2134-2210`
- `validate_non_tool_capability` also omits chain validation and attenuation enforcement: `crates/arc-kernel/src/lib.rs:1814-1824`
- `check_revocation` only checks `cap.id` and the `link.capability_id` values present in the token: `crates/arc-kernel/src/lib.rs:2603-2617`
- observed capability lineage is persisted only after admission begins, not used as a prerequisite for admission: `crates/arc-kernel/src/lib.rs:3525-3536`

## Current Evidence

The repo is not empty here. There is meaningful groundwork:

- `ArcScope::is_subset_of` already defines semantic subset checks across tool, resource, and prompt grants: `crates/arc-core-types/src/capability.rs:141-162`
- `ToolGrant::is_subset_of` already checks operations, constraints, invocation caps, cost caps, and DPoP monotonicity: `crates/arc-core-types/src/capability.rs:931-1003`
- `validate_attenuation` already rejects child scopes that are not subsets of the parent: `crates/arc-core-types/src/capability.rs:1257-1268`
- `validate_delegation_chain` already checks signature validity, hop connectivity, timestamp monotonicity, and max depth: `crates/arc-core-types/src/capability.rs:1211-1255`
- there are unit tests for attenuation and structural chain validation: `crates/arc-core-types/src/capability.rs:1528-1630`
- the kernel has at least one descendant-revocation test: `crates/arc-kernel/src/lib.rs:6412-6447`
- the kernel and control plane can persist capability snapshots in the lineage index: `crates/arc-cli/src/issuance.rs:152-160`, `crates/arc-kernel/src/capability_lineage.rs:1-48`, `crates/arc-kernel/src/lib.rs:6450-6500`
- the spec explicitly claims attenuation, revocation completeness, and delegation-chain structural validity as launch-candidate safety properties: `spec/PROTOCOL.md:289-325`

The formal side is also suggestive but incomplete:

- the Lean model includes a simplified delegation-chain and revocation model: `formal/lean4/Pact/Pact/Core/Capability.lean:35-89`, `formal/lean4/Pact/Pact/Core/Revocation.lean:40-125`
- the release audit already narrows the honest proof boundary to executable alignment and empirical runtime behavior rather than whole-system theorem-prover closure: `docs/release/RELEASE_AUDIT.md:222-245`

## Why Claims Overreach

The current implementation overclaims for five reasons.

1. **The kernel does not enforce the helpers it advertises.**
   `validate_delegation_chain` and `validate_attenuation` exist, but the runtime admission path does not invoke them before allow/deny.

2. **Delegation links are not bound to the concrete child capability.**
   A `DelegationLink` carries `capability_id`, `delegator`, `delegatee`, `attenuations`, and `timestamp`, but not the child capability ID or a child-body hash: `crates/arc-core-types/src/capability.rs:1104-1166`. That means the link does not prove "this exact child token was derived from this exact parent token."

3. **The runtime does not resolve actual parent state.**
   The kernel never reconstructs the parent capability chain from the lineage index before authorizing execution. As a result, attenuation is not checked against the real parent scopes and time windows.

4. **Revocation completeness is only as good as the presented IDs.**
   If the runtime trusts a truncated or malformed `delegation_chain`, `check_revocation` only sees what the attacker presented. That is not true lineage-complete revocation.

5. **The trust model is not yet a true recursive delegation model.**
   `verify_capability_signature` currently trusts CA/kernel/authority keys, not an arbitrary parent subject chained back to a trusted root: `crates/arc-kernel/src/lib.rs:2576-2600`. In practice, this makes delegation look more like authority-mediated reissuance plus metadata than recursively validated authority transfer.

Until those gaps are closed, the strongest honest claim is: CHIO has delegation data structures, helper validators, and some lineage persistence, but not a fully enforced delegated-authority acceptance model in the runtime.

## Target End-State

The target state should be explicit and narrow enough to test:

- every non-root capability is admitted only if the kernel can resolve a **complete ancestry path** from the leaf capability to a trusted root
- every hop is **cryptographically bound** to the exact parent capability and exact child capability
- every hop is validated for **issuer/subject continuity**, **scope attenuation**, **expiry monotonicity**, and **structural integrity**
- revocation of **any ancestor capability** or **any delegation edge** in that ancestry causes the descendant capability to be denied
- missing lineage, missing snapshots, ambiguous ancestry, or unverifiable imported ancestry fail closed
- the same validation routine is used for tool calls, resource access, prompt access, and any other entry point that accepts capabilities

To make the public claims true, CHIO should commit to a real delegation semantics:

- **Recommended model:** the immediate parent subject signs the child capability, or signs a dedicated delegation proof that is bound to the child capability body; the kernel recursively validates that chain to a trusted root
- **Not recommended if the claims stay strong:** continuing to rely on centralized authority reissuance while describing the result as runtime-enforced recursive delegation

This memo assumes the recommended model.

## Required Runtime Changes

### 1. Introduce a single fail-closed lineage verifier in the kernel

Create one shared kernel routine, for example `validate_capability_lineage_and_scope(...)`, and make every capability-accepting entry point call it before any scope, budget, or governed-intent logic.

It should replace the current fragmented sequence in:

- `validate_non_tool_capability`: `crates/arc-kernel/src/lib.rs:1814-1824`
- `evaluate_tool_call`: `crates/arc-kernel/src/lib.rs:1850-1945`
- the nested-flow bridge path: `crates/arc-kernel/src/lib.rs:2128-2210`

That routine should return a `VerifiedCapabilityLineage` object that includes:

- leaf capability ID
- root capability ID
- ordered verified ancestor snapshots
- verified delegation edges
- matched grant set
- lineage hash or chain digest for receipts and audits

No later stage should re-parse raw delegation metadata from the request token.

### 2. Add explicit parent/child binding to the data model

The current `DelegationLink` is too weak. Extend the model so every delegation edge proves a concrete derivation event.

Required additions:

- add `parent_capability_id` to the child capability body if it is not root-issued
- add a stable `delegation_id` to each delegation edge so edges can be revoked directly
- extend the signed delegation payload to include at least:
  - `parent_capability_id`
  - `parent_capability_hash`
  - `child_capability_id`
  - `child_capability_hash` or child-body hash
  - `delegator`
  - `delegatee`
  - `issued_at`
  - the declared attenuation metadata

The child capability must then be rejected unless:

- `child.parent_capability_id == edge.parent_capability_id`
- `hash(parent_snapshot.body) == edge.parent_capability_hash`
- `hash(child.body) == edge.child_capability_hash`
- `parent.subject == edge.delegator`
- `child.subject == edge.delegatee`
- `child.issuer == parent.subject` or a parent-authorized delegation subkey

Without those bindings, the chain remains descriptive metadata rather than cryptographic lineage.

### 3. Resolve and require complete lineage at admission time

The kernel must stop trusting the presented `delegation_chain` as self-sufficient.

Admission should require the kernel to resolve every parent reference by one of:

- local capability-lineage snapshot store
- trusted imported evidence bundle
- trusted federation continuation artifact

If any referenced parent capability cannot be resolved, the request must fail closed.

Specific requirements:

- detect and reject missing ancestors
- detect and reject cycles
- detect and reject duplicate or conflicting parent bindings
- require the root capability to terminate at a trusted issuer anchor
- require every intermediate capability snapshot needed for recursive verification

The existing lineage index is the right place to start, but it must become an admission dependency rather than just an audit aid: `crates/arc-kernel/src/capability_lineage.rs:1-48`.

### 4. Enforce semantic attenuation hop by hop

For each parent/child pair in the resolved ancestry:

- call `validate_attenuation(parent.scope, child.scope)`
- separately check issuance and expiry monotonicity:
  - `parent.issued_at <= child.issued_at`
  - `child.expires_at <= parent.expires_at`
- check that DPoP requirements do not weaken across the hop
- check that tool/resource/prompt grants never widen across the hop
- check monetary caps and invocation limits never widen across the hop

`ArcScope::is_subset_of` and `ToolGrant::is_subset_of` already provide much of this semantics: `crates/arc-core-types/src/capability.rs:141-162`, `crates/arc-core-types/src/capability.rs:931-1003`. The missing work is to apply them to the real parent/child lineage during admission.

The `attenuations` vector should remain, but the runtime should treat it as an auditable explanation, not the source of truth. The source of truth is the semantic relation between parent and child capabilities.

If the project wants to claim that the declared attenuation list itself is truthful, add a canonical "scope diff" function and require it to match the declared attenuation set.

### 5. Make recursive issuer validation real

`verify_capability_signature` must evolve from "issuer key is in the trusted CA set" to "issuer authority is justified by the verified parent."

Recommended validation rule:

- root capability: issuer must be a trusted authority key
- delegated capability:
  - child signature must verify under `child.issuer`
  - `child.issuer` must equal the immediate parent subject or an explicit delegation subkey bound by the parent
  - the immediate parent must itself be valid and recursively anchored to a trusted root

This is the change that converts delegation from metadata into authority flow.

### 6. Extend revocation to both capabilities and delegation edges

Revocation completeness currently covers only capability IDs: `crates/arc-kernel/src/lib.rs:2603-2617`.

To make the claim true:

- extend the revocation store schema to support `RevocationTarget::CapabilityId` and `RevocationTarget::DelegationId`
- check revocation for:
  - the leaf capability
  - every resolved ancestor capability
  - every resolved delegation edge
- reject the capability if any one of those is revoked

This also enables an important operational distinction:

- revoke a parent capability to kill the whole subtree
- revoke a specific delegation edge to kill one branch while leaving the parent capability alive

### 7. Persist verified lineage at issuance, import, and evaluation boundaries

Observed lineage persistence after admission is useful but too late: `crates/arc-kernel/src/lib.rs:3525-3536`.

Required changes:

- persist capability snapshots at issuance time for all local issuance paths
- persist imported ancestry bundles before they can be used
- persist delegation-edge artifacts alongside capability snapshots
- store parent/child hashes and root capability IDs
- record the verified lineage digest into receipts so auditors can tell which exact ancestry the kernel accepted

The local CLI issuance path already records root snapshots: `crates/arc-cli/src/issuance.rs:152-160`. Build on that until every delegated issuance path and every federated continuation path does the same.

### 8. Add an explicit compatibility and migration mode

Already-issued tokens will not satisfy the stronger lineage contract.

Use a staged rollout:

- `legacy_delegation_mode`: current behavior, but docs and release notes must not claim runtime delegation enforcement
- `strict_lineage_mode`: requires complete ancestry and parent/child binding
- `strict_lineage_mode` becomes default only after validation gates are green

This keeps deployment realistic without pretending the old tokens satisfy the new claims.

## Spec/Proof Changes

### Spec changes

Update `spec/PROTOCOL.md` so Section 5.3 and Section 5.4 match the real runtime contract.

Add or tighten the following protocol requirements:

- a delegated capability must carry an explicit parent reference
- a delegation edge must bind exact parent and child artifacts
- runtime verification must resolve the full ancestry to a trusted root
- attenuation is checked against actual parent and child capabilities, not just declared metadata
- revocation completeness covers both ancestor capabilities and delegation edges
- missing lineage is a denial condition, not a best-effort audit limitation

Also split the current broad safety properties into narrower properties that can be individually tested:

- `P1` hop-by-hop scope attenuation
- `P2` lineage completeness
- `P3` ancestor and edge revocation completeness
- `P4` recursive issuer continuity to trusted root
- `P5` structural chain validity

### Proof changes

The current Lean model is too small for the public claim boundary: `formal/lean4/Pact/Pact/Core/Capability.lean:35-89`, `formal/lean4/Pact/Pact/Core/Revocation.lean:40-125`.

To support the stronger delegation claims:

- extend the Lean model with:
  - explicit parent references
  - child/parent binding hashes
  - recursive issuer continuity
  - edge revocation in addition to capability revocation
  - resource and prompt grants, not just the simplified tool subset
  - TTL monotonicity and DPoP monotonicity as delegation invariants
- prove that if the kernel accepts a delegated capability, then:
  - the ancestry is complete
  - every hop attenuates
  - every hop is cryptographically linked
  - no revoked ancestor or edge exists in the resolved chain

Do not restore broad "formally verified recursive delegation" language until the executable validator and the proof model cover the same surface.

### Executable proof boundary

Keep the proof story honest:

- Lean proves the abstract safety properties for the expanded delegated-capability model
- differential and integration tests prove the Rust implementation matches those properties on concrete cases
- release docs say "proved for the delegated-capability model and tested in the runtime," not "fully proved end to end"

## Validation Plan

### Unit tests

Add unit coverage for:

- parent/child binding validation
- missing-parent rejection
- wrong-parent rejection
- wrong-child-hash rejection
- cycle detection
- duplicate-ancestor detection
- edge-revocation rejection
- TTL widening rejection
- DPoP weakening rejection
- resource/prompt grant widening rejection

### Property tests

Generate random parent/child capability pairs and assert:

- generated attenuating children always validate
- any widened child is rejected
- any chain with a missing or permuted ancestor is rejected
- revoking any randomly chosen ancestor or edge denies the leaf

### Kernel integration tests

Add end-to-end runtime tests for:

- delegated tool calls accepted only when full lineage is present
- delegated resource/prompt flows share the same validator
- denial on missing lineage snapshots
- denial on malformed continuation bundles
- denial on revoked delegation edge
- denial on parent/child subject-issuer mismatch
- denial on child signed by a key not justified by the parent

### Migration tests

Add explicit tests that:

- legacy tokens still work only in compatibility mode
- the same tokens fail in strict lineage mode with precise denial reasons
- mixed fleets do not silently downgrade strict-mode verification

### Proof and spec tests

- add executable fixtures for canonical parent/child chains
- add diff tests between the Rust validator and the formal model for the delegated-capability subset
- gate release claims on the strict-lineage test suite, not just helper-function tests

## Milestones

### Milestone 1: Model decision and schema hardening

- choose the delegation semantics and document it
- add parent references and delegation-edge IDs/hashes to the core types
- add revocation-target support for delegation edges
- add a feature flag for strict lineage mode

### Milestone 2: Issuance and persistence closure

- update issuance paths to emit the stronger delegation artifacts
- persist capability snapshots and delegation edges at issuance/import time
- ensure federated continuation writes enough data for recursive verification

### Milestone 3: Kernel admission rewrite

- build the shared lineage validator
- make all capability entry points call it
- enforce full ancestry resolution, attenuation, issuer continuity, and revocation checks
- emit receipts that carry verified lineage digests

### Milestone 4: Test and proof closure

- add unit, property, and integration tests
- expand the formal model
- add executable diff fixtures for delegated chains
- narrow docs until the new gates pass

### Milestone 5: Rollout and claim unlock

- turn on strict lineage mode in CI and qualification
- migrate local/control-plane issuance
- deprecate legacy mode
- only then restore strong delegation-chain claims in README and protocol positioning

## Acceptance Criteria

- every capability-accepting kernel entry point uses one shared strict-lineage validator
- a delegated capability is denied if any ancestor capability is missing, unverifiable, revoked, or inconsistent with the child
- a delegated capability is denied if any delegation edge is missing, unverifiable, revoked, or inconsistent with the child
- a child capability is denied if it widens scope, time bounds, DPoP requirements, invocation caps, or monetary caps relative to its immediate parent
- the kernel can produce a verified lineage digest and root capability ID for every admitted delegated capability
- strict-lineage integration tests cover tool, resource, and prompt flows
- spec text matches the runtime behavior exactly
- public docs do not claim runtime-enforced recursive delegation until strict-lineage mode is the release-gated default

## Risks/Non-Goals

- This remediation does **not** solve cluster-wide revocation propagation or HA consistency by itself. It fixes local runtime truth; distributed consistency remains a separate hole.
- This remediation does **not** make the economic "cost-responsibility chain" claims true on its own. It only makes the authorization lineage honest enough to support later economic reasoning.
- Recursive delegation requires real key custody and possibly delegation subkeys for agents. That increases operational complexity.
- Existing tokens and imported artifacts may need migration or compatibility shims.
- This memo does **not** require full Rust-to-Lean refinement proof before shipping. It does require that the claims be narrowed until the proof and executable validators cover the same delegated-capability surface.
