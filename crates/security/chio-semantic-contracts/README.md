# chio-semantic-contracts

Portable, pure validation for bounded symbolic dependency graphs, explicit effect
contracts and semantic tool contracts. The crate defaults to `no_std + alloc` with an
additive `std` feature. Provider facts, authority authentication of live state,
materialization and execution belong to the owning deployment and kernel components.

- `validate_dependency_graph` orders at most 16 steps with at most 16 dependencies each,
  deterministically by readiness and then opaque step identifier. One shared,
  irreversible `chio_security_types::work::VerificationBudget` charges the bounded sort,
  every edge lookup, every indexed update and every ready-step search before the work
  runs. Missing dependencies, duplicate identities, cycles, unsafe cost arithmetic and
  exhaustion refuse. A validated graph is not a reviewed action or a permit.
- `EffectContractV1` permits one submission under the original native operation with
  automatic retries disabled and no provider deduplication assumed. Lookup finality and
  the 1 to 16 effect cardinality are explicit metadata the operator verifies.
- `compile_semantic_registry` binds a deployment signed by the operator root for the
  expected scope, packages signed by distinct publisher roots and the host's actual
  exposed tool manifest, within 16 packages, 16 operations and 16 tools.
- `verify_semantic_invocation` recomputes one invocation against those bindings and an
  explicit native observation: the signed audience, every selected annotator's answer
  for every input, endorsements of the exact action, transformation and prerequisite
  proofs bound to the dependent action's exact input versions, and freshness of every
  signed claim at the caller's instant. `verify_semantic_input_restrictions` performs
  the same checks except live native disclosure target acceptance.
- `validate_semantic_plan` orders at most 8 plan steps and requires every future input
  to come from a declared dependency.

Every refusal is an exact `ContractError`.
