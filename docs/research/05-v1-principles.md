# V1 Principles

## 1. Compatibility at the edge, stronger guarantees underneath

PACT should meet the ecosystem where it is.

That means:

- speak the protocol shape people can already integrate with
- enforce a stricter internal model than the one the edge exposes

If the project chooses purity over adoption too early, it loses leverage.

## 2. Security invariants must stay central

Do not trade away the reason PACT exists.

The following should remain non-negotiable:

- no ambient authority
- mediation before execution
- fail-closed evaluation
- receipts for all decisions
- explicit delegation and revocation

## 3. Session auth and action auth are separate concerns

PACT needs both:

- transport/session authentication
- action-level capability authorization

These should not be collapsed into one mechanism.

## 4. Human control must survive nested flows

Sampling and elicitation must be designed so that:

- users can review high-risk requests
- clients remain in control of model credentials
- tools and servers cannot silently escalate privilege through callbacks

This is one of the hardest design areas and should be treated as core architecture, not a late add-on.

## 5. Resources and prompts are first-class, not secondary

MCP's primitives encode different control models:

- prompts are user-controlled
- resources are application-controlled
- tools are model-controlled

PACT needs equally first-class representations for all three. If everything gets flattened into "tool call," the protocol will be less expressive and less usable than MCP.

## 6. One policy language

The `v1` line should not ship with competing policy paths.

Pick one canonical policy model, likely HushSpec plus PACT compilation, and make it the runtime truth.

## 7. Remote trust must be real

`v1` should include:

- persistent receipts
- revocation propagation
- remote transport auth
- key lifecycle and trust bootstrap
- identity binding for tool servers

Otherwise "cryptographic protocol" stays mostly local theater.

## 8. Evidence matters as much as enforcement

PACT's differentiator is not only blocking.

It is producing verifiable evidence about:

- what was asked
- what was allowed or denied
- under what authority
- under which policy hash

The product should treat receipt retrieval, verification, and operator visibility as primary surfaces.

## 9. Formalism should target invariants, not marketing

Formal verification is valuable when it proves important invariants:

- attenuation monotonicity
- revocation completeness
- receipt integrity
- fail-closed behavior

It is less valuable when it is used as broad positioning without coverage of the operational system around the core.

## 10. Adoption tooling is part of the protocol strategy

`v1` should include:

- compatibility test suites
- migration adapters
- example servers and clients
- SDKs or generated schema bindings
- operator documentation

If those are missing, the protocol remains intellectually interesting and operationally expensive.
