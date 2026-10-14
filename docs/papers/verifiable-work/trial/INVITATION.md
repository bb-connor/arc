# Draft invitation for an independent implementation partner

This draft is prepared for the project owner to adapt and send. No invitation
has been sent, no partner is enrolled, and no funding or schedule is promised.

We are testing a public contract for exchanging checked work between separately
operated agent systems. The concrete question is whether independent providers
can change partners with less new integration work while preserving equivalent
authority, acceptance and payment guarantees. Existing escrow, ERC-8183 and
ordinary application protocols are allowed to match or outperform Chio.

We are looking for an organization willing to implement a provider from a frozen
profile and conformance vectors, using its own language, infrastructure, keys
and decisions. Public cryptographic libraries are fine; copying the reference
application logic would not test implementation independence. We would record
every specification question, source change and assistance session.

The first stage uses development funds and a deliberately simple, reproducible
OpenAPI-declaration task. It tests compatibility and failure recovery, including
an accepted child collecting after its parent fails. It is not a commercial
benchmark. A later, separately agreed stage uses held-out useful source-repair
tasks, a matched ordinary baseline, complete cost accounting and published
uncertainty. The full design needs three core work operators, a newcomer, two
independent provider implementations and an independent acceptance verifier.

You would receive the [operator handoff](README.md), exact wire profiles,
positive and malformed vectors, source and dependency pins, transition traces,
a matched baseline, and [prospective recording templates](manifest.template.json).
You would retain control of your deployment and credentials. The Chio team
would not need administrative access to your host or the power to sign for you.

Before starting, we would agree on the role, implementation scope, actual
prerequisites, time and compute budget, permitted data, public versus restricted
evidence, attribution and stopping conditions. Stage F involving real funds is
outside this initial invitation and needs its own operator decisions.

A useful result can be a successful exchange, a concrete protocol defect, an
unreasonable integration burden, or an ordinary composition that works just
as well. The trial will retain those outcomes and will not require a favorable
conclusion as a condition of participation.
