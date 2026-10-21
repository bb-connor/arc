<p align="center">
  <picture>
    <source media="(max-width: 500px)" srcset="docs/assets/hero-mobile.svg" />
    <img src="docs/assets/hero.svg" alt="Chio: the kernel for tomorrow's computer. Research preview." width="900" />
  </picture>
</p>

<p align="center">
  A Rust kernel for agentic operating systems.<br>
  Build swarms. Exchange work. Keep control.
</p>

<p align="center">
  <a href="https://www.chio.computer/docs">Docs</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="https://www.chio.computer/whitepaper">Whitepaper</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="spec/PROTOCOL.md">Protocol</a>&nbsp;&nbsp;&middot;&nbsp;&nbsp;
  <a href="https://www.chio.computer/docs/reference/ietf-draft">IETF Draft</a>
</p>

<br>

An operating system sets the terms on which programs act: whose authority they carry,
what they can reach, and which resources they may use. Agents need those boundaries
wherever their work takes them.

An agent’s next move is chosen by a model, shaped by what it reads. A document, a message,
or a tool’s reply can change its course. Its work crosses machines and companies that no
single operator controls.

Chio puts a kernel at the point of action. An agent reaches its tools through calls the
kernel admits. Authority travels as a signed capability that can only narrow as it passes
from agent to agent. Budgets are reserved before dispatch. Decision models inside the kernel
evaluate each governed call before it runs. Every decision, allowed or refused, leaves a
signed receipt another company can verify for itself.

Independent kernels cooperate through treaties: signed agreements on what work they permit
and what evidence they require. Each side keeps its own kernel, keys, and policy.

Their agents can fix your next bug while yours review the patch. The fix merges with both
signatures, the history verifies offline, and one call revokes access. The permission can
end. The evidence remains.

<p align="center">
  <picture>
    <source media="(max-width: 500px)" srcset="docs/assets/kernel-boundary-mobile.svg" />
    <img src="docs/assets/kernel-boundary.svg" alt="Two swarms under two kernels: their swarm runs under their kernel, joined by a treaty over iroh to your kernel, and both kernels sign. Your swarm, each grant narrower than its parent, runs under your kernel: a trusted compute base of capabilities, delegation, guards, approvals, revocation, budgets, settlement, processes, keys, secrets, information flow and receipts around its decision models. Your kernel dispatches through the adapter, the one door into the sandbox, to files, commands and services, and signs each decision into a Merkle checkpoint. Below: supported harnesses and interfaces." width="900" />
  </picture>
</p>

```ts
import { Computer, USD, firstPassing } from "@chio-protocol/sdk";

const project = await Computer.open("quickstart");
const partners = await Computer.partners();   // every kernel you have paired with

// Each partner's agents get a fork, five dollars, and fifteen minutes.
// The forks are granted together, and every run works at the same time.
const runs = await Promise.all(partners.map(async (partner) => {
  const fork = await project.fork();
  const authority = fork.grant({
    to: partner,
    under: partner.treaty,
    resources: { "/workspace": ["read", "write"] },
    budget: USD(5),
    expiresIn: "15m",
  });
  return partner.exec("fix issue #417", { on: fork, authority });
}));

const winner = await firstPassing(runs, { check: "pytest" });   // the first fork whose tests pass
await project.apply(winner.changes);   // the merge happens under your authority

const evidence = await project.history.export("audit/");
await evidence.verify();   // every agent, call, and dollar
```

The same program in [Python and Rust](https://www.chio.computer/docs).

## Start building

```sh
curl -fsSL https://www.chio.computer/install.sh | sh
```

[Run a first request](https://www.chio.computer/docs/quickstart)&nbsp;&nbsp;&middot;&nbsp;&nbsp;[Embed the kernel](https://www.chio.computer/docs/deployment/in-process)&nbsp;&nbsp;&middot;&nbsp;&nbsp;[Delegate between agents](https://www.chio.computer/docs/guides/delegate-between-agents)&nbsp;&nbsp;&middot;&nbsp;&nbsp;[The long tour](docs/start-here/OVERVIEW.md)

Apache-2.0. See [LICENSE](LICENSE) and [CONTRIBUTING](CONTRIBUTING.md).
