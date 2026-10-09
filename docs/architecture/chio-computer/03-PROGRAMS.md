# C3: Portable programs and executable composition

Status: proposed contract, revision 4. Parent: [Computer proposal](PROPOSAL.md).

## Purpose and owner

The program compiler describes and validates work using the completed W1/D1/S1
contracts. Actual allocation, selection, sealing, graph extension, dispatch,
acceptance and recovery remain with their existing owners. SDK syntax is input
to authoritative validation, not a trusted plan execution shortcut.

## Proposed representation

Abbreviated design notation, not compiling Rust or an allocated wire version:

```rust
enum ProgramExpr {
    Leaf(LeafRef),
    Parallel(Vec<ProgramExpr>),
    Sequence(Vec<ProgramExpr>),
}

enum LeafRef {
    Program(ProgramRef),
    Task(TaskRef),
}

struct TaskRef {
    contract: ContentRef,
    input_schema: SchemaRef,
    output_schema: SchemaRef,
    acceptance: AcceptanceRef,
    harness_requirements: HarnessRequirements,
}

struct ProgramRef {
    bundle: ContentRef,
    entrypoint: EntrypointId,
    input_schema: SchemaRef,
    output_schema: SchemaRef,
    requirements: ResourceRequirements,
}

enum Executable {
    Computer(ComputerImageRef),
    Program(ProgramExpr),
}
```

ProgramBundle pins code, dependencies, entrypoint, ABI, schema, host requirements
and permitted resource requirements. References do not resolve mutable package
tags during launch or recovery. Descriptor inspection must not execute untrusted
package initialization on the owner's host. Images do not serialize arbitrary
closures with pickle/cloudpickle or migrate live language stacks.

The concrete bundle format is a profile choice, including a supported container
payload where appropriate. Content identity is separate from approved bootstrap
trust, recipient permission, compatible host enforcement and code admission.

## Leaf kinds

Both kinds ship from day one (roadmap decision D22). They share composition,
acceptance and recovery. They differ in whose code runs.

| Kind | Whose code runs | Receiver obligation |
| --- | --- | --- |
| TaskLeaf | The receiver's own admitted harness performs a contract. Examples are the receiver's Claude Code or Codex in its HOST-M2 tree. | Bind the task to one of the receiver's admitted harness profiles that satisfies `harness_requirements`. If none does, refuse with a typed error. The source never names a receiver harness binary, and it never forces one. |
| ProgramLeaf | The source's pinned bundle | Admit the bundle as code, and run it only under a qualified KSPEC-07 confinement kind. Without one, refuse before any transfer or materialization. |

**Rules for both kinds.**

- The acceptance procedure belongs to the work owner. Neither leaf kind can
  edit its own verifier.
- Classify each effect at its actual enforcement point under ADR-0011 and
  HOST-CONTRACT. `prevent` requires a qualified decision path before that
  effect; hooks that observe afterward are `detect_only`, and unmediated
  activity is `cannot_see`, including inside a confined process. Confinement
  evidence separately establishes the qualified isolation restrictions.
  Ordinary writes allowed inside a sandbox do not acquire individual Chio
  authorization or receipts. Missing confinement evidence means "unconfined"
  for that isolation claim, without changing a separately mediated call's class.

## Composition semantics

| Expression | Initial qualified semantics |
| --- | --- |
| `a & b` | Same immutable input/base, distinct invocation occurrences and independent writable branches; ordered/named accepted outputs. |
| `a \| b` | A dependent commitment consuming the exact accepted output of `a` through authorized input release and schema/dependency checks. |
| `a & b \| c` | An all-success join with a protected exact parent-input manifest; `c` performs any actual integration. |
| `a & a` | Two distinct invocation occurrences, even when the bundle and input hashes match. |
| Failed required stage | Dependent stages do not commit; the admitted failure policy requests bounded sibling cancellation and drains existing effects through their owners. |

**Syntax (roadmap decision D23).** `&` is parallel and `|` is sequence. Python
and Rust bind `&` more tightly than `|`, so `a & b & c | d | e` parses as
`((a & b & c) | d) | e` with no parentheses.

The canonical form is `parallel(a, b, c).pipe(d).pipe(e)`. TypeScript and every
language without operator overloading use it. Operators are sugar over that
form, and every language produces the same canonical description (PRG-01).

Operator evaluation has no filesystem, network, process or model effects. Enforce
bounded expression size/depth before recursive normalization; flatten only
where associativity preserves node identities, order, schema and observable
semantics. The supported initial join is the work design's all-success predicate.
Races, quorum, streams and reactive edges require separate qualified contracts.

In the hero, `challenge` runs alongside `prototype`, so it sees the original
input and challenges the starting assumptions. Reviewing the produced prototype
requires a dependency such as `prototype | challenge`.

`integrate` consumes the admitted result manifest and produces a revision in its
own branch. The owner fences writers and freezes that exact result. `verify`
uses the configured protected evaluator/procedure, reading the frozen revision
without permission to rewrite the result or its check bundle. Its acceptance
refers to that revision; it does not replace the workspace with a verifier log.
Producer success and evaluator acceptance remain different observations.

## Compilation and native preparation

1. Resolve bounded descriptors and compatible approved work/host profiles.
2. Normalize syntax and bind revision/input/resource generations.
3. Assign per-occurrence IDs from the retained execution request and canonical
   occurrence path. Duplicate retry uses the same IDs; a new invocation does not.
4. Check schemas, dataflow, resource subsets, required acceptance and supported
   joins; derive an exact canonical description and digest.
5. Use existing work preparation for allocations, receiver offers and selections.
   Preserve its required ordering through seal, graph/treaty context, exact
   invocation custody, agreement, funding where applicable, and submit.
6. Revalidate at owning commitments. Pure preflight cannot replace current
   predicates, held reservations, or final native admission.

The compiler must preserve separate digest domains for programs, process/native
request bindings, approval/flow material, graph evidence and funded agreements.
Do not insert an agreement digest into the request whose bytes it signs. Use
protected exact invocation custody; no clonable public plan contains an
unrestricted ToolCallRequest with credentials and single-use approvals.

## Dynamic participation

Running programs may request additional work from approved visible catalogs
within their admitted policy, resource/depth/count limits and current treaty.
The receiver prepares its own offer/local capability. D1 allocates/selects/seals
the work; S1 qualifies an additive graph extension and consumes the appropriate
continuation under its graph-head compare-and-swap rule.

Neither the application nor this compiler appends to an already signed graph,
chooses an arbitrary signer, enrolls a discovered URL, or mints a join receipt
from an unverified success claim. Catalog visibility does not grant execution.
The preserved graph contract determines which extension is admissible.

Static program structure, dynamic work graphs and receiver-local process trees
are different records connected by exact bindings. Ordinary delegated children
retain the appropriate authority/observation ancestry. A REC P5 observation
boundary is a separate admitted operation.

## Preservation laws

- **PRG-01:** canonical Rust/Python/TypeScript descriptions agree; both exec
  forms use equivalent binding/admission when their inputs match.
- **PRG-02:** no widened rights, reset limits, hidden uncharged model path, or
  bypass of native checks is introduced by lowering or dynamic graph growth.
- **PRG-03:** unique occurrences and original retry identities remain distinct;
  code equality cannot deduplicate effectful work.
- **PRG-04:** exact producer/contract/evaluator/artifact bindings precede joins;
  signature validity alone does not establish parent acceptance.
- **PRG-05:** REC's label and influence joins apply at every dependent
  commitment, together with its HistoricalFact, CurrentPredicate and
  HeldReservation rules. Computer adds that every compiled join carries the
  exact parent-input manifest those rules evaluate.
- **PRG-06:** the [qualified owner profile](ROADMAP-CROSSWALK.md#qualification-profiles)
  supplies KSPEC-04 closure and KSPEC-08 stop fences. Computer-0 requires
  KSPEC-04 phases 1 to 3 and KSPEC-08 phases 0 and 1.
  Computer adds that dynamic descendants admitted through S1 belong to the
  closure membership that C5 counts.
- **PRG-08:** a TaskLeaf binds only to a receiver-admitted harness profile,
  and a ProgramLeaf runs only under receiver code admission and a qualified
  KSPEC-07 confinement kind. Neither binding can be supplied by the source.
- **PRG-07:** compiler outputs remain untrusted checked descriptions. A forged
  plan must still be refused by the serving owners.

Acceptance: **C3-01 through C3-11** in [ACCEPTANCE.md](ACCEPTANCE.md).
