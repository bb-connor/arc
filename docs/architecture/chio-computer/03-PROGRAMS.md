# C3: Portable programs and executable composition

Status: proposed contract, revision 2. Parent: [Computer proposal](PROPOSAL.md).

## Purpose and owner

The program compiler describes and validates work using the completed W1/D1/S1
contracts. Actual allocation, selection, sealing, graph extension, dispatch,
acceptance and recovery remain with their existing owners. SDK syntax is input
to authoritative validation, not a trusted plan execution shortcut.

## Proposed representation

Abbreviated design notation, not compiling Rust or an allocated wire version:

```rust
enum ProgramExpr {
    Leaf(ProgramRef),
    Parallel(Vec<ProgramExpr>),
    Sequence(Vec<ProgramExpr>),
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

## Composition semantics

| Expression | Initial qualified semantics |
| --- | --- |
| `a \| b` | Same immutable input/base, distinct invocation occurrences and independent writable branches; ordered/named accepted outputs. |
| `a >> b` | A dependent commitment consuming the exact accepted output of `a` through authorized input release and schema/dependency checks. |
| `(a \| b) >> c` | An all-success join with a protected exact parent-input manifest; `c` performs any actual integration. |
| `a \| a` | Two distinct invocation occurrences, even when the bundle and input hashes match. |
| Failed required stage | Dependent stages do not commit; the admitted failure policy requests bounded sibling cancellation and drains existing effects through their owners. |

Operator evaluation has no filesystem, network, process or model effects. Enforce
bounded expression size/depth before recursive normalization; flatten only
where associativity preserves node identities, order, schema and observable
semantics. The supported initial join is the work design's all-success predicate.
Races, quorum, streams and reactive edges require separate qualified contracts.

In the hero, `challenge` runs alongside `prototype`, so it sees the original
input and challenges the starting assumptions. Reviewing the produced prototype
requires a dependency such as `prototype >> challenge`.

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
- **PRG-05:** artifact labels and influence join across admitted input flows;
  current predicates/reservations are rechecked at dependent commitment using
  REC's HistoricalFact, CurrentPredicate and HeldReservation vocabulary.
- **PRG-06:** cancellation, stop, graph closure and process closure are enforced
  by existing owners at their commitment fences, including dynamic descendants.
- **PRG-07:** compiler outputs remain untrusted checked descriptions. A forged
  plan must still be refused by the serving owners.

Acceptance: **C3-01 through C3-07** in [ACCEPTANCE.md](ACCEPTANCE.md).
