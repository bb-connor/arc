# Strategy Options

## The Core Decision

There are three realistic ways ARC can evolve from here.

## Option A: Clean-slate replacement

ARC defines its own native wire protocol and asks the ecosystem to move to it.

### Pros

- architecturally pure
- can optimize everything around capabilities and receipts
- fewer compromises from MCP history

### Cons

- worst adoption path
- duplicates the entire MCP server and client ecosystem
- makes every integration team choose between compatibility and security
- likely slows `v1` by forcing protocol and ecosystem creation at the same time

### Verdict

Do not choose this as the primary strategy.

It may remain the long-term native protocol form, but it is a bad go-to-market plan.

## Option B: MCP-compatible edge, ARC-native core

ARC presents an MCP-compatible session surface externally, while internally enforcing:

- capabilities
- guard pipelines
- signed manifests
- signed receipts
- stronger trust and authorization

### Pros

- best migration path
- easiest way to prove value quickly
- lets existing MCP tools keep working
- makes ARC an additive security and governance layer, not a total rewrite demand

### Cons

- protocol translation complexity
- some MCP concepts map awkwardly onto ARC's stronger trust model
- may require a larger compatibility matrix and conformance suite

### Verdict

This is the strongest primary strategy.

It lets ARC replace MCP operationally before it replaces it culturally.

## Option C: Security runtime beneath MCP, without trying to own the whole protocol

ARC becomes mainly:

- a secure execution kernel
- a guard engine
- a receipt and trust layer

The outer session contract stays MCP indefinitely.

### Pros

- easiest short-term adoption
- clear product value
- lower protocol governance burden

### Cons

- ARC never really becomes the replacement standard
- the project stays dependent on MCP's evolution
- ARC-native ideas may always be constrained by another protocol's shape

### Verdict

This is viable as an interim phase, but too small as the final ambition if the goal is replacement.

## Recommended Direction

Choose Option B:

- MCP-compatible edge
- ARC-native security core
- optional ARC-native extensions where MCP has no equivalent

This gives the project a staged path:

1. Replace MCP deployments operationally.
2. Prove stronger security and governance.
3. Introduce ARC-native capabilities that clients adopt because they are better, not because they are mandatory.

## What This Means in Practice

### External contract

Expose:

- JSON-RPC session semantics
- MCP-compatible lifecycle
- MCP server and client feature coverage

### Internal contract

Enforce:

- capability issuance and attenuation
- kernel mediation
- signed receipts
- server manifests
- policy guards

### ARC-native extensions

Add:

- capability-bound tool exposure
- receipt retrieval and verification APIs
- stronger denial and evidence structures
- step-up authorization based on explicit capability grants

## Design Rule

Anything required for compatibility should be available at the edge.

Anything required for trust should be implemented at the core.
