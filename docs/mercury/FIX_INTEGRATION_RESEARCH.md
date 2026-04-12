# MERCURY FIX Integration Research

**Date:** 2026-04-02  
**Audience:** Engineering, product, and integration leads

---

## 1. Executive Conclusion

FIX matters for MERCURY because many production trading workflows terminate in
FIX-speaking systems, but FIX should be treated as a focused production
integration program after the evidence platform proves value.

Recommended position:

- do not build a homegrown FIX engine
- do not require FIX for the first pilot
- adopt one production FIX path only when a buyer funds it

---

## 2. Integration Modes

### Mode A: mirrored or drop-copy evidence

MERCURY consumes mirrored workflow or execution events and produces evidence
without sitting in the live path.

Best for:

- initial pilots
- post-trade investigation support
- low-friction deployment

### Mode B: supervised routed integration

MERCURY receives a production workflow event and records evidence while an
existing OMS or gateway remains primary for live routing.

Best for:

- funded production deployment with controlled scope

### Mode C: mediated in-line FIX path

MERCURY participates directly in live authorization before a FIX message is
dispatched.

Best for:

- selected workflows with explicit operational ownership

This mode carries the highest resiliency and credential-custody burden and
should be started only with a clear business case.

---

## 3. Architecture Recommendation

For a production FIX path, prefer:

- an adopted FIX engine or gateway
- clear separation between evidence logic and session-management logic
- retention of raw FIX-side identifiers for reconciliation

MERCURY should focus on:

- evidence capture
- source-identifier retention
- publication and verification

It should not try to turn itself into a general-purpose FIX engine.

---

## 4. Required Evidence for a FIX Path

At minimum, a production FIX integration should retain:

- workflow intent ID
- order or route identifier
- broker / session identifiers
- execution or fill identifiers
- referenced raw or normalized FIX event artifacts
- mapping from workflow action to downstream FIX lifecycle events

Without that reconciliation layer, a FIX integration adds complexity without
delivering enough investigation value.

---

## 5. Security and Operations Considerations

Important design constraints:

- FIX credentials must not be exposed to workflow actors
- downstream session ownership must be explicit
- fail-open versus fail-closed behavior must be decided before go-live
- raw identifiers and mirrored events must be retained for reconstruction
- latency budgets must be stated honestly for any in-line design

---

## 6. Commercial Implication

A production FIX path should be built only when:

- a pilot has proven evidence value
- a buyer funds the integration
- the workflow is narrow enough to own operationally

That sequencing keeps the evidence platform from being consumed by a premature
connectivity program.

---

## Summary

FIX is an important expansion path, but MERCURY wins by being a strong evidence
platform first and a selective production integration platform second.
