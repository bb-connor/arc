# Chio M1 - Phase-0 Launch Readiness Bundle

Branch: `chio/m1-launch` (off `chio/m0-pass-build`). This is the M1-26 launch-readiness
evidence assembly: the fail-closed go/no-go record over the spec Section 8.3 gates 1-7 plus
the program gates. Companion to `docs/brainstorm/CHIO-M1-LAUNCH-SPEC.md` (the 26-task spec).

## 0. Verdict

The M1 launch-critical SOFTWARE is complete, independently code-reviewed, fixed, and green on
every engineering gate. The remaining open items are NOT software: two legal sign-offs, their
two gated config/prose deliverables, and the founder go/no-go. M1 is launch-ready pending those.

## 1. Task ledger (M1-1 .. M1-26)

Legend: DONE (committed + verified) | OPEN-LEGAL (blocked on counsel) | OPEN-FOUNDER (board/sign-off).

| Task | Kind | Status | Evidence |
|------|------|--------|----------|
| M1-1 Pin ChioPassConfig | decision/code | DONE | `f23ccd031` m1_launch_default, fail-closed validate |
| M1-2 Swarm model | decision | DONE | glm-5.2 chosen; fleet wedged at TUI-submit, cleanup completed via Claude per founder relax |
| M1-3 Gate-6 round-trip at M1 | decision | DONE | shipped (M1-20); proof panel + cadence deferred to M2 |
| M1-4 Marketplace cut | decision | DONE | primary posted-price + escrow + live selection |
| M1-5 RG-MTMEMO | legal | OPEN-LEGAL | outside counsel 50-state MTL/MSB + FinCEN CVC + GENIUS memo |
| M1-6 RG-NONCUSTODY | legal | OPEN-LEGAL | protocol-security non-custody key-surface demonstration |
| M1-7 DO-NOT-WEAKEN suite | code | DONE | `fbf24e41f` 11 regression tests, all invariants already enforced |
| M1-8 Digest baseline keystone | evidence | DONE | `7264f4e92` baseline `3931b972f`, gate runs green |
| M1-9 Comptroller namespace isolation | code | DONE | `1f79644c2` freetier:global excluded both directions (Gate 7 code gap) |
| M1-10 Kernel pool suite + Gate 1 | evidence | DONE | `add237b7d` 8 tests incl pool-exhaustion fail-closed |
| M1-11 Pass CLI entrypoint | code | DONE | `7aeb4331d` chio pass issue/refresh/anchor, deterministic mint |
| M1-12 E2e Gates 2 and 5 | evidence | DONE | `85ad3d0c4` issue->charge->rollover + dormant |
| M1-13 Own-data DisclosureLineageBundle | code | DONE | `92d4cfbbd` C2 over the 3-key strip |
| M1-14 Five-stream gift + Gate 4 | evidence | DONE | `4ffa5f2e3` byte-identical tiers + cross-tenant denial via the single shared `validate_reputation_import` gate, reached from both the eligibility and the verifier entrypoints (no parallel admission path) |
| M1-15 Escrow-wire accept() | code | DONE | `9ba2a35a1` + review hardening `3d84864f9` (offer-token auth) |
| M1-16 Pass eligibility + selection | code | DONE | `04d32117c` + review fix `45e8d7533` (saturation) |
| M1-17 RR2-TM-01 authority keys | config | DONE | `26bf0ba9c` pinned key set + rotation seam. The registry is provenance, not a runtime lookup: the shipped verifier trusts policy-and-bundle intersection and the CLI trusts env/policy keys, so a rotation takes effect by regenerating those key sets from the active epoch and redeploying (no runtime epoch switch). |
| M1-18 Order-passport replay | evidence | DONE | `dff290d86` escrow digest pinned, tamper-evident |
| M1-19 PASS-NAMING copy-lint + free-tier copy | docs | DONE | `f11113ce5` no-future-value recital |
| M1-20 Gate-6 anchor round-trip | evidence | DONE | `43b3c59f6` mock ChioRootRegistry publish + verify |
| M1-21 Cleanup swarm (13 economy crates) | infra | DONE | docs(<crate>) merges, comment-only, digest-clean (Claude per founder relax after glm-5.2 fleet TUI wedge) |
| M1-22 Contract-surface config | config | OPEN-LEGAL | gated by M1-5 + M1-6; stablecoin-feeds-only, advisory allowlist |
| M1-23 Regulatory prose (flat-vs-bps) | docs | OPEN-LEGAL | gated by M1-5 |
| M1-24 Re-verify DO-NOT-WEAKEN post-swarm | evidence | DONE | suite green post-cleanup |
| M1-25 Final launch-acceptance digest-diff | evidence | DONE | digest gate green + fmt + clippy --workspace + test delta == baseline |
| M1-26 Launch-readiness sign-off | decision | OPEN-FOUNDER | this bundle; board go/no-go |

## 2. Launch-readiness gates (spec 8.3 gates 1-7 + program gates)

- Gate 1 aggregate-pool-denies-fail-closed: SATISFIED (M1-10; 4th distinct-subject XCC denies cost_charged==0, committed==POOL).
- Gate 2 re-mint-reset-closed: SATISFIED (M1-12; one-row accumulation, monthly roll, B7 rejection).
- Gate 3 soulbinding-holds: SATISFIED (M0; holder-binding + non-Ed25519 rejection).
- Gate 4 five-stream parity + own-data-never-tier-gated + cross-tenant denied: SATISFIED (M1-13/14; one shared reputation-import gate serves both entrypoints, so there is no divergent path, not two independent guards).
- Gate 5 dormant-stops-drawing: SATISFIED (M1-12; dormant denies, 5 baseline reads still serve).
- Gate 6 anchoring round-trip read-only: SATISFIED (M1-20; mock publishRoot + verifyInclusionDetailed, no value transfer).
- Gate 7 namespace-isolation + copy: SATISFIED (M1-9 code gap closed both directions; M1-19 copy). Sealed proof-room panel deferred to M2.
- Program G9 escrow-wire replay: SATISFIED (M1-15/18; order-passport replay with escrow digest pinned).
- Program G8/G10 launch-acceptance digest-diff clean: SATISFIED (M1-25; digest gate green vs M0 baseline, one-liner green).
- Program RG-NONCUSTODY: OPEN-LEGAL (M1-6).
- Program RG-MTMEMO + stablecoin-feeds-only: OPEN-LEGAL (M1-5/22).
- Build green one-liner: SATISFIED (fmt --all + clippy --workspace -D warnings green; build green; test --workspace zero regressions vs baseline).

## 3. Engineering evidence

- Digest gate (`cargo xtask verify launch-acceptance` + proof-room release-truth + transaction-passport): GREEN, re-run at every signed-body merge (M1-9, M1-13, M1-15, M1-21 docs, the review fixes). Zero canonical-JSON digest drift vs the committed baseline `3931b972f`.
- DO-NOT-WEAKEN invariants: intact (no-CHIO pin, premium 3-letter-uppercase validator, chio-credit netting/capital flags false, chio-web3-bindings ABI byte-identical). Re-verified post-cleanup and post-fix.
- `test --workspace`: the 72 failing tests are PRE-EXISTING fixture/branch drift (identical set on the pre-M1 baseline); M1 introduced ZERO regressions and added the full Pass/marketplace/escrow/review coverage on top.
- Immutable four value contracts (ChioRootRegistry, ChioEscrow, ChioBondVault, ChioPriceResolver) byte-unchanged; ChioIdentityRegistry admin = multisig+timelock.

## 4. Code review and fix wave (post-build)

An adversarial multi-dimension review of the full M1 delta raised 16 findings; adversarial
verification confirmed 9 real (0 critical, 2 high, 2 medium, 5 low). All 9 fixed, merged, and
re-verified digest-clean:
- ESCROW-1 (high): `accept()` now authenticates the offer token (verify_signature + window + counterparty-distinct issuer) before deriving custodial liability. Residual full issuer-to-merchant-key binding documented as deferred (needs a wire-format change).
- C1 (med): locked amount now bound to the signed quote (`liability.units == quote_amount_minor`).
- C3 (low): tier projection saturation removed via u128 widening.
- F3 (low): `# Errors` doc accuracy.
- TC-1/2/3/4/5: fail-closed deny-branch test coverage added across escrow accept/release/liability/dispatch.

## 5. Open blockers (the ONLY things between here and launch)

1. M1-5 RG-MTMEMO - outside fintech counsel memo (50-state MTL/MSB + FinCEN 2019 CVC non-custodial-software + GENIUS). Longest lead; start engagement now. Gates M1-22 + M1-23 + the Phase0->1 escalation. Does NOT gate the Pass software (on-chain leg prepare-only).
2. M1-6 RG-NONCUSTODY - internal protocol-security demonstration that no Chio-held key can move escrow/bond funds. Gates M1-22.
3. M1-22 contract-surface config - stablecoin-feeds-only + advisory non-gating allowlist, zero immutable edits. Gated by M1-5 + M1-6.
4. M1-23 regulatory prose - strike the flat-vs-bps over-claim, re-ground the MT defense. Gated by M1-5.
5. M1-26 founder sign-off - board pins the ChioPassConfig numbers (POOL, tier units, MIN_GENUINE_USE_RECEIPTS, board_approval_ref) and the accepted_kernel_keys, then go/no-go.

`chio/m1-launch` is ready to merge / open a PR; the launch ships once the five items above close.
