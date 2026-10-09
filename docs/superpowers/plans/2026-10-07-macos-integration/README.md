# macOS native host delivery plan

`boundary_class: advisory_only` for this planning index; `planning_status: ready_after_adr` for HOST-M1 and platform packets, `deferred` for macOS HOST-M2. No runtime qualification is implied.

Use the [shared delivery plan](../2026-10-07-desktop-integration.md), the [native host contract](../../specs/2026-10-07-desktop-integration/HOST-CONTRACT.md), [CASES](../../specs/2026-10-07-desktop-integration/CASES.md), then the [macOS implementation plan](IMPLEMENTATION.md), which groups the M0-M11 packets by flow.

Before the success test, macOS carries HOST-M1: `chio trust serve` and the governed tool behind `chio api protect` as a LaunchAgent, Keychain key custody on #1160's `signing_custody`, operator approval, signed arm64 packaging and a timed outsider install. A macOS-only organization takes part in HOST-M3 as the requesting organization; the executing organization runs Linux.

macOS HOST-M2 (Darwin process runner, Keychain and XPC broker, `LOCAL_PEERTOKEN` IPC, Seatbelt and VM backends, and the protected Claude Code, Codex, Pi, Hermes and Herdr cells on the Mac) is `planning_status: deferred` until after the success test (unified roadmap section 11). [FIRST-CLASS-INTEGRATIONS](../../specs/2026-10-07-desktop-integration/FIRST-CLASS-INTEGRATIONS.md) keeps those cells as open requirements. Mini-swe is optional reference code only; Cursor and OpenClaw keep their broader doc 19 obligations.

[ADR-0038](../../../adr/ADR-0038-native-host-program.md) owns the planning direction. Historical tests, source compatibility, package signing and bot approval do not enable a runtime profile.
