# Native Mac Operator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the native read-only operator first, then attach bounded selection, exact review and recovery controls after the native authority and shared protocol gates pass.

**Architecture:** SwiftUI presents validated task/evidence state; AppKit supplies Services and desktop lifecycle. A generated protocol client reaches the per-user Rust authority through authenticated XPC. The UI never signs approval, evaluates authority, stores credentials or invents native operation identities.

**Tech Stack:** Swift 6 language mode, Swift Package Manager, SwiftUI, AppKit, App Intents, XCTest, String Catalogs, authenticated XPC under the shared controller plan.

**Spec:** [Product](../../specs/2026-10-07-macos-integration/01-product-scope.md), [native experience](../../specs/2026-10-07-macos-integration/02-native-experience.md), [operator protocol](../../specs/2026-10-07-macos-integration/06-operator-protocol.md), [resources](../../specs/2026-10-07-macos-integration/10-project-resources.md).

## Global Constraints

- The initial qualification candidate is macOS 15 or newer on Apple Silicon (arm64), subject to the exact OS/build matrix in the qualification specification; it is not a supported-release claim.
- The first template is `project-change-v1`; publication is separately gated by `publication-v1`.
- The shared wire contract is `chio.desktop.operator.v1`; its field definitions and opaque references come only from the operator protocol.
- OS consent, Chio resource grant, and exact endorsement remain separate facts.
- M1 can ship a read-only development operator; consequential work requires M0, M2 and M6 prerequisites plus the selected execution/resource gates.
- All implementation paths below are proposed and absent at the specification baseline unless explicitly identified as current. Do not add product code while approving this plan.
- Use Chio naming, no em dashes, no public private-repository URLs, and preserve unrelated edits.

## Review Focus

- A file promise, malicious URL or huge multi-selection reaches Services before app initialization; Task 2 rejects it without task creation.
- Lock/session notifications are delayed or absent; Tasks 4 and 5 require native freshness and never treat a UI Boolean as endorsement.
- Screen sharing exposes accessibility text or restored windows despite visual redaction; Task 5 removes sensitive content from every presentation path.
- Unicode/RTL/localized text changes how a destination is perceived; Task 6 preserves exact identity and exposes ambiguous characters.
- Lost replies, repeated clicks and menu-item removal create misleading success or task death; Tasks 3, 4 and 7 preserve original-operation identity and service lifetime.

---

## File and dependency map

| Proposed path | Responsibility |
| --- | --- |
| `integrations/macos/native/Package.swift` | macOS 15 Swift 6 library/test manifest; evolves jointly with the protocol plan. |
| `integrations/macos/native/Sources/ChioMacUI/` | Pure presentation projections, selection validation, redaction, review state and native views. |
| `integrations/macos/native/Tests/ChioMacUITests/` | Deterministic projection, invalidation, selection and localization tests. |
| `integrations/macos/app/ChioMac/` | SwiftUI app scenes, AppKit delegate, Services and App Intent entry points, string catalog. |
| `integrations/macos/app/ChioMacUITests/` | Installed-window and accessibility XCTest cases. |
| `integrations/macos/qualification/native-operator/` | Same-build signed UI, lifecycle, privacy and manual assistive-technology evidence. |

The shared protocol plan owns generated `ChioDesktopContract` types at `integrations/macos/native/Sources/ChioDesktopContract` and authenticated transport. ChioMacUI consumes validated typed snapshots through an injected client; it does not decode generic Data into its own wire DTOs. The packaging plan owns `integrations/macos/app/ChioMac.xcodeproj` and the `ChioMac` scheme, entitlements, signing and app installation. Coordinate package targets rather than replacing the package manifest created by another track. Runtime tests against fixture projections are component evidence only.

### Task 1: Add a testable state projection and read-only native shell

**Files:** Create `integrations/macos/native/Sources/ChioMacUI/WorkPresentation.swift`, `WorkViews.swift`, `Tests/ChioMacUITests/WorkPresentationTests.swift`; create or extend `integrations/macos/native/Package.swift`; create `integrations/macos/app/ChioMac/ChioMacApp.swift`.

**Interfaces:** Introduce presentation-only `WorkPhase`, `Freshness`, `WorkPresentation`, and `StatusText.make(phase:freshness:) -> String`. Validated native snapshots are projected by the protocol adapter in Task 3. A presentation phase cannot be passed back as native authority.

- [ ] **Step 1: Write a failing projection test.**

```swift
import XCTest
@testable import ChioMacUI

final class WorkPresentationTests: XCTestCase {
    func testUnknownOutcomeCannotRenderSuccess() {
        XCTAssertEqual(StatusText.make(phase: .unresolved, freshness: .current),
                       "Outcome unknown")
        XCTAssertEqual(StatusText.make(phase: .succeeded, freshness: .stale),
                       "Latest state unavailable")
    }
}
```

- [ ] **Step 2: Run `swift test --package-path integrations/macos/native --filter WorkPresentationTests`; expect missing-target/type failure before implementation.**
- [ ] **Step 3: Add the minimum pure model and SwiftUI shell.**

```swift
public enum WorkPhase: Sendable {
    case running, awaitingReview, blockedPermission, degraded, stopping
    case succeeded, failed, unresolved
}
public enum Freshness: Sendable { case current, stale }
public enum StatusText {
    public static func make(phase: WorkPhase, freshness: Freshness) -> String {
        if freshness == .stale { return "Latest state unavailable" }
        switch phase {
        case .running: return "Working"
        case .awaitingReview: return "Ready for review"
        case .blockedPermission: return "Permission needed"
        case .degraded: return "Coverage unavailable"
        case .stopping: return "Stopping"
        case .succeeded: return "Completed"
        case .failed: return "Failed"
        case .unresolved: return "Outcome unknown"
        }
    }
}
```

Create `WorkPresentation: Identifiable, Sendable` with display-only `id: String`, `title: String`, `phase: WorkPhase`, `freshness: Freshness`, `location: String`, and `lastChecked: Date`. No initializer accepts a grant or creates one. In `WorkViews.swift`, render `NavigationSplitView` with Work, Review, Resources and Evidence & Recovery. A Task 1 fixture source is visibly labeled Sample Data. App scenes use an ordinary `WindowGroup` plus `MenuBarExtra("Chio", systemImage: "circle.hexagongrid")`; the latter exposes Open Chio and a disabled Stop Work until Task 3 supplies authenticated state. Removing the extra cannot own task lifetime.

The package manifest uses `.macOS(.v15)`, a `ChioMacUI` library target and `ChioMacUITests` test target. Follow the protocol track's package layout if already created, adding only these targets. Replace hard-coded display strings with catalog keys in Task 6 before qualification.

- [ ] **Step 4: Run the projection test plus `swift build --package-path integrations/macos/native`; expect pass and no signer, authority store or kernel imports in ChioMacUI.**
- [ ] **Step 5: Commit only Task 1 paths with `git commit -m "feat: add native Mac operator state views"`.**

### Task 2: Add bounded Finder Services and native selection

**Files:** Create `integrations/macos/native/Sources/ChioMacUI/ProjectSelection.swift`, `Tests/ChioMacUITests/ProjectSelectionTests.swift`, `integrations/macos/app/ChioMac/ProjectServices.swift`, `AppDelegate.swift`; modify proposed `integrations/macos/app/ChioMac/Info.plist`.

**Interfaces:** Introduce `SelectionError: Error, Equatable` with `count`, `notFileURL`, `notDirectory`, `notReady`; `ProjectSelection.validate(_ urls: [URL], isDirectory: (URL) -> Bool) throws -> URL`. `ProjectServices` invokes a `@MainActor (URL) -> Void` composer callback, never the controller's `task.create`. Native intake and bookmark handling belong to resource-plan Task 1.

- [ ] **Step 1: Write the boundary test.**

```swift
func testSelectionCannotBeACommandOrRemoteURL() throws {
    let remote = try XCTUnwrap(URL(string: "https://example.test/repo"))
    XCTAssertThrowsError(try ProjectSelection.validate([remote], isDirectory: { _ in true }))
    XCTAssertThrowsError(try ProjectSelection.validate([], isDirectory: { _ in true }))
    let folder = URL(fileURLWithPath: "/tmp/chio-selected", isDirectory: true)
    XCTAssertThrowsError(try ProjectSelection.validate([folder, folder], isDirectory: { _ in true }))
    XCTAssertEqual(try ProjectSelection.validate([folder], isDirectory: { _ in true }), folder)
}
```

- [ ] **Step 2: Run `swift test --package-path integrations/macos/native --filter ProjectSelectionTests`; expect missing selection type failure.**
- [ ] **Step 3: Implement validation before any filesystem inspection or asynchronous intake.**

```swift
public enum SelectionError: Error, Equatable { case count, notFileURL, notDirectory, notReady }
public enum ProjectSelection {
    public static func validate(_ urls: [URL], isDirectory: (URL) -> Bool) throws -> URL {
        guard urls.count == 1 else { throw SelectionError.count }
        let url = urls[0]
        guard url.isFileURL else { throw SelectionError.notFileURL }
        guard isDirectory(url) else { throw SelectionError.notDirectory }
        return url
    }
}
```

The service method has exact Objective-C selector `runWithChio:userData:error:` with Swift signature `@objc func runWithChio(_ pasteboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>)`. Bound `pasteboardItems` to one, require `.fileURL`, cap encoded URL bytes at 16 KiB, read only file URLs, and send only a validated URL to the composer. Reject file promises and aliases until the native selection flow resolves them explicitly. Register `NSApp.servicesProvider` after the composer is ready; return a localized bounded error before readiness. Add `NSServices` with `NSMessage = runWithChio`, `NSMenuItem.default = Run with Chio`, `NSSendTypes = [public.file-url]`, `NSSendFileTypes = [public.folder]`, `NSPortName = Chio` and `NSRequiredContext.NSApplicationIdentifier = com.apple.finder`. Add an Open Project `NSOpenPanel` with directory-only, single-selection behavior as fallback. The composer also captures a user objective bounded to 16 KiB and passes it to resource-plan Task 1 for native sealing and bootstrap influence. It receives the distinct task-input resource reference before task creation; raw objective text never enters operator event payloads.

- [ ] **Step 4: Extend the test with 65,536 selections, a file-promise pasteboard, a symlink/alias folder and pre-initialization callback; run selection tests. Expect bounded rejection and zero task admissions.**
- [ ] **Step 5: Commit with `git commit -m "feat: add bounded Finder project selection"`.**

### Task 3: Connect validated read-only snapshots and durable stop presentation

**Files:** Create `integrations/macos/native/Sources/ChioMacUI/OperatorProjection.swift`, `StopPresentation.swift`, `Tests/ChioMacUITests/StopPresentationTests.swift`; modify `WorkViews.swift` and `ChioMacApp.swift`. Consume generated client paths owned by [protocol-controller plan](02-protocol-controller.md).

**Interfaces:** Introduce display-only `StopPresentation` with `admissionFenced`, `workerClosed`, `networkClosed`, `resourcesClosed: Bool?`, and `unresolvedEffects: Int`; `closureText: String` is derived. Native stop/result references remain in the generated client and are never synthesized from these booleans. Read-only methods use `hello`, `health.get`, `tasks.list`, `task.get`, `operation.get`, `events.subscribe`, `events.ack` exactly as specified.

- [ ] **Step 1: Write the false-closure regression.**

```swift
func testWorkerDeathDoesNotMeanEffectClosure() {
    let s = StopPresentation(admissionFenced: true, workerClosed: true,
                            networkClosed: nil, resourcesClosed: false,
                            unresolvedEffects: 1)
    XCTAssertEqual(s.closureText, "Stop incomplete")
}
```

- [ ] **Step 2: Run `swift test --package-path integrations/macos/native --filter StopPresentationTests`; expect missing model failure.**
- [ ] **Step 3: Implement all closure rows; never reduce them to worker process state.**

```swift
public struct StopPresentation: Sendable {
    public let admissionFenced: Bool?
    public let workerClosed: Bool?
    public let networkClosed: Bool?
    public let resourcesClosed: Bool?
    public let unresolvedEffects: Int
    public var closureText: String {
        admissionFenced == true && workerClosed == true && networkClosed == true
          && resourcesClosed == true && unresolvedEffects == 0
          ? "Stop complete" : "Stop incomplete"
    }
}
```

Implement the wire-to-presentation adapter against generated validated types. On subscription gaps or peer restart, mark snapshots stale and perform authoritative lookup before changing controls. Stop requests use a stable client intent and reconcile through `operation.get` after transport loss. A progress hint alone never flips a row to confirmed. Avoid adding a second Codable wire DTO in this target. Task list, current-user filtering and observer lifecycle use the protocol client's bounds and native identity, not user-provided owner names.

- [ ] **Step 4: Feed controller fixtures for one pre-stop committed effect, missing network observation, disconnect/reconnect and user switch; run the Swift tests and protocol conformance tests from plan 02. Expect truthful stale/incomplete presentation and no cross-user metadata.**
- [ ] **Step 5: Commit with `git commit -m "feat: project authoritative task and stop state"`.**

### Task 4: Add exact-review invalidation and original-operation recovery

**Files:** Create `integrations/macos/native/Sources/ChioMacUI/ReviewReadiness.swift`, `ReviewView.swift`, `Tests/ChioMacUITests/ReviewReadinessTests.swift`; consume M0/M2 native review/endorsement client and M6 original-operation reconciliation.

**Interfaces:** Introduce presentation-only `ReviewReadiness` with `hasFreshContent`, `isRevealed`, `isSubmitting`, `outcomeUnresolved: Bool` and `showsSubmissionControl: Bool`. The native generated client's opaque review/endorsement references are retained privately by its actor. This state can hide a button but cannot authorize a crossing.

- [ ] **Step 1: Write the stale and unknown-outcome tests.**

```swift
func testStaleAndUnresolvedReviewCannotOfferSubmission() {
    XCTAssertFalse(ReviewReadiness(hasFreshContent: false, isRevealed: true,
        isSubmitting: false, outcomeUnresolved: false).showsSubmissionControl)
    XCTAssertFalse(ReviewReadiness(hasFreshContent: true, isRevealed: true,
        isSubmitting: false, outcomeUnresolved: true).showsSubmissionControl)
}
```

- [ ] **Step 2: Run `swift test --package-path integrations/macos/native --filter ReviewReadinessTests`; expect missing type failure.**
- [ ] **Step 3: Implement readiness and exact-content view; do not implement an approval signer.**

```swift
public struct ReviewReadiness: Sendable {
    public let hasFreshContent: Bool
    public let isRevealed: Bool
    public let isSubmitting: Bool
    public let outcomeUnresolved: Bool
    public var showsSubmissionControl: Bool {
        hasFreshContent && isRevealed && !isSubmitting && !outcomeUnresolved
    }
}
```

`ReviewView` renders the native-verified effect, exact destination/account, artifact/diff, released data, cost, expiry, original state and changed relevant influence with selectable wrapped text. `review.open` fetches current content. Native authority owns issuing the opaque endorsement under its own session/binding rules; `approval.submit` forwards that reference with the unchanged original operation context. The UI cannot implement the missing native session contract: if M0 is incomplete, the submission feature remains disabled. Use an effect-named button without default Return shortcut, explicit Decline, and a fresh-content action after invalidation. On duplicate click reuse the original client intent; on dropped reply show Checking original outcome and call `operation.get`.

- [ ] **Step 4: Add integration fixtures that mutate destination, artifact, policy generation and influence after review and lose the commit response. Run review tests plus native binding tests from plan 00. Expect native rejection, one effect maximum and persistent unresolved state where reconciliation lacks proof.**
- [ ] **Step 5: Commit with `git commit -m "feat: add native exact review and recovery presentation"`.**

### Task 5: Add lifecycle redaction, presenter mode and bounded App Intents

**Files:** Create `integrations/macos/native/Sources/ChioMacUI/PrivacyPresentation.swift`, `Tests/ChioMacUITests/PrivacyPresentationTests.swift`, `integrations/macos/app/ChioMac/SessionObserver.swift`, `ChioIntents.swift`, `NotificationRouter.swift`.

**Interfaces:** Introduce `PrivacyPresentation` with `isAppActive`, `isSessionCurrent`, `presenterMode`, `userRevealed: Bool`; `canRenderSensitive: Bool`; `visibleText(_:) -> String`. These are rendering decisions only. Define `OpenChioReviewIntent: AppIntent` using `requiresLocalDeviceAuthentication`; other intent types use generated client operations only and never accept raw commands or approval flags.

- [ ] **Step 1: Write an accessibility-data redaction test.**

```swift
func testPresenterModeNeverReturnsSensitiveLabel() {
    let p = PrivacyPresentation(isAppActive: true, isSessionCurrent: true,
                               presenterMode: true, userRevealed: true)
    XCTAssertEqual(p.visibleText("private@example.test"), "Hidden")
    XCTAssertFalse(p.canRenderSensitive)
}
```

- [ ] **Step 2: Run `swift test --package-path integrations/macos/native --filter PrivacyPresentationTests`; expect missing type failure.**
- [ ] **Step 3: Implement actual content substitution rather than cosmetic blur.**

```swift
public struct PrivacyPresentation: Sendable {
    public let isAppActive: Bool
    public let isSessionCurrent: Bool
    public let presenterMode: Bool
    public let userRevealed: Bool
    public var canRenderSensitive: Bool {
        isAppActive && isSessionCurrent && !presenterMode && userRevealed
    }
    public func visibleText(_ value: String) -> String {
        canRenderSensitive ? value : "Hidden"
    }
}
```

Bind both `Text` and accessibility labels to substituted strings; remove Copy when hidden; persist only opaque window routing state. Reset userRevealed on app resignation, `NSWorkspace.sessionDidResignActiveNotification`, `willSleepNotification` and `screensDidSleepNotification` using their documented notification centers. Initialize unknown session as hidden. Restore/reveal requires current native review; notifications remain hints. Add explicit presenter toggle and explain that visible content may be screen-shared. Do not use `sharingType = .none` as a security gate.

Register resource-bearing intents with `.requiresLocalDeviceAuthentication`. Pin and compile foreground behavior using `supportedModes` where available, with the macOS 15 compatibility route under availability checks. Intent metadata includes fixed template composer, redacted status, evidence routing and stop; there is no approve/publish verb. Notifications contain generic text and opaque routes. A stale or other-user route returns Unavailable without a title/path disclosure.

- [ ] **Step 4: Add tests for inactive app, unknown session, user switch, presenter mode, stale notification and malicious intent parameters. Run privacy tests and generated App Intent metadata inspection in signed app qualification. Expect no sensitive accessible/copy/restored text and no approval route.**
- [ ] **Step 5: Commit with `git commit -m "feat: add private native lifecycle and bounded intents"`.**

### Task 6: Localize and make complete review flows accessible

**Files:** Create `integrations/macos/app/ChioMac/Localizable.xcstrings`, `integrations/macos/app/ChioMac/en.lproj/ServicesMenu.strings`, `integrations/macos/native/Sources/ChioMacUI/IdentityDisplay.swift`, `Tests/ChioMacUITests/IdentityDisplayTests.swift`, `integrations/macos/app/ChioMacUITests/ReviewAccessibilityTests.swift`; modify all native views.

**Interfaces:** Introduce `IdentityDisplay.escaped(_ input: String) -> String`, a display-only escaped view of control/bidi code points. Raw native identity remains unchanged and the Copy Exact action copies verified original bytes where the wire representation permits it. UI test identifiers are `review.destination`, `review.release`, `review.effect`, `review.submit`, `review.decline`, `stop.progress`, `privacy.presenter`.

- [ ] **Step 1: Add the ambiguous-destination test.**

```swift
func testBidiControlCannotHideDestinationSuffix() {
    XCTAssertEqual(IdentityDisplay.escaped("safe\u{202E}txt"), "safe\\u{202E}txt")
    XCTAssertEqual(IdentityDisplay.escaped("café"), "café")
}
```

- [ ] **Step 2: Run `swift test --package-path integrations/macos/native --filter IdentityDisplayTests`; expect missing function failure.**
- [ ] **Step 3: Implement escaping and semantic accessibility.**

```swift
public enum IdentityDisplay {
    public static func escaped(_ input: String) -> String {
        input.unicodeScalars.map { scalar in
            let n = scalar.value
            let bidi = (0x202A...0x202E).contains(n) || (0x2066...0x2069).contains(n)
            return n < 0x20 || n == 0x7F || bidi
              ? "\\u{\(String(n, radix: 16, uppercase: true))}" : String(scalar)
        }.joined()
    }
}
```

Create `ServicesMenu.strings` with `"Run with Chio" = "Run with Chio";` and localized variants for the Services label. Create catalog entries for all messages from Tasks 1-5, pluralized counts, and error recovery actions. Keep authority identifiers out of translated format strings; display long values with wrapping and selectable full text. Use labels/values/hints, heading grouping and deliberate focus after Review changed. Provide keyboard shortcuts for navigation/stop, not approval; honor reduced-motion and contrast settings. Logs strip ANSI effects in the viewer and keep raw bounded evidence behind explicit export. No HTML/script/network preview engine is introduced.

- [ ] **Step 4: Run Swift tests, then `xcodebuild -project integrations/macos/app/ChioMac.xcodeproj -scheme ChioMac -destination 'platform=macOS,arch=arm64' test -only-testing:ChioMacUITests/ReviewAccessibilityTests`. Expect full effect/destination inspectability in English, pseudolocalized double-length and RTL fixtures, with no color-only or clipped controls.**
- [ ] **Step 5: Commit with `git commit -m "feat: make native review accessible and localizable"`.**

### Task 7: Qualify the signed native flow and failure states

**Files:** Create `integrations/macos/app/ChioMacUITests/OperatorLifecycleTests.swift`, `integrations/macos/qualification/native-operator/checklist.md`, `integrations/macos/qualification/native-operator/result.schema.json`, `integrations/macos/qualification/native-operator/README.md`. Consume the signed app and matrix records from plan 08 and profile gates from plans 00/02/03/04/06.

**Interfaces:** Qualification records refer to exact build, OS, SDK, architecture, native profile evidence and test artifacts. They do not add a new authority schema. Manual checklist rows require tester, build, operation reference, action and observed result; incomplete rows fail acceptance.

- [ ] **Step 1: Add the menu/window lifetime UI test using seeded task state.**

```swift
func testClosingWindowDoesNotReportStopped() throws {
    let app = XCUIApplication()
    app.launchArguments = ["--ui-test-scenario", "active-task"]
    app.launch()
    app.typeKey("w", modifierFlags: .command)
    app.activate()
    XCTAssertFalse(app.staticTexts["Stop complete"].exists)
}
```

The `--ui-test-scenario` entry exists only in the UI-test build configuration and seeds display fixtures; it cannot bypass production authorization or ship in the release product. Add real signed-service tests separately for task lifetime, stop and recovery.

- [ ] **Step 2: Run `xcodebuild -project integrations/macos/app/ChioMac.xcodeproj -scheme ChioMac -destination 'platform=macOS,arch=arm64' test -only-testing:ChioMacUITests/OperatorLifecycleTests`; expect failure until app reconnection and window restoration are wired.**
- [ ] **Step 3: Wire reopen to authoritative lookup and record failure scenarios.** Cover clean account Services, declined notifications/folder access, stale bookmark, killed app/service, lost response, disk full, long logs, missing qualification, revoked grant, stop with unresolved effect, user switch, lock without sleep, sleep/wake and presenter mode during actual screen sharing. Record exact screenshot/accessibility snapshot and native operation evidence where applicable. Fix false-success or privacy defects in their owning task modules, not in test-only routes.
- [ ] **Step 4: Run the entire Swift suite and signed UI suite; manually complete keyboard/VoiceOver, Voice Control, contrast, reduced motion and text scaling checklist. Expect every spec acceptance to have scoped evidence; record untested OS cells as unavailable.**
- [ ] **Step 5: Commit with `git commit -m "test: qualify native operator lifecycle and review"`.**

## Acceptance coverage and handoff

Product acceptance is shared with resource and VM plans: Tasks 1-3 own entry/state/stop, Task 4 exact review/recovery, Task 5 consent/privacy/intents, Task 6 accessibility/localization/inert display, and Task 7 installed evidence. Resource confinement and correctness are not established by UI tests. Execute M1 read-only work independently. Resource-plan Tasks 1, 3, 2 and 5 provide foundation after M0/M2/M6 before the first useful M3 task; they do not wait for VM qualification or publication. Defer consequential review in this plan Task 4 and live Task 7 project/publication cases until the M3 backend and the corresponding resource-plan worker/publication integration are ready, then collect qualification evidence before user enablement. This plan does not authorize implementation, OS permission changes or publication by itself.
