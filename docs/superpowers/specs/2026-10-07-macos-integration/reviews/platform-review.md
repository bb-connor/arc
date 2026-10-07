# macOS platform and execution review

This report records the initial local review before the first hosted review round. Later corrections and validation are recorded in [validation](validation.md) and [work log](work-log.md); hosted verdicts must be checked on the live current commit.

Review date: 2026-10-07. Scope: proposed specifications and implementation plans only. No product implementation, installation, entitlement, or runtime qualification was attempted. Confidence: high in the two concrete findings below; high in the directly checked Apple documentation findings; unknown in eventual installed platform behavior.

Final platform-review verdict: ready within the reviewed documentation scope, with no remaining P1/P2 findings. The two initial findings were corrected and reinspected below. The design consistently separates native kernel authority from OS restrictions and treats missing installed evidence as unavailable. This verdict covers the proposed contracts and executable handoff, not runtime implementation, installed qualification, or the coordinating reviewer's final whole-package decision.

## P1: Editable code can make the protected test pass without correct behavior

Initial locations: `docs/superpowers/plans/2026-10-07-macos-integration/04-resources-publication.md:219-230` and `:234-244`; associated obligation `10-project-resources.md:50`, `:85`, and `:110`.

The proposed immutable `test_greeting.py` imports editable `greeting.py` into its own Python interpreter. The tested module can replace `unittest.TestCase.assertEqual` with a no-op, then return an incorrect greeting. The fixed command exits zero and reports a completed passing test while the protected harness bytes, invocation, and expected artifact digests remain unchanged. An authenticated guest report accurately describing that invocation and exit does not repair the oracle. An early `os._exit(0)` is another relevant control, but the monkeypatch case is stronger because it actually reports a completed test.

Reproduced without changing repository files using an in-memory module and the specified test structure under `python3 -I`: candidate behavior `WRONG`; exit code `0`; `Ran 1 test`; `OK`. Only the candidate module changes this behavior:

```python
import unittest
unittest.TestCase.assertEqual = lambda *args, **kwargs: None

def greeting(name):
    return "WRONG"
```

Impact: the task can obtain a verified-successful result for a bad patch, contradicting the first workflow's independent protected-test requirement. A signed record of the wrong oracle would preserve the false conclusion rather than prevent it.

Required remedy: move the assertion oracle and completion record outside the tested code's authority and, for the documented compromised-guest threat, outside that guest. Exchange bounded data only. Bind the tested sealed artifact and actual admitted invocation to the result through an independently trusted owner. A subprocess with the same UID or an oracle inside a guest that the adversary controls is insufficient. Early exit, missing/truncated output, assertion monkeypatch, and forged guest completion must fail or remain explicitly unverified. Keep the ordinary correct patch as the positive control.

Disposition: resolved in the proposed design after reinspection. Updated plan 04 Task 4 (`:208-320`) now defines a host Rust oracle over data-only CLI observations, exact output and complete-case checks, native supervisory attribution, a distinct `Unverified` outcome, and the concrete monkeypatch/early-exit/forged-output corpus. Updated resource specification (`10-project-resources.md:48-54`) explicitly puts the oracle outside the candidate worker and guest and rejects guest authentication as proof of invocation/output attribution. This closes the documentation defect; it does not assert the future supervisory lane has been implemented or qualified.

## P2: The VM plan has no owner for its required guest image and bootstrap

Initial locations: `docs/superpowers/plans/2026-10-07-macos-integration/03-vm-project.md:19-33`, `:133-149`, and `:155-161`; consuming dependency `07-adapters-delegation.md:77-78`.

M3 creates the host Virtualization configuration, host registry, host decoder/server, and lab probes. Its factory consumes retained kernel/initrd/root/scratch image inputs, and its host protocol expects a peer inside the guest. M7 then expects a trusted supervisor to launch the worker with a private input pipe on FD 3. No task or named external prerequisite in the nine plans or relevant source research produces the architecture-matched image, guest init/bootstrap/supervisor, guest virtio client, or private-input handoff. M8 inventories and signs the composition but does not supply those missing artifacts.

Impact: completing the enumerated M3 host tasks still cannot boot a specified project worker, perform the guest handshake, or supply M7's private input. Implementers would need to invent an unreviewed execution component and its trust boundary. This is a missing plan dependency, not a demand to implement the product in this documentation change.

Required remedy: assign an explicit M3 guest-foundation task, with paths or a pinned external artifact owner, before actual guest integration. It must define image/kernel/initrd provenance, architecture and package locks, init/bootstrap, the guest protocol implementation and challenge delivery, immutable-input/scratch mount layout, fixed worker launch and FD 3/private-input setup, stop behavior, and host-enforced resource limits. State which guest components are untrusted under compromised-guest testing and which claims therefore require an outside observer. Add boot/handshake/useful-work and hostile-guest controls. Connect M4 and M7 to that delivered prerequisite.

Disposition: resolved in the proposed design after reinspection. M3 now owns an explicit Task 0 (`03-vm-project.md:40-135`) with image/build/package-lock/SBOM/provenance paths, an initially closed external-artifact selection gate, reproducible offline builds, PID 1, a guest virtio peer, exact private FD 3/4 handoff, isolated nonroot workers, an inaccessible root-owned supervisor, stop/orphan controls and signed boot/useful-work probes. Its preparation and integrated probes have distinct positions in the local dependency order. The host schema explicitly consumes the supervisor protocol (`:257`). The matching specification (`07-vm-execution.md:28-32`, `:58`, `:83`) adds guest ownership and the test-attribution boundary. A fresh verification VM isolates the tested generation from the editing agent, and guest-root/supervisor compromise leaves attribution Unverified. M4/M7 receive named delivered artifacts rather than an assumed guest. This closes the missing-owner defect without claiming that any image or supervisory lane has already been implemented or qualified.

## Apple primary-source checks

Retrieved primary documentation directly on 2026-10-07. Apple's web-rendered pages returned JavaScript shells or unsupported Markdown content types, so the linked Apple Markdown representations were read directly. No installed behavior was inferred from them.

- [Descendant ES client](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:).md): confirms caller notifications, descendant authorization/notification coverage including already-existing descendants, restricted entitlement, no root/TCC requirement, and the documented non-root setuid/setgid behavior. The specification's explicit installed SDK/OS gate is appropriate. No beta/stable qualification conclusion was drawn from documentation metadata.
- [Updating NE flow verdicts](https://developer.apple.com/documentation/networkextension/nefilterdataprovider/update(_:using:for:).md): confirms socket-flow update types and direction handling. The separate existing-flow and client-loss experiments remain necessary; no API call was treated as proof of actual flow closure.
- [TN3137: Mac keychains](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains.md): confirms user-context restrictions for the Data Protection Keychain, access groups/provisioning, and app-like bundle requirements. The proposal explicitly avoids assuming iOS lock semantics or global-provider access to user secrets.
- [VZVirtioSocketConnection](https://developer.apple.com/documentation/virtualization/vzvirtiosocketconnection.md): confirms VM-created connections delivered through the listener and the use of an owned connection descriptor. Port values alone do not prove task identity; the proposed VM-instance binding is consistent with that boundary.
- [Services properties](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/Articles/properties.html): confirms the planned service selector, file-type advertisement, Finder context restriction, and localization mechanism.

No additional P1/P2 Apple factual error was established by these checks. Existing qualification-bootstrap and M3/M4 resource-foundation sequencing edits were reviewed as concurrent corrections, not duplicated as new findings. Runtime implementation and platform experiments remain later release gates rather than requirements for this docs-only change.

## Reviewed material

Read repository `AGENTS.md` and `README.md`; specification index and specifications 01, 02, 07, 08, 09, 10, 12, 13, 14, 15, 16, 17, and 18; the Apple platform, distribution, workflow, and relevant source/decision research; matching plan sections for native UI, VM, resources, native enforcement, adapters/delegation, and distribution/qualification. Searched all nine plans for the missing guest artifact owner, then reinspected the corrective M3 Task 0 and M4 external oracle plus corresponding specifications. Review changes are limited to this file.
