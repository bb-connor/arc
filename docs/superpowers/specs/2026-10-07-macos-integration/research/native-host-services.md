# Native macOS services and systems integration

Research date: 2026-10-07. Status: primary-source and SDK research supporting the native-host amendment. No Chio runtime, installation, signing identity, entitlement eligibility, service activation, credential backend or enforcement behavior was built or qualified by this research.

Confidence: high in the cited platform distinctions and inspected source paths; moderate in the proposed composition; unknown in installed behavior until exact-tuple experiments. The accepted [annex](../ANNEX.md) and [implementation plan](../../../plans/2026-10-07-macos-integration/IMPLEMENTATION.md) own current direction. Historical desktop-first research is not normative ordering.

## Native services without a required frontend

Chio is a Rust kernel for building agentic operating systems. macOS hosts its userspace native services and OS adapters; this does not require an XNU replacement or kernel extension. Applications, agent harnesses and Herdr can consume the actual owner bindings without workbench, menu bar or browser. Their UX and orchestration strategy remain application responsibilities.

An `.app`-shaped service bundle is compatible with this architecture. Apple's official [GUI-less ServiceManagement package sample](https://developer.apple.com/documentation/servicemanagement/updating-your-app-package-installer-to-use-the-new-service-management-api) packages a LaunchAgent and a non-graphical executable that registers, unregisters, checks status and tests XPC from the command line. The sample demonstrates packaging, not Chio's machine-service availability. [Signing a daemon with a restricted entitlement](https://developer.apple.com/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement) likewise describes a non-UI app-like structure that holds an embedded provisioning profile and is tested in daemon context.

The two deployment profiles remain separate:

| Profile | Platform composition | What requires qualification |
| --- | --- | --- |
| User-session host | Per-user headless service, normally a registered LaunchAgent | Current enrolled user/session, lock/logout/switch fences, per-user broker, selected native bindings and ordinary-user installation. No Chio UI required; no login-independent claim. |
| Service host | System-domain LaunchDaemon with explicit service principal; least privilege compatible with native owners | Machine authority and credential policy, protected storage availability, boot/restart, scoped resources, consent, installation-wide lifecycle/floor and cross-user separation. No personal-login impersonation. |

A service alive in launchd is not proof that its selected credential, source resource, model release, human endorsement or backend is available. An incomplete machine profile cannot borrow the user profile's evidence. A partial user-profile release may ship with machine-profile work still explicitly unavailable.

## Service registration, installation and bootstrap context

| Source | Verified fact | Design consequence and unresolved experiment |
| --- | --- | --- |
| [SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice), [register](https://developer.apple.com/documentation/servicemanagement/smappservice/register()) | macOS 13+ supports bundled LoginItems, LaunchAgents and LaunchDaemons. LaunchAgents register once per running user and bootstrap on later logins. Approved LaunchDaemons bootstrap on later boots. | Record registration/authorization, running state, authenticated reachability and qualified owner operations separately. Qualify both deployment contexts; a LaunchAgent result cannot prove logged-out operation. |
| [Updating helper executables](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) | Plists and helpers can live in the app bundle; BundleProgram is relative to that bundle. Daemons require system-level authorization. | A GUI-less bundle can host native executables; a Swift menu target is not the service. Refused approval remains unavailable. |
| [Apple DTS managed daemon guidance](https://developer.apple.com/forums/thread/771162) | Apple staff describes installer-package deployment to `/Library/LaunchDaemons`; its corrected guidance says BundleProgram only works for SMAppService registration, while traditional launchd deployment uses Program/ProgramArguments. | Qualify one explicit install mode and lifecycle owner per installation. Managed and app updaters must not compete. No inferred unattended consent bypass. |
| [TN2083](https://developer.apple.com/library/archive/technotes/tn2083/_index.html), archived | UID does not fully determine execution context; bootstrap namespace and user security context matter. A daemon using the console user's UID is not equivalent to that user's app. | No root impersonation, active-console-user guessing or changing UID to reach a human Keychain/session. Current ServiceManagement documentation supersedes the archive's old install recipes. |
| [Manage background tasks](https://support.apple.com/guide/deployment/manage-login-items-background-tasks-mac-depdca572563/web) | Managed rules can approve matching background items. Current guidance also describes a macOS 26 prompt for app-started tasks remaining after app quit. | Test no-frontend cold start and quitting optional apps on each selected OS; distinguish permissions from health. |
| [Intro to FileVault](https://support.apple.com/guide/deployment/intro-to-filevault-dep82064ec40/web) | Credentials are required during FileVault boot. Apple silicon/macOS 26+ can unlock over SSH after restart with Remote Login and networking configured. | Machine-service qualification starts after required OS/storage availability. Do not claim pre-unlock execution or require weaker host security. Remote unlock is an OS deployment choice, not Chio secret recovery. |

System-domain lifetime and root privilege are distinct. The installed `launchd.plist(5)` documents `UserName` and `GroupName` for system-domain services. Prefer an unprivileged service identity; retain a narrow privileged lifecycle surface only where necessary. Packaging must bind service labels, owner principal, state/endpoints, executable identities, entitlements, install mode and original lifecycle operation.

## Darwin authenticated IPC

M1 remains work in `chio-secure-ipc`, preserving its framing, endpoint custody and Linux semantics. Its existing AF_UNIX `LOCAL_PEERTOKEN` source record remains conditional: socket token acquisition through `last_pid`/`proc_find`, later audit-token code checks and descriptor handoff must form a qualified path. Do not reduce it to PID-only or getpeereid admission.

Apple's [XPC code-signing requirement API](https://developer.apple.com/documentation/xpc/xpc_connection_set_peer_code_signing_requirement(_:_:)) is documented for macOS 12+, and [NSXPCConnection.setCodeSigningRequirement](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement(_:)) for macOS 13+. The installed XPC header says received messages are checked. `SecCodeCreateWithXPCMessage` derives dynamic code from the received message's audit token. These are useful per-message identity mechanisms, not sufficient Chio authorization.

**Outgoing secrecy is a separate obligation.** [Apple DTS confirms](https://developer.apple.com/forums/thread/837286) that a first outgoing request can reach a replacement service even though the client's code-signing requirement later rejects its reply. Preserve intended-service authentication before private bytes or reusable credentials, including non-sensitive negotiation, namespace/reply custody, accepted release and reconnect. A call to a signing-check API is not proof of a mutually authenticated confidential channel.

For both transports and deployment contexts, retain separate-process tests for wrong UID/code, same-team unaccepted builds, user/service-principal confusion, exit/exec/reuse, transferred descriptors/rights, malformed input, replay, replaced endpoints, first outgoing private request, established-channel fencing across updates/removal and bounded pre-authentication load with useful legitimate-client headroom. Signature validity, a global namespace, root status or UID equality supplies neither a current grant nor exact accepted release inventory.

Browser authentication cases apply only when a browser consumer is included; direct native consumers still pass all relevant native identity, parser, correlation, replay and lifecycle obligations. No browser route is an authority prerequisite for another supported owner binding.

## Process custody, resource sharing and time

Apple source supports mechanisms, not a complete Darwin process/container contract:

- The installed launchd manual says job death normally kills remaining members of the same process group unless AbandonProcessGroup is set. It does not establish closure for reparented/re-sessioned descendants or delegated services.
- The [kqueue manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html) documents process events. The selected SDK says NOTE_TRACK, NOTE_TRACKERR and NOTE_CHILD are unsupported since 10.5, and NOTE_FORK does not deliver the child's PID in the kevent. FreeBSD-style automatic child tracking is not a usable assumption.
- The [setrlimit manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html) describes per-process CPU/file/descriptor bounds, per-user process limits and RSS reclaim preference. The installed launchd manual notes that some system-daemon limit keys also affect global sysctl values. Those mechanisms do not prove hard aggregate per-task memory/process/Mach-object ceilings and can affect unrelated users.
- [mach_continuous_time](https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time) advances while asleep; Apple points to `clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)` for nanoseconds. Join the selected supported clock to native boot/incarnation and authority expiry; do not persist its raw value as a cross-boot timestamp.

Keep M4/M5's finite per-task and aggregate CPU/time, memory, disk/inode, thread/process, descriptor, Mach/right/message, output and concurrency tests, plus control/stop headroom and positive useful work. Keep spawn/exec/reparent closure races and live owner cancellation. If an adapter cannot enforce a selected boundary, that profile remains unavailable or uses a separately qualified existing runtime. Removing UI cannot repair a missing quota or custody mechanism.

Application resource sharing consumes actual owner scheduling/reservation/lease semantics. Changing consumer, service incarnation, user session or frontend cannot refresh a shared allowance. Cross-organization resource sharing requires independent authorization, disclosure and accounting boundaries from existing owners; a machine-wide daemon must not collapse those organizations into one trust domain.

## Credential custody and no-login work

[Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains) expressly limits the data-protection Keychain to a user login context. A launchd daemon outside that context must use the file-based implementation if it uses Keychain. A dummy app-like bundle or changed UID does not change that rule. File-based Keychain uses ACLs; data-protection Keychain uses access groups and optional access control.

Keep the current user-session policy: explicit data-protection implementation, no synchronization, narrow qualified accessibility, exact access group/audience/code and native lock/session/freshness fencing, with no weaker fallback. Service hosts require a separately provisioned native broker backend and caller policy. Candidate directions are reviewed system/file-based Keychain custody or an existing remote credential broker. Neither is selected or qualified by this research, and neither is a fallback after a failed user lookup.

The current TN3137 revision dated 2026-09-24 additionally explains that file-based keychains on macOS 26.4+ may depend on protected entropy outside a single keychain file, whose format/location is not API. Supported machine restoration or a declared synthetic fixture must cover the actual credential closure. Copying one file cannot automatically qualify rollback. Do not add private OS-file manipulation or SIP changes to the product.

Unattended service authority and human endorsement are distinct. A service can use only explicitly valid service-scoped grants; it cannot fabricate a passkey/Touch ID approval or borrow a human session. Test exact intent, atomic retention, deny/mismatch, post-verification revocation, fresh/expired/spent grants, broker caches, store outage, no-login startup, restart, migration/restore and wrong-principal release. Missing credentials or freshness fence the affected path.

## Isolation, network boundaries and managed endpoint work

| Source | Verified fact | Retained boundary |
| --- | --- | --- |
| [System Extensions](https://developer.apple.com/documentation/systemextensions) | Privileged system extensions run in userspace and have app-bundle, signing and activation requirements. | Ordinary native services need no KEXT or host-wide ES/NE activation. |
| [TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment) | NE app extensions run per user and terminate at logout; system extensions run globally. macOS content filters use system extensions. | Qualify the exact provider type and multi-user scope, separately from native service installation. |
| [ES entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client) | Apple must grant the entitlement. | Source compilation and downloaded SDKs do not establish eligibility. |
| [Descendant ES client](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:)) | Current macOS 27 API documentation describes scoped descendants, entitlement required, no root/TCC requirement. | This is documentation, not installed support. `native-descendant-v1` remains retired; a future profile requires its own decision and complete gates. |
| [Flow process audit token](https://developer.apple.com/documentation/networkextension/nefilterflow/sourceprocessaudittoken) | Optional process attribution can differ from app attribution when a system process makes the connection. | Missing attribution never becomes guessed task/user authority. |
| [VM NAT](https://developer.apple.com/documentation/virtualization/vznatnetworkdeviceattachment) | NAT routes guest traffic to external networks through the host. | NAT is not broker-only confinement; retain independent direct-egress denial. |
| [TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api) | PF is not a supported product API. | Do not replace an absent NE/network guarantee with a distributed pfctl product layer. |

Keep managed endpoint M11 independent: eligibility, final SDK/OS, activation/refusal/removal, wrong/missing audit tokens, actual file/flow denial, inherited/open handles and existing flows, queue/deadline/provider failure, policy convergence, other providers and two-user scope. No native service, optional UI or consumer success qualifies ES/NE.

## Owner delivery and acceptance consequences

M0 must reconcile actual paths and commands before implementation. The current program map's foundation source contains `chio-secure-ipc/src/{lib,credentials}.rs`, `chio-process/src/registry.rs` and `worker/unix.rs`, `chio-secret-broker/src/{backend,daemon,authority_ipc}.rs`, and the process-host CLI documentation. These were inspected through immutable source objects, not assumed present in the docs worktree. The existing `chio-keyring/src/darwin_acl.rs` handles filesystem ACL inspection, not Apple Keychain backend integration.

The lifecycle/install/release/floor owner is a concrete open delivery question: existing documents demand its authority, serialized custody and authenticated history but do not identify an implementation path in PROGRAM-MAP. M0 must locate or deliver that shared owner before privileged installation/update/removal, rather than creating a controller-owned lock or machine authority.

The amended sequence retains packet identities:

1. M0 maps actual owners, deployment contexts and external consumers, including all existing per-stimulus obligations.
2. M1 qualifies Darwin IPC in its existing owner, including first-outgoing-message secrecy and principal/context scope.
3. M2 builds native service packaging and proves an external harness plus independent application with all Chio frontends absent. User-session and service-host evidence remains separate. Optional clients are separate subpackets.
4. M3 independently qualifies selected approval and stop controls. M4/M5 qualify selected execution backends. M6 is an optional coding-resource/acceptance/delivery profile, not a host prerequisite.
5. M7 covers each actual host/consumer profile and applicable I01-I08. M8/M9 close native privacy, no-login lifecycle, credential and install/restore/removal evidence on the exact signed candidate; optional rendering tests remain required for delivered clients.
6. M10 promotes only each passing capability/context. Remove an unrelated UI/coding artifact and the native capability stays usable; remove an applicable native acceptance case and that capability must refuse. M11 stays separate.

No-native-UI and no-graphical-login tests must include useful authenticated work, wrong user/service/organization, identical names/IDs, consumer death, native owner death, resource saturation, original-ID recovery, background permission revocation, cold boot with delayed dependencies, cross-user update/removal and restored older authority/history. Human-only routes stay pending/unavailable without current endorsement. UI-only tests may be absent only when the corresponding UI is absent; all native parser, secrecy, authorization, duplicate/conflict, resource, custody, review-binding, release, anti-rollback and independent-effect tests remain required for exposed capabilities.

## Local source record

Inspected host: macOS 26.4, build `25E246`; selected Xcode SDK: macOS 26.5 at `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk`. This is a research-machine record, not a supported-release matrix. No runtime experiment was performed.

| Apple-distributed file | SHA-256 | Inspected source fact |
| --- | --- | --- |
| SDK `usr/include/xpc/connection.h` | `fee99c719a44ff57f5f3bd9e3e2d2b5518d093a476c0df9d4fbcc6a358750d51` | Received-message signing requirement, lines 772-803 |
| SDK `Security.framework/Headers/SecCode.h` | `47a0cf42f3babd16f5f8523464f9895cc2302650c35e401e1d9923d6c30769db` | XPC message audit-token code identity, lines 192-211 |
| SDK `usr/include/sys/event.h` | `b09a4fdd9e88a5c1c9a29bded36a6f8b96b39a3054f0075a07c19da587f0e062` | Process event limitations, lines 247-265 and 354-361 |
| SDK `usr/include/sys/resource.h` | `7d16930e6b75f11ba203238faa5580d31d48fcd4230f2b3f604aaa5fd7e86b58` | Resource constants, not enforcement qualification |
| CommandLineTools SDK `usr/share/man/man5/launchd.plist.5` | `1c5f5041c1d3492988bfa6f9dc6d969dfd072d20af2703c28d9a8f6ed6aaadcb` | UserName/GroupName, process-group cleanup, resource limits and ProcessType; not asserted identical to selected Xcode SDK |

Primary DocC Markdown was retrieved directly when rendered pages exposed only JavaScript. Apple documentation, local headers, source compatibility, signed distribution, service registration, authenticated operation and effective runtime enforcement are distinct evidence classes. Reverify final documentation/headers and installed behavior for each release candidate.
