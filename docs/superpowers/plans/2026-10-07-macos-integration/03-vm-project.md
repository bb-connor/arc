# Mac VM Project Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver one separately qualified local Linux VM project workflow with immutable input, no guest network device, bounded native-broker access and truthful stop/recovery evidence.

**Architecture:** The existing native serving writer owns effect admission, integrity, budgets, original operation identity and stop. A new Swift Virtualization backend creates and supervises a VM, while the shared Rust controller retains launch custody and binds the private guest connection to that exact instance. Independent host/receiver observations qualify confinement; guest messages and VM telemetry never become authority receipts.

**Tech Stack:** Rust workspace and shared desktop controller, Swift Package/Virtualization framework, architecture-matched Linux image, bounded canonical JSON over virtio sockets, Python qualification verifier, signed installed Mac test application.

---

Status: Proposed implementation work, not executed by writing this plan. All `integrations/macos/` paths and `crates/products/chio-desktop/` paths below are new planned paths unless an earlier track has created them. Commands are future commands from repository root. Source inspection occurred at local baseline `6573b8980a1e5331028b7e688169f033a39d0384`; this is not a public checkout instruction. At that baseline the MCP stdio path directly spawns a process and there is no Mac VM backend. Reconcile the actual execution checkout before implementation.

Prerequisites: M0 native prerequisite acceptance, M2 shared controller/operator contract and M6 durable recovery, followed by the resource foundation in [plan 04](04-resources-publication.md) Tasks 1-3 and 5. Those resource tasks provide selected/sealed inputs, immutable import and the bounded model route needed by the VM backend; they do not depend on completed M4 publication. Establish and probe the VM backend first, then integrate plan 04's output quarantine/protected tests and publication tasks against that backend. Full workflow qualification covers the resulting composition. Numeric track names are not chronological order. This plan does not authorize publishing or adding a native host-shell fallback.

Production entry and the dedicated signed qualification probe have separate eligibility checks. Production requires verified installed qualification. The probe collects candidate evidence using the exact production driver bytes under separate native fixture authority limited to declared synthetic inputs, controlled receivers, fixed recipes and isolated lab custody. It retains all entitlement, native admission, stop, identity and containment checks; it cannot set production availability, accept user resources outside its fixture scope or self-assert qualification. [Spec 17](../../specs/2026-10-07-macos-integration/17-qualification.md) owns this candidate-to-independent-qualification path. No production enable flag substitutes for its verified result.

## Files and ownership

| Proposed file | Responsibility |
| --- | --- |
| `integrations/macos/guest/image/` | Reviewed architecture-specific source/package locks, reproducible kernel/initrd/rootfs build, SBOM and immutable image manifest |
| `integrations/macos/guest/bootstrap/` | Guest PID 1, private virtio peer, bounded launch controller, worker containment and invocation/capture ownership |
| `integrations/macos/guest/tests/` | Image closure, boot, FD 3, supervisor isolation, orphan-fork, stop and false-attribution tests |
| `integrations/macos/native/Sources/ChioVM/VMTopology.swift` | Closed safe device/input topology values and validation |
| `integrations/macos/native/Sources/ChioVM/VirtualMachineFactory.swift` | Actual VZ configuration and instance creation from retained files |
| `integrations/macos/native/Sources/ChioVM/VMInstanceRegistry.swift` | Host-owned instance/connection identity and launch custody |
| `integrations/macos/native/Sources/ChioVM/GuestFrameDecoder.swift` | Incremental bounded parsing with strict wire validation |
| `integrations/macos/native/Sources/ChioVM/GuestSocketServer.swift` | Per-VM listeners, single-use handshake and request limits |
| `integrations/macos/native/Sources/ChioVM/VMLifecycle.swift` | Start barrier, stop request, forced stop and external state projection |
| `integrations/macos/native/Sources/ChioVMProbe/main.swift` | Signed-installation VM probe executable, without authority signing |
| `integrations/macos/contracts/guest-v1.schema.json` | Proposed closed private guest protocol, distinct from operator IPC |
| `crates/products/chio-desktop/src/platform/macos/vm.rs` | Controller orchestration and mapping to actual M0 native owners |
| `crates/products/chio-desktop/tests/macos_vm_contract.rs` | Cross-component native-owner and VM custody tests |
| `integrations/macos/qualification/verify_vm_evidence.py` | Outside-observer evidence checks, not receipt signature replacement |

Modify the M1-owned `integrations/macos/native/Package.swift` to add `ChioVM`, `ChioVMTests` and `ChioVMProbe` targets; coordinate that change with the native-operator owner. M2 owns the shared crate scaffold and module exports. Existing native owner files are `crates/kernel/chio-kernel/src/admission_operation/capture.rs`, its state/store siblings, and `crates/platform/chio-store-sqlite/src/admission_operation_store.rs`; any missing crossing/backend contract is implemented and reviewed in M0, not copied into this controller.

### Task 0: Build the pinned guest image, private peer and isolated supervisor

**Readiness and owner:** M3 owns this guest foundation and its qualification, including all new paths below. Task 0's pure image/decoder work may proceed while native prerequisites are delivered; actual boot/admission uses Task 1's M0/M2/M6 and native fixture gates. Its image/peer artifacts are prerequisites for Task 3's real VM factory and Task 4's handshake. Its isolated invocation/capture lane is a prerequisite for plan 04 Task 4's external test oracle and plan 07 Task 2's private FD 3 launch. Neither dependent plan may treat an authenticated guest message as sufficient attribution.

Execution order is explicit: Task 0 image/peer/supervisor preparation -> Task 1 prerequisite gates -> Tasks 2-4 host configuration/channel construction -> Task 0's integrated signed boot/supervision probes -> Tasks 5-7 effect/lifecycle integration -> plan 04 output/protected-test integration -> Task 8 full candidate evidence and spec 17 independent qualification. Task 0's final installed probes consume the later host factory; they do not make completed runtime qualification a prerequisite for building that factory. Production remains closed throughout candidate collection.

**Proposed files:** Create `integrations/macos/guest/image/selection.schema.json`, `image.lock.json`, `packages.lock.json`, `build.py`, `verify_image.py`, `buildroot-external/external.desc`, `buildroot-external/Config.in`, `buildroot-external/external.mk`, `buildroot-external/configs/chio_arm64_defconfig`, `buildroot-external/board/chio/linux.config`, and `buildroot-external/package/chio-guest/{Config.in,chio-guest.mk}`. Create `integrations/macos/guest/bootstrap/{CMakeLists.txt,init.c,guest_peer.c,launch_controller.c,worker_isolation.c,private_input.c,capture.c,guest_protocol.h}`; `integrations/macos/guest/tests/{test_image_lock.py,test_image_closure.py,test_guest_protocol.c,test_private_input.c,test_guest_supervision.py}`; and `integrations/macos/qualification/guest/supervisor-cases.json`. Extend the private schema in Task 4 and the signed probe in Task 8; no new operator method or native authority API is introduced by the guest.

- [ ] **Close external image selection before downloading/building.** Use a project-owned Buildroot external tree to produce the image, not an arbitrary user's existing VM. No external kernel/Buildroot/toolchain version has been selected or qualified by this plan. M3's image owner must choose exact primary-source artifacts and record, for each, immutable version/commit, source URL, SHA-256, signature/provenance result, approved signer/key reference where signatures exist, patch-set digest, architecture and license/source provenance. Pin the Linux source/config, Buildroot source, compiler/binutils/libc, builder OCI image digest, every transitive target/host package and the Python interpreter needed by plan 04's fixed CLI fixture. Later Node/Pi additions change package/image digests and need their own qualified tuple. Floating tags, version ranges, unknown package sources and unhashed local archives fail `image_selection_incomplete` before any fetch or boot. This is an owned closed selection gate, not an assumed downloadable image.

- [ ] **Implement lock validation and negative tests before the build wrapper.** `selection.schema.json` defines two explicit states: `unselected` (valid planning state, never buildable) and `locked` (complete immutable source and package closure). `image.lock.json` begins as `{"schema":"chio.macos.guest-image-selection.v1","state":"unselected","architecture":"aarch64","artifacts":[]}`. `packages.lock.json` is generated only from a fully resolved exact package graph and reviewed before image eligibility. The complete refusal predicate starts with:

```python
def selection_can_build(selection):
    if selection.get("state") != "locked":
        return False
    if selection.get("architecture") not in {"aarch64", "x86_64"}:
        return False
    artifacts = selection.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False
    kinds = {a.get("kind") for a in artifacts if isinstance(a, dict)}
    if not {"linux", "buildroot", "toolchain", "builder"}.issubset(kinds):
        return False
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            return False
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            return False
        if any(c not in "0123456789abcdef" for c in digest):
            return False
        if artifact.get("provenance") != "verified":
            return False
    return True
```

The real validator additionally verifies signatures against independently configured trust roots, source URLs/versions, package closure and referenced bytes; this predicate cannot confer provenance by trusting a JSON field. `test_image_lock.py` rejects the unselected record, missing source hash, mutable tag, wrong architecture, forged provenance result, omitted transitive package and changed toolchain. Run `python3 -m unittest discover -s integrations/macos/guest/tests -p 'test_image_*.py'`; expect missing validator before implementation and explicit closed-gate tests afterward.

- [ ] **Implement reproducible source acquisition and offline construction.** `build.py fetch --lock PATH --packages PATH --cache DIR` is the sole acquisition command and verifies every fetched byte/signature before cache admission. `build.py build --lock PATH --packages PATH --cache DIR --output DIR --offline` runs the pinned builder with network disabled and fails if any required source is absent. It materializes the Buildroot external config, runs source-locked package/kernel compilation, and emits `Image`, `initramfs.cpio.gz`, `rootfs.ext4`, `image-manifest.json`, `sbom.spdx.json` and `source-provenance.json`. Build cgroup-v2, namespaces, seccomp-filter, virtio block/console and virtio-vsock support into the selected guest kernel; verify exact config symbols/features against that source revision. The immutable rootfs contains `/sbin/chio-init`, `/usr/libexec/chio-guest-supervisor`, the fixed runtime/tool binaries and their full library closure, with no login/getty/SSH service, host credentials, setuid/setgid files or online package installation path. No host share or guest NIC is added.

Use the [Buildroot manual](https://buildroot.org/downloads/manual/manual.html) for external-tree/package/`legal-info` mechanics. Produce the SBOM from the complete resolved build graph and installed-file digest inventory, checking that no runtime library/package is absent; Buildroot's declared package/license manifest alone is not complete runtime closure. Follow [Linux reproducible-build guidance](https://docs.kernel.org/kbuild/reproducible-builds.html): freeze build timestamp/user/host, source epoch, filesystem UUID/timestamps/order, path remapping and any randomness/signing inputs. Run two clean offline builds in different absolute directories, then `python3 integrations/macos/guest/image/verify_image.py --first output/macos-guest-build-a --second output/macos-guest-build-b --require-byte-identical`. Expected: identical kernel/initrd/rootfs and reproducible manifests. If bytes differ, retain the difference and keep image eligibility closed; do not declare reproducibility from identical package names.

- [ ] **Implement PID 1 and immutable boot custody.** `init.c` is the actual PID 1 in the initrd. It mounts only required proc/sys/dev/cgroup filesystems, verifies selected device roles and the root-image manifest, mounts the base root read-only, mounts private scratch separately with `nodev,nosuid`, spawns the root-owned supervisor and reaps all adopted children. It never evaluates boot-capsule text as shell, runs cloud-init, sources user startup files or starts untrusted code before the host start barrier. Guest root and supervisor code are part of the optional invocation-attribution TCB, not a substitute for the host VM boundary. A supervisor crash leaves PID 1 refusing further launches and shutting down after reporting failure if possible; PID 1 failure or a nonresponsive guest is handled by host force-stop.

Device custody is explicit: immutable system root, ephemeral scratch, read-only per-launch boot capsule, and read-only sealed source/candidate generations. The host attaches disks from retained generation owners and records their roles/digests before boot. The capsule contains the fresh transport challenge, enrolled launch reference, expected image/protocol digests and fixed port only; it contains no signing/provider keys or authority permit. It is readable only by root in the guest, is not mounted into worker namespaces, and is retired on stop/reboot. Challenge possession authenticates the selected transport under the trusted-supervisor assumptions, not measured boot or resistance to compromised guest root.

- [ ] **Implement the guest virtio peer and closed control protocol.** The host listens on fixed virtio port `4050` for `chio.macos.guest.v1`; `guest_peer.c` connects using `AF_VSOCK`/`SOCK_STREAM` and `VMADDR_CID_HOST`, as defined in the [Linux vsock interface](https://man7.org/linux/man-pages/man7/vsock.7.html). The supervisor alone owns that socket. A connection is not eligible until the host associates it with the actual VM instance, checks the single-use challenge and exact image/protocol/launch binding, and the peer receives the matching host acknowledgement. Connect/read/write deadlines use monotonic elapsed time, including the 10-second hello bound; reconnect never mints a fresh run or replays an uncertain effect. Implement the same four-byte length/canonical JSON limits as Task 4. Unknown client/version/image, wrong challenge, missing client and duplicate supervisor fail before worker execution. Raw CID is not authority.

Add closed supervisor-only methods `launch.prepare`, `launch.ready`, `invocation.start`, `invocation.finished` and `stop.ack` to Task 4's proposed schema, alongside existing resource/artifact/heartbeat methods. `launch.prepare` carries only native-verified opaque run/launch/input/recipe references, immutable generation/image commitments and limits retained by the host; it is not a guest-chosen executable command. `launch.ready` acknowledges actual mount/containment setup. `invocation.start` names a predeclared recipe, sealed candidate/runtime/input/case digests and a fresh host-enrolled invocation reference. `invocation.finished` reports wait status, all-descendant closure and bounded stream commitments as observations requiring native verification. `stop.ack` records receipt, not termination. Untrusted worker requests can only traverse the resource subset and never inject these supervisor control messages.

- [ ] **Implement fixed launches with exact FD 3 ownership.** `launch_controller.c` accepts only the host-frozen installed recipe entrypoint/runtime digest and argv contract, with no shell interpolation or guest-supplied path. The supervisor first receives the exact sealed task-input generation through native-authorized resource delivery, checks length/digest against the retained host commitment, and supplies those bytes to the worker through a dedicated anonymous pipe. FD 3 is the read end of a single-use, EOF-terminated, at most 262,144-byte UTF-8 JSON startup document, matching plan 07's `readPrivateInput(3)`. It has no length prefix, no prompt in argv/environment, no fallback file and no supervisor challenge/provider key/native signing secret. Reject empty/malformed/oversized input before normal work; input bytes are already integrity-joined and authorized for that worker, not thereby trusted instructions. Close the writer after the exact bounded document; worker closes FD 3 after consumption. Launch must allow concurrent bounded pipe writing/reading so a 256 KiB input cannot deadlock on pipe capacity.

FD 0 is `/dev/null` unless the fixed recipe has a separately declared bounded stdin contract. FDs 1 and 2 are separate supervisor-owned capture pipes. FD 4 is an optional `AF_UNIX` socketpair for bounded resource request/reply frames from the worker to the supervisor relay; it exposes no supervisor-control verbs, host credentials or `SCM_RIGHTS` forwarding. All other inherited FDs, including the supervisor's vsock, boot capsule, native-control and root-directory descriptors, close before exec. FD 3/4 are not native capability/operation IDs. Complete the child-only FD setup helper in `private_input.c` around this core and test actual inherited descriptor tables:

```c
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int install_private_input_fd(int read_end) {
    int status = fcntl(read_end, F_GETFL);
    if (status < 0) return -1;
    if ((status & O_ACCMODE) != O_RDONLY) { errno = EINVAL; return -1; }
    if (read_end != 3 && dup2(read_end, 3) < 0) return -1;
    if (fcntl(3, F_SETFD, 0) < 0) return -1;
    if (read_end != 3 && close(read_end) < 0) return -1;
    return 0;
}
```

The supervisor keeps its copy close-on-exec and performs the wider descriptor cleanup and per-invocation remapping without clobbering capture/resource ends. `test_private_input.c` checks FD 3 read-only/EOF/exact bytes, over-limit and truncated input, inherited-fd closure, no secrets in argv/environment and no deadlock at the maximum document size.

- [ ] **Isolate the supervisor from agents and candidates before releasing the start barrier.** `worker_isolation.c` starts each untrusted invocation with a dedicated nonroot UID/GID, no supplementary groups or capabilities, `no_new_privs`, a private mount/PID namespace, read-only runtime/candidate mounts, bounded scratch and an undelegated cgroup-v2 subtree controlled only by the supervisor. The worker cannot mount devices, write supervisor/root/cgroup state, inspect supervisor `/proc` descriptors/memory, ptrace/signal the supervisor, gain guest root or open AF_VSOCK/host channels. Apply an architecture-checked seccomp policy for the selected recipe and qualify required syscalls per architecture. [Seccomp is one boundary component](https://docs.kernel.org/userspace-api/seccomp_filter.html), not a complete sandbox. [Cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) supplies descendant/resource ownership, not protection of supervisor memory. The composed namespace/UID/FD/mount/LSM-or-equivalent restrictions must prove that protection independently; a missing mechanism closes invocation verification. Limits are admitted on the host and reflected into guest cgroups; the guest cannot raise host CPU/memory/disk/channel caps.

- [ ] **Own actual invocation/artifact attribution, leaving the oracle external.** Plan 04's host Rust oracle evaluates untrusted output bytes. It can return a verified test result only after the native evidence owner validates this lane's matching qualified isolation record and exact sealed artifact/runtime/input/case/argv/invocation bindings. After an agent creates a candidate, retire that editing process group, quarantine its output on the host, and construct a new immutable candidate generation. Run each fixed test case from a fresh verification VM or an independently qualified fresh supervisor epoch with no surviving agent access, mounting that exact generation read-only. Initially choose the fresh verification VM. The supervisor executes the sealed candidate with the pinned interpreter (plan 04 uses `/usr/bin/python3 -I /work/candidate/greeting.py NAME`) and captures only that invocation group's exclusive stdout/stderr. It does not load or evaluate host oracle logic. Native records bind capture-stream ownership, offsets, totals, EOF, real wait result and complete descendant closure; printed PASS/exit markers and guest-reported file hashes cannot substitute.

If candidate code controls the supervisor, guest kernel/root, capture channel or artifact mount, invocation attribution is `Unverified`, even if the external comparator sees expected bytes. A compromised-guest/root experiment can still test the independent host VM/broker boundary, but cannot qualify the guest's own testimony. Authenticating or signing those claims does not repair this gap. No missing attribution result can enable the verified-test/publication route in plan 04.

- [ ] **Implement stop, orphan cleanup and bounded completion.** Stop first closes the host native dispatch route and sends `stop.notice`; the supervisor marks the launch stopped, stops accepting FD 4 requests and acknowledges only receipt via `stop.ack`. It then terminates the invocation cgroup, including forked/orphaned descendants, reaps adopted children and drains or explicitly truncates bounded capture. Where the pinned kernel supports it, use `cgroup.kill` and require `cgroup.events` population zero; ordinary PID/parent exit is insufficient. A descendant retaining a pipe, daemonizing, double-forking or ignoring graceful stop prevents complete capture until actually closed; timeout produces `Unknown`/`Truncated`, never passing completion. Supervisor/guest failures preserve unresolved native operations; host `VZVirtualMachine.stop` confirms VM termination independently. Neither closure nor stop ACK proves an already dispatched remote effect was cancelled.

- [ ] **Run complete boot/handshake/useful-work and hostile controls.** The new `supervisor-cases.json` names subcases under AT-MAC-VM-001, 003, 005-013, 017 and 018: missing kernel/initrd/rootfs/client; wrong architecture/image digest/package closure; unknown/mismatched peer; duplicate or replayed launch; modified task-input generation; maximum FD 3 document and hidden credential canaries; worker vsock/ptrace/supervisor-FD access; sibling invocation capture; artifact/runtime/argv substitution; forged completion; root-compromise false testimony; orphan-fork/held-pipe exit; supervisor death; stop with in-flight broker effect. A correct fixed CLI fixture proves useful boot, private startup and attributable capture; each no-effect assertion includes an effective positive control. The guest harness checks process/mount/FD mechanics, while host/controlled-receiver observers check actual exports and host effects. Every result records which observer remains trusted for that subcase.

Future commands, after creating these files and locking real sources:

```bash
python3 integrations/macos/guest/image/build.py fetch --lock integrations/macos/guest/image/image.lock.json --packages integrations/macos/guest/image/packages.lock.json --cache output/macos-guest-source-cache
python3 integrations/macos/guest/image/build.py build --lock integrations/macos/guest/image/image.lock.json --packages integrations/macos/guest/image/packages.lock.json --cache output/macos-guest-source-cache --output output/macos-guest-build-a --offline
python3 integrations/macos/guest/image/build.py build --lock integrations/macos/guest/image/image.lock.json --packages integrations/macos/guest/image/packages.lock.json --cache output/macos-guest-source-cache --output output/macos-guest-build-b --offline
python3 integrations/macos/guest/image/verify_image.py --first output/macos-guest-build-a --second output/macos-guest-build-b --require-byte-identical
python3 integrations/macos/guest/tests/test_guest_supervision.py --installation-manifest output/macos-lab/installation.json --image-manifest output/macos-guest-build-a/image-manifest.json --fixture-authority-file output/macos-lab/fixture-authority.ref --cases integrations/macos/qualification/guest/supervisor-cases.json --output output/macos-guest-supervision
```

The final runner invokes Task 8's actual signed VM probe rather than an arbitrary shell launcher. It rejects absent installation/image/native fixture evidence and returns nonzero for missing/unverified supervisory attribution. Build commands fail closed while selection is unselected; no external version or successful build is claimed by this plan. Pass requires byte-reproducible image construction, successful actual boot/handshake/useful recipe, all relevant hostile negatives and independent host effect evidence. Deliver `image-manifest.json` to Task 3, peer schema/fixtures to Task 4, scoped native supervisory qualification to plan 04 Task 4, and exact FD 3/4 contract to plan 07 Task 2.

- [ ] **Commit guest foundation only after its scoped checks:** stage the named `integrations/macos/guest/` files and supervisor-case catalog, then `git commit -m "feat(macos): construct pinned guest and isolated supervisor"`. This is an implementation-plan step, not an instruction to commit this specification change.

### Task 1: Close owned prerequisite and baseline gates

**Files:** Create `integrations/macos/qualification/vm-prerequisites.json`, `integrations/macos/tests/fixtures/vm/missing-native-owner.json`, `integrations/macos/tests/fixtures/vm/lab-authority-boundary.json`; use M0/M2/M6 evidence and plan 04 Tasks 1-3 and 5.

- [ ] Record current implementation SHA, installed binary hashes, available native owner symbols and concrete tests. Run `git rev-parse HEAD` and `rg -n 'pub (struct|enum|trait)|fn ' crates/kernel/chio-kernel/src/admission_operation/capture.rs`. Confirm actual owner integration against M0, rather than assuming the north-star docs are an API.
- [ ] Create this negative prerequisite fixture. These are evidence assertions, never configuration switches that enable authority:

```json
{
  "schema": "chio.macos.vm-prerequisites.v1",
  "profile": "vm-project-v1",
  "native_crossing_owner_verified": false,
  "durable_stop_verified": false,
  "original_operation_recovery_verified": false,
  "immutable_import_verified": false,
  "backend_launch_binding_verified": false,
  "installed_tuple_verified": false,
  "expected": "profile_unavailable"
}
```

- [ ] Add `missing_native_owner_refuses_before_launch` to the M2 controller integration suite. Arrange the negative fixture, request task preparation through the actual M2 method, and assert zero VM starts, zero model requests and `profile_unavailable`. The test must inspect a fake VM launch counter and an independent resource listener, not only compare the returned string.
- [ ] Run `cargo test -p chio-desktop --test macos_vm_contract missing_native_owner_refuses_before_launch -- --exact`. Before integration expect a missing test/module or failed zero-start assertion; after wiring expect pass with zero effects. A fixture's booleans are not sufficient to pass production preflight: the native owner and qualification verifier must validate referenced evidence.
- [ ] Add the lab authority boundary fixture: `{"production_qualification_present":false,"signed_driver_digest_matches":true,"native_fixture_authority_verified":true,"fixture_scope":"synthetic-resources-only","expected_probe_class":"candidate","expected_production_launches":0}`. The native verifier must validate the actual authority and referenced resources; these booleans only describe test conditions. Test that the dedicated probe can collect candidate observations with otherwise valid prerequisites, while production rejects the same authority, an out-of-scope user resource is denied, and a changed driver digest prevents candidate execution. Run `cargo test -p chio-desktop --test macos_vm_contract lab_authority_cannot_enable_production -- --exact`; expect zero production launches and no qualified availability transition.
- [ ] Assign unsatisfied work: M0 kernel owner delivers native admission/fence/launch-reference verification and verification of separately scoped fixture authority; M6 owner supplies lost-result reconciliation; plan 04 Tasks 1-3 and 5 supply retained immutable input and bounded model-route foundations; this plan's owner delivers the VZ/transport/lifetime boundary. Keep production unavailable until each production prerequisite record is verified. Candidate probes need authentic fixture authority and their own prerequisites, not a preexisting production qualification artifact.
- [ ] Commit only the prerequisite fixtures, gate tests and source crosswalk after review: `git add integrations/macos/qualification/vm-prerequisites.json integrations/macos/tests/fixtures/vm/missing-native-owner.json integrations/macos/tests/fixtures/vm/lab-authority-boundary.json crates/products/chio-desktop/tests/macos_vm_contract.rs`; `git commit -m "test(macos): gate VM execution on native prerequisites"`.

### Task 2: Define and test a closed VM topology

**Files:** Create `VMTopology.swift` and `integrations/macos/native/Tests/ChioVMTests/VMTopologyTests.swift`; modify the shared Swift package target list.

- [ ] Add the failing test below before the production model. It tests forbidden effects in configuration, not an arbitrary default value.

```swift
import XCTest
@testable import ChioVM

final class VMTopologyTests: XCTestCase {
    func testRejectsNetworkAndHostShares() throws {
        let safe = VMTopology(architecture: .arm64, cpuCount: 2,
                              memoryBytes: 2_147_483_648,
                              networkDeviceCount: 0, sharedDirectoryCount: 0)
        XCTAssertNoThrow(try safe.validate(hostArchitecture: .arm64))
        let networked = VMTopology(architecture: .arm64, cpuCount: 2,
                                   memoryBytes: 2_147_483_648,
                                   networkDeviceCount: 1, sharedDirectoryCount: 0)
        XCTAssertThrowsError(try networked.validate(hostArchitecture: .arm64))
        XCTAssertThrowsError(try safe.validate(hostArchitecture: .x86_64))
        let shared = VMTopology(architecture: .arm64, cpuCount: 2,
                                memoryBytes: 2_147_483_648,
                                networkDeviceCount: 0, sharedDirectoryCount: 1)
        XCTAssertThrowsError(try shared.validate(hostArchitecture: .arm64))
    }
}
```

- [ ] Run `swift test --package-path integrations/macos/native --filter VMTopologyTests`. Expect compile failure until the new type exists.
- [ ] Implement the complete pure topology model below. Resource limits supplied to it originate from the retained native task preparation; the model itself grants no resources.

```swift
public enum VMArchitecture: String, Codable, Sendable { case arm64, x86_64 }
public enum VMTopologyError: Error { case architecture, resources, ambientAccess }

public struct VMTopology: Equatable, Sendable {
    public let architecture: VMArchitecture
    public let cpuCount: Int
    public let memoryBytes: UInt64
    public let networkDeviceCount: Int
    public let sharedDirectoryCount: Int

    public init(architecture: VMArchitecture, cpuCount: Int, memoryBytes: UInt64,
                networkDeviceCount: Int, sharedDirectoryCount: Int) {
        self.architecture = architecture
        self.cpuCount = cpuCount
        self.memoryBytes = memoryBytes
        self.networkDeviceCount = networkDeviceCount
        self.sharedDirectoryCount = sharedDirectoryCount
    }

    public func validate(hostArchitecture: VMArchitecture) throws {
        guard architecture == hostArchitecture else { throw VMTopologyError.architecture }
        guard cpuCount > 0, memoryBytes > 0 else { throw VMTopologyError.resources }
        guard networkDeviceCount == 0, sharedDirectoryCount == 0 else {
            throw VMTopologyError.ambientAccess
        }
    }
}
```

- [ ] Rerun the focused test and add negative memory/CPU values. Apple-supported resource ranges are checked separately by the factory using the actual OS, not guessed constants.
- [ ] Commit the model/tests and coordinated package edits with `git commit -m "feat(macos): define closed VM topology"` after adding only the four named files.

### Task 3: Construct the real Virtualization boundary

**Files:** Create `VirtualMachineFactory.swift`, `VMInstanceRegistry.swift`, `integrations/macos/native/Tests/ChioVMTests/VMConfigurationTests.swift`, `integrations/macos/tests/fixtures/vm/topology-negative.json`.

- [ ] Define proposed local factory input `PreparedVMFiles` as retained, owner-controlled kernel/initrd/root-disk/scratch-disk file references plus verified digests, architecture, input-generation reference and resource limits. File references must remain under trusted custody across validation/start; do not accept guest paths or reopen a mutable user pathname. The native preparation owner supplies the opaque native binding separately. Define `VMInstanceID` as a fresh host UUID used only for instance lookup, never a native operation ID.
- [ ] Add configuration tests that inspect the actual `VZVirtualMachineConfiguration`: zero NICs/shares, one allowed socket device, no audio/clipboard/USB/passthrough, read-only root image and private scratch. Include replaced-image/changed-inode failures before start and an architecture mismatch. Run `swift test --package-path integrations/macos/native --filter VMConfigurationTests`; expect failure until factory construction enforces each invariant.
- [ ] Implement the actual VZ configuration with this minimum closed device setup inside the factory, after retained file/digest checks and architecture validation:

```swift
import Virtualization

func installClosedDevices(on configuration: VZVirtualMachineConfiguration) {
    configuration.networkDevices = []
    configuration.directorySharingDevices = []
    configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
    configuration.audioDevices = []
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
}
```

The complete factory additionally constructs `VZLinuxBootLoader`, immutable root and fresh writable scratch attachments, sets admitted CPU/memory, calls `validate()`, and retains the resulting `VZVirtualMachine` with files and binding until termination. Keep `VZVirtualMachine` access on its required dispatch queue. Reject every undeclared device before start. The storage constructor and supported SDK symbols must be verified against the pinned SDK as part of Task 1; do not guess platform availability.
- [ ] In `VMInstanceRegistry`, define `insert(instanceID:vm:nativeBindingRef:launchGeneration:)`, `bindConnection(instanceID:connection:)`, `lookupOwned(instanceID:)`, and `retire(instanceID:)` as internal owner-only operations. Store actual VM object identity and current lifecycle state. Duplicate insertion or binding after retirement fails; no guest-provided run ID indexes an arbitrary registry entry. Test two VMs, identical guest names and stale instance reuse.
- [ ] Run configuration/registry tests, then build `swift build --package-path integrations/macos/native --target ChioVM`. This proves component compilation, not a signed launch. Commit only the named files with `git commit -m "feat(macos): create isolated VM instances"`.

### Task 4: Bound and authenticate the private guest channel

**Files:** Create `guest-v1.schema.json`, `GuestFrameDecoder.swift`, `GuestSocketServer.swift`, `integrations/macos/native/Tests/ChioVMTests/GuestChannelTests.swift`, fixtures under `integrations/macos/tests/fixtures/vm/guest-channel/`.

- [ ] Define the new `chio.macos.guest.v1` schema with no additional properties. Envelope fields: `version` fixed to that string; `request_id` bounded to 128 ASCII bytes for transport dedupe only; `launch_generation` an exact opaque host-issued string; `method` one of `hello`, `launch.prepare`, `launch.ready`, `invocation.start`, `invocation.finished`, `resource.call`, `resource.result`, `artifact.chunk`, `artifact.finish`, `heartbeat`, `stop.notice`, `stop.ack`; and a method-specific closed `body`. Task 0 owns the supervisor-only launch/invocation/control semantics and the actual guest peer. The `hello` body contains one single-use challenge and the enrolled image/protocol binding. Resource bodies carry opaque native resource/operation references and bounded canonical input, never credentials or approval signatures. Artifact chunk body contains stream ID, monotonic offset and bounded bytes; finish carries admitted total and content digest. Worker FD 4 relays cannot send supervisor control/completion messages; an authenticated guest message remains an observation until native attribution verification passes.
- [ ] Use a four-byte unsigned network-order payload length and a maximum payload of 1,048,576 bytes. Decoder state includes at most one bounded in-progress frame. Define `feed(_ bytes: Data) throws -> [Data]`; reject excessive length before allocating payload, reject duplicate JSON keys/invalid numeric representations/depth over 32, and require one complete canonical JSON envelope with no trailing bytes. Reuse a verified canonical decoder rather than trusting `JSONDecoder` to reject duplicate keys.
- [ ] Create exact adversarial fixtures: prefix `00 10 00 01` with no body; truncated prefix; two `method` keys; 33 nested arrays; foreign launch; replayed hello; unknown `approval.submit`; 33 outstanding calls; request ID reused with different body. Add a fragmented valid hello and valid bounded resource call as controls. Each negative has expected `transport_bound_exceeded`, `guest_identity_mismatch` or protocol refusal and zero broker calls.
- [ ] Run `swift test --package-path integrations/macos/native --filter GuestChannelTests`; expect failure for the unimplemented decoder/binding, then pass after implementation. Fuzz incremental chunking so every possible split of a valid frame returns exactly one equivalent message; every prefix of an incomplete frame returns no dispatch.
- [ ] Implement one listener per retained VM instance; admission comes from actual listener/VM ownership plus fresh handshake, never CID/run strings alone. Enforce 10-second hello timeout, 32 outstanding calls and 16 MiB aggregate unprocessed channel data; close on excess. Provider/resource work is outside the listener callback. Retire challenge on first acceptance and connection on stop/epoch change.
- [ ] Commit the schema/parser/server/fixtures after focused tests with `git commit -m "feat(macos): bind bounded guest channels to VM launches"`.

### Task 5: Connect native resource dispatch and output custody

**Files:** Create `crates/products/chio-desktop/src/platform/macos/vm.rs`; extend `macos_vm_contract.rs`; add `integrations/macos/tests/fixtures/vm/release-channels.json`.

This task integrates the established VM backend from Tasks 2-4 with the resource foundations from plan 04 Tasks 1-3 and 5. Resource output quarantine/protected-test integration proceeds against that backend; completed publication is not a prerequisite for creating or probing it. Candidate runs use native fixture authority until independent production qualification exists.

- [ ] Map each guest resource call to the actual M0 native owner entry point and retain its original opaque operation reference before returning any result. Obtain native-owned integrity, budget, policy and stop binding from that owner. Do not add a Swift or controller `admit`, approval signer, stop counter or surrogate receipt store. If no owner API exists, return Task 1's missing prerequisite result.
- [ ] Add fixture inputs for revoked capability, changed import generation, wrong launch, exhausted budget, changed exact approval and reused transport ID. Assert zero effect at a controlled host resource receiver for each negative. For a valid call, lose the response and resend the same client intent; assert one receiver effect and delivery/reconciliation of the original native result.
- [ ] Add all output channels to the fixture:

```json
{
  "channels": ["artifact", "stdout", "stderr", "diagnostic", "metric_label"],
  "canary": "CHIO_VM_RESTRICTED_TEST_INPUT",
  "return_contract": "summary_only",
  "expected_raw_canary_exports": 0,
  "expected_native_release_references": 1
}
```

The controlled test input is synthetic. Invoke actual native release and inspect the exported bytes independently. Count the release reference according to the one summary operation, not one receipt per channel; confirm every suppressed channel remains in protected custody.
- [ ] Run `cargo test -p chio-desktop --test macos_vm_contract native_resource_and_release_custody`. Expected: denied calls never reach receiver, one valid effect survives retry, no raw canary escapes, and the original native verifier validates release evidence. Commit controller mapping and these tests with `git commit -m "feat(macos): route VM effects through native owners"`.

### Task 6: Implement launch custody, stop and restart reconciliation

**Files:** Create `VMLifecycle.swift`, `integrations/macos/native/Tests/ChioVMTests/VMLifecycleTests.swift`; extend Rust integration tests and M6 recovery mapping.

- [ ] Define the local projection below. It deliberately cannot collapse VM termination into native effect completion:

```swift
public enum VMExitObservation: String, Codable, Sendable {
    case notObserved, stopped, forced, failedToStop
}
public struct VMClosureObservation: Codable, Sendable {
    public let instanceID: String
    public let stopRequested: Bool
    public let exit: VMExitObservation
    public let nativeFenceReference: String?
    public let unresolvedNativeOperationReferences: [String]
}
```

- [ ] Add failing tests with crash cutpoints after allocation, durable binding, socket registration, start request and start completion. The same client intent must reconcile one VM or close abandoned custody; two live VM objects for one intent fail. Test `requestStop()` acknowledgement without exit, force-stop error, a guest ignoring shutdown and a delayed broker response after VM exit.
- [ ] Implement the sequential lifecycle `allocated -> prepared -> binding_retained -> channel_ready -> starting -> running -> stopping -> terminated`, with explicit failed/unresolved states retained by M6. Before start, revalidate native owner eligibility and retained configuration. Before forced stop, request native fence and track acknowledgement independently; close guest dispatch promptly even if the authority response is unknown. Use the owned VM object's request/force-stop APIs and actual completion/delegate events.
- [ ] On disconnect/crash/wake, invalidate channel eligibility and ask M6 to reconcile original native operations before resuming. No task inherits an old launch challenge or guest snapshot authority. Confirm launcher process incarnation before any OS signal. Failed broker closure leaves original outcome unresolved even with confirmed VM termination.
- [ ] Run `swift test --package-path integrations/macos/native --filter VMLifecycleTests` and `cargo test -p chio-desktop --test macos_vm_contract vm_stop_and_recovery`. Expected: all cutpoints maintain single custody, post-fence release denies, precommitted effects remain possible and truthfully recorded. Commit with `git commit -m "feat(macos): retain VM closure and recovery state"`.

### Task 7: Make placement and native build exclusions executable

**Files:** Create `integrations/macos/tests/fixtures/vm/placement.json`; extend controller/profile tests; coordinate remote implementation with delegation/host owner.

- [ ] Add this fixed matrix to profile preparation tests:

```json
[
  {"selected":"vm-project-v1","requires":"portable-linux","fallback":null,"expected":"eligible_if_qualified"},
  {"selected":"vm-project-v1","requires":"xcode","fallback":null,"expected":"profile_unavailable"},
  {"selected":"vm-project-v1","requires":"simulator","fallback":"native-descendant-v1","expected":"new_binding_required"},
  {"selected":"vm-project-v1","requires":"portable-linux","fallback":"remote-project-v1","expected":"new_export_authority_required"},
  {"selected":"native-descendant-v1","requires":"arbitrary-build-script","fallback":null,"expected":"independent_native_qualification_required"}
]
```

- [ ] Test changed remote provider/region/worker certificate before upload against an independent export listener. Preserve remote operation identity after lost result and reject automatic new-operation retries. Native signing input must bind exact artifact, identity and entitlements with zero reusable private-key material in guest/channel/process environment.
- [ ] Keep the candidate Mac-native alternatives in [the VM specification](../../specs/2026-10-07-macos-integration/07-vm-execution.md): bounded native broker, qualified native descendant, separately qualified macOS VM or declared remote Mac. An arbitrary native build script cannot be enabled by classifying `xcodebuild` as a trusted command.
- [ ] Run `cargo test -p chio-desktop --test macos_vm_contract placement_and_native_build_refusals`. Expected: every negative has zero unintended native starts/exports; qualified explicit choice uses its own evidence. Commit tests and profile logic with `git commit -m "feat(macos): enforce execution placement boundaries"`.

### Task 8: Build independent VM qualification probes

**Files:** Create `integrations/macos/native/Sources/ChioVMProbe/main.swift`, `integrations/macos/qualification/verify_vm_evidence.py`, `integrations/macos/tests/test_vm_evidence.py`, `integrations/macos/qualification/vm-cases.json`, guest corpus `integrations/macos/qualification/guest/vm_probes.py`.

- [ ] Define the dedicated probe executable command contract: `ChioVMProbe run --cases PATH --output DIRECTORY --installation-manifest PATH --fixture-authority-file PATH`. The last file contains an opaque native fixture-authority reference verified by the actual owner, not a signing key or a flag disabling production checks. The probe must reject absent/mismatched signed-installation evidence, driver digests or fixture authority; it does not require a preexisting production qualification artifact. It exercises the exact production driver bytes and restricts all admitted resources/effects to the fixture authority. Never request SIP disablement or self-sign qualification. `vm-cases.json` enumerates every acceptance ID, environment pins and independent observer requirements. Required cases include guest root networking, host/sibling canaries, transport floods, image substitution, controller/launcher death, native stop race, sleep/wake, reboot, restore, remote placement refusal and attempted promotion of fixture authority into production.
- [ ] Define each result as `case_id`, `profile`, `host_os_build`, `host_arch`, `guest_arch`, `component_digests`, `native_evidence_refs`, `observer_digest`, `positive_control_passed`, `effect_count`, `expected_effect_count`, `coverage_complete`, and `verdict`. Missing/unknown fields reject. The probe emits untrusted observations; native references are verified by the existing M0/M6 verifier before the final release gate.
- [ ] Implement this complete minimum independent row check in `verify_vm_evidence.py`, then extend parsing/digest/native-verifier composition without weakening it:

```python
def check_observed_case(row):
    required = {"positive_control_passed", "effect_count", "expected_effect_count",
                "coverage_complete", "observer_digest"}
    if not required.issubset(row):
        return False
    if row["positive_control_passed"] is not True or row["coverage_complete"] is not True:
        return False
    if type(row["effect_count"]) is not int or type(row["expected_effect_count"]) is not int:
        return False
    digest = row["observer_digest"]
    if not isinstance(digest, str) or len(digest) != 64:
        return False
    if any(c not in "0123456789abcdef" for c in digest):
        return False
    return row["effect_count"] == row["expected_effect_count"]
```

- [ ] Add a test that fails when a denied probe has zero effects because the receiver is broken: `assert not check_observed_case({"positive_control_passed": False, "coverage_complete": True, "effect_count": 0, "expected_effect_count": 0, "observer_digest": "a" * 64})`. Add unknown coverage, architecture mismatch, missing native launch lane and forged observer digest tests. The full verifier recomputes referenced file digests and verifies independently pinned native signers; the helper above is not a security verifier by itself.
- [ ] Run `python3 -m unittest discover -s integrations/macos/tests -p 'test_vm_evidence.py'`. Expected: the deliberately incomplete/sensor-only bundles all reject; a fixture with valid external observations passes only fixture verification, never installed qualification.
- [ ] On an explicitly enrolled clean lab Mac, run the signed installed probe binary with M8's exact installation path and separately verified native fixture authority. It collects candidate observations without changing production availability. Then run `python3 integrations/macos/qualification/verify_vm_evidence.py --bundle output/macos-vm-qualification --profile vm-project-v1`. Expected: all 18 acceptance IDs covered, matching OS/architecture/component pins, independently observed effect counts and native verification pass. Compose these results through spec 17's independent semantic verifier and reviewed qualification artifact before the native compatibility owner may enable production. If entitlement/hardware/native fixture prerequisites are missing, exit nonzero with `unqualified`; missing production qualification alone does not block the properly authorized candidate probe.
- [ ] Commit probe/verifier/corpus with `git commit -m "test(macos): qualify VM boundaries with outside observers"` after adding only this task's files. Store machine-specific evidence outside source fixtures and route release claims to M8.

## Requirement coverage and final checks

| Task | Acceptance coverage |
| --- | --- |
| 0 | AT-MAC-VM-001, AT-MAC-VM-003, AT-MAC-VM-005 through AT-MAC-VM-013, AT-MAC-VM-017 and AT-MAC-VM-018, with image/peer/FD/attribution subcases |
| 1 | AT-MAC-VM-001, AT-MAC-VM-007, AT-MAC-VM-017 |
| 2-3 | AT-MAC-VM-003, AT-MAC-VM-004, AT-MAC-VM-005, AT-MAC-VM-009 |
| 4 | AT-MAC-VM-006, AT-MAC-VM-009 |
| 5 | AT-MAC-VM-007, AT-MAC-VM-013, AT-MAC-VM-017 |
| 6 | AT-MAC-VM-008, AT-MAC-VM-010, AT-MAC-VM-011, AT-MAC-VM-012 |
| 7 | AT-MAC-VM-002, AT-MAC-VM-014, AT-MAC-VM-015, AT-MAC-VM-016 |
| 8 | All preceding cases, plus AT-MAC-VM-018 integrated adversarial qualification |

- [ ] Run focused Rust/Swift/Python suites, then repository-required `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`, `cargo build --workspace`, and `cargo test --workspace` on the final implementation head. Record environmental failures separately from passing focused checks.
- [ ] Audit the evidence for every output channel and both worker/tool lanes; no guest claim or provider receipt can replace the native crossing/launch binding. Record installed profile qualification separately from component checks and source review.
- [ ] Hand the established backend to plan 04's integrated output/protected-test and publication tasks; hand the complete candidate composition to M8/spec 17 for independent qualification. Only the matching verified-qualification artifact can enable production. If a candidate native/remote profile is still unavailable, keep its refusal fixtures and document its owned unmet gate rather than weakening the local VM definition.
