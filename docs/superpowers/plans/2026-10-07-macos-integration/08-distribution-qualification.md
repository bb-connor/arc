# Mac Distribution and Independent Qualification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a signed Mac release pipeline and independently verify each selected execution profile against exact installed evidence, including operations, privacy, performance, and recovery failure cases.

**Architecture:** The native authority remains the sole owner of task grants, approvals, stop generations, budgets, and recovery. The package updater and qualification harness orchestrate platform lifecycle and external observations; an independent semantic verifier consumes native proofs and a pre-run immutable applicability manifest. Document/schema validation never qualifies runtime behavior.

**Tech Stack:** Swift, Swift Package Manager, Xcode, Security/SystemExtensions/ServiceManagement frameworks, Rust controller/native verifier, Python 3 standard-library harness with a locked JSON Schema dependency, Developer ID, `codesign`, `notarytool`, `stapler`, `spctl`, and independently controlled test receivers.

---

This is a future implementation plan. No listed app, installer, certificate, entitlement, provider, semantic verifier, or runtime result is delivered by the specification change. Commands below run only after their owning step creates the files and the required native implementation is accepted. Signing, notarization, host permission changes, destructive lab fault injection, and release publication belong to the later authorized execution, not this documentation task.

Inputs: [distribution](../../specs/2026-10-07-macos-integration/12-distribution.md), [privacy/performance](../../specs/2026-10-07-macos-integration/13-privacy-performance.md), [operations](../../specs/2026-10-07-macos-integration/14-operations.md), [qualification](../../specs/2026-10-07-macos-integration/17-qualification.md), and [research](../../specs/2026-10-07-macos-integration/research/distribution.md).

Prerequisite order: M0 native kernel contracts; M1 native presentation; M2 authenticated shared operator/controller; M6 durable recovery/evidence; then the selected M3 VM, M4 publication/resources, M5 native enforcement, and M7 adapter/delegation tracks. M8 can build packaging and verifier tooling earlier, but qualifies a profile only after all of its applicable tracks pass. Track numbers do not imply a simple ascending execution order.

Qualification bootstrap uses a dedicated signed lab probe against the exact installed driver/runtime bytes, isolated to test-user or VM-host resources and explicit native fixture authority. It does not launch a user execution profile or bypass production qualification. Once independent verification constructs the exact-tuple qualification artifact, re-exercise ordinary production admission with that actual artifact and bounded ordinary native test authority before release approval. Production binaries receive no skip-qualification flag or unsafe environment/feature override. Real installed observations using synthetic resources are distinct from fabricated component evidence.

## File and ownership map

Current design inputs are the four linked specifications and `docs/superpowers/specs/2026-10-07-macos-integration/contracts/release-evidence.schema.json`. Existing native proof/state owners are identified by M0 and M6; change those owners if a required proof is missing, rather than adding a substitute Swift approval store. Every implementation path below is proposed or is a scaffold delivered by a prerequisite track, not an assertion that it exists now.

| Proposed path | Responsibility |
| --- | --- |
| `integrations/macos/app/ChioMac.xcodeproj` | Xcode app project, scheme `ChioMac`, target signing/build settings, nested helper/provider embedding |
| `integrations/macos/native/Package.swift` | Shared native package, `ChioMacUI` library and tests, plus focused lifecycle/distribution targets added here |
| `integrations/macos/native/Sources/ChioMacDistribution/` | Platform approval observations, extension lifecycle, package generation reconciliation |
| `integrations/macos/native/Sources/ChioMacOperations/` | User-session observation and scoped keychain broker adapter; no authority signer |
| `crates/products/chio-desktop/src/platform/macos/` | Existing-by-M2 controller adapter hooks for native fence/reconciliation and lifecycle projections |
| `integrations/macos/distribution/release-inputs.json` | Exact approved build/signing identifiers, inputs, component closure, security floor, and matrix candidate |
| `integrations/macos/distribution/scripts/` | Build, inventory, packaging, notarization, and installed identity capture |
| `integrations/macos/qualification/manifests/` | Pre-run immutable per-profile applicability, exact tuple, required subcases, controls, oracles, thresholds |
| `integrations/macos/qualification/verifier/` | Safe artifact loading, trusted-manifest verification, independent case predicates, native-proof adapter, scoped report |
| `integrations/macos/qualification/observers/` | Outside filesystem/process/receiver/permission/energy collectors with explicit identity and run nonce |
| `integrations/macos/qualification/cases/` | Executable distribution, lifecycle, privacy, performance, and selected-profile attack scenarios |
| `integrations/macos/qualification/probe/` | Dedicated signed lab-probe source/target with distinct code identity, scoped native fixture-authority binding, and exact installed driver observation |
| `integrations/macos/qualification/run.py` | Bounded lab runner with separate component and installed modes; unavailable prerequisites return closed results |
| `integrations/macos/qualification/tests/` | Shape-valid fraud corpus, manifest coverage tests, observer-health tests, statistical tests |
| `integrations/macos/qualification/results/` | Ignored local runs; content-addressed artifacts and candidate reports, never committed secrets or purported fixture qualification |
| `integrations/macos/docs/` | Public consumer installation, permission, incident, recovery, update, removal, and evidence runbooks |

## Task 1: Freeze applicability and a release candidate tuple

**Files:** Create `integrations/macos/qualification/manifests/profile-manifest.schema.json`, `integrations/macos/qualification/manifests/observe-v1.json`, `integrations/macos/qualification/tests/test_applicability.py`, and `integrations/macos/qualification/verifier/applicability.py`. Modify the candidate-only schema only if a reviewed incompatibility requires an explicit new version.

- [ ] **Step 1: Write a failing exact-coverage test.** Define the new API `required_cases(manifest: dict) -> set[str]` and `check_case_set(manifest: dict, cases: list[dict]) -> None`; duplicate IDs, missing IDs, and unbound extras raise `ValueError`. The fixture deliberately names only two component-stage cases so the unit test makes no installed claim.

```python
import unittest
from verifier.applicability import check_case_set

class ApplicabilityTests(unittest.TestCase):
    def test_missing_and_duplicate_cases_are_rejected(self):
        manifest = {"required_cases": ["AT-MAC-VER-001", "AT-MAC-VER-002"]}
        with self.assertRaisesRegex(ValueError, "case_set_mismatch"):
            check_case_set(manifest, [{"acceptance_id": "AT-MAC-VER-001"}])
        with self.assertRaisesRegex(ValueError, "duplicate_case"):
            check_case_set(manifest, [
                {"acceptance_id": "AT-MAC-VER-001"},
                {"acceptance_id": "AT-MAC-VER-001"},
            ])
```

- [ ] **Step 2: Run** `PYTHONPATH=integrations/macos/qualification python3 -m unittest discover -s integrations/macos/qualification/tests -p test_applicability.py -v`. Expected: import failure before creation of the implementation.
- [ ] **Step 3: Implement the pure coverage rule.** Keep manifest trust, exact tuple, classification, and subcase predicates separate from this small set function.

```python
def required_cases(manifest):
    values = manifest["required_cases"]
    if len(values) != len(set(values)):
        raise ValueError("duplicate_manifest_case")
    return set(values)

def check_case_set(manifest, cases):
    values = [case["acceptance_id"] for case in cases]
    if len(values) != len(set(values)):
        raise ValueError("duplicate_case")
    if set(values) != required_cases(manifest):
        raise ValueError("case_set_mismatch")
```

- [ ] **Step 4: Define the manifest schema and expand real applicability.** Require profile/features, exact host/component tuple, prerequisite proof digests, explicit acceptance IDs/subcases, required evidence class, control and observer digests, predicate ID/version, thresholds, invalidation map, and an externally authenticated pre-run binding. Enumerate the complete candidate-evidence set separately from final production-admission confirmation; this separation cannot remove a candidate case to make the first artifact pass. Derive `observe-v1` from the specs, including refusal of mutation and authority restoration when excluded. Permit null restore freshness only under that explicit exclusion and required refusal case. Do not use a wildcard “all tests passed” field or allow a candidate to select its own one-case manifest. Add the exact missing/duplicate/extra-case negatives from the test.
- [ ] **Step 5: Rerun the test and review the manifest before any installed run.** Expected: coverage tests pass; the complete `observe-v1` manifest is candidate-only, with no `qualified` field. Proposed first build experiment is arm64/macOS 15.0 deployment target. Exact installed OS builds remain selected by measured lab availability and evidence, never invented as passed rows.
- [ ] **Step 6: Commit only these implementation files.** Suggested message: `feat(macos): define immutable qualification applicability`.

## Task 2: Safe content-addressed artifact loading and fraud fixtures

**Files:** Create `integrations/macos/qualification/verifier/artifacts.py`, `integrations/macos/qualification/tests/test_artifacts.py`, and `integrations/macos/qualification/tests/fixtures/fraud/`.

- [ ] **Step 1: Add failures for random digest-shaped references, traversal, symlinks, duplicate JSON keys, and overlarge inputs.** Use temporary directories and `hashlib.sha256` over actual bytes. Tests must verify the artifact root's outside sentinel is unchanged.

```python
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from verifier.artifacts import load_artifact, parse_object

class ArtifactTests(unittest.TestCase):
    def test_bytes_not_digest_shape_establish_integrity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = hashlib.sha256(b"valid").hexdigest()
            (root / digest).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                load_artifact(root, digest)

    def test_duplicate_keys_fail(self):
        with self.assertRaisesRegex(ValueError, "duplicate_key"):
            parse_object(b'{"result":"fail","result":"pass"}')

    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = hashlib.sha256(b"fifo-fixture").hexdigest()
            os.mkfifo(root / digest)
            result = subprocess.run(
                [sys.executable, "-c",
                 "import sys; from pathlib import Path; "
                 "from verifier.artifacts import load_artifact; "
                 "load_artifact(Path(sys.argv[1]), sys.argv[2])",
                 str(root), digest],
                capture_output=True, text=True, timeout=1,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid_artifact_size_or_type", result.stderr)
```

- [ ] **Step 2: Run** `PYTHONPATH=integrations/macos/qualification python3 -m unittest discover -s integrations/macos/qualification/tests -p test_artifacts.py -v`. Expected: missing-module failure.
- [ ] **Step 3: Implement bounded loading with no symbolic-link following.** Artifact names are SHA-256 hex, not relative paths supplied by test data. Open with `O_NONBLOCK` before inspecting type so a FIFO cannot block the verifier before `fstat`. Reject every nonregular node before reading. Add bounded actual FIFO-without-writer, directory, Unix-socket, symlink, and disposable character-device fixtures; each must refuse within one second with no read attempted. Keep the artifact directory immutable during verification; later signed observer transport writes to staging before atomically publishing objects.

```python
import hashlib
import json
import os
import re
import stat

LIMIT = 16 * 1024 * 1024

def load_artifact(root, digest):
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("invalid_digest")
    fd = os.open(root / digest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
            raise ValueError("invalid_artifact_size_or_type")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError("oversized_artifact")
    finally:
        os.close(fd)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("digest_mismatch")
    return data

def parse_object(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError("nonfinite_json_constant")
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("object_required")
    return value
```

- [ ] **Step 4: Add schema-valid fraud candidates.** Create separate complete fixtures for absent artifacts, wrong source/installed correspondence, duplicated cases, untrusted manifest, synthetic release attempt, wrong observer, and stale restore reference. Preserve `status=candidate`; never create a fixture falsely presented as an installed qualification report. Tests assert shape acceptance where expected and semantic rejection independently.
- [ ] **Step 5: Run the artifact tests and all applicability tests.** Expected: each negative names a specific failure; no fixture ever causes a qualification artifact to be emitted.
- [ ] **Step 6: Commit** with `feat(macos): verify qualification artifact custody`.

## Task 3: Build and inspect the signed application closure

**Files:** Modify the M1-created `integrations/macos/app/ChioMac.xcodeproj`; create `integrations/macos/distribution/release-inputs.json`, `integrations/macos/distribution/scripts/inspect-bundle.py`, and `integrations/macos/qualification/tests/test_bundle_inventory.py`.

- [ ] **Step 1: Add fixture bundles with a modified nested helper, wrong-team provider, undeclared entitlement, duplicate component ID, wrong architecture, and `get-task-allow=true`.** The inventory test consumes captured `codesign`, `security cms`, `file`, and `lipo` output from fixtures first, then runs the same assertions on final installed bytes. Expected: each unacceptable closure is rejected for its own cause.
- [ ] **Step 2: Implement `inspect-bundle.py` with required CLI arguments `--app`, `--release-inputs`, and `--output`.** Use `subprocess.run` with argument arrays and `check=True`; enumerate all executable Mach-O files and nested bundles without following links outside the bundle; compare exact identifiers, Team ID, architectures, entitlements, provisioning capabilities, and content digests against `release-inputs.json`. Return nonzero for missing inputs or any mismatch. The script records raw platform outputs as supporting evidence, never `qualified=true`.

- [ ] **Step 2a: Materialize source, license, and build provenance.** Create `integrations/macos/distribution/scripts/build-provenance.py` and `integrations/macos/qualification/tests/test_build_provenance.py`. Bind every shipped executable/library/guest asset to immutable public source revision or archive digest, dependency lock entry, vendored patch digest, exact toolchain/build environment, unsigned content digest, final signed digest, and license/source-obligation record. Emit `source-provenance.json` and `sbom.spdx.json`; inventory packaging scripts as executable build inputs. Run two isolated offline rebuilds and compare unsigned content before claiming reproducibility. Reject a missing license, unresolved dependency, unrecorded patch, floating source, unpublished instructed revision, or generated executable absent from the closure.

- [ ] **Step 2b: Enforce production signature and executable-selection policy.** Extend bundle inspection to require Hardened Runtime flags and a secure signing timestamp on every applicable executable, reject `get-task-allow`, and validate actual provisioning capability grants rather than entitlement text alone. Implement `PinnedExecutableResolver` in the M2 Mac controller adapter using package-owned absolute paths, manifest identity/digest verification, a sanitized fixed environment, and no interactive-shell initialization. Add substituted PATH helper, startup-file command, injected-library environment, altered nested helper, missing timestamp, and invalid runtime-flag tests; the external fake-tool sentinel must remain untouched and incompatible code must refuse before launch.

```python
import subprocess

def signature_observation(bundle_path):
    verified = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=4", str(bundle_path)],
        check=True, capture_output=True, text=True,
    )
    identity = subprocess.run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(bundle_path)],
        check=True, capture_output=True, text=True,
    )
    return {"verification": verified.stderr, "identity": identity.stderr}
```

- [ ] **Step 3: Configure scheme `ChioMac`, product name `Chio`, for the proposed arm64/macOS 15.0 experiment.** Embed reviewed helpers and selected providers from their owning tracks with inside-out signing; exact entitlement allowlists and actual provisioned Team ID are release inputs. Do not use `codesign --deep` as an implicit signing policy, disable library validation broadly, or add debug entitlements to make a production build run. Read-only and VM configurations omit unused providers.
- [ ] **Step 4: Archive the actual project.** Run `xcodebuild -project integrations/macos/app/ChioMac.xcodeproj -scheme ChioMac -configuration Release -archivePath output/macos-release/ChioMac.xcarchive archive`. Expected: either a correctly signed archive for the selected real team or a closed signing prerequisite; absence of identity/entitlement is not worked around with ad hoc signing for release evidence.
- [ ] **Step 5: Inspect the archive app.** Run `python3 integrations/macos/distribution/scripts/inspect-bundle.py --app output/macos-release/ChioMac.xcarchive/Products/Applications/Chio.app --release-inputs integrations/macos/distribution/release-inputs.json --output output/macos-release/bundle-inventory.json`. Expected: complete nested closure or precise refusal. Compare independently rebuilt unsigned content before any reproducibility claim.
- [ ] **Step 6: Commit packaging configuration and tests, excluding certificates, provisioning secrets, app binaries, and generated evidence.** Suggested message: `build(macos): pin and inspect release bundle closure`.

## Task 4: Platform service, extension, and keychain observations

**Files:** Create `integrations/macos/native/Sources/ChioMacDistribution/ProviderLifecycle.swift`, `integrations/macos/native/Sources/ChioMacOperations/ServiceRegistration.swift`, `integrations/macos/native/Sources/ChioMacOperations/CredentialQuery.swift`, and matching Swift tests. Modify the prerequisite-created Swift `Package.swift` with these focused targets.

- [ ] **Step 1: Write lifecycle projection tests.** Define local enum `ProviderAvailability` with `absent`, `approvalPending`, `restartPending`, `activeUnqualified`, and `unavailable`; test activation success remains `activeUnqualified`, not execution-ready. Test service denial and missing keychain access stay distinct. Native qualification comes only from the verified reference provided by M2/M6.
- [ ] **Step 2: Run** `swift test --package-path integrations/macos/native --filter DistributionLifecycleTests`. Expected: missing targets/types until added.
- [ ] **Step 3: Implement actual platform calls with explicit error/status observations.** The caller supplies identifiers read from the validated bundle manifest; this code does not supply signing or grant authority.

```swift
import ServiceManagement
import SystemExtensions
import Security

func controllerServiceStatus(plistName: String) -> SMAppService.Status {
    SMAppService.agent(plistName: plistName).status
}

func submitActivation(
    identifier: String,
    delegate: OSSystemExtensionRequestDelegate
) {
    let request = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: identifier,
        queue: .main
    )
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)
}

func credentialQuery(service: String, account: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecUseDataProtectionKeychain as String: true,
        kSecAttrSynchronizable as String: false,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
}
```

- [ ] **Step 4: Complete the delegate with exact observation transitions.** `requestNeedsUserApproval` sets approval pending; `.willCompleteAfterReboot` sets restart pending; immediate completion triggers independent active-code remeasurement; failure records bounded OS error. Replacement returns `.replace` only for the previously validated compatibility decision, otherwise `.cancel`. Keep the delegate alive until terminal callback. Deactivation uses the containing app and retains pending restart until actual provider inspection confirms removal.
- [ ] **Step 5: Add credential creation policy and locked-session tests.** Use the real signed per-user access group and selected accessibility candidate; test denied/missing/migrated/logged-out behavior on the exact Mac build. Never add file-based keychain fallback. Cache lifetime follows native session fencing and token rotation; zeroize/drop broker-owned copies after use where the implementation can guarantee it.
- [ ] **Step 5a: Verify credential rotation against an in-flight external effect.** Bind every broker cache entry to its current native credential generation and invalidate new use on rotation, explicit removal, or session fence. Dispatch one held synthetic request, rotate/delete the token while its reply is withheld, and submit a second request. The independent receiver records token-generation use: no new request uses the old cache, while the first remains attached to its original native operation and known/unknown outcome. Test lost rotation notification by requiring a current-generation check before use; no unconditional retry or new operation identity is permitted.
- [ ] **Step 5b: Implement explicit service opt-in and bounded permission recovery.** Extend `ServiceRegistration.swift` with `notRequested`, `pendingApproval`, `enabled`, `denied`, and `unregistered` projections derived from actual OS observations and retained user choice. Register only after explicit background-service selection; reopening the app must not repeat a denied request. Keep read-only diagnosis usable and open relevant settings only on explicit action. Add fresh-install, opt-out, five-reopen denial, approval withdrawal, and later opt-in cases with outside launch counts; no denied path starts a controller or requests broader permissions.
- [ ] **Step 5c: Implement full aged operational health.** Add `OperationalHealth.swift` and matching tests with separate connectivity, authentication, compatibility, permission, activation, convergence, observation coverage, storage, authority, and closure dimensions. Every observation carries source and observation time; unknown or expired facts remain unknown and cannot become a combined protected Boolean. Map actual native/provider/OS observations through M2's shared health envelope. Independently break each dimension, replay a stale provider heartbeat, lose a reply, and remove storage access; assert exact reason, age, affected-scope refusal, and continued read-only diagnosis.
- [ ] **Step 6: Run Swift tests, then record installed cases through the lab runner introduced next.** Expected: unit tests pass and signed installed tests remain unavailable until actual team/profile access exists. Commit with `feat(macos): observe service provider and credential lifecycle`.

## Task 5: Outside observers and a bounded qualification runner

**Files:** Create `integrations/macos/qualification/run.py`, `integrations/macos/qualification/observers/receiver.py`, `integrations/macos/qualification/observers/processes.py`, `integrations/macos/qualification/observers/files.py`, `integrations/macos/qualification/tests/test_observer_health.py`, `integrations/macos/qualification/tests/test_probe_authority.py`, `integrations/macos/qualification/probe/`, and `integrations/macos/qualification/cases/registry.py`.

- [ ] **Step 1: Add tests proving an unavailable observer cannot pass a no-effect test.** Introduce observer transcript fields `run_nonce`, `observer_digest`, `started_at`, `ready_control`, `events`, and `completed_at`; source code and tool version are pinned by the profile manifest. A ready control must produce an externally observed synthetic event before a zero-effect assertion is meaningful.

```python
def effect_predicate(positive, enforced, bypass):
    for transcript in (positive, enforced, bypass):
        if transcript["ready_control"] != "observed":
            return "inconclusive"
    if len(positive["events"]) != 1:
        return "fail"
    if len(bypass["events"]) != 1:
        return "inconclusive"
    return "pass" if len(enforced["events"]) == 0 else "fail"
```

- [ ] **Step 2: Run** `PYTHONPATH=integrations/macos/qualification python3 -m unittest discover -s integrations/macos/qualification/tests -p test_observer_health.py -v`. Expected: negative disconnected-receiver fixtures are inconclusive, not passing.
- [ ] **Step 3: Implement the external receiver and sentinels.** The receiver runs on a separately controlled lab endpoint, accepts only synthetic run-scoped tokens, records request identity/body digest/connection bytes and time, and exposes read-only results to the verifier. The process observer samples actual process incarnations and audit identities from outside the tested worker/controller; the filesystem observer hashes known synthetic sentinels before/after and records deliberate bypass writes. No observer takes expected outcomes from the tested application's health report.
- [ ] **Step 4: Implement runner arguments `--mode component|installed`, `--manifest`, `--case`, `--output`, and `--record-unavailable`.** Load only a statically registered case implementation for an exact acceptance/subcase ID; arguments are data and never shell source. Generate a unique run nonce, prepare synthetic fixtures, establish observer readiness, invoke the case, record controls/raw artifacts, clean test-owned resources, and write candidate results. Installed candidate cases requiring execution use the dedicated signed probe, not production user-profile admission. Component mode is always `synthetic=true`; genuinely observed installed behavior may use synthetic resource contents without becoming fabricated evidence. Exit nonzero for failed required cases; emit `unavailable` on absent entitlement, native API, host, permission, observer, or fixture authority.
- [ ] **Step 4a: Build the dedicated probe and its native fixture-authority binding.** Give the probe a distinct code identity; bind its native fixture authority to the exact installed driver/runtime digests, run nonce, isolated test-user or VM host, enumerated synthetic resources/test accounts/receivers, budgets, and expiry. Native integrity, approval, crossing, stop, and recovery checks still run. Test missing/wrong probe identity, absent fixture authority, scope expansion, expired fixture authority, and attempts to invoke the probe from production user-profile admission. Expected: all negatives deny before an outside effect. If the native fixture-authority contract is missing, assign it to the M0 owner and keep installed cases unavailable; do not construct an app-local grant shim.
- [ ] **Step 4b: Prove production has no bootstrap bypass.** Inspect built production options/configuration and attempt `--skip-qualification`, unsafe feature/environment overrides, and forged probe principals. Expected: ordinary production admission rejects missing verified qualification regardless of these inputs. Deliberately weakened negative-control code is a separately signed/digested disposable fixture, never a production flag or substituted passing driver.
- [ ] **Step 5: Run** `python3 integrations/macos/qualification/run.py --mode component --manifest integrations/macos/qualification/manifests/observe-v1.json --case AT-MAC-VER-004 --output output/macos-qualification/oracle-controls`. Expected: component observer tests prove efficacy but emit no installed qualification.
- [ ] **Step 6: Commit** with `test(macos): add independent qualification observers`.

## Task 6: Notarization and clean consumer installation

**Files:** Create `integrations/macos/distribution/scripts/package-release.sh`, `integrations/macos/distribution/scripts/notarize-release.sh`, `integrations/macos/qualification/cases/distribution.py`, and `integrations/macos/docs/install.md`.

- [ ] **Step 1: Add installed cases for notarized positive, corrupt nested code, non-notarized artifact, wrong embedding/location/team, denied service/provider/privacy permissions, ambient PATH substitution, and exact tuple mismatch.** Bind them to the distribution acceptance IDs from the spec and include signed negative fixture provenance. Fixture safety settings must not become consumer setup instructions.
- [ ] **Step 2: Package exact reviewed bytes and notarize using a preconfigured secure credential profile.** The script requires the artifact path and keychain profile as arguments, validates they are nonempty, uses arrays/quoted arguments, and stores logs under the run directory. Do not put passwords or signing keys in shell arguments, environment dumps, or source.

```bash
#!/bin/bash
set -euo pipefail
artifact_path=${1:?artifact path required}
notary_profile=${2:?keychain profile required}
record_dir=${3:?record directory required}
mkdir -p "$record_dir"
xcrun notarytool submit "$artifact_path" --keychain-profile "$notary_profile" --wait --output-format json > "$record_dir/notary-submit.json"
xcrun stapler staple "$artifact_path"
xcrun stapler validate "$artifact_path" > "$record_dir/stapler-validate.txt" 2>&1
shasum -a 256 "$artifact_path" > "$record_dir/final-artifact.sha256"
```

- [ ] **Step 3: Make acceptance of the submission status explicit.** Parse `notary-submit.json`, require successful final status, retain submission ID and full log, and reject errors even if a command returned output. Notarize/staple the intended container or app under Apple's documented supported workflow and capture the final post-staple digest. `spctl` app assessment remains a separate installed observation.
- [ ] **Step 4: Execute the clean-Mac consumer case.** Run `python3 integrations/macos/qualification/run.py --mode installed --manifest integrations/macos/qualification/manifests/observe-v1.json --case AT-MAC-DST-003 --output output/macos-qualification/consumer-launch --record-unavailable`. The runner records host build/security settings, download quarantine, online/offline launch, signature and ticket checks. Expected: passing controls on a real qualified tuple or precise closed unavailability, never a local developer exception counted as consumer success.
- [ ] **Step 5: Write install instructions using public artifacts and revisions only.** Explain actual optional approvals, selected unavailable profiles, and how to inspect the release evidence. Verify any instructed Git revision exists in the public repository before publishing. Commit with `build(macos): add notarized consumer distribution path`.
- [ ] **Step 5a: Implement a separately qualified managed installation path.** Create `integrations/macos/distribution/managed/render_payloads.py` and `integrations/macos/qualification/cases/managed_deployment.py`. Render extension, supported PPPC, background-service, and removability payloads from the actual approved Team ID, bundle identities, designated code requirements, and selected OS payload schema; never infer MDM entitlement from a consumer approval. Install and withdraw those exact payloads on an enrolled test Mac, separately testing a standard user, admin, wrong-team identity, denied user override, and managed uninstall. Compare OS/MDM observations with native history: external restrictions are attributed to their administrator, removal cannot create a native grant, no MDM event creates approval/publication authority, and changed management invalidates affected profile evidence.

## Task 7: Update, downgrade, removal, and incident state machines

**Files:** Create `integrations/macos/native/Sources/ChioMacDistribution/UpdateJournal.swift`, `integrations/macos/native/Sources/ChioMacDistribution/UpdateCoordinator.swift`, `integrations/macos/native/Tests/ChioMacDistributionTests/UpdateTests.swift`, `integrations/macos/qualification/cases/update_removal.py`, and `integrations/macos/docs/update-and-remove.md`. Modify the M2/M6 controller lifecycle adapter only through its native fence/reconciliation interfaces.

- [ ] **Step 1: Define and test update stages with one immutable transaction identity.** Introduce the stages exactly as in the distribution spec; journal old/new code digests, state ABI, pending native fence reference, and actual active provider observation. A reducer may choose only the next operational action, never declare native authority. Add tests for new app/old provider, denied replacement, interrupted migration, stale release floor, incompatible schema, and unresolved operation.

```swift
enum UpdateReadiness: Equatable {
    case waitingForFence
    case waitingForReconciliation
    case waitingForProvider
    case readyForNativeRecheck
}

func updateReadiness(
    fenceVerified: Bool,
    originalsReconciled: Bool,
    activeProviderMatches: Bool
) -> UpdateReadiness {
    guard fenceVerified else { return .waitingForFence }
    guard originalsReconciled else { return .waitingForReconciliation }
    guard activeProviderMatches else { return .waitingForProvider }
    return .readyForNativeRecheck
}
```

- [ ] **Step 2: Run** `swift test --package-path integrations/macos/native --filter UpdateTests`. Expected: reducers demonstrate safe intermediate states; Boolean unit fixtures cannot substitute for real native proof verification in the coordinator.
- [ ] **Step 3: Implement the coordinator transaction.** Verify metadata against installer-owned trust roots and expiry/security floor, stage safe files, call the native fence, persist exact proof references, reconcile originals, execute an explicitly supported state migration, replace app/provider, independently remeasure active code, then request native compatibility recheck. Any unknown step enters `recovery-required` with original custody retained. Compatible code rollback never overwrites native authority from the migration backup.
- [ ] **Step 3a: Implement authenticated publisher rotation and revocation.** Create `PublisherTrustPolicy.swift` and `PublisherTrustTests.swift`. Installer-owned authenticated policy binds current and successor signing/update-key identities, accepted metadata generation, expiry no later than seven days, security floor, and revocation records; downloaded metadata cannot replace its own trust root. A valid authenticated rotation permits only its named successor; same bundle name, unrelated key, or TLS alone does not. Test unsigned successor, replayed old metadata, expired offline metadata, revoked current build, interrupted rotation, and an allowed nonrevoked code rollback. Expiry prevents new update activation; observed revocation fences affected admission while retaining original custody and minimal signed incident evidence. Resume requires a newly verified exact-profile record and independent production confirmation, not clearing the warning.
- [ ] **Step 4: Implement removal through the containing app.** Fence and stop owned work, preserve unknown outcomes, deactivate providers, unregister services, inventory actual residuals, and distinguish restart-pending. Default removal preserves projects/evidence/custody; purge is a separate explicit inventory-bound operation. An incident revokes affected trust through its owner and uses the same fence/recovery path.
- [ ] **Step 5: Fault every transition.** Run `python3 integrations/macos/qualification/run.py --mode installed --manifest integrations/macos/qualification/manifests/observe-v1.json --case AT-MAC-DST-009 --output output/macos-qualification/update-crashes --record-unavailable`, then the registered downgrade, removal, storage-fault, and incident cases. Expected: outside effect count remains at most one for an original operation; unknowns survive; a mixed generation never becomes active for governed work.
- [ ] **Step 6: Commit** with `feat(macos): preserve authority across update and removal`.

## Task 8: Shared-Mac lifecycle and rollback-resistant recovery cases

**Files:** Create `integrations/macos/qualification/cases/session_lifecycle.py`, `integrations/macos/qualification/cases/keychain_restore.py`, `integrations/macos/docs/recovery.md`, and `integrations/macos/docs/shared-mac.md`. Modify session-observation integration under `crates/products/chio-desktop/src/platform/macos/` only after M2/M6 have supplied its native fence/reconcile API.

- [ ] **Step 1: Encode the complete session matrix as data.** Each row carries initial user/session, transition, expected native fence disposition, review validity, credential availability, worker closure status, and external outcome. Include window-close without session loss, lock, lost lock signal, user switch, logout, no-user, sleep/wake, reboot, and clock shift. Do not assume launchd sends a complete or timely policy event by itself.

```python
SESSION_CASES = (
    # transition, admission, review, credential, worker closure, external outcome
    ("window_close", "custody_continues", "native_expiry", "unchanged",
     "not_implied_by_ui", "unchanged"),
    ("screen_lock", "new_crossings_fenced", "invalidated", "blocked",
     "independently_confirm", "precommitted_effect_may_finish"),
    ("owner_unknown", "new_crossings_fenced", "invalidated", "blocked",
     "independently_confirm", "retain_unknown"),
    ("fast_user_switch", "new_crossings_fenced", "invalidated", "blocked",
     "independently_confirm", "retain_original_outcome"),
    ("logout", "new_crossings_fenced", "invalidated", "blocked",
     "independently_confirm", "retain_original_outcome"),
    ("no_user_logged_in", "no_user_task_authority", "invalidated", "unavailable",
     "global_restriction_is_separate", "retain_original_outcome"),
    ("sleep", "fence_or_record_unconfirmed", "invalidated", "blocked",
     "unconfirmed_until_observed", "retain_unknown"),
    ("wake", "reconcile_before_admission", "invalidated", "revalidate",
     "fresh_identity_and_closure_check", "reconcile_original"),
    ("login", "reauthenticate_then_reconcile", "invalidated", "revalidate",
     "no_automatic_worker_replay", "reconcile_original"),
    ("reboot", "freshness_then_reconcile", "invalidated", "revalidate",
     "new_boot_and_process_identities", "reconcile_original"),
    ("provider_restart", "affected_profile_fenced", "invalidated", "blocked",
     "restriction_coverage_remeasure", "retain_original_outcome"),
    ("clock_shift", "native_deadline_revalidation", "invalidated", "revalidate",
     "no_cross_boot_clock_comparison", "retain_original_outcome"),
)
```

- [ ] **Step 1a: Verify complete lifecycle rows and non-fabricated closure.** Add `test_session_matrix.py` asserting the exact transition set above, six nonempty fields per row, and separate outside worker/flow/external observations. Exercise sleep before/after native fence durability, reboot with an unresolved original effect, no-user global-provider lifetime, and forward/backward wall-clock shifts. Expected: unconfirmed sleep fencing stays unconfirmed, no logged-out user task obtains authority, a new boot does not reuse process identity, and the native deadline owner determines expiry without treating wall-clock adjustment as renewed grant lifetime.

- [ ] **Step 2: Add independent two-user tests.** Use two synthetic standard-user lab accounts, distinct secret/path canaries, identical task labels, simultaneous service instances, forged request identities, and reused numeric UID fixture. Compare OS connection/audit identity, native scope, outside effects, and export contents. Global provider records cannot expose another user's raw task data.
- [ ] **Step 2a: Implement bounded controller restart and single-writer custody.** Create `crates/products/chio-desktop/src/platform/macos/service_lifecycle.rs` and `tests/macos_service_lifecycle.rs`. Persist operational attempt timing separately from native authority, enforce at most three automatic starts in 60 seconds with at least five seconds between attempts, then require explicit recovery. Multiple app instances authenticate and attach to the same native serving-writer scope; an application-local lock cannot elect a second native writer. Add five simultaneous app launches, repeated crashes, launchd restarts, lost post-commit reply, and stale owner-generation tests. Independent process census, native writer records, and destination counters must show bounded restarts, one serving owner, one original operation/effect, and no automatic task replay.
- [ ] **Step 3: Bind restore to M6's real freshness proof.** Snapshot state before a grant is spent, spend/revoke/fence it, then restore database/keychain/home/guest snapshot and clone to a second machine. Remove connectivity to the independent freshness owner. Expected: no restored authority becomes current from a local database, keychain key, or internally consistent hash chain. A missing native freshness API is an owned M0/M6 prerequisite and yields `unavailable`; do not add an application-local counter as a substitute.
- [ ] **Step 3a: Implement a consistent, non-authorizing backup manifest.** Create `integrations/macos/native/Sources/ChioMacOperations/BackupManifest.swift` and `integrations/macos/qualification/cases/backup_inventory.py`. Classify configuration, presentation, protected payload, native snapshot/custody, and required secret-key metadata separately; bind exact schema/component identities, payload digests, original unresolved operations, and the native consistent-snapshot reference when supported. Exclude sockets, transient launch identities, and raw provider secrets. Test missing snapshot/key metadata, concurrent snapshot interruption, tampered digest, unsafe archive path, and unavailable native snapshot API; incomplete backups cannot be labeled complete. Extraction is quarantined and grants nothing. Corrupt store, missing key, truncated provider mapping, or EIO preserves original bytes and unresolved custody, closes affected admission, and exposes bounded diagnosis instead of resetting state.
- [ ] **Step 4: Run** `python3 integrations/macos/qualification/run.py --mode installed --manifest integrations/macos/qualification/manifests/observe-v1.json --case AT-MAC-OPS-011 --output output/macos-qualification/restore-freshness --record-unavailable`. Also register/run every applicable OPS case through the immutable manifest. Expected: external effect counter stays unchanged for stale grants; read-only historical inspection remains possible.
- [ ] **Step 5: Reproduce the runbooks independently.** Each stable reason code maps to a specific operator action, retained evidence, and outside verification. Remove any instruction that deletes an authority database, reuses an old approval, resets a generation, or widens permissions to clear a warning. Commit with `test(macos): qualify shared session and restore boundaries`.

## Task 9: Privacy, retention, and evidence export verification

**Files:** Create `integrations/macos/qualification/cases/privacy.py`, `integrations/macos/qualification/tests/test_redaction.py`, `integrations/macos/qualification/fixtures/privacy-canaries.json`, and `integrations/macos/docs/privacy.md`. Modify the existing-by-M6 diagnostics/export adapter rather than creating another receipt format.

- [ ] **Step 1: Add distinct canaries for each data class and surface.** Include numeric ID, prompt, raw path, provider secret, URL query, untrusted stderr, approval handle, task title, and model response. Scan persisted app diagnostics, available OS logs, argv/env, notifications, crash output, archive names and members, metric labels, and caches after success, denial, failure, restart, and overload.
- [ ] **Step 2: Add a byte-level support-export oracle.** This helper demonstrates exact forbidden-byte matching; production export additionally uses the declared field allowlist, archive bounds, and native evidence disclosure rules.

```python
def leaked_canaries(artifact_bytes, canaries):
    return sorted(
        name for name, value in canaries.items()
        if value.encode("utf-8") in artifact_bytes
    )

def test_support_export_has_no_secret_canary():
    canaries = {"provider_secret": "synthetic-provider-secret-9471"}
    assert leaked_canaries(b'{"reason":"authority_unreachable"}', canaries) == []
    assert leaked_canaries(b"synthetic-provider-secret-9471", canaries) == ["provider_secret"]
```

- [ ] **Step 3: Implement retention and bounded diagnostics against the spec inventory.** Separate native custody from disposable logs; expire payload/caches/indexes consistently, record explicit retained obligations, and shed diagnostics with counters before authority durability is threatened. Preserve signed receipt bytes or clearly identify a redacted derivative; never relabel an edited body as signature-valid.
- [ ] **Step 3a: Implement the versioned collection/disclosure inventory and export preview.** Add `privacy-inventory.json` and enforce it in M6's diagnostic/export adapter: default clipboard, screen, whole-home, host-network-payload, analytics, and crash-upload collectors stay off; task read, model release, app effect, and support export have separate native authority. Generate an exact archive-member/field/time-window/size preview, validate the user's explicit local destination through the existing export contract, and enforce archive bounds and traversal/symlink rejection before materialization. Test project-read-only against model/support release, unrequested collectors, secret-bearing signed payload, oversized archive, preview/body mismatch, and external upload attempt with outside receiver and canaries. Preserve original signed bytes or declare omitted payload/unverified derivative honestly.
- [ ] **Step 3b: Implement fixed-cardinality metrics and diagnostic shedding.** Add `metrics_inventory.json` and a bounded collector using only reviewed enum labels, queue/deadline/drop counters, durations, and scoped opaque IDs where permitted; reject user task names, paths, URLs, prompts, and arbitrary error strings as labels. Bound buffers and storage before callbacks enqueue; callback/authority paths never wait for metric export or log flush. Send one million unique hostile labels, stall the reader, fill disk, and inject a failed native durable commit. Independent producer counts must reconcile gaps; memory/cardinality caps hold, and no failed authoritative commit dispatches an effect.
- [ ] **Step 3c: Gate public artifacts and external telemetry disclosure.** Create `public-artifact-policy.json`, `cases/public_artifacts.py`, and `cases/dependency_telemetry.py`. Public screenshots, recordings, evidence, and bug reports use synthetic task data and per-export host pseudonyms; scan names, metadata, paths, numeric IDs, and low-entropy hashes before export. Public witnessing stays disabled until its separate metadata-disclosure contract is approved. Inventory every dependency/updater/provider/crash destination and payload class, then capture launch, idle, error, update, provider call, and crash traffic independently. Seed a real-looking home/account canary, an unlisted analytics endpoint, and unexpected SDK crash upload; reject undisclosed traffic/artifacts and verify opt-out paths send nothing beyond declared necessary traffic.
- [ ] **Step 4: Execute** `python3 integrations/macos/qualification/run.py --mode installed --manifest integrations/macos/qualification/manifests/observe-v1.json --case AT-MAC-PRV-002 --output output/macos-qualification/privacy-canaries --record-unavailable`, followed by each applicable retention/archive/deletion/telemetry case. Expected: permitted export only, no undeclared network upload, precise statement of OS-managed surfaces the app cannot erase.
- [ ] **Step 5: Commit** with `feat(macos): bound diagnostics and verify evidence privacy`.

## Task 10: Performance and energy measurement with fixed thresholds

**Files:** Create `integrations/macos/qualification/cases/performance.py`, `integrations/macos/qualification/observers/energy.py`, `integrations/macos/qualification/verifier/statistics.py`, `integrations/macos/qualification/tests/test_statistics.py`, and immutable workload fixtures under `integrations/macos/qualification/fixtures/workloads/`.

- [ ] **Step 1: Test percentile computation, paired energy comparisons, missing samples, and low-resolution rejection.** Define nearest-rank percentile for the fixed 30-run latency suite; raw samples remain in evidence and report the estimator. Reject empty or nonfinite values. Energy inference uses a declared paired statistical method and interval, not battery-percentage subtraction.

```python
import math
import unittest

def nearest_rank(samples, percentile):
    if not samples or not 0 < percentile <= 1:
        raise ValueError("invalid_samples_or_percentile")
    if any(not math.isfinite(value) or value < 0 for value in samples):
        raise ValueError("invalid_sample")
    ordered = sorted(samples)
    return ordered[math.ceil(percentile * len(ordered)) - 1]

class StatisticsTests(unittest.TestCase):
    def test_p95_uses_raw_distribution(self):
        self.assertEqual(nearest_rank(list(range(1, 31)), 0.95), 29)
```

- [ ] **Step 2: Instrument distinct boundaries.** Add non-sensitive signposts for view usability, IPC response, native durable acknowledgment, broker overhead, VM start, first result, stop fence, worker death, and flow closure. OS/native/remote clock domains retain their mapping and uncertainty. The outside observer supplies actual process/resource state, not UI labels.
- [ ] **Step 2a: Implement coalesced observation and power-aware work.** Add a shared observer coordinator under `ChioMacOperations` keyed by authenticated native scope, so 20 UI subscribers share one bounded upstream subscription. Stop nonessential polling when no view/task needs it and adapt only optional sampling/rendering to low-power and thermal-pressure notifications. Safety-critical fence propagation and required native/provider callbacks retain their deadlines and dedicated bounded path. Test hidden/visible app, 20 subscribers, lost subscriber cleanup, low-power mode, thermal pressure, and revocation during throttling; outside wakeup/IPC counts must fall while native fence/callback oracles still pass. Missing required deadline or coverage closes the affected profile, never a performance waiver.
- [ ] **Step 3: Implement immutable workload and environment capture.** Record hardware, OS, display, power mode, thermal range, battery health/charge band, SDK/toolchain, source/installed tuple, observer version, baseline digest, model/provider route, and fixture digests. Run five warm-ups plus 30 samples, idle settling and ten-minute idle measurements, contention at 1/8/32 tasks, and hostile event ramp. Apply the pre-run budgets from the privacy/performance specification without post hoc adjustment.
- [ ] **Step 4: Execute paired energy trials.** At least five randomized baseline/candidate 60-minute idle pairs and equivalent useful-work pairs use a declared supported instrument or external meter, calibrated units, tool overhead, raw traces, and paired uncertainty. A high-wakeup regression must fail; inadequate resolution yields inconclusive. Instrument privileges belong to the lab, not the consumer app.
- [ ] **Step 5: Run** `PYTHONPATH=integrations/macos/qualification python3 -m unittest discover -s integrations/macos/qualification/tests -p test_statistics.py -v`, then `python3 integrations/macos/qualification/run.py --mode installed --manifest integrations/macos/qualification/manifests/observe-v1.json --case AT-MAC-PRV-011 --output output/macos-qualification/energy --record-unavailable`. Expected: valid scoped results or explicit inconclusive/unavailable gates, never fabricated measurements. Commit with `perf(macos): measure scoped latency and energy budgets`.

## Task 11: Native-backed semantic verification and scoped result issuance

**Files:** Create `integrations/macos/qualification/verifier/native_proofs.py`, `integrations/macos/qualification/verifier/predicates.py`, `integrations/macos/qualification/verifier/main.py`, `integrations/macos/qualification/tests/test_semantic_verifier.py`, and `integrations/macos/qualification/verifier/verified-qualification.schema.json`.

- [ ] **Step 1: Introduce explicit proof adapter outcomes.** `verify_native_evidence(reference_bytes, trusted_context)` returns verified native semantics or one of invalid/unavailable. The implementation calls the real M0/M6 native verifier contract; the function must not infer validity from JSON fields, shell exit code alone, an unverified child-provided trust root, or a local signature checked against a candidate-provided key. Test adapters are confined to `--mode component` and cannot issue a release artifact.
- [ ] **Step 2: Write fraud tests before the orchestrator.** Cover false `pass`, absent artifact, bad signature, untrusted root, forged observer, mismatched run nonce/tuple, stale anchor, duplicate case, missing required subcase, broken positive/negative control, wrong evidence class, absent/expanded native fixture authority, and omitted payload falsely claimed inspected. Null restore freshness is accepted only for an approved authority-restore exclusion with its required refusal observation. The unchanged fabricated verifier fixture may pass component predicates but is still rejected for release; real signed lab-probe observations are independently checked against their scope and installed bytes.
- [ ] **Step 3: Implement the verifier pipeline in the nine ordered stages defined in the qualification specification.** The following small predicate demonstrates why a candidate result is insufficient. Native proofs and observer transcripts must already be authenticated through the preceding stages.

```python
def derive_case_result(case, trusted_expected, authenticated_observed):
    if case["classification"] != trusted_expected["required_classification"]:
        return "fail"
    if authenticated_observed["run_nonce"] != trusted_expected["run_nonce"]:
        return "fail"
    if authenticated_observed["control_health"] != "verified":
        return "inconclusive"
    return (
        "pass"
        if authenticated_observed["effect_count"] == trusted_expected["effect_count"]
        else "fail"
    )
```

- [ ] **Step 4: Define CLI arguments `--candidate`, `--artifact-root`, `--trusted-release-policy`, `--mode component|release`, and `--output`.** External trusted policy pins accepted verifier/native proof contract, approved manifest, trust roots, observer contracts, and freshness. The candidate's `verifier` entry is compared with that policy; it cannot select policy. Safe loading and schema validation precede semantics; release mode refuses fabricated/synthetic-envelope evidence and missing native API. Output the separate verified qualification report only after every required candidate-evidence gate passes; the manifest's distinct final production-confirmation gate remains necessary for release approval.
- [ ] **Step 5: Bind native compatibility to a verified report reference.** Use the M2/M6 native evidence import/verification path to derive `qualified_for_tuple`; do not let the app set it from a local report Boolean. The report binds candidate/manifest digests, exact tuple, verifier/trust identities, case verdicts, claim exclusions, and invalidation rules. Missing required native import contract remains a prerequisite, not a new app signer. Initial probe execution never sets this state. Retain the immutable report for the ordinary production-admission confirmation in Task 12.
- [ ] **Step 6: Run** `PYTHONPATH=integrations/macos/qualification python3 -m unittest discover -s integrations/macos/qualification/tests -p test_semantic_verifier.py -v`. Then run `python3 -m verifier.main --candidate output/macos-qualification/candidate.json --artifact-root output/macos-qualification/artifacts --trusted-release-policy integrations/macos/qualification/manifests/trusted-release-policy.json --mode release --output output/macos-qualification/verified.json` with `PYTHONPATH=integrations/macos/qualification` set by the lab command wrapper. Expected: release rejection until authentic installed evidence and externally provisioned trust policy exist. Commit with `feat(macos): independently verify profile qualification`.

## Task 12: Profile expansion, adversarial closure, and public release review

**Files:** Create per-profile manifests under `integrations/macos/qualification/manifests/`, selected execution/provider/publication cases under `integrations/macos/qualification/cases/`, and `integrations/macos/docs/release-evidence.md`. Modify public release instructions only after verifying public artifact/revision availability.

- [ ] **Step 1: Expand one profile at a time using the explicit matrix.** `brokered-v1` adds route mediation and credentials; `vm-project-v1` adds exact guest architecture/image and compromised-guest probes; `remote-project-v1` binds both hosts and remote observer; native and managed profiles add their own installed ES/NE/multi-user failure suites. `publication-v1` adds exact effect review/binding/reconciliation to the selected profile. No profile copies another row's pass status.
- [ ] **Step 2: Add actual boundary attacks from the qualification table.** Register pre-existing/inherited handles, direct network and host-socket bypass, symlink/rename/dirty-writer races, PID reuse, exec/reparenting/delegated services, sensor gaps, queue pressure, callback deadline miss, client death, stale provider cache/policy, and HTTP keep-alive/HTTP2/UDP/QUIC flow cases. Each case names its independent destination/sentinel oracle and successful bypass control before it can enter an approved manifest.
- [ ] **Step 3: Close the descendant experiment independently.** Save rendered documentation and DocC metadata, inspect final SDK headers, record actual final OS build and granted entitlement, and run every descendant-specific case. Documentation metadata disagreement is evidence to resolve, not a reason to assume beta or final behavior. If any mechanism is unavailable or a required guarantee fails, retain `native-descendant-v1` as unavailable and release other qualified profiles only.
- [ ] **Step 4: Run every required installed candidate-evidence case from the immutable manifest.** Proposed command: `python3 integrations/macos/qualification/run.py --mode installed --manifest integrations/macos/qualification/manifests/vm-project-v1.json --case all --output output/macos-qualification/vm-project-release --record-unavailable`. Here `all` expands to the manifest's exact complete candidate-evidence case/subcase set; final production confirmation is invoked explicitly after qualification exists. It does not discover only passing tests or silently move failed candidate cases into the later gate. Retain every attempt, prior failure, invalidation reason, control artifact, and raw observation.
- [ ] **Step 5: Confirm the ordinary production admission path with the actual verified artifact.** Run `python3 integrations/macos/qualification/run.py --mode installed --manifest integrations/macos/qualification/manifests/vm-project-v1.json --case AT-MAC-VER-018 --output output/macos-qualification/production-admission --record-unavailable` after Task 11 has produced and natively imported the exact-tuple artifact. Use the normal user-profile path with bounded ordinary native test authority, not the probe. Record one useful allowed effect and one denied-effect control; repeat with missing, forged, wrong-tuple, and revoked qualification references. Expected: both real verified qualification and native task authority are necessary, all negative references refuse admission, and the confirmation binds the immutable artifact digest. This run is a separate final gate and does not rewrite the candidate evidence to claim it qualified itself.
- [ ] **Step 5a: Independently review and reproduce release claims.** A reviewer other than the implementer uses the exact final signed artifact on a clean supported Mac and reconciles passing production confirmation, user-visible capability availability, semantic verifier result, public installation instructions, same-profile privacy/performance evidence, update/removal behavior, and known exclusions. Required failure/unavailable/gap/skip/inconclusive results close the gate. No warning waiver promotes source evidence to installed qualification.
- [ ] **Step 6: Publish only after concrete release review approval under the execution session's authority.** The deliverable before publication is a reviewable final artifact, scoped verified report, source/SBOM closure, consumer runbook, and precise release claim. Do not claim a package was published, activated on customer machines, or qualified in this planning work. Suggested final implementation commit: `docs(macos): publish scoped installation and qualification evidence`.

## Coverage and verification before closing M8

| Specification scope | Implementing tasks | Required evidence |
| --- | --- | --- |
| Distribution source/signing/notary/eligibility/runtime pins | 1, 3, 4, 6 | Actual final code inventory, signatures, provisioning, consumer launch, denied approvals, tuple drift |
| Distribution update/rollback/key rotation/removal/storage/public claims | 7, 8, 11, 12 | Every-stage faults, security floor, current native custody, residual inventory, independent claim audit |
| Privacy inventory/redaction/retention/export/lock/telemetry | 4, 8, 9 | Canary scans, archive audit, retained obligations, same-user/cross-user/session checks, external network capture |
| Metrics/performance/power/overload | 5, 9, 10, 11 | Raw samples, fixed thresholds, paired energy uncertainty, queue/drop counters, distinct closure timing |
| Operations roles/identity/registration/restart/session/secrets | 4, 5, 7, 8 | Authenticated real IPC, singleton/restart bound, keychain state matrix, actual global/per-user separation |
| Operations backup/restore/health/runbook/managed/incident | 7, 8, 11, 12 | Native current freshness, outside effect counters, corruption quarantine, reason-specific reproduction |
| Qualification coverage/tuple/controls/semantic verdict/artifact safety | 1, 2, 5, 11 | Approved pre-run applicability, immutable bytes, outside oracles, native verification, shape-valid fraud rejection |
| Qualification profile attacks/release invalidation/descendant finality | 6, 8, 10, 12 | Exact-profile installed matrix, no inherited pass, final-SDK evidence, independent review and exclusions |

- [ ] Run all focused Swift, Python, and modified Rust crate tests appropriate to the changed owners. Run workspace formatting and repository-required build/test/lint checks before implementation readiness; document any unavailable hosted or hardware gate separately.
- [ ] Run the document validator for traceability and links. Its success proves document coherence only.
- [ ] Search this plan and resulting files for unresolved placeholders, private repository URLs in public instructions, fabricated measured results, em dashes, and self-asserted qualified candidate status.
- [ ] Verify every selected profile's complete case/subcase set against its approved manifest, every artifact digest against bytes, and every public claim against the separate verified qualification result.
- [ ] Report implemented tooling, source/component results, clean installed results, verified profile claims, distribution publication, and external deployment as distinct outcomes.
