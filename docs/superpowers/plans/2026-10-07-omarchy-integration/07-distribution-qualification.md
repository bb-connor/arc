# Omarchy Linux and Distribution Qualification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a narrowly scoped Linux qualification harness and reproducible Arch distribution process that can independently qualify named Chio profiles on actual x86_64 Omarchy.

**Architecture:** The harness observes actual guests, native resource effects and system lifecycle from outside the guest. Package delivery stages immutable signed code separately from operator state and activates only a verified compatible generation. Native authority, recovery and receipts remain in the existing Chio implementation.

**Tech Stack:** Python 3 standard library `unittest`/subprocess/JSON for test orchestration, native C syscall fixtures, Rust controller tests, Arch devtools/pacman, systemd user services, bubblewrap, Linux namespaces/cgroup v2, native Chio verification tooling.

---

Status: Proposed implementation plan. All paths below marked Create are future files. All commands that mention these files or proposed package/controller binaries are future commands and must not be reported as passing until their task is implemented and executed. This document adds no runtime implementation.

Confidence: high in the evidence boundaries and source-grounded prerequisites; moderate in the selected deployment until the independent clean-host run passes.

Read first: [Linux contract](../../specs/2026-10-07-omarchy-integration/08-linux-confinement.md), [distribution contract](../../specs/2026-10-07-omarchy-integration/12-distribution-operations.md), [release evidence](../../specs/2026-10-07-omarchy-integration/15-verification-release.md) and [Linux research](../../specs/2026-10-07-omarchy-integration/research/linux-platform.md).

## Ordering and hard prerequisites

Tasks 1 through 4 develop the P0 probe/evidence scaffolding. They may produce component evidence without qualifying any execution profile. Tasks 5 through 10 are the P7 distribution/lifecycle campaign and require the selected implementation profile from the other plans.

Before actual `project-v1` qualification, require all of these named artifacts: `native-resource-compatibility`, `pi-omarchy-runtime-manifest`, `omarchy-session-lifecycle`, exact public source/package locks, real native authority/recovery/receipt acceptance and a working protected project resource with fixed recipe/review artifact. P1 `observe-v1` needs actual read-only controller/plugin and session acceptance but must not run mutating cases. P3 `reviewed-publish-v1` needs the native exact approval decision gate and reviewed destination publication. P4/P5/P6 are opt-in profile gates with their own native prerequisites. P7 never enables a missing optional profile.

The inspected ARM64 privileged-container results do not satisfy x86_64 Omarchy prerequisites. An unavailable native dependency blocks the affected real case. Record outcome `unknown` with a blocking reason, or `skipped`; never fabricate fixture success as release evidence. No proposed plan command is an existing general-purpose Chio CLI promise.

## File responsibility map

| Future path | Responsibility |
|---|---|
| `integrations/omarchy/qualify.py` | Thin CLI dispatch for one explicitly selected case or verification of a completed evidence index |
| `integrations/omarchy/qualification/evidence.py` | Strict case envelope, artifact digest and profile-completeness checks |
| `integrations/omarchy/qualification/process.py` | Bounded literal-argv execution and captured command evidence |
| `integrations/omarchy/qualification/platform.py` | Host/boot/architecture/effective-feature observation and tuple comparison |
| `integrations/omarchy/qualification/oracle.py` | Outside-guest sentinel/effect-count/process-census comparison |
| `integrations/omarchy/tests/test_evidence.py` | False-green, missing, skipped, wrong tuple and altered artifact regressions |
| `integrations/omarchy/tests/test_process.py` | Launch-refusal/timeout/argv/output-limit harness behavior |
| `integrations/omarchy/tests/test_platform.py` | Host facts and feature refusal behavior |
| `integrations/omarchy/tests/test_oracle.py` | Unreachable fixture, outside mutation and descendant-survival detection |
| `integrations/omarchy/tests/test_linux_cases.py` | Actual named Linux cases; real-host marker mandatory |
| `integrations/omarchy/tests/test_distribution_cases.py` | Package/lifecycle/restore cases on owned disposable installation |
| `integrations/omarchy/fixtures/linux/syscall_probe.c` | Independent native probes compiled outside the guest and mounted as exact test fixture |
| `integrations/omarchy/fixtures/linux/cases.json` | Closed case definitions with explicit positive control and observer requirements |
| `integrations/omarchy/fixtures/distribution/cases.json` | Exact package/update/rollback fault windows and required oracles |
| `packaging/omarchy/release-lock.json` | Reviewed public sources, digests, package versions, support tuple and required profile list |
| `packaging/omarchy/PKGBUILD` | Controller/shim packaging from immutable public source archive with vendored locked build inputs |
| `packaging/omarchy/units/chio-desktop.service` | User service intent, separately checked for actual effective protection |
| `packaging/omarchy/units/chio-tasks.slice` | Task resource grouping |
| `integrations/omarchy/fixtures/desktop/computer.chio.desktop.desktop` | Consume the controller plan's desktop entry for package-owned installation |
| `integrations/omarchy/fixtures/desktop/menu-fragment.json` | Consume the controller plan's static menu fragment as package data for optional ownership-aware onboarding |
| `packaging/omarchy/tests/test_release_lock.py` | Refuse floating/unverifiable/incomplete release inputs |
| `packaging/omarchy/tests/test_package_contents.py` | Exact code/unit/desktop-registration inventory, permissions and absence of self-install hooks |
| `packaging/omarchy/README.md` | Signed install/upgrade/recovery instructions derived from delivered behavior |

Controller runtime changes belong in `crates/products/chio-desktop/src/supervision/` and `src/store/` under the controller/state plans. This plan adds focused integration tests against those components and reports defects to their owners. Do not implement a parallel authority, journal or recovery engine in Python.

## Task 1: Make missing evidence fail visibly

**Files:** Create `integrations/omarchy/qualification/evidence.py`, `integrations/omarchy/tests/test_evidence.py` and empty `__init__.py` files in `integrations/omarchy/qualification` and `integrations/omarchy/tests`.

- [ ] Write this first negative test. It is intentionally a component test, not runtime proof.

```python
import unittest
from integrations.omarchy.qualification.evidence import require_cases

class EvidenceTests(unittest.TestCase):
    def test_missing_case_is_not_pass(self):
        with self.assertRaisesRegex(ValueError, "missing: AT-LNX-006"):
            require_cases({"AT-LNX-006"}, [], "tuple-a")

    def test_fixture_and_wrong_tuple_cannot_qualify(self):
        row = {"acceptance_id": "AT-LNX-006", "outcome": "pass",
               "evidence_class": "component", "compatibility_sha256": "tuple-a",
               "positive_control": True, "oracle": "outside-listener"}
        with self.assertRaisesRegex(ValueError, "runtime evidence"):
            require_cases({row["acceptance_id"]}, [row], "tuple-a")
        row["evidence_class"] = "independent_integration"
        with self.assertRaisesRegex(ValueError, "tuple mismatch"):
            require_cases({row["acceptance_id"]}, [row], "tuple-b")
```

- [ ] Run `python3 -m unittest integrations.omarchy.tests.test_evidence -v`. Expected red: missing module/function, then the defined negative assertions when implementation is deliberately incomplete.
- [ ] Add this pure completeness gate. Treat it as one necessary condition; native artifact signature verification and independent review are added in Task 10. These raw sidecar records include observer fields and per-case tuple binding. The final release-index rows use only the closed shared schema fields `acceptance_id`, `outcome`, `evidence_class` and `artifact_sha256`; Task 10 binds each row to its hashed sidecar. The short `tuple-a` strings here are component-test inputs, not valid release SHA-256 values.

```python
def require_cases(required, rows, tuple_digest):
    by_id = {}
    for row in rows:
        if row["acceptance_id"] in by_id:
            raise ValueError("duplicate case: " + row["acceptance_id"])
        by_id[row["acceptance_id"]] = row
    missing = sorted(set(required) - by_id.keys())
    if missing:
        raise ValueError("missing: " + ", ".join(missing))
    for case_id in sorted(required):
        row = by_id[case_id]
        if row["compatibility_sha256"] != tuple_digest:
            raise ValueError("tuple mismatch: " + case_id)
        if row["evidence_class"] not in {"independent_integration", "clean_install"}:
            raise ValueError("runtime evidence required: " + case_id)
        if row["outcome"] != "pass":
            raise ValueError("required case did not pass: " + case_id)
        if row["positive_control"] is not True or not row["oracle"]:
            raise ValueError("independent oracle missing: " + case_id)
```

- [ ] Add explicit tests for duplicate cases, `skipped`, `unknown`, false positive control and a valid independent-integration raw envelope. Run the same command. Expected green: all component checks pass; output says nothing about runtime qualification.
- [ ] Commit only these files with `test(omarchy): reject incomplete qualification evidence`.

## Task 2: Bound harness commands and capture literal arguments

**Files:** Create `integrations/omarchy/qualification/process.py`, `integrations/omarchy/tests/test_process.py`.

- [ ] Write the launch-refusal, timeout, no-shell and wrapper-exit regression tests below. The regression child closes stdout/stderr before sleeping, so pipe EOF cannot masquerade as descendant termination.

```python
import errno
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path
from integrations.omarchy.qualification.process import command_passed, run_bounded

class ProcessTests(unittest.TestCase):
    def assert_launch_refused(self, argv, expected_errno, reason):
        result = run_bounded(argv, timeout=0.1, limit=64,
                             prerequisite="AT-LNX-006.native-fixture")
        self.assertEqual(result["launch_error"], {
            "prerequisite": "AT-LNX-006.native-fixture",
            "errno": expected_errno, "reason": reason})
        self.assertFalse(result["launched"])
        self.assertIsNone(result["returncode"])
        self.assertEqual(result["stdout"], b"")
        self.assertEqual(result["stderr"], b"")
        self.assertFalse(result["wrapper_reaped"])
        self.assertFalse(result["descendants_absent"])
        self.assertFalse(command_passed(result))

    def test_missing_fixture_retains_prerequisite_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assert_launch_refused([str(Path(directory) / "missing-fixture")],
                                       errno.ENOENT, "not_found")

    def test_nonexecutable_fixture_retains_prerequisite_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "nonexecutable-fixture"
            fixture.write_text("#!/bin/sh\nexit 0\n")
            fixture.chmod(0o600)
            self.assert_launch_refused([str(fixture)], errno.EACCES, "not_executable")

    def test_shell_metacharacters_are_data(self):
        result = run_bounded([sys.executable, "-c",
                              "import sys; print(sys.argv[1])", "$(touch nope)"],
                             timeout=2, limit=1024)
        self.assertEqual(result["stdout"], b"$(touch nope)\n")
        self.assertTrue(command_passed(result))

    def test_timeout_is_not_success(self):
        result = run_bounded([sys.executable, "-c",
                              "import time; time.sleep(10)"],
                             timeout=0.1, limit=1024)
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["wrapper_reaped"])
        self.assertTrue(result["descendants_absent"])
        self.assertFalse(command_passed(result))

    def test_wrapper_exit_zero_with_closed_pipe_descendant(self):
        script = (
            "import os,time\n"
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.close(1); os.close(2)\n"
            "    time.sleep(20)\n"
            "    os._exit(0)\n"
            "print(os.getpid(), child, flush=True)\n")
        result = run_bounded([sys.executable, "-c", script], timeout=2, limit=1024)
        pgid, child = map(int, result["stdout"].split())
        try:
            # Outside observation is independent of the returned evidence flags.
            with self.assertRaises(ProcessLookupError):
                os.killpg(pgid, 0)
            self.assertEqual(result["returncode"], 0)
            self.assertTrue(result["wrapper_reaped"])
            self.assertTrue(result["descendants_absent"])
            self.assertTrue(result["unexpected_descendants"])
            self.assertFalse(command_passed(result))
        finally:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_session_escape_requires_a_qualified_cgroup_executor(self):
        with self.assertRaisesRegex(ValueError, "qualified cgroup"):
            run_bounded([sys.executable, "-c", "import os; os.setsid()"],
                        timeout=2, limit=1024, may_escape_group=True)
```

- [ ] Run `python3 -m unittest integrations.omarchy.tests.test_process -v`; expected red until the bounded runner exists.
- [ ] Implement literal-argv process execution with a new session, no inherited secrets, pipe readers that terminate once the combined byte limit is exceeded, a monotonic deadline, TERM/KILL and observed wait. Use this exact result contract and failure condition in `process.py`. `wrapper_reaped` and `descendants_absent` are independent observations. This helper is restricted to reviewed harness fixtures whose complete descendant behavior excludes `setsid` and `setpgid`; `may_escape_group=False` is not an enforcement mechanism. Any command that may change process group/session, including arbitrary guest code, requires the qualified per-task cgroup executor and its independently observed unpopulated state. Such commands must set `may_escape_group=True` here and are refused before spawn. There is no process-group fallback for them:

```python
import errno
import os
import selectors
import signal
import subprocess
import time


def command_passed(result):
    return (result["launched"] and result["launch_error"] is None
            and result["returncode"] == 0 and not result["timed_out"]
            and not result["overflow"] and result["wrapper_reaped"]
            and result["descendants_absent"] is True
            and not result["unexpected_descendants"]
            and not result["cleanup_errors"])


def _group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return None  # Inaccessible/unverifiable is not absent.


def _stop_and_observe_group(process, result):
    # This group is owned by a reviewed harness fixture, not arbitrary code.
    state = _group_exists(process.pid)
    result["unexpected_descendants"] = (
        process.poll() is not None and state is not False)
    for sig, grace in ((signal.SIGTERM, 0.2), (signal.SIGKILL, 1.0)):
        if state is False:
            break
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError as error:
            result["cleanup_errors"].append(error.errno)
        until = time.monotonic() + grace
        while True:
            process.poll()  # Reap the wrapper, independently of group absence.
            state = _group_exists(process.pid)
            if state is False or time.monotonic() >= until:
                break
            time.sleep(0.01)
    process.poll()
    result["returncode"] = process.returncode
    result["wrapper_reaped"] = process.returncode is not None
    result["descendants_absent"] = state is False


def run_bounded(argv, *, timeout, limit, may_escape_group=False,
                prerequisite="harness-fixture-executable"):
    if may_escape_group:
        raise ValueError("qualified cgroup executor required")
    if (not isinstance(argv, list) or not argv
            or any(not isinstance(a, str) or "\0" in a for a in argv)
            or not 0 < timeout <= 600 or not 0 < limit <= 16 * 1024 * 1024
            or not isinstance(prerequisite, str) or not 1 <= len(prerequisite) <= 128
            or not prerequisite.isascii()
            or any(not (c.isalnum() or c in "._-") for c in prerequisite)):
        raise ValueError("invalid bounded command")
    result = {"launched": False, "launch_error": None,
              "returncode": None, "stdout": b"", "stderr": b"",
              "timed_out": False, "overflow": False, "wrapper_reaped": False,
              "descendants_absent": False, "unexpected_descendants": False,
              "cleanup_errors": [], "containment": "reviewed-fixture-process-group"}
    with selectors.DefaultSelector() as selector:
        try:
            process = subprocess.Popen(
                argv, shell=False, start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as error:
            # Fixed reason vocabulary and a bounded prerequisite ID retain evidence
            # without copying arbitrary exception text, paths or command output.
            reason = {errno.ENOENT: "not_found", errno.EACCES: "not_executable",
                      errno.EPERM: "not_executable", errno.ENOEXEC: "invalid_executable"}
            result["launch_error"] = {"prerequisite": prerequisite,
                                      "errno": error.errno,
                                      "reason": reason.get(error.errno, "launch_failed")}
            return result
        result["launched"] = True
        deadline = time.monotonic() + timeout
        total = 0
        try:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result["timed_out"] = True
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    allowed = max(0, limit - total)
                    result[key.data] += chunk[:allowed]
                    total += len(chunk)
                    if total > limit:
                        result["overflow"] = True
                        break
                if result["overflow"]:
                    break
            if not result["timed_out"] and not result["overflow"]:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    result["timed_out"] = True
        finally:
            # Always clean and observe, even after wrapper exit 0 and pipe EOF.
            _stop_and_observe_group(process, result)
            process.stdout.close()
            process.stderr.close()
    return result
```

- [ ] Preserve launch refusals as failed command records with `launched=false`, `returncode=null`, empty output and the bounded `launch_error` object. No wrapper/group observation occurred, so neither observation flag becomes true. The case dispatcher supplies the checked-in fixture's prerequisite ID and retains this record alongside the literal argv/adapter identity before returning exit 2 for that named unavailable prerequisite. It records the case outcome as `unknown` with its blocker, never `pass`; an observation failure after launch returns exit 1. Do not let an uncaught `Popen` exception erase partial case evidence. Test missing file, denied execution, invalid executable format and a generic OS launch error; exception text must not enter the artifact.
- [ ] Add executable tests for a 2 MiB stdout/stderr flood with a 64 KiB cap, nonzero exit, invalid argv, unverifiable group observation and a descendant that keeps stdout open. Retain the separate closed-pipe descendant regression above. Expected: captured bytes never exceed the cap; failures remain failures and all stoppable owned fixture processes disappear. Unverifiable absence returns `descendants_absent=false` and can never pass. An unexpected surviving child makes the command fail even when cleanup subsequently proves absence. Run `python3 -m unittest integrations.omarchy.tests.test_process -v`.
- [ ] Commit with `test(omarchy): bound qualification command execution`. The product task cgroup implementation remains a separate prerequisite; this runner is not a substitute for it.

## Task 3: Collect actual platform facts and immutable runtime identities

**Files:** Create `integrations/omarchy/qualification/platform.py`, `integrations/omarchy/tests/test_platform.py`, `integrations/omarchy/fixtures/linux/platform-required.json`.

- [ ] Add the following refusal test, plus a positive matching record.

```python
import unittest
from integrations.omarchy.qualification.platform import require_platform

class PlatformTests(unittest.TestCase):
    def test_kernel_string_does_not_imply_landlock(self):
        facts = {"machine": "x86_64", "euid": 1000, "kernel": "6.20.1",
                 "userns": True, "landlock_abi": 0, "seccomp": True,
                 "cgroup_v2": True, "controllers": ["cpu", "memory", "pids"]}
        with self.assertRaisesRegex(ValueError, "Landlock"):
            require_platform(facts)
```

- [ ] Run `python3 -m unittest integrations.omarchy.tests.test_platform -v`; expected red until the function is implemented.
- [ ] Implement the component eligibility function exactly; do not use it alone as a real-host probe.

```python
def require_platform(facts):
    if facts["machine"] != "x86_64" or facts["euid"] == 0:
        raise ValueError("non-root x86_64 required")
    if facts["landlock_abi"] < 4:
        raise ValueError("Landlock ABI 4 required")
    if not facts["userns"] or not facts["seccomp"] or not facts["cgroup_v2"]:
        raise ValueError("required effective isolation unavailable")
    if not {"cpu", "memory", "pids"}.issubset(facts["controllers"]):
        raise ValueError("required cgroup controllers unavailable")
```

- [ ] Collect actual `os.uname`, `os.geteuid`, boot ID, cgroup/controller files and package versions in the real-host case. Use effective native prerequisite probes supplied by `native-resource-compatibility`, plus an actual bubblewrap child under the proposed user service; never derive syscall/LSM support from a version string. Record binaries' SHA-256 and `/proc` executable/maps identity. The `platform-required.json` fixture is:

```json
{"architecture":"x86_64","non_root":true,"landlock_abi_min":4,
 "required_probes":["userns","seccomp","no_new_privs","pidfd_open",
 "pidfd_send_signal","waitid_pidfd","openat2","close_range","execveat",
 "sealed_memfd","statx_mount_id","parent_child_ptrace_exec"],
 "required_controllers":["cpu","memory","pids"]}
```

- [ ] Add component negatives for root, ARM64, missing userns and missing controllers. Run the specific unittest command again; expected green. Run actual `AT-LNX-001` and `AT-LNX-004` only after Task 4 exposes the real-host CLI and the native probe bundle exists.
- [ ] Commit with `test(omarchy): separate platform facts from runtime qualification`.

## Task 4: Add independent syscall and outside-effect cases

**Files:** Create `integrations/omarchy/fixtures/linux/syscall_probe.c`, `integrations/omarchy/qualification/oracle.py`, `integrations/omarchy/tests/test_oracle.py`, `integrations/omarchy/tests/test_linux_cases.py`, `integrations/omarchy/fixtures/linux/cases.json`, `integrations/omarchy/qualify.py`.

- [ ] Add an independent native fixture with explicit success/failure conventions. Compile it outside the guest; pin its binary digest in each case.

```c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 2) return 64;
  if (!strcmp(argv[1], "read") && argc == 3) {
    int fd = open(argv[2], O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 77;
    char byte; int result = read(fd, &byte, 1) == 1 ? 0 : 78;
    close(fd); return result;
  }
  if (!strcmp(argv[1], "fork")) {
    pid_t pid = fork();
    if (pid < 0) return 77;
    if (!pid) _exit(0);
    int status; return waitpid(pid, &status, 0) == pid ? 0 : 78;
  }
  if (!strcmp(argv[1], "socket")) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 77;
    close(fd); return 0;
  }
  return 64;
}
```

- [ ] Run the future fixture build command `cc -O2 -Wall -Wextra -Werror integrations/omarchy/fixtures/linux/syscall_probe.c -o /tmp/chio-omarchy-syscall-probe`. On the owned non-root qualification host, the unrestricted positive `fork` and `socket` controls must return 0. No passing negative is accepted without that control.
- [ ] Add this oracle test and minimal implementation.

```python
# tests/test_oracle.py
import unittest
from integrations.omarchy.qualification.oracle import require_denial

class OracleTests(unittest.TestCase):
    def test_dead_listener_cannot_prove_network_denial(self):
        with self.assertRaisesRegex(ValueError, "positive control"):
            require_denial(False, 0, 0, True)

    def test_effect_or_survivor_invalidates_denial(self):
        for before, after, absent in [(0, 1, True), (0, 0, False)]:
            with self.assertRaises(ValueError):
                require_denial(True, before, after, absent)

# qualification/oracle.py
# Keep this implementation in its own source file, not in the test file.
def require_denial(positive_control, before_count, after_count, absent):
    if positive_control is not True:
        raise ValueError("positive control missing")
    if after_count != before_count:
        raise ValueError("forbidden outside effect observed")
    if absent is not True:
        raise ValueError("descendant absence not proven")
```

- [ ] Run `python3 -m unittest integrations.omarchy.tests.test_oracle -v` first with no implementation (red), then with the implementation (green).
- [ ] Implement the thin `qualify.py` CLI with explicit options `--phase P0|P1|P2|P3|P4|P5|P6|P7 --profile --bundle --output`, repeatable `--case AT-...`, `--fixture-only` and `--verify-only`, matching the [shared harness ABI](README.md#proposed-qualification-harness-abi). Every phase dispatches to that phase's declared gates; a missing implementation is a named unavailable prerequisite, never a parser rejection of a valid phase or a fallback to P0/P7. The selected-case path resolves IDs only from checked-in case definitions, refuses non-Linux/root/wrong architecture for real cases, requires a new owned output directory and runs only exact fixture commands through Task 2. Verification-only reads an existing evidence directory without runtime effects. Fixture-only always records synthetic evidence. It imports the real host adapter installed by the selected-profile plans; it never invents a privileged/unconfined fallback. Command and adapter identities go into the artifact. Unknown IDs return exit 1; missing prerequisites, including recorded launch refusals, return exit 2. Preserve partial evidence in both cases.
- [ ] Use the same closed phase choices in the real parser and component tests. Test acceptance of every P0 through P7, rejection of P8, lowercase and missing phase, and dispatch to the selected phase without substitution:

```python
def add_phase_argument(parser):
    parser.add_argument("--phase", required=True,
                        choices=[f"P{index}" for index in range(8)])
```

- [ ] Add one separately addressable actual case for each row. Each writes the exact AT artifact from the Linux spec. Expand the native probe with one named operation per additional syscall; do not accept JavaScript exceptions as syscall evidence.

| Future exact case command suffix | Positive control | Negative trigger and outside oracle |
|---|---|---|
| `--case AT-LNX-003` | Exact Pi/runtime starts | Replace loader/bootstrap, inject mount aliases; retained executable/maps and outside sentinels |
| `--case AT-LNX-005` | Required Node thread/bootstrap and unrestricted probe | Fork, clone/x32, nested namespaces, io_uring, process memory/FD, partial Landlock; native signals and outside effects |
| `--case AT-LNX-006` | Exact native/model route reaches observer | Operator/Wayland/D-Bus/SSH/container/abstract socket, DNS/CONNECT/wrong Host; listener counters |
| `--case AT-LNX-007` | Model/tool flow works with canary credentials in trusted custody | Inherited env/FD and argv exposure; external `/proc` scan |
| `--case AT-LNX-008` | Normal transport/export publication | Linked/multiply-linked transport and 1,000 parent swaps; outside sentinel plus crash readback |
| `--case AT-LNX-009` | Normal bounded task | Memory/thread/CPU/output/byte/inode floods; cgroup and filesystem counters |
| `--case AT-LNX-010` | Worker/recipe completes | TERM/KILL/controller crash/session-changing fixture child; pidfd and cgroup population |
| `--case AT-LNX-016` | Fixed project edit/test/review artifact | Direct host writes, changed source lineage, failed tests and early publish; host hashes/native verifier |

Future example after implementing the selected case: `python3 integrations/omarchy/qualify.py --phase P7 --profile project-v1 --bundle /var/tmp/chio-omarchy-qualification/qualified-bundle.json --output /var/tmp/chio-omarchy-qualification/evidence/lnx-006 --case AT-LNX-006`. Expected red before closure: nonzero with a named missing prerequisite or observed escape. Expected green after closure: positive-control request count increments, every forbidden destination remains unchanged, artifact class `independent_integration` with the exact observed Omarchy tuple. A component fixture cannot set that class.

- [ ] Commit the harness and focused fixtures with `test(omarchy): observe real Linux confinement boundaries`.

## Task 5: Lock public package inputs and produce a reproducible package

**Files:** Create `packaging/omarchy/release-lock.json`, `packaging/omarchy/release_lock.py`, `packaging/omarchy/tests/test_release_lock.py`, `packaging/omarchy/PKGBUILD`, `packaging/omarchy/tests/test_package_contents.py`.

Consume the controller plan's three explicitly declared binaries and its desktop entry/menu fixtures. Their source ownership remains with that plan; package their reviewed bytes without generating alternate registration assets here.

- [ ] Define the release lock as strict data with required fields `version`, `architecture`, `source_url`, `source_sha256`, `public_revision`, `runtime_inventory_sha256`, `compatibility_sha256`, `profiles`, `state_read_abis`, `state_write_abi`, `signer_identity` and `native_prerequisites`. Populate only from publicly reachable pinned artifacts. An absent field is a hard error, not an empty default.
- [ ] Add the first tests around the proposed parser `validate_release_lock` in `packaging/omarchy/release_lock.py`:

```python
import unittest
from pathlib import Path
import importlib.util
spec = importlib.util.spec_from_file_location(
    "release_lock", Path(__file__).parents[1] / "release_lock.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ReleaseLockTests(unittest.TestCase):
    def test_empty_lock_is_rejected(self):
        with self.assertRaises(ValueError):
            module.validate_release_lock({})

    def test_floating_revision_is_rejected(self):
        with self.assertRaises(ValueError):
            module.validate_release_lock({"public_revision": "main"})
```

- [ ] Run `python3 -m unittest discover -s packaging/omarchy/tests -p test_release_lock.py -v`; expected red. Add the validator with exact required-field checks, `architecture == "x86_64"`, 40-hex public revision, 64-hex digests, an HTTPS URL on the reviewed publisher host, closed known profiles and nonempty native prerequisite bindings. Test each rejected field and a real reviewed lock; expected green. Do not create a fake production lock just to pass a test.
- [ ] Build `PKGBUILD` around the actual reviewed public source archive and vendored dependency closure. The key package steps are:

```bash
build() {
  cd "$srcdir/chio"
  cargo build --frozen --offline --release -p chio-desktop
}
check() {
  cd "$srcdir/chio"
  cargo test --frozen --offline -p chio-desktop
}
package() {
  cd "$srcdir/chio"
  install -Dm755 target/release/chio-desktop-controller "$pkgdir/usr/bin/chio-desktop-controller"
  install -Dm755 target/release/chio-desktop-client "$pkgdir/usr/bin/chio-desktop-client"
  install -Dm755 target/release/chio-desktop-open "$pkgdir/usr/bin/chio-desktop-open"
  install -Dm644 packaging/omarchy/units/chio-desktop.service "$pkgdir/usr/lib/systemd/user/chio-desktop.service"
  install -Dm644 packaging/omarchy/units/chio-tasks.slice "$pkgdir/usr/lib/systemd/user/chio-tasks.slice"
  install -Dm644 integrations/omarchy/fixtures/desktop/computer.chio.desktop.desktop "$pkgdir/usr/share/applications/computer.chio.desktop.desktop"
  install -Dm644 integrations/omarchy/fixtures/desktop/menu-fragment.json "$pkgdir/usr/share/chio/omarchy/menu-fragment.json"
}
```

The `source`, `sha256sums`, version and dependency declarations must be literal reviewed values derived from `release-lock.json` when the release is cut; the package builder rejects disagreement. Bundle the helper/runtime through a separately reviewed runtime package according to the exact tuple. Do not add a post-install hook or network download to compensate for missing prerequisites.

Require these exact package paths as root-owned regular files, with no setuid/setgid or group/other write bits. Include every additional delivered schema, diagnostic formatter, public document and optional icon in the reviewed complete package manifest; the following mandatory launcher/unit inventory is not permission to omit those selected deliverables.

| Required installed path | Mode | Content assertion |
|---|---|---|
| `/usr/bin/chio-desktop-controller` | `0755` | Matches the reviewed controller build |
| `/usr/bin/chio-desktop-client` | `0755` | Matches the reviewed protocol client build |
| `/usr/bin/chio-desktop-open` | `0755` | Matches the reviewed navigation-only opener build |
| `/usr/lib/systemd/user/chio-desktop.service` | `0644` | Literal controller path resolves within the package manifest |
| `/usr/lib/systemd/user/chio-tasks.slice` | `0644` | Matches the reviewed task resource-group unit |
| `/usr/share/applications/computer.chio.desktop.desktop` | `0644` | Exact P1 fixture bytes, `Exec=chio-desktop-open`, no shell or dynamic arguments |
| `/usr/share/chio/omarchy/menu-fragment.json` | `0644` | Exact P1 fixture bytes, only the owned static `chio` menu action invoking the opener |

The clean-install launcher check below observes whether the desktop-entry `Exec` basename resolves to the delivered `/usr/bin/chio-desktop-open`. If the desktop entry declares an `Icon`, its package-owned asset is required in the complete manifest or the entry must omit that optional field. The menu fragment is inert package data. Explicit optional onboarding applies it transactionally through P1's ownership-aware merge; package installation does not edit user menus or shortcuts.

- [ ] On two independent clean Arch builders run `extra-x86_64-build` from `packaging/omarchy` after its devtools clean-chroot setup is explicitly recorded. Compare extracted files/digests and retain both `.BUILDINFO`, SBOM and license inventory. Expected first red can be a genuine public source/dependency gap; close the gap, do not bypass offline/locked flags. Expected green: matching package content and complete source correspondence.
- [ ] Run `python3 -m unittest discover -s packaging/omarchy/tests -p test_package_contents.py -v` against both built archives, checking every exact path/mode/content assertion above plus the complete release manifest, no credentials and no installer self-download or enable/linger side effects. Delete each mandatory member in turn, especially the opener and both registration files; every mutated archive must fail. Also reject altered desktop/menu bytes, an unresolved or shell-based `Exec`, a missing declared icon and wrong ownership/modes. A clean installed desktop entry must reach the navigation-only opener under the real launcher. Commit with `build(omarchy): package pinned desktop components`.

## Task 6: Ship and measure role-specific user services

**Files:** Create `packaging/omarchy/units/chio-desktop.service`, `packaging/omarchy/units/chio-tasks.slice`; Create focused cases in `integrations/omarchy/tests/test_distribution_cases.py`.

- [ ] Write a package/unit test that installation leaves the user service disabled, and a runtime test that enabling it exposes the expected protocol while guest mutations remain gated by actual profile prerequisites. Expected red until units/onboarding exist.
- [ ] Add this initial controller unit intent, replacing the executable invocation only if the controller plan's delivered CLI uses a different validated literal invocation:

```ini
[Unit]
Description=Chio desktop controller
PartOf=graphical-session.target
After=graphical-session.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
ExecStart=/usr/bin/chio-desktop-controller
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
LimitCORE=0
KillMode=control-group
TimeoutStopSec=10s
Restart=on-failure
RestartSec=5s
RuntimeDirectory=chio-desktop
RuntimeDirectoryMode=0700

[Install]
WantedBy=graphical-session.target
```

This is intentionally the minimal role definition, not a claim that it confines the guest. Add only measured controller hardening from the per-role matrix. Namespace/procfs/ptrace exceptions needed by the launcher belong in its own measured role; guest policy is installed before guest code. Add `chio-tasks.slice` with accounting enabled and per-task limits supplied by the qualified supervision owner. Do not enable lingering.
- [ ] Run future case commands individually for `AT-OPS-006` and `AT-OPS-007`; retain unit source, `systemctl --user show` effective properties, namespace/cgroup observations and guest negative probes. A stopped `graphical-session.target` on the actual Omarchy host is red even if the unit syntax parses. Implement the qualified session adapter under the controller plan before retrying.
- [ ] Run the hostile PATH/mise case `AT-OPS-005`; expected green requires zero shim executions and correct drift refusal after the final mise phase.
- [ ] Commit with `feat(omarchy): qualify session-owned desktop services`.

## Task 7: Test staged activation and irreversible state knowledge

**Files:** Create `integrations/omarchy/fixtures/distribution/cases.json`; extend `integrations/omarchy/tests/test_distribution_cases.py`; add controller tests in `crates/products/chio-desktop/tests/update_recovery.rs` under the state owner's implementation.

- [ ] Write a controller regression with exact assertions: after dispatch has external count 1, inject a crash before receipt retention, stage a compatible update, restart and reconcile the original. Assert the same task UUID/native operation ID, external count still 1 and no new executable generation launches work before recovery. The state test fixture supplies the real store/native client interface from the controller plan; a mocked native response is labelled component evidence.
- [ ] Run the future focused Rust command `cargo test -p chio-desktop --test update_recovery update_after_unknown_preserves_original -- --exact`. Expected red: any ID substitution/replay or activation before custody reconciliation. Implement the fix in the owned controller/state modules, never in the evidence harness. Expected green: original bindings and reservations remain unchanged.
- [ ] Add deterministic fault entries as closed fixture data:

```json
{"cases":[
 {"id":"AT-OPS-008","faults":["before_stage_sync","after_stage_sync","during_migration","before_activation_rename","after_activation_rename","before_recovery_complete"]},
 {"id":"AT-OPS-009","faults":["older_read_abi","older_write_abi","root_snapshot_newer_home","missing_old_package"]},
 {"id":"AT-OPS-016","faults":["enospc","inode_exhaustion","eio","read_only_state","partial_package_extract"]}
]}
```

- [ ] Implement one test per listed fault in the real disposable VM. Each starts with a successful old-generation task, captures outside mutation count and native anchors, applies the fault at the named durable boundary, restarts via installed packages and reads back active generation/state. Assert old-or-new complete binding or explicit refusal, never mixed fields or restored pre-effect knowledge.
- [ ] Run individual future case commands for `AT-OPS-008`, `AT-OPS-009`, `AT-OPS-016`; retain each fault row. Expected green requires all rows, not a majority and not only successful updates. Commit with `test(omarchy): preserve custody across update and rollback`.

## Task 8: Qualify real session, time and storage failures

**Files:** Extend `integrations/omarchy/tests/test_linux_cases.py`, `integrations/omarchy/fixtures/linux/cases.json`; add `integrations/omarchy/fixtures/linux/lifecycle-scenarios.json`.

- [ ] Add exact lifecycle fixture data:

```json
{"scenarios":[
 {"case":"AT-LNX-011","events":["realtime_backwards","realtime_forwards","suspend_past_deadline","reboot","old_guest_checkpoint"]},
 {"case":"AT-LNX-012","events":["sleep_before_dispatch","sleep_after_dispatch","missed_sleep_signal","wake_without_resume"]},
 {"case":"AT-LNX-013","events":["lock","unlock","logout_linger_enabled","compositor_restart","second_session","shutdown_after_effect"]},
 {"case":"AT-LNX-014","events":["credential_expiry","old_bearer_after_rotation","changed_provider_on_resume"]},
 {"case":"AT-LNX-015","events":["enospc_before_intent","eio_after_dispatch","read_only_during_receipt","power_loss_during_profile_export"]}
]}
```

- [ ] Add a red component assertion in the controller supervision tests: restoring a checkpoint after boottime expiry with the same boot ID cannot increase remaining lifetime; reboot changes boot ID and requires authoritative expiry/reconciliation. Run the future focused command `cargo test -p chio-desktop --test supervision_lifecycle checkpoint_cannot_renew_deadline -- --exact`; expected red before the BOOTTIME implementation, green after it. Preserve native operation/reservation fixtures unchanged.
- [ ] Execute each real event in an explicitly owned disposable Omarchy VM. Use host/VM automation for time changes, power loss and disk faults, not arbitrary commands in the user's current desktop session. Capture before/after realtime, boottime, boot/session identity, cgroup census and native external effect count. `wake_without_resume` must show zero fresh requests.
- [ ] Run individual future harness cases `AT-LNX-011`, `AT-LNX-012`, `AT-LNX-013`, `AT-LNX-014`, `AT-LNX-015`. Expected green: every event preserves original custody and no uncertain operation is replayed; absent notification or stopped worker is not proof of effect absence.
- [ ] Commit with `test(omarchy): qualify desktop lifecycle recovery`.

## Task 9: Exercise privacy, backup, restore and removal

**Files:** Extend `integrations/omarchy/tests/test_distribution_cases.py`; Create `integrations/omarchy/fixtures/distribution/privacy-canaries.json`; Create `packaging/omarchy/README.md`.

- [ ] Add a failing export test using only synthetic values. Seed separate canaries for provider secret, prompt, file body, window title, clipboard and user path. Run normal and flooded diagnostics, credential import/removal and encrypted backup; assert none of the forbidden values occurs in public diagnostics/archive/journal, and no external connection occurs. The encrypted custody export is tested through its own explicit path, never included in generic diagnostics.
- [ ] Run `AT-OPS-012` alone through the future CLI. Expected red if raw text leaks, storage grows past its bound or export omits a truncation marker. Fix the product serializer/logger, not the scanner. Expected green: bounds hold and authority state remains intact.
- [ ] Add independent restore scenarios: valid backup, corrupt digest, archive traversal/symlink, older pre-effect state, missing native anchor, unavailable native service and missing credential custody. Check outside sentinels plus the original native effect count. Run `AT-OPS-013` and `AT-OPS-014` separately. Expected green requires uncertainty fencing, not merely successful file extraction.
- [ ] Run `AT-OPS-015` on a fixture with an unresolved effect: disable UI, stop user unit, remove backend package, attempt purge. Compare package/filesystem inventory and assert task/receipt/anchor/project/backup preservation. Purge must refuse unresolved custody.
- [ ] Run `AT-OPS-011` in panel-visible/idle windows and with 20 subscribers; capture real RSS/CPU/request counts. Adjust the product if defaults are exceeded; do not relabel an unmeasured target as achieved.
- [ ] Write the operator README from the delivered commands and measured outputs: publisher trust, exact package/profile support, backend absence, signed update/recovery, root-snapshot mismatch, credentials, backup/restore, safe removal and local export. Do not include an unavailable download URL or a private source revision. Commit with `docs(omarchy): document qualified recovery and removal`.

## Task 10: Verify signed artifacts and independent clean installation

**Files:** Extend `integrations/omarchy/qualification/evidence.py`, `integrations/omarchy/qualify.py`, `integrations/omarchy/tests/test_evidence.py`; release outputs live under `output/omarchy` and are not silently treated as source files.

- [ ] Add evidence-index mutants: alter an artifact after hashing, omit an applicable case, label component evidence real, change tuple/provider/kernel, use an unknown signer, omit a positive control and enable an unqualified optional profile. Run the exact unit suite from Task 1; red is required before adding native artifact verification and profile mapping.
- [ ] The shared full-phase command uses no `--case`: `python3 integrations/omarchy/qualify.py --phase P7 --profile project-v1 --bundle /var/tmp/chio-omarchy-qualification/qualified-bundle.json --output /var/tmp/chio-omarchy-qualification/evidence/full-profile`. It requires a fresh output directory. Any `--case` selection is debugging/partial evidence and can never mark a profile qualified. `--verify-only` reads an existing output directory, causes no runtime effects and refuses missing or stale artifacts.

- [ ] Bind release-index structure to the shared `release-evidence.schema.json` and source/profile mapping. Verify digests and required native evidence through the delivered native verifier with pinned trust inputs, not a Python signature substitute. Extend `--verify-only` to fail any missing/unknown/skipped case, untrusted artifact or unavailable public dependency. JSON labels alone cannot prove an oracle ran; retain raw commands and outside artifacts for independent review.
- [ ] Run actual trust/security/protocol cases independently: `AT-OPS-002`, `AT-OPS-004`, `AT-OPS-010`, `AT-OPS-017` and `AT-LNX-017`. Expected green requires rejection of tuple/substitution/revocation/forged evidence mutants with zero unintended effects.
- [ ] An independent tester starts from the locked clean x86_64 Omarchy installation, with no development checkout, and uses only signed public artifacts/docs. Run `AT-OPS-001`, `AT-OPS-018` and `AT-LNX-018` for the named selected profiles, plus every applicable preceding case. Capture architecture, package/source identities, exact profiles, original IDs, signed native receipts and outside effects. A missing public native package is a release blocker, not an instruction to borrow the implementer's machine.
- [ ] Run the future final index command `python3 integrations/omarchy/qualify.py --phase P7 --profile project-v1 --bundle /var/tmp/chio-omarchy-qualification/qualified-bundle.json --output /var/tmp/chio-omarchy-qualification/evidence/full-profile --verify-only`. Expected green only after all required current-tuple artifacts exist and independent review is recorded. This aggregation does not replace any named test above.
- [ ] Prepare release notes distinguishing source implementation, test qualification, package availability and operator adoption. Do not publish, deploy or externally send artifacts merely because the verifier is green; follow the release authorization in the active task.
- [ ] Commit source harness/package/docs with `test(omarchy): gate selected profile release evidence`; retain large qualification artifacts in the explicitly selected evidence channel with immutable digest references.

## Acceptance coverage and handoff

Tasks 1 and 10 cover false-green rejection and exact profile closure. Tasks 3 and 4 cover platform, runtime, namespaces, syscalls, routes, secrets, publication races, resource limits and project effects. Task 8 covers clocks, suspend, session loss, credentials and storage. Tasks 5 and 6 cover reproducible distribution, dependency drift and user services. Task 7 covers activation and rollback. Task 9 covers monitoring, privacy, backup/restore and removal.

The implementer must run the specific tests in each task before the relevant commit, then the actual named acceptance cases when their prerequisites are satisfied. Passing component tests is not permission to skip actual Omarchy/native/provider evidence. The work is complete only for the explicitly named support tuple and profiles in the independent release bundle.
