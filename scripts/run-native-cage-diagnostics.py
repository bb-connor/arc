#!/usr/bin/env python3
"""Full native development diagnostics; no trusted qualification or attestations."""

import argparse
from collections import Counter
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import time
import tomllib


SOURCE_SHA = "09a3e50f43be444c69c93ddc841ac7d816d02349"
SETUP_SCRIPT_SHA256 = "b76f943d6f99b69fc2b67459d529658a2c710ca28ce41714d758ab52d8440543"
NATIVE_TARGET = "x86_64-unknown-linux-gnu"
PACKAGES = ("chio-cage", "chio-cage-plan", "chio-cage-init")
SUMMARY = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", re.M)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(root, destination):
    entries = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        if Path(directory) == root:
            dirs[:] = [name for name in dirs if name != ".git"]
            files = [name for name in files if name != ".git"]
        dirs.sort()
        for name in sorted(files + [name for name in dirs if (Path(directory) / name).is_symlink()]):
            path = Path(directory) / name
            info = path.lstat()
            entry = {"path": path.relative_to(root).as_posix(), "mode": oct(stat.S_IMODE(info.st_mode))}
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                entry.update(kind="symlink", target=target, sha256=hashlib.sha256(os.fsencode(target)).hexdigest())
            elif stat.S_ISREG(info.st_mode):
                entry.update(kind="file", bytes=info.st_size, sha256=digest(path))
            else:
                raise RuntimeError(f"unsupported source file type: {entry['path']}")
            entries.append(entry)
    entries.sort(key=lambda item: item["path"])
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    result = {"root": str(root), "excluded": [".git"], "entries": entries,
              "content_sha256": hashlib.sha256(encoded).hexdigest()}
    write_json(destination, result)
    return result["content_sha256"]


def enable_subreaper():
    # Diagnostic ownership only: adopt orphaned descendants of our own commands.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def open_pidfd(pid):
    # x86_64 and aarch64 use these asm-generic Linux syscall numbers. Some
    # Python builds omit the convenience functions despite kernel support.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(ctypes.c_long(434), ctypes.c_int(pid), ctypes.c_uint(0))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(result)


def kill_pidfd(pidfd):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    if libc.syscall(ctypes.c_long(424), ctypes.c_int(pidfd), ctypes.c_int(signal.SIGKILL), ctypes.c_void_p(), ctypes.c_uint(0)) < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def clean_owned_descendants(exclude=()):
    """Signal exact adopted children only; consume only our terminal child statuses."""
    excluded = set(exclude)
    events = []
    deadline = time.monotonic() + 3
    remaining = []
    while True:
        children_path = Path(f"/proc/self/task/{os.getpid()}/children")
        children = [int(value) for value in children_path.read_text().split()]
        remaining = [pid for pid in children if pid not in excluded]
        for pid in remaining:
            try:
                pidfd = open_pidfd(pid)
            except ProcessLookupError:
                continue
            try:
                status = Path(f"/proc/{pid}/status").read_text()
                if not re.search(r"^PPid:\s+" + str(os.getpid()) + r"$", status, re.M):
                    continue
                try:
                    kill_pidfd(pidfd)
                    events.append({"pid": pid, "action": "kill-owned-adopted-child"})
                except ProcessLookupError:
                    pass
            finally:
                os.close(pidfd)
            try:
                waited, wait_status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    events.append({"pid": waited, "action": "reaped", "raw_wait_status": wait_status})
            except ChildProcessError:
                pass
        if not remaining or time.monotonic() >= deadline:
            break
        time.sleep(0.02)
    # Refresh after the last reap so a successfully consumed child is not stale.
    remaining = [int(value) for value in children_path.read_text().split() if int(value) not in excluded]
    return {"events": events, "unreaped_owned_children": remaining}


def run_owned(command, *, cwd, env, log, timeout):
    preexisting = tuple(int(value) for value in Path(f"/proc/self/task/{os.getpid()}/children").read_text().split())
    record = {"argv": command, "shell_command": shlex.join(command), "cwd": str(cwd),
              "environment": env.copy(), "started_unix": time.time(), "timeout_seconds": timeout,
              "excluded_preexisting_children": list(preexisting), "log": str(log)}
    process = None
    def kill_session(sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
    with log.open("wb") as stream:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            record["root_pid"] = record["owned_session_id"] = process.pid
            try:
                record["exit_code"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record["timed_out"] = True
                # The unreaped Popen child pins this session leader's PID.
                kill_session(signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    kill_session(signal.SIGKILL)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        record["unreaped_root_pid"] = process.pid
                record["process_exit_code"] = process.returncode
                record["exit_code"] = 124
            except BaseException:
                kill_session(signal.SIGKILL)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    record["unreaped_root_pid"] = process.pid
                record.update(exit_code=130, interrupted=True, process_exit_code=process.returncode)
                raise
        except OSError as error:
            record.update(exit_code=127, spawn_error=str(error))
            stream.write((str(error) + "\n").encode())
        finally:
            exclude = preexisting + ((process.pid,) if process and process.returncode is None else ())
            record["descendant_cleanup"] = clean_owned_descendants(exclude)
            record["finished_unix"] = time.time()
    return record, log.read_text(errors="replace")


def list_inventory(text):
    entries = re.findall(r"^(.+): (test|benchmark)$", text, re.M)
    counts = re.findall(r"^(\d+) tests?, (\d+) benchmarks?$", text, re.M)
    tests = [name for name, kind in entries if kind == "test"]
    benchmarks = [name for name, kind in entries if kind == "benchmark"]
    valid = len(counts) == 1 and len(tests) == len(set(tests)) and len(benchmarks) == len(set(benchmarks))
    valid &= bool(counts) and tuple(map(int, counts[0])) == (len(tests), len(benchmarks))
    return {"tests": tests, "benchmarks": benchmarks, "counts": counts, "valid": valid}


def harness_wrapper():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=("list", "run"), required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(sys.argv[2:])
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        raise RuntimeError("Cargo did not provide a native test executable")
    enable_subreaper()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    executable = Path(command[0]).resolve(strict=True)
    key = hashlib.sha256(str(executable).encode()).hexdigest()
    path = output / (key + ".json")
    record = {"mode": args.mode, "executable": str(executable), "executable_sha256": digest(executable), "status": "running"}
    write_json(path, record)
    executed, text = run_owned(command, cwd=Path.cwd(), env=dict(os.environ),
                               log=output / (key + ".log"), timeout=args.timeout)
    record.update(executed)
    if args.mode == "list":
        record["inventory"] = list_inventory(text)
    else:
        record["summaries"] = [list(value) for value in SUMMARY.findall(text)]
        record["observed_nodes"] = re.findall(r"^test (.+?) \.\.\. ", text, re.M)
        record["ignored_nodes"] = re.findall(r"^test (.+?) \.\.\. ignored(?:$|,)", text, re.M)
        record["failed_nodes"] = sorted(set(re.findall(r"^test (.+?) \.\.\. FAILED$", text, re.M) +
                                               re.findall(r"^    ([^\s]+)$", text, re.M)))
    incomplete = executed.get("timed_out") or executed.get("unreaped_root_pid") or executed["descendant_cleanup"]["unreaped_owned_children"]
    record["status"] = "incomplete" if incomplete else "passed" if executed["exit_code"] == 0 else "failed"
    write_json(path, record)
    sys.stdout.write(text)
    sys.stdout.flush()
    return 124 if incomplete else executed["exit_code"] if executed["exit_code"] >= 0 else 128 - executed["exit_code"]


def compare_phase(build_text, list_dir, run_dir, package_manifests):
    artifacts = {}
    for line in build_text.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("reason") != "compiler-artifact" or not item.get("profile", {}).get("test") or not item.get("executable"):
            continue
        if item.get("manifest_path") not in package_manifests:
            continue
        executable = str(Path(item["executable"]).resolve())
        artifacts[executable] = {"package_id": item["package_id"], "target": item["target"], "executable": executable}
    listed = {item["executable"]: item for path in sorted(list_dir.glob("*.json")) for item in [json.loads(path.read_text())]}
    executed = {item["executable"]: item for path in sorted(run_dir.glob("*.json")) for item in [json.loads(path.read_text())]}
    errors = []
    if not artifacts or set(artifacts) != set(listed) or set(artifacts) != set(executed):
        errors.append("compiled/listed/executed harness inventory differs or is empty")
    harnesses = []
    totals = Counter()
    for executable in sorted(set(artifacts) | set(listed) | set(executed)):
        item = dict(artifacts.get(executable, {"executable": executable}))
        inventory = listed.get(executable)
        execution = executed.get(executable)
        item.update(list=inventory, run=execution, status="incomplete")
        if not inventory or not execution or not inventory.get("inventory", {}).get("valid") or inventory.get("status") != "passed":
            errors.append("invalid or absent list/run for " + executable)
            harnesses.append(item)
            continue
        expected = inventory["inventory"]["tests"]
        observed = execution.get("observed_nodes", [])
        summaries = execution.get("summaries", [])
        if inventory["inventory"]["benchmarks"] or Counter(expected) != Counter(observed) or len(summaries) != 1:
            errors.append("node inventory/summary mismatch for " + executable)
        elif inventory["executable_sha256"] != execution["executable_sha256"]:
            errors.append("test executable changed between list and run: " + executable)
        else:
            state, passed, failed, ignored, measured, filtered = summaries[0]
            counts = dict(zip(("passed", "failed", "ignored", "measured", "filtered"), map(int, (passed, failed, ignored, measured, filtered))))
            totals.update(counts)
            failed_nodes = sorted(set(expected) & set(execution.get("failed_nodes", [])))
            item["counts"] = counts
            item["nodes"] = [{"node": node, "status": "failed" if node in failed_nodes else "ignored" if node in execution.get("ignored_nodes", []) else "passed"} for node in expected]
            valid = counts["passed"] + counts["failed"] == len(expected) and counts["ignored"] == counts["measured"] == 0
            valid &= len(failed_nodes) == counts["failed"] and execution["status"] in ("passed", "failed")
            valid &= (execution["exit_code"] == 0 and state == "ok" and counts["failed"] == 0) or (execution["exit_code"] != 0 and state == "FAILED" and counts["failed"] > 0)
            if valid:
                item["status"] = "empty" if not expected else "failed" if counts["failed"] else "passed"
            else:
                errors.append("ignored, missing, timed-out, or inconsistent result for " + executable)
        harnesses.append(item)
    if totals["passed"] + totals["failed"] == 0:
        errors.append("phase executed zero tests")
    return {"harnesses": harnesses, "counts": dict(totals), "inventory_errors": errors,
            "status": "incomplete" if errors else "failed" if totals["failed"] else "passed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "definition", "source_repository", "source_sha", "expected_definition_sha", "output", "work"):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    args = parser.parse_args()
    os.umask(0o022)
    candidate = Path(args.candidate).resolve(strict=True)
    definition = Path(args.definition).resolve(strict=True)
    output = Path(args.output).resolve()
    work = Path(args.work).resolve()
    output.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    env = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "CARGO_HOME", "RUSTUP_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR") if key in os.environ}
    env.update(CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="1", CARGO_TERM_COLOR="never", LC_ALL="C", RUST_BACKTRACE="1",
               CARGO_TARGET_DIR=str(work / "target"), GIT_OPTIONAL_LOCKS="0", RUSTUP_TOOLCHAIN="1.95.0")
    challenge = secrets.token_hex(32)
    env["CHIO_CAGE_EVIDENCE_CHALLENGE"] = challenge
    result = {"schema": "chio.native-cage-full-diagnostics.v1", "evidence_class": "diagnostic-only-unattested",
              "status": "running", "source_repository": args.source_repository, "source_sha": args.source_sha,
              "definition_sha": args.expected_definition_sha, "uid": os.geteuid(), "gid": os.getegid(),
              "groups": os.getgroups(), "uname": list(platform.uname()), "commands": [],
              "challenge": challenge, "challenge_origin": "diagnostic-runner-random-not-qualification-authority",
              "timeouts_seconds": {"harness": 120, "phase_execution": 600, "build_or_setup": 1800},
              "phases": {phase: {"status": "not_run"} for phase in ("full", "mutations")}}
    write_json(output / "result.json", result)

    def run(label, command, *, command_env=None, timeout=1800):
        print("+ " + shlex.join(command), flush=True)
        record, content = run_owned(command, cwd=candidate, env=command_env or env, log=output / (label + ".log"), timeout=timeout)
        record["label"] = label
        result["commands"].append(record)
        write_json(output / "result.json", result)
        print(f"{label}: exit={record['exit_code']}\n" + content[-3000:], flush=True)
        return record, content

    def require(label, command, **kwargs):
        record, content = run(label, command, **kwargs)
        if record["exit_code"] != 0 or record.get("unreaped_root_pid") or record["descendant_cleanup"]["unreaped_owned_children"]:
            raise RuntimeError(f"setup command {label} failed or left owned children")
        return content

    def capture_fixture_env(path):
        for item in path.read_bytes().split(b"\0"):
            if b"=" not in item:
                continue
            key, value = item.split(b"=", 1)
            key = os.fsdecode(key)
            if key.startswith("CHIO_CAGE_TEST_") or key == "CHIO_CAGE_PARENT_SECRET":
                env[key] = os.fsdecode(value)

    def phase(name, cargo_args):
        phase_root = output / name
        phase_root.mkdir(exist_ok=True)
        for mode in ("list", "run"):
            (phase_root / mode).mkdir(exist_ok=True)
        cargo = ["cargo", "+1.95.0", "test", "--locked", "--target", NATIVE_TARGET, "--no-fail-fast"] + cargo_args
        build, build_text = run(name + "-build", cargo + ["--no-run", "--message-format=json"])
        records = {"build_exit_code": build["exit_code"]}
        for mode in ("list", "run"):
            wrapper = [sys.executable, "-I", str(definition / "scripts/run-native-cage-diagnostics.py"), "--harness-wrapper",
                       "--output", str(phase_root / mode), "--mode", mode, "--timeout", "120", "--"]
            config = "target." + NATIVE_TARGET + ".runner=" + json.dumps(wrapper)
            command = cargo[:2] + ["--config", config] + cargo[2:] + ["--", "--list" if mode == "list" else "--nocapture", "--test-threads=1"]
            record, _ = run(name + "-" + mode, command, timeout=600)
            records[mode + "_exit_code"] = record["exit_code"]
            records[mode + "_timed_out"] = bool(record.get("timed_out"))
            records[mode + "_unreaped_owned_children"] = record["descendant_cleanup"]["unreaped_owned_children"]
        manifests = {str(candidate / "crates/security" / package / "Cargo.toml") for package in PACKAGES}
        try:
            observed = compare_phase(build_text, phase_root / "list", phase_root / "run", manifests)
        except (OSError, ValueError, KeyError) as error:
            observed = {"status": "incomplete", "harnesses": [], "inventory_errors": [f"{type(error).__name__}: {error}"]}
        observed.update(records)
        if name == "full" and observed.get("counts", {}).get("filtered", 0) != 0:
            observed["status"] = "incomplete"
            observed["inventory_errors"].append("full phase unexpectedly filtered tests")
        if records["build_exit_code"] != 0 or records["list_exit_code"] != 0 or records["list_timed_out"] or records["run_timed_out"] or records["list_unreaped_owned_children"] or records["run_unreaped_owned_children"]:
            observed["status"] = "incomplete"
        elif observed["status"] == "passed" and records["run_exit_code"] != 0:
            observed["status"] = "incomplete"
        result["phases"][name] = observed
        write_json(phase_root / "result.json", observed)
        write_json(output / "result.json", result)

    source_before = None
    try:
        if args.source_repository != "bb-connor/arc" or args.source_sha != SOURCE_SHA:
            raise RuntimeError("this full diagnostic is bound to the reviewed exact source SHA")
        if not re.fullmatch("[0-9a-f]{40}", args.expected_definition_sha):
            raise RuntimeError("invalid full diagnostic definition SHA")
        if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
            raise RuntimeError("native Linux x86_64 under the existing non-root user is required")
        if candidate in (output, work) or candidate in output.parents or candidate in work.parents:
            raise RuntimeError("artifacts and build outputs must be outside the source checkout")
        enable_subreaper()
        if require("source-head-before", ["git", "rev-parse", "HEAD"]).strip() != SOURCE_SHA:
            raise RuntimeError("candidate HEAD differs from exact requested source")
        if require("definition-head", ["git", "-C", str(definition), "rev-parse", "HEAD"]).strip() != args.expected_definition_sha:
            raise RuntimeError("diagnostic definition HEAD differs from dispatch SHA")
        require("source-tree", ["git", "rev-parse", "HEAD^{tree}"])
        if require("source-status-before", ["git", "status", "--porcelain=v1", "--untracked-files=all"]).strip():
            raise RuntimeError("source checkout dirty before diagnostics")
        source_before = snapshot(candidate, output / "source-before.json")
        result["source_before_sha256"] = source_before
        result["definition_files"] = {path: digest(definition / path) for path in (".github/workflows/enterprise-hardening.yml", "scripts/run-native-cage-diagnostics.py")}
        for source in map(Path, ("/etc/os-release", "/proc/version", "/proc/self/status")):
            if source.is_file():
                (output / source.name).write_bytes(source.read_bytes())
        require("uname", ["uname", "-a"])
        require("identity", ["id", "-a"])
        toolchain = tomllib.loads((candidate / "rust-toolchain.toml").read_text())["toolchain"]
        if toolchain != {"channel": "1.95.0", "profile": "minimal", "components": ["clippy", "rustfmt"]}:
            raise RuntimeError("candidate toolchain differs from reviewed exact Rust toolchain")
        result["toolchain"] = toolchain
        setup_source = candidate / "crates/security/chio-cage/scripts/check-linux-enforcement.sh"
        if digest(setup_source) != SETUP_SCRIPT_SHA256:
            raise RuntimeError("native setup script differs from reviewed exact source")
        result["setup_files"] = {path: digest(candidate / path) for path in ("rust-toolchain.toml", "Cargo.lock", "crates/security/chio-cage/scripts/check-linux-enforcement.sh", "crates/security/chio-cage/tests/fixtures/cage_probe.c", "crates/security/chio-cage/tests/fixtures/cage_dynamic_probe.c")}
        require("rust-toolchain-install", ["rustup", "toolchain", "install", "1.95.0", "--profile", "minimal", "--component", "clippy", "--component", "rustfmt", "--target", "x86_64-unknown-linux-musl"])
        require("rustc-version", ["rustc", "+1.95.0", "-vV"])
        require("cargo-version", ["cargo", "+1.95.0", "--version"])
        require("rust-targets", ["rustup", "target", "list", "--installed", "--toolchain", "1.95.0"])
        require("cc-version", ["cc", "--version"])
        require("musl-gcc-version", ["musl-gcc", "--version"])
        probes = output / "probes"
        probes.mkdir(mode=0o755, exist_ok=True)
        original = setup_source.read_text()
        marker = 'crate="$root/crates/security/chio-cage"\n'
        prefix = marker + original.split(marker, 1)[1].split("\nrun_cargo_lane() {", 1)[0] + "\n"
        header = "#!/usr/bin/env bash\nset -euo pipefail\numask 022\nset -x\n" + "root=" + shlex.quote(str(candidate)) + "\nprobe_dir=" + shlex.quote(str(probes)) + "\n"
        normal_env = output / "normal-fixtures.env"
        normal_setup = output / "normal-setup.sh"
        normal_setup.write_text(header + prefix + "env -0 > " + shlex.quote(str(normal_env)) + "\n")
        result["extracted_setup_sha256"] = digest(normal_setup)
        require("normal-native-setup", ["bash", str(normal_setup)])
        capture_fixture_env(normal_env)
        for label, option in (("header", "-hW"), ("segments", "-lW"), ("dynamic", "-dW")):
            require("normal-helper-elf-" + label, ["readelf", option, str(probes / "cage-init-normal")])
        if set(path.name for path in probes.glob("probe-*")) != {"probe-" + str(mode) for mode in range(1, 40)}:
            raise RuntimeError("exact source native probe set was not built completely")
        runtime_paths = env["CHIO_CAGE_TEST_DYNAMIC_RUNTIME"].splitlines()
        write_json(output / "native-fixtures-normal.json", {"modes": list(range(1, 40)), "mode_zero": "absent-in-source-invalid", "environment": {key: value for key, value in env.items() if key.startswith("CHIO_CAGE_")}, "binaries": {path.name: digest(path) for path in sorted(probes.iterdir())}, "dynamic_runtime": {path: digest(Path(path)) for path in runtime_paths}})
        all_args = [arg for package in PACKAGES for arg in ("-p", package)] + ["--all-targets", "--features", "real-linux-enforcement"]
        phase("full", all_args)

        # Full-suite failure never bypasses the independently built mutant helper/phase.
        function = "build_static_helper() {" + prefix.split("build_static_helper() {", 1)[1].split('\nbuild_static_helper real-linux-enforcement "$probe_dir/cage-init-normal"', 1)[0]
        mutant_env = output / "mutant-fixtures.env"
        mutant_setup = output / "mutant-setup.sh"
        mutant_setup.write_text(header + 'static_target_dir="$CARGO_TARGET_DIR/static-pie"\n' + function + '\nbuild_static_helper real-linux-enforcement,enforcement-mutants "$probe_dir/cage-init-mutants"\n' + "env -0 > " + shlex.quote(str(mutant_env)) + "\n")
        try:
            require("mutant-native-setup", ["bash", str(mutant_setup)])
            capture_fixture_env(mutant_env)
            for label, option in (("header", "-hW"), ("segments", "-lW"), ("dynamic", "-dW")):
                require("mutant-helper-elf-" + label, ["readelf", option, str(probes / "cage-init-mutants")])
            write_json(output / "native-fixtures-mutant.json", {"environment": {key: value for key, value in env.items() if key.startswith("CHIO_CAGE_")}, "helper_sha256": digest(probes / "cage-init-mutants")})
            phase("mutations", ["-p", "chio-cage", "--test", "linux_enforcement", "--features", "real-linux-enforcement,enforcement-mutants", "mutation_"])
        except BaseException as error:
            result["phases"]["mutations"] = {"status": "incomplete", "error": f"{type(error).__name__}: {error}"}
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        print(result["error"], file=sys.stderr, flush=True)
    finally:
        try:
            result["final_owned_descendant_cleanup"] = clean_owned_descendants()
            if result["final_owned_descendant_cleanup"]["unreaped_owned_children"]:
                result["finalization_error"] = "diagnostic still owns unreaped children"
        except BaseException as error:
            result["finalization_error"] = f"{type(error).__name__}: {error}"
        for phase_result in result["phases"].values():
            if phase_result["status"] == "not_run":
                phase_result.update(status="unavailable", reason=result.get("error", "execution interrupted"))
        try:
            if source_before is not None:
                result["source_after_sha256"] = snapshot(candidate, output / "source-after.json")
                result["source_unchanged"] = source_before == result["source_after_sha256"]
                result["source_unchanged"] &= require("source-head-after", ["git", "rev-parse", "HEAD"]).strip() == SOURCE_SHA
                result["source_unchanged"] &= not require("source-status-after", ["git", "status", "--porcelain=v1", "--untracked-files=all"]).strip()
        except BaseException as error:
            result["finalization_error"] = f"{type(error).__name__}: {error}"
        incomplete = "error" in result or "finalization_error" in result or not result.get("source_unchanged") or any(item["status"] not in ("passed", "failed") for item in result["phases"].values())
        result["status"] = "incomplete" if incomplete else "failed" if any(item["status"] == "failed" for item in result["phases"].values()) else "passed"
        result["finished_unix"] = time.time()
        write_json(output / "result.json", result)
        print(json.dumps({"status": result["status"], "phases": {name: value["status"] for name, value in result["phases"].items()}}, sort_keys=True), flush=True)
    return 2 if result["status"] == "incomplete" else 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(harness_wrapper() if sys.argv[1:2] == ["--harness-wrapper"] else main())
