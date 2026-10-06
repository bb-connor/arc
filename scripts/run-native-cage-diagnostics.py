#!/usr/bin/env python3
"""Native regression diagnostics only. No qualification or attestation output."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib


DESIGN_SHA = "c8e0ed88ecbf92e7b6276644c74888a32af568cf"
CASES = (
    ("F057-admission", "linux_compile", "admission_with_a_missing_write_grant_creates_nothing"),
    ("F057-denied-admission", "linux_compile", "a_denied_admission_leaves_no_write_grant_behind"),
    ("F057-write-owner", "linux_compile", "compile_creates_a_pending_write_grant_owned_by_the_execution_identity"),
    ("F059-absolute", "linux_enforcement", "a_second_exec_by_absolute_path_is_killed"),
    ("F059-proc-fd", "linux_enforcement", "a_second_exec_through_proc_self_fd_is_killed"),
    ("F059-interpreter", "linux_enforcement", "a_second_exec_through_the_interpreter_is_killed"),
    ("control-empty-path", "linux_enforcement", "target_exec_exception_cannot_be_recreated_after_exec"),
)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(root, destination):
    """Hash all repository content, including untracked files; exclude Git internals."""
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
                entry.update(kind="symlink", target=target,
                             sha256=hashlib.sha256(os.fsencode(target)).hexdigest())
            elif stat.S_ISREG(info.st_mode):
                entry.update(kind="file", bytes=info.st_size, sha256=digest(path))
            else:
                raise RuntimeError(f"unsupported source file type: {entry['path']}")
            entries.append(entry)
    entries.sort(key=lambda entry: entry["path"])
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    result = {"root": str(root), "excluded": [".git"], "entries": entries,
              "content_sha256": hashlib.sha256(encoded).hexdigest()}
    write_json(destination, result)
    return result["content_sha256"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "definition", "source_repository", "source_sha",
                 "expected_definition_sha", "output", "work"):
        parser.add_argument("--" + name.replace("_", "-"), required=True)
    args = parser.parse_args()
    os.umask(0o022)
    candidate = Path(args.candidate).resolve(strict=True)
    definition = Path(args.definition).resolve(strict=True)
    output = Path(args.output).resolve()
    work = Path(args.work).resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "cases").mkdir(exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    env = {key: os.environ[key] for key in
           ("PATH", "HOME", "LANG", "LC_ALL", "CARGO_HOME", "RUSTUP_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR")
           if key in os.environ}
    env.update(CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="1", CARGO_TERM_COLOR="never", LC_ALL="C",
               CARGO_TARGET_DIR=str(work / "target"), GIT_OPTIONAL_LOCKS="0", RUST_BACKTRACE="1")
    result = {"schema": "chio.native-cage-diagnostics.v1",
              "evidence_class": "diagnostic-only-unattested", "status": "running",
              "setup_reference_sha": DESIGN_SHA, "source_repository": args.source_repository,
              "source_sha": args.source_sha, "definition_sha": args.expected_definition_sha,
              "uname": list(platform.uname()), "uid": os.geteuid(), "gid": os.getegid(),
              "groups": os.getgroups(), "commands": [],
              "cases": [{"id": case_id, "target": target, "node": node, "status": "not_run"}
                        for case_id, target, node in CASES]}
    write_json(output / "result.json", result)
    write_json(output / "expected-inventory.json", result["cases"])

    def run(label, command, *, command_env=None, timeout=1800):
        child_env = command_env or env
        record = {"label": label, "argv": command, "shell_command": shlex.join(command),
                  "cwd": str(candidate), "started_unix": time.time(), "timeout_seconds": timeout,
                  "environment": child_env.copy(), "log": label + ".log"}
        result["commands"].append(record)
        write_json(output / "result.json", result)
        print("+ " + record["shell_command"], flush=True)
        with (output / record["log"]).open("wb") as log:
            try:
                process = subprocess.Popen(command, cwd=candidate, env=child_env,
                                           stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    record["exit_code"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                    record["process_exit_code"] = process.returncode
                    record["exit_code"] = 124
                except BaseException:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    record.update(exit_code=130, interrupted=True, process_exit_code=process.returncode)
                    record["finished_unix"] = time.time()
                    write_json(output / "result.json", result)
                    raise
            except OSError as error:
                record.update(exit_code=127, spawn_error=str(error))
                log.write((str(error) + "\n").encode())
        record["finished_unix"] = time.time()
        write_json(output / "result.json", result)
        content = (output / record["log"]).read_text(errors="replace")
        print(f"{label}: exit={record['exit_code']}\n" + content[-3000:], flush=True)
        return record, content

    def require(label, command, **kwargs):
        record, content = run(label, command, **kwargs)
        if record["exit_code"] != 0:
            raise RuntimeError(f"setup command {label} failed with exit {record['exit_code']}")
        return content

    def case(case_result):
        prefix = ["cargo", "+" + result["toolchain"]["channel"], "test", "--locked", "-p", "chio-cage",
                  "--test", case_result["target"], "--features", "real-linux-enforcement", case_result["node"], "--", "--exact"]
        listed, inventory = run(case_result["id"] + "-list", prefix + ["--list"])
        case_result["list_exit_code"] = listed["exit_code"]
        case_result["observed_inventory"] = [line for line in inventory.splitlines() if line.endswith(": test")]
        case_result["inventory_valid"] = listed["exit_code"] == 0 and case_result["observed_inventory"] == [case_result["node"] + ": test"]
        executed, text = run(case_result["id"] + "-run", prefix + ["--nocapture", "--test-threads=1"], timeout=600)
        case_result["run_exit_code"] = executed["exit_code"]
        summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", text, re.M)
        observed = bool(re.search(r"^test " + re.escape(case_result["node"]) + r" \.\.\. ", text, re.M))
        case_result["node_observed"] = observed
        case_result["test_summaries"] = summaries
        if len(summaries) == 1:
            _, passed, failed, ignored, measured, _ = summaries[0]
            case_result["exactly_one_executed"] = int(passed) + int(failed) == 1 and int(ignored) == int(measured) == 0 and observed
        else:
            case_result["exactly_one_executed"] = False
        if executed.get("timed_out"):
            case_result["status"] = "timed_out"
        elif not case_result["exactly_one_executed"]:
            case_result["status"] = "not_executed"
        elif not case_result["inventory_valid"]:
            case_result["status"] = "inventory_failed"
        elif executed["exit_code"] == 0 and summaries[0][1:5] == ("1", "0", "0", "0"):
            case_result["status"] = "passed"
        elif executed["exit_code"] != 0 and summaries[0][1:5] == ("0", "1", "0", "0"):
            case_result["status"] = "failed"
        else:
            case_result["status"] = "result_inconsistent"
        write_json(output / "cases" / (case_result["id"] + ".json"), case_result)
        write_json(output / "result.json", result)

    source_before = None
    try:
        if args.source_repository != "bb-connor/arc" or not re.fullmatch("[0-9a-f]{40}", args.source_sha):
            raise RuntimeError("invalid repository or full source SHA")
        if not re.fullmatch("[0-9a-f]{40}", args.expected_definition_sha):
            raise RuntimeError("invalid full diagnostic definition SHA")
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise RuntimeError("native Linux x86_64 required; no emulation or cross-platform evidence")
        if os.geteuid() == 0:
            raise RuntimeError("root execution refused; F057 ownership case uses actual UID and rejects root identity")
        if candidate in (output, work) or candidate in output.parents or candidate in work.parents:
            raise RuntimeError("diagnostic artifacts and build outputs must be outside the source checkout")
        head = require("source-head-before", ["git", "rev-parse", "HEAD"]).strip()
        if head != args.source_sha:
            raise RuntimeError("candidate HEAD differs from requested source SHA")
        definition_head = require("definition-head", ["git", "-C", str(definition), "rev-parse", "HEAD"]).strip()
        if definition_head != args.expected_definition_sha:
            raise RuntimeError("diagnostic definition HEAD differs from dispatched workflow SHA")
        require("source-tree", ["git", "rev-parse", "HEAD^{tree}"])
        dirty = require("source-status-before", ["git", "status", "--porcelain=v1", "--untracked-files=all"])
        if dirty.strip():
            raise RuntimeError("candidate checkout is dirty before diagnostics")
        source_before = snapshot(candidate, output / "source-before.json")
        result["source_before_sha256"] = source_before
        result["definition_files"] = {path: digest(definition / path) for path in
                                      (".github/workflows/enterprise-hardening.yml", "scripts/run-native-cage-diagnostics.py")}
        for path in ("/etc/os-release", "/proc/version", "/proc/self/status"):
            source = Path(path)
            if source.is_file():
                (output / source.name).write_bytes(source.read_bytes())
        require("uname", ["uname", "-a"])
        require("identity", ["id", "-a"])
        toolchain = tomllib.loads((candidate / "rust-toolchain.toml").read_text())["toolchain"]
        if toolchain != {"channel": "1.95.0", "profile": "minimal", "components": ["clippy", "rustfmt"]}:
            raise RuntimeError("candidate Rust toolchain differs from the reviewed exact toolchain")
        result["toolchain"] = toolchain
        result["setup_files"] = {path: digest(candidate / path) for path in
                                 ("rust-toolchain.toml", "Cargo.lock", "crates/security/chio-cage/scripts/check-linux-enforcement.sh",
                                  "crates/security/chio-cage/tests/fixtures/cage_probe.c", "crates/security/chio-cage/tests/fixtures/cage_dynamic_probe.c")}
        require("rust-toolchain-install", ["rustup", "toolchain", "install", toolchain["channel"], "--profile", toolchain["profile"],
                                            "--component", "clippy", "--component", "rustfmt", "--target", "x86_64-unknown-linux-musl"])
        require("rustc-version", ["rustc", "+" + toolchain["channel"], "-vV"])
        require("cargo-version", ["cargo", "+" + toolchain["channel"], "--version"])
        require("rust-targets", ["rustup", "target", "list", "--installed", "--toolchain", toolchain["channel"]])
        require("cc-version", ["cc", "--version"])
        require("musl-gcc-version", ["musl-gcc", "--version"])
        for item in result["cases"][:3]:
            case(item)

        # Bounded fixture/helper setup derived from DESIGN_SHA's check-linux-enforcement.sh.
        crate = candidate / "crates/security/chio-cage"
        probes = output / "probes"
        probes.mkdir(mode=0o755, exist_ok=True)
        static_cc = ["cc", "-nostdlib", "-static", "-fno-stack-protector", "-fno-pie", "-no-pie", "-Wl,--build-id=none"]
        fixture = str(crate / "tests/fixtures/cage_probe.c")
        dynamic_fixture = str(crate / "tests/fixtures/cage_dynamic_probe.c")
        marker = probes / "probe-36"
        dynamic = probes / "dynamic-probe"
        dynamic_marker = probes / "dynamic-exec-marker"
        require("probe-36-build", static_cc + ["-DPROBE_MODE=36", fixture, "-o", str(marker)])
        require("dynamic-probe-build", ["cc", "-O2", "-fno-stack-protector", "-Wl,--build-id=none", dynamic_fixture, "-o", str(dynamic)])
        dependencies = require("dynamic-probe-ldd", ["ldd", str(dynamic)])
        dynamic_paths, interpreter = [], None
        for line in dependencies.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[1] == "=>" and fields[2].startswith("/"):
                dynamic_paths.append(fields[2])
            elif fields and fields[0].startswith("/"):
                interpreter = interpreter or fields[0]
                dynamic_paths.append(fields[0])
        if Path("/etc/ld.so.cache").is_file():
            dynamic_paths.append("/etc/ld.so.cache")
        runtime_paths = []
        for index, path in enumerate(dynamic_paths):
            resolved = require("dynamic-runtime-resolve-" + str(index), ["readlink", "-e", "--", path]).strip()
            if not Path(resolved).is_file():
                raise RuntimeError("dynamic runtime artifact is not a regular file")
            if resolved not in runtime_paths:
                runtime_paths.append(resolved)
        if not interpreter or len(runtime_paths) < 2:
            raise RuntimeError("dynamic probe did not resolve interpreter and shared library")
        interpreter = require("interpreter-resolve", ["readlink", "-e", "--", interpreter]).strip()
        require("dynamic-marker-build", ["cc", "-O2", "-fno-stack-protector", "-Wl,--build-id=none", "-DPROBE_EXIT=171", dynamic_fixture, "-o", str(dynamic_marker)])
        for mode, path in ((10, probes / "probe-10"), (34, marker), (35, marker), (37, dynamic_marker)):
            defines = ["-DPROBE_MODE=" + str(mode), "-DPROBE_PATH=" + json.dumps(str(path))]
            if mode == 37:
                defines.append("-DPROBE_LDSO=" + json.dumps(interpreter))
            require("probe-" + str(mode) + "-build", static_cc + defines + [fixture, "-o", str(probes / ("probe-" + str(mode)))])
        static_target = work / "static-pie"
        helper_env = dict(env, CARGO_TARGET_DIR=str(static_target))
        require("static-helper-build", ["cargo", "+" + toolchain["channel"], "build", "--locked", "--target", "x86_64-unknown-linux-musl", "-p", "chio-cage-init", "--bin", "chio-cage-init", "--features", "real-linux-enforcement"], command_env=helper_env)
        helper = static_target / "x86_64-unknown-linux-musl/debug/chio-cage-init"
        header = require("helper-elf-header", ["readelf", "-hW", str(helper)])
        segments = require("helper-elf-segments", ["readelf", "-lW", str(helper)])
        dynamic_section = require("helper-elf-dynamic", ["readelf", "-dW", str(helper)])
        if not os.access(helper, os.X_OK) or not re.search(r"^\s*Type:\s+DYN\b", header, re.M) or re.search(r"\bINTERP\b", segments) or re.search(r"\((NEEDED|RPATH|RUNPATH)\)", dynamic_section):
            raise RuntimeError("cage-init failed the reference static PIE executable checks")
        retained_helper = probes / "cage-init-normal"
        shutil.copy2(helper, retained_helper)
        env.update(CHIO_CAGE_TEST_HELPER=str(retained_helper), CHIO_CAGE_TEST_REEXEC=str(probes / "probe-10"),
                   CHIO_CAGE_TEST_EXEC_MARKER=str(marker), CHIO_CAGE_TEST_EXEC_DYNAMIC_MARKER=str(dynamic_marker),
                   CHIO_CAGE_TEST_EXEC_ABSOLUTE=str(probes / "probe-34"), CHIO_CAGE_TEST_EXEC_PROC_FD=str(probes / "probe-35"),
                   CHIO_CAGE_TEST_EXEC_INTERPRETER=str(probes / "probe-37"), CHIO_CAGE_TEST_DYNAMIC_RUNTIME="\n".join(runtime_paths))
        write_json(output / "native-fixtures.json", {"environment": {key: value for key, value in env.items() if key.startswith("CHIO_CAGE_TEST_")},
                                                     "binaries": {path.name: digest(path) for path in sorted(probes.iterdir())},
                                                     "dynamic_runtime": {path: digest(Path(path)) for path in runtime_paths}})
        for item in result["cases"][3:]:
            case(item)
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        print(result["error"], file=sys.stderr, flush=True)
    finally:
        for item in result["cases"]:
            if item["status"] == "not_run":
                item.update(status="unavailable", reason=result.get("error", "execution interrupted"))
            write_json(output / "cases" / (item["id"] + ".json"), item)
        try:
            if source_before is not None:
                result["source_after_sha256"] = snapshot(candidate, output / "source-after.json")
                result["source_unchanged"] = source_before == result["source_after_sha256"]
                head_after = require("source-head-after", ["git", "rev-parse", "HEAD"]).strip()
                dirty_after = require("source-status-after", ["git", "status", "--porcelain=v1", "--untracked-files=all"])
                result["source_unchanged"] &= head_after == args.source_sha and not dirty_after.strip()
        except BaseException as error:
            result["finalization_error"] = f"{type(error).__name__}: {error}"
        incomplete = "error" in result or "finalization_error" in result or not result.get("source_unchanged") or any(item["status"] not in ("passed", "failed") for item in result["cases"])
        result["status"] = "incomplete" if incomplete else "failed" if any(item["status"] == "failed" for item in result["cases"]) else "passed"
        result["finished_unix"] = time.time()
        write_json(output / "result.json", result)
        print(json.dumps({"status": result["status"], "cases": {item["id"]: item["status"] for item in result["cases"]}}, sort_keys=True), flush=True)
    return 2 if result["status"] == "incomplete" else 1 if result["status"] == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
