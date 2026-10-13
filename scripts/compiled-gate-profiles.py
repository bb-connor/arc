#!/usr/bin/env python3
"""Produce ordinary host Cargo evidence using the original qualification inspector.

This records a host-trusted source/image graph. Shared OS runtime metadata is an
explicit host assumption, without retained OS-image or confinement coverage.
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

FORMAT = "chio.local-command-provenance.v1"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write(path, value):
    with path.open("xb") as output:
        output.write(canonical(value) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    return path


def reference(root, path):
    return {"path": str(path.relative_to(root)), "sha256": sha(path)}


def create_evidence(root, requested, recorder):
    path = recorder.absolute(requested)
    target = root/"target"
    recorder.require(path != target and path.is_relative_to(target), "host_evidence_not_fresh")
    parts = path.relative_to(target).parts
    with ExitStack() as stack:
        parent = stack.enter_context(recorder.HeldPath(target, directory=True))
        for index, part in enumerate(parts):
            if index == len(parts)-1:
                parent.verify(content=False)
                os.mkdir(part, 0o700, dir_fd=parent.fd)
                parent = stack.enter_context(recorder.HeldPath(parent.path/part, directory=True))
            else:
                try:
                    selected = recorder.HeldPath(parent.path/part, directory=True)
                except FileNotFoundError:
                    selected = recorder.mkdir(parent, part)
                parent = stack.enter_context(selected)
        parent.verify(content=False)
    return path


def original_image(recorder, path, purpose):
    with recorder.HeldPath(path) as held:
        body = held.read()
        return {"path": str(path), "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "purpose": purpose}


def selected_tool(command):
    return Path(subprocess.check_output(command, text=True).strip()).resolve(strict=True)


def prepare_host(root, evidence, inventory, recorder):
    recorder.require(platform.system() == "Darwin", "host_execution_platform")
    compiler = selected_tool(["rustup", "which", "rustc"])
    cargo = selected_tool(["rustup", "which", "cargo"])
    linker = selected_tool(["xcrun", "--find", "clang"])
    sdk = selected_tool(["xcrun", "--show-sdk-path"])
    linker_binary = selected_tool(["xcrun", "--find", "ld"])
    toolchain = compiler.parent.parent
    namespace = evidence/"namespace"
    target = evidence/"cargo-target"
    namespace.mkdir()
    target.mkdir()
    images = [original_image(recorder, cargo, "cargo"), original_image(recorder, linker, "linker"),
              original_image(recorder, linker_binary, "linker-support"), original_image(recorder, Path("/usr/lib/dyld"), "loader")]
    lto = linker.parent.parent/"lib/libLTO.dylib"
    if lto.exists():
        images.append(original_image(recorder, lto.resolve(strict=True), "linker-support"))
    aliases = []
    for directory, directories, files in os.walk(sdk, followlinks=False):
        for name in sorted([*directories, *files]):
            path = Path(directory)/name
            if path.is_symlink():
                text = os.readlink(path)
                recorder.require(not recorder.secret_path(text) and path.resolve(strict=True).is_relative_to(sdk), "host_tool_alias")
                aliases.append({"path": str(path), "text": text})
            elif path.is_file() and (path.suffix == ".tbd" or path.parent == sdk and path.name.startswith("SDKSettings.")):
                images.append(original_image(recorder, path, "sdk"))
    cache_directory = Path("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld")
    cache_rows = []
    if cache_directory.is_dir():
        architecture = "arm64e" if platform.machine() == "arm64" else "x86_64"
        for path in sorted(cache_directory.glob("dyld_shared_cache_"+architecture+"*")):
            info = path.stat(follow_symlinks=False)
            recorder.require(stat.S_ISREG(info.st_mode), "host_runtime_metadata")
            cache_rows.append({"path": str(path), "size": info.st_size, "mtime_ns": info.st_mtime_ns})
    host = {"schema": "chio.ordinary-host-execution.v1", "repository": str(root), "namespace": str(namespace),
        "source_binding": inventory["source_binding"], "target_directory": str(target),
        "target": {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}[platform.machine()],
        "machine": platform.machine(), "compiler": str(compiler), "cargo": str(cargo), "linker": str(linker),
        "sdk": str(sdk), "toolchain": str(toolchain), "images": sorted(images, key=lambda item: item["path"]),
        "aliases": sorted(aliases, key=lambda item: item["path"]),
        "runtime_metadata": {"coverage": "ordinary-host-observation-no-retained-os-image-coverage",
            "system": platform.system(), "release": platform.release(), "version": platform.version(),
            "macos_version": platform.mac_ver()[0], "shared_cache_file_metadata": cache_rows},
        "vendor_roots": [str(Path.home()/".cargo/registry/src")],
        "runtime_inventory": {key: value for key, value in original_image(recorder, evidence/"runtime-preparation.json", "runtime-inventory").items() if key != "purpose"}}
    configuration = write(evidence/"host-execution.json", host)
    python_bin = Path(sys.executable).resolve().parent
    environment = {"PATH": os.pathsep.join([str(compiler.parent), str(python_bin), "/opt/homebrew/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
        "HOME": str(Path.home()), "CARGO_HOME": str(Path.home()/".cargo"), "RUSTC": str(compiler),
        "RUSTDOC": str(compiler.parent/"rustdoc"), "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
        "CARGO_PROFILE_DEV_DEBUG": "0", "CARGO_PROFILE_TEST_DEBUG": "0", "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never", "CARGO_TARGET_DIR": str(target), "SDKROOT": str(sdk),
        "RUSTFLAGS": "-Csplit-debuginfo=off -Clinker="+str(linker),
        "RUSTC_WRAPPER": str(root/"scripts/record-rust-compilation.py"),
        "CHIO_COMPILATION_SOURCE_ROOT": str(root), "CHIO_COMPILATION_SOURCE_BINDING": inventory["source_binding"],
        "CHIO_COMPILATION_RECORDS": str(namespace), "CHIO_COMPILATION_HOST_EXECUTION": str(configuration)}
    return host, configuration, environment


def git(root, arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments])


def snapshot(root, pins, verifier, recorder):
    """Measure Git-visible paths without opening excluded file contents."""
    listed = git(root, ["ls-files", "--stage", "-z"])
    others = git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    head = git(root, ["rev-parse", "--verify", "HEAD"]).decode().strip()
    entries = {}
    for item in filter(None, listed.split(b"\0")):
        metadata, name = item.split(b"\t", 1)
        mode, blob, stage = metadata.split()
        entries.setdefault(os.fsdecode(name), {"membership": "tracked", "index": []})["index"].append(
            {"mode": mode.decode(), "object": blob.decode(), "stage": int(stage)})
    for item in filter(None, others.split(b"\0")):
        entries.setdefault(os.fsdecode(item), {"membership": "nonignored-untracked"})
    for name, entry in entries.items():
        relative = verifier.relative_path(name)
        exclusion = verifier.source_exclusion(name)
        if exclusion is not None:
            metadata = verifier.source_metadata(root, relative)
            entry.update({key: value for key, value in metadata.items() if key != "path"})
            if "index" in entry:
                entry["index"] = [{key: value for key, value in item.items() if key != "object"} for item in entry["index"]]
            continue
        if set(relative.parts).intersection(verifier.BUILD_DIRECTORIES):
            info = (root/relative).lstat()
            entry.update(state="symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "file",
                         mode=stat.S_IMODE(info.st_mode), content_coverage="metadata-only", exclusion_reason="cache-tree-policy")
            continue
        path = root/relative
        try:
            info = path.lstat()
        except FileNotFoundError:
            entry["state"] = "missing"
            continue
        entry["mode"] = stat.S_IMODE(info.st_mode)
        if stat.S_ISLNK(info.st_mode):
            text = os.readlink(path)
            entry.update(state="symlink", content_coverage="link-text-only", target=text,
                         target_sha256=hashlib.sha256(os.fsencode(text)).hexdigest())
            recorder.require(recorder.identity(path.lstat()) == recorder.identity(info), "source_changed_during_read")
        elif stat.S_ISREG(info.st_mode):
            with recorder.HeldPath(path) as held:
                body = held.read()
            entry.update(state="file", content_coverage="sha256-bytes", size_bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
        else:
            entry.update(state="directory" if stat.S_ISDIR(info.st_mode) else "special", content_coverage="metadata-only")
    explicit = []
    for path, purpose in pins:
        with recorder.HeldPath(path) as held:
            body = held.read()
        explicit.append({"path": str(path), "purpose": purpose, "observed": {"state": "file", "content_coverage": "sha256-bytes",
            "size_bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}})
    recorder.require(listed == git(root, ["ls-files", "--stage", "-z"])
                     and others == git(root, ["ls-files", "--others", "--exclude-standard", "-z"])
                     and head == git(root, ["rev-parse", "--verify", "HEAD"]).decode().strip(), "source_changed_during_read")
    manifest = {"git": {"head": head}, "entries": entries, "explicit_file_pins": explicit}
    return {"format": FORMAT, **manifest, "content_manifest_sha256": hashlib.sha256(canonical(manifest)).hexdigest()}


def inventory(root, verifier):
    head = git(root, ["rev-parse", "--verify", "HEAD"]).decode().strip()
    sources = verifier.current_source_inventory(root)
    return {"source_inventory_version": verifier.INVENTORY_VERSION, "base_commit": head,
            "sources": sources, "source_binding": verifier.binding(sources, head)}


def wait_owned_group_exit(process, grace=5):
    """Observe only the dedicated process group created by this launch."""
    deadline = time.monotonic()+grace
    while True:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def stop_owned_group(process):
    # A reaped leader does not mean its remaining group members have stopped.
    for selected_signal in [signal.SIGTERM, signal.SIGKILL]:
        try:
            os.killpg(process.pid, selected_signal)
        except ProcessLookupError:
            return
        if wait_owned_group_exit(process):
            return
    raise subprocess.TimeoutExpired("owned command process group", 10)


def capture_command(root, command, environment, log, timeout):
    """Own, bound and reap this launch even when logging or pipe polling fails."""
    began = time.monotonic()
    process = None
    actual = None
    failure = None
    cleanup_errors = []
    timed_out = disk_floor = completed_pipe = False
    cleanup_deadline = None
    try:
        process = subprocess.Popen(command, cwd=root, env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while not completed_pipe or process.poll() is None:
                now = time.monotonic()
                if cleanup_deadline is None and (now-began >= timeout or shutil.disk_usage(root).free < 10*1024**3):
                    timed_out = now-began >= timeout
                    disk_floor = not timed_out
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    cleanup_deadline = now+5
                if cleanup_deadline is not None and now >= cleanup_deadline:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    if now >= cleanup_deadline+5:
                        break
                for key, _ in selector.select(0.2):
                    body = os.read(key.fd, 64*1024)
                    if body:
                        log.write(body)
                    else:
                        selector.unregister(key.fileobj)
                        completed_pipe = True
            actual = process.wait(timeout=5)
    except BaseException as error:
        failure = error
    finally:
        if process is not None:
            try:
                if failure is not None or timed_out or disk_floor or not completed_pipe or process.poll() is None:
                    stop_owned_group(process)
            except BaseException as error:
                cleanup_errors.append(type(error).__name__)
                if failure is None:
                    failure = error
            try:
                actual = process.wait(timeout=5)
            except BaseException as error:
                cleanup_errors.append(type(error).__name__)
                if failure is None:
                    failure = error
            finally:
                try:
                    process.stdout.close()
                except BaseException as error:
                    cleanup_errors.append(type(error).__name__)
                    if failure is None:
                        failure = error
        try:
            log.flush()
            os.fsync(log.fileno())
        except BaseException as error:
            if failure is None:
                failure = error
    return {"actual": actual, "timed_out": timed_out, "disk_floor": disk_floor,
            "completed_pipe": completed_pipe, "cleanup_errors": cleanup_errors,
            "elapsed": time.monotonic()-began, "ended": time.time()}, failure


def execute(root, evidence, name, command, environment, pins, verifier, recorder, timeout):
    stage = evidence/name
    stage.mkdir()
    before_runtime = inventory(root, verifier)
    before = snapshot(root, pins, verifier, recorder)
    write(stage/"runtime-before.json", before_runtime)
    write(stage/"before.json", before)
    write(stage/"start.json", {"format": FORMAT, "repository": str(root), "cwd": str(root),
        "command": command, "environment": environment, "started_unix_seconds": time.time()})
    recorder.require(shutil.disk_usage(root).free >= 10*1024**3, "host_disk_floor")
    with (stage/"command.log").open("xb") as log:
        observation, failure = capture_command(root, command, environment, log, timeout)
    actual = observation["actual"]
    timed_out, disk_floor, completed_pipe = (observation[key] for key in ["timed_out", "disk_floor", "completed_pipe"])
    after = snapshot(root, pins, verifier, recorder)
    after_runtime = inventory(root, verifier)
    write(stage/"after.json", after)
    write(stage/"runtime-after.json", after_runtime)
    drift = before["content_manifest_sha256"] != after["content_manifest_sha256"] or before_runtime != after_runtime
    log_ref = reference(evidence, stage/"command.log")
    write(stage/"result.json", {"format": FORMAT, "actual_command_exit": actual,
        "runner_exit": 86 if failure is not None or actual is None else actual if actual != 0 else 86 if drift or timed_out or disk_floor or not completed_pipe else 0,
        "inventories_complete": True, "output_pipe_completed": completed_pipe,
        "provenance_error": type(failure).__name__ if failure is not None else None,
        "cleanup_errors": observation["cleanup_errors"],
        "source_drift": {"detected": drift}, "before_manifest_sha256": before["content_manifest_sha256"],
        "after_manifest_sha256": after["content_manifest_sha256"], "log": log_ref,
        "ended_unix_seconds": observation["ended"], "elapsed_seconds": observation["elapsed"],
        "timed_out": timed_out, "disk_floor_reached": disk_floor})
    proof = {key: reference(evidence, stage/filename) for key, filename in {
        "start": "start.json", "result": "result.json", "before": "before.json", "after": "after.json",
        "runtime_sources_before": "runtime-before.json", "runtime_sources_after": "runtime-after.json"}.items()}
    row = {"command": command, "cwd": ".", "environment": environment, "exit_code": actual,
        "source_stable": not drift, "source_binding": before_runtime["source_binding"], "log": log_ref, "provenance": proof}
    write(stage/"execution.json", row)
    if failure is not None:
        raise failure
    recorder.require(actual == 0 and not drift and not timed_out and not disk_floor and completed_pipe, "host_command_failed")
    return row, before_runtime


def export(root, evidence, gate, producer, runtime, host, environment, verifier, recorder, timeout):
    namespace = Path(host["namespace"])
    rows = [json.loads(path.read_bytes()) for path in sorted((namespace/"records").glob("*.json"))]
    # Cargo build scripts can deliberately compile feature probes that fail.
    # Preserve their outcomes; the original graph consumer accepts producers
    # only from successful units. Instrumentation refusals still fail the gate.
    recorder.require(rows and all(type(row["compiler_exit"]) is int and
        (row["status"] == "success" and row["compiler_exit"] == 0 or
         row["status"] == "compiler_failed" and row["compiler_exit"] != 0)
        for row in rows), "host_compilation_failed")
    current = {str(root/item["path"]): item["sha256"] for item in runtime["sources"] if "sha256" in item}
    inputs, images = {}, {}
    for row in rows:
        for image in [*row["inputs"], *row["outputs"], *([row["compiler"]] if row["compiler"] else [])]:
            key = (image["sha256"], image["size"])
            images[key] = {**reference(evidence, namespace/image["artifact"]), "size": image["size"]}
            if image.get("role") == "source":
                path = image["path"]
                role = "candidate" if path in current else "campaign-produced" if Path(path).is_relative_to(root/"target") else "vendor"
                recorder.require(role != "candidate" or current[path] == image["sha256"], "host_source_binding")
                recorder.require(role != "vendor" or any(Path(path).is_relative_to(Path(vendor)) for vendor in host["vendor_roots"]), "host_vendor_scope")
                inputs[path] = {"path": path, "sha256": image["sha256"], "size": image["size"], "role": role}
    # Tooling is normalized through invocation-bound declarations. Every CAS
    # object is still exported and independently checked by the consumer.
    for path in sorted((namespace/"artifacts").iterdir()):
        with recorder.HeldPath(path) as held:
            body = held.read()
        digest = hashlib.sha256(body).hexdigest()
        recorder.require(digest == path.name, "host_cas_binding")
        images[(digest, len(body))] = {"path": str(path.relative_to(evidence)), "sha256": digest, "size": len(body)}
    import tomllib
    packages = []
    for index, argument in enumerate(producer["command"][:-1]):
        if argument == "-p":
            packages.append(producer["command"][index+1])
    package_roots = set()
    for row in rows:
        for item in row["inputs"]:
            path = Path(item["path"])
            if item.get("role") == "source" and path.name == "Cargo.toml" and str(path) in current:
                body = tomllib.loads((namespace/item["artifact"]).read_text())
                if body.get("package", {}).get("name") in packages:
                    package_roots.add(path.parent)
    roots = [{key: image[key] for key in ["path", "sha256", "size"]} for row in rows
             if row["kind"] == "compilation" and any(Path(row["semantics"]["source"]).is_relative_to(path) for path in package_roots)
             for image in row["outputs"] if image["role"] == "unit"]
    recorder.require(roots, "host_gate_roots")
    runtime_ref = producer["provenance"]["runtime_sources_before"]
    request = {"schema": "chio.compiler-profile-custody-request.v1", "namespace": str(namespace), "repository": str(root),
        "runtime_inventory": {"path": str(evidence/runtime_ref["path"]), "sha256": runtime_ref["sha256"]},
        "source_binding": runtime["source_binding"], "roots": roots,
        "additional_inputs": [image for image in inputs.values() if image["role"] != "candidate"],
        "selected_invocation_ids": [row["invocation_id"] for row in rows], "mode": "host-trusted-fresh", "linux": None}
    # The existing provenance consumer normalizes repository-contained argv.
    # Its inspector contract requires an absolute request argument, so retain
    # the original request in a private external directory and archive its bytes.
    request_directory = Path(tempfile.mkdtemp(prefix="chio-host-profile-", dir="/private/tmp"))
    request_path = write(request_directory/"request.json", request)
    request_copy = write(evidence/"request.json", request)
    write(evidence/"request-location.json", {"original_path": str(request_path), "sha256": sha(request_path)})
    inspector = root/"scripts/verify-recovery-qualification.py"
    command = ["python3", "-I", "-B", "scripts/verify-recovery-qualification.py", "--compiler-profile-request", str(request_path)]
    inspector_environment = {"PATH": environment["PATH"], "HOME": environment["HOME"]}
    observed, inspector_runtime = execute(root, evidence, "inspector", command, inspector_environment,
        [(request_path, "compiler-profile-request"), (inspector, "compiler-profile-inspector")], verifier, recorder, timeout)
    recorder.require(inspector_runtime == runtime, "host_source_binding")
    records = [json.loads(line[len("COMPILER_PROFILE_CUSTODY "):]) for line in (evidence/observed["log"]["path"]).read_text().splitlines()
               if line.startswith("COMPILER_PROFILE_CUSTODY ")]
    recorder.require(len(records) == 1, "host_inspector_observation")
    report_path = write(evidence/"custody-report.json", records[0])
    tool_copy = evidence/"inspector.py"
    with tool_copy.open("xb") as output:
        output.write(inspector.read_bytes())
    rows_path = write(evidence/"rows.json", rows)
    profile = {"schema": "chio.compiled-profile-evidence.v1", "source_binding": runtime["source_binding"],
        "mode": "host-trusted-fresh", "subjects": {"gate/"+gate: roots}, "producer": producer,
        "runtime_inventory": runtime_ref, "custody_request": reference(evidence, request_copy),
        "custody_report": reference(evidence, report_path), "custody_execution": observed,
        "custody_tool": reference(evidence, tool_copy), "rows": reference(evidence, rows_path),
        "inputs": list(inputs.values()), "roots": roots, "images": list(images.values()), "linux": None}
    profile_path = write(evidence/"compiled-profile.json", profile)
    result = verifier.audit_compiled_profile(evidence, profile, runtime["source_binding"], runtime["sources"], runtime["base_commit"])
    aggregate = verifier.audit_compiled_profiles(evidence,
        {"gates": [producer], "compiled_profiles": [reference(evidence, profile_path)]},
        runtime["source_binding"], runtime["sources"], runtime["base_commit"])
    negative = {}
    all_gate_subjects = verifier.compiled_subjects(evidence,
        {"gates": [{"id": identifier, **entry} for identifier, entry in verifier.gate_catalog().items()]})
    negative_subjects = {"relabelled-kernel": {"gate/kernel": roots},
                         "unrelated-all-gates": {name: roots for name in sorted(all_gate_subjects)}}
    recorder.require({"gate/contracts", "gate/kernel"} <= set(all_gate_subjects), "host_gate_catalog")
    for label, subjects in negative_subjects.items():
        changed = {**profile, "subjects": subjects}
        try:
            verifier.audit_compiled_profile(evidence, changed, runtime["source_binding"], runtime["sources"], runtime["base_commit"])
        except ValueError as error:
            negative[label] = str(error)
        else:
            raise recorder.Refusal("host_unrelated_subject_accepted")
        recorder.require(negative[label] == "qualification.compiled_profile_producer_subject", "host_negative_control_reason")
    write(evidence/"acceptance.json", {"accepted_subjects": sorted(result["subjects"]), "mode": result["mode"],
        "graph": result["graph"], "aggregate": aggregate, "negative_controls": negative,
        "negative_subjects": {label: sorted(subjects) for label, subjects in negative_subjects.items()}, "qualified": False})
    print(json.dumps({"evidence": str(evidence), "accepted_subjects": sorted(result["subjects"]), "negative_controls": negative, "qualified": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--gate", choices=["contracts"], default="contracts")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    verifier = load(root/"scripts/verify-recovery-qualification.py", "ordinary_gate_verifier")
    recorder = load(root/"scripts/record-rust-compilation.py", "ordinary_gate_recorder")
    evidence = recorder.absolute(args.evidence)
    recorder.require(0 < args.timeout <= 7200 and shutil.disk_usage(root).free >= 10*1024**3, "host_execution_limits")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, max(soft, 16384)), hard))
    evidence = create_evidence(root, evidence, recorder)
    runtime = inventory(root, verifier)
    write(evidence/"runtime-preparation.json", runtime)
    host, configuration, environment = prepare_host(root, evidence, runtime, recorder)
    command = verifier.gate_catalog()[args.gate]["command"]
    producer, measured = execute(root, evidence, "producer", command, environment,
        [(configuration, "ordinary-host-execution"), (root/"scripts/record-rust-compilation.py", "compiler-recorder")], verifier, recorder, args.timeout)
    recorder.require(measured == runtime, "host_source_binding")
    producer["id"] = args.gate
    write(evidence/"producer.json", producer)
    export(root, evidence, args.gate, producer, runtime, host, environment, verifier, recorder, args.timeout)


if __name__ == "__main__":
    main()
