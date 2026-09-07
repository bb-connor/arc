"""Run an installed, unmodified mini-SWE-agent baseline against a local fixture.

The crash trial deliberately starts a fresh agent after the first process dies.
The harness retains one DockerEnvironment; upstream does not resume the agent.
"""

import argparse
import hashlib
import importlib.metadata
import json
import logging
import os
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from urllib.parse import urlsplit

DOCKER = "/usr/bin/docker"
LABEL = "chio.comparison.owner"
MAX_STREAM = 4 * 1024 * 1024
MAX_DIAGNOSTICS = 64 * 1024
TASK = "Fix addition and verify the existing unit tests."
FILES = ("calculator.py", "test_calculator.py", "effects.txt", "test-output.txt")


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def write_control(path, value):
    temporary = path.with_name("." + path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read(path, limit=MAX_STREAM):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise ValueError("Expected a bounded regular fixture file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("Fixture file exceeds its bound")
        return content
    finally:
        os.close(descriptor)


def command(arguments, *, data=None, cwd=None, timeout=60, accepted=(0,)):
    """Bound driver output and wait time without writing unlimited diagnostics."""
    with tempfile.TemporaryFile() as source:
        if data is not None:
            if len(data) > MAX_STREAM:
                raise ValueError("Command input exceeds its bound")
            source.write(data)
            source.seek(0)
        process = subprocess.Popen(
            [str(argument) for argument in arguments],
            cwd=cwd,
            stdin=source if data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for name in buffers:
                    pipe = getattr(process, name)
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("Baseline driver command exceeded its deadline")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        content = os.read(key.fileobj.fileno(), 65536)
                        if not content:
                            selector.unregister(key.fileobj)
                            continue
                        buffer = buffers[key.data]
                        limit = MAX_STREAM if key.data == "stdout" else MAX_DIAGNOSTICS
                        if len(buffer) + len(content) > limit:
                            raise ValueError("Baseline driver command exceeded its output bound")
                        buffer.extend(content)
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            raise
        finally:
            process.stdout.close()
            process.stderr.close()
        if process.returncode not in accepted:
            raise RuntimeError(
                f"{Path(str(arguments[0])).name} returned {process.returncode}: "
                + buffers["stderr"].decode(errors="replace")[:4096]
            )
        return process.returncode, bytes(buffers["stdout"])


def docker(*arguments, **kwargs):
    return command([DOCKER, *arguments], **kwargs)[1]


def configuration(path):
    value = json.loads(read(path, MAX_DIAGNOSTICS))
    if set(value) != {"source", "revision", "image", "endpoint", "output", "scenario", "owner"}:
        raise ValueError("Unexpected comparison configuration fields")
    if not all(isinstance(item, str) for item in value.values()):
        raise ValueError("Comparison configuration values must be strings")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value["image"]) is None:
        raise ValueError("An immutable local execution image is required")
    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value["revision"]) is None:
        raise ValueError("An exact source revision is required")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value["owner"]) is None:
        raise ValueError("A bounded container ownership label is required")
    if value["scenario"] not in {"clean", "patch-return-crash"}:
        raise ValueError("Unknown comparison scenario")
    endpoint = urlsplit(value["endpoint"])
    if (
        endpoint.scheme != "http"
        or endpoint.hostname != "127.0.0.1"
        or endpoint.port is None
        or not 1 <= endpoint.port <= 65535
        or endpoint.path != "/v1"
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
    ):
        raise ValueError("The fixture provider must be an explicit loopback HTTP endpoint")
    value["source"] = str(Path(value["source"]).resolve(strict=True))
    value["output"] = str(Path(value["output"]).absolute())
    return value


def private_environment(output, endpoint):
    """Do not import upstream while ambient provider credentials are available."""
    home = output / "home"
    home.mkdir(mode=0o700)
    os.environ.clear()
    os.environ.update(
        {
            "HOME": str(home),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TMPDIR": str(output),
            "PYTHONDONTWRITEBYTECODE": "1",
            "MSWEA_GLOBAL_CONFIG_DIR": str(output / "mini-config"),
            "MSWEA_SILENT_STARTUP": "1",
            "MSWEA_GLOBAL_COST_LIMIT": "0",
            "MSWEA_GLOBAL_CALL_LIMIT": "0",
            "MSWEA_MODEL_RETRY_STOP_AFTER_ATTEMPT": "1",
            "LITELLM_LOCAL_MODEL_COST_MAP": "True",
            "LITELLM_TELEMETRY": "False",
            "DO_NOT_TRACK": "1",
            "OTEL_SDK_DISABLED": "true",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    sys.dont_write_bytecode = True
    allowed = ("127.0.0.1", urlsplit(endpoint).port)

    def network_audit(event, arguments):
        if event == "socket.getaddrinfo":
            if (arguments[0], arguments[1]) != allowed:
                raise PermissionError("Baseline permits only its loopback fixture provider")
        elif event in {"socket.connect", "socket.sendto"}:
            address = arguments[-1]
            if not isinstance(address, tuple) or address[:2] != allowed:
                raise PermissionError("Baseline permits only its loopback fixture provider")
        elif event == "socket.sendmsg" and arguments[-1] is not None:
            if arguments[-1][:2] != allowed:
                raise PermissionError("Baseline permits only its loopback fixture provider")

    sys.addaudithook(network_audit)


def run_arguments(owner):
    return [
        "--pull=never",
        "--label=" + LABEL + "=" + owner,
        "--network=none",
        "--ipc=private",
        "--cgroupns=private",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user=65534:65534",
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--pids-limit=64",
        "--shm-size=8m",
        "--init",
        "--restart=no",
        "--log-driver=none",
        "--no-healthcheck",
        "--ulimit=core=0",
        "--ulimit=nofile=128:128",
        "--ulimit=fsize=16777216:16777216",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--tmpfs=/workspace:rw,nosuid,nodev,size=64m,mode=0700,uid=65534,gid=65534",
        "--env=HOME=/workspace",
        "--env=TMPDIR=/tmp",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint=/usr/bin/env",
    ]


def owned_containers(owner):
    return (
        docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "label=" + LABEL + "=" + owner)
        .decode()
        .splitlines()
    )


def container_record(identifier, owner, image):
    value = json.loads(docker("inspect", identifier))[0]
    if (
        re.fullmatch(r"[0-9a-f]{64}", identifier) is None
        or value["Id"] != identifier
        or value["Image"] != image
        or value["Config"].get("Labels", {}).get(LABEL) != owner
    ):
        raise ValueError("Baseline container ownership or image changed")
    return value


def cleanup(owner, image, environment):
    expected = environment.container_id if environment is not None else None
    if environment is not None:
        # Disable upstream's unchecked asynchronous destructor even if our
        # ownership verification or synchronous removal fails.
        environment.container_id = None
    if expected is not None and exact_container_exists(expected):
        container_record(expected, owner, image)
    removed = []
    for identifier in owned_containers(owner):
        record = container_record(identifier, owner, image)
        docker("rm", "--force", "--volumes", record["Id"])
        removed.append(identifier)
    if owned_containers(owner):
        raise RuntimeError("Baseline container cleanup is unresolved")
    if expected is not None and exact_container_exists(expected):
        raise RuntimeError("The original baseline container remains after cleanup")
    return {
        "removed_container_ids": removed,
        "owned_containers_remaining": 0,
        "original_container_absence_verified": expected is not None,
    }


def exact_container_exists(identifier):
    if re.fullmatch(r"[0-9a-f]{64}", identifier) is None:
        raise ValueError("An exact baseline container ID is required")
    matches = (
        docker("ps", "--all", "--quiet", "--no-trunc", "--filter", "id=" + identifier)
        .decode()
        .splitlines()
    )
    if matches not in ([], [identifier]):
        raise ValueError("Baseline container identity is ambiguous")
    return bool(matches)


def child_attempt(environment, config, attempt, directory):
    """The only execution hook is the requested crash after a real return."""
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_STREAM, MAX_STREAM))
    with (directory / "diagnostics.log").open("xb") as diagnostics:
        os.dup2(diagnostics.fileno(), 1)
        os.dup2(diagnostics.fileno(), 2)
    try:
        import litellm
        from minisweagent.agents.default import DefaultAgent
        from minisweagent.models.litellm_model import LitellmModel

        litellm.telemetry = False
        registry = directory / "model-registry.json"
        metadata = {
            "max_tokens": 1024,
            "input_cost_per_token": 0.000002,
            "output_cost_per_token": 0.000008,
            "litellm_provider": "openai",
            "mode": "chat",
        }
        write(
            registry,
            {name: metadata for name in ("openai/comparison-fixture", "comparison-fixture")},
        )
        model = LitellmModel(
            model_name="openai/comparison-fixture",
            model_kwargs={
                "api_base": config["endpoint"],
                "api_key": "comparison-fixture-value",
                "timeout": 30,
                "max_tokens": 1024,
                "temperature": 0,
                "num_retries": 0,
            },
            litellm_model_registry=registry,
        )
        agent = DefaultAgent(
            model,
            environment,
            system_template="Repair the Python repository using bash commands.",
            instance_template="{{task}}",
            step_limit=8,
            cost_limit=1,
            wall_time_limit_seconds=600,
            output_path=directory / "trajectory.json",
        )
        if config["scenario"] == "patch-return-crash" and attempt == 1:
            execute = environment.execute

            def execute_then_crash(action, *arguments, **keywords):
                result = execute(action, *arguments, **keywords)
                if "checkpoint-gap" in action.get("command", ""):
                    with (directory / "crash-boundary.json").open("x") as marker:
                        json.dump(
                            {"event": "execute-returned", "action": action, "result": result},
                            marker,
                        )
                        marker.flush()
                        os.fsync(marker.fileno())
                    os.kill(os.getpid(), signal.SIGKILL)
                return result

            environment.execute = execute_then_crash
        write(directory / "agent-result.json", agent.run(TASK))
        os._exit(0)
    except BaseException:
        (directory / "failure.txt").write_text(traceback.format_exc()[-MAX_DIAGNOSTICS:])
        os._exit(1)


def attempt(environment, config, number, output, deadline, configuration_path=None):
    directory = output / f"attempt-{number}"
    directory.mkdir(mode=0o700)
    started = time.monotonic()
    sys.stdout.flush()
    sys.stderr.flush()
    ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
    try:
        pid = os.fork()
    except BaseException:
        os.close(ready_read)
        os.close(ready_write)
        raise
    if pid == 0:
        try:
            os.close(ready_write)
            try:
                if os.read(ready_read, 1) != b"1":
                    os._exit(1)
            finally:
                os.close(ready_read)
            child_attempt(environment, config, number, directory)
        finally:
            # A diagnostics failure must never unwind into parent-only cleanup.
            os._exit(1)
    os.close(ready_read)
    timed_out = False
    child_reaped = False
    control = None
    try:
        process_stat = read(Path(f"/proc/{pid}/stat"), MAX_DIAGNOSTICS).decode()
        process_fields = process_stat.rsplit(") ", 1)[1].split()
        control = {
            "schema": "chio.mini-swe.comparison-process.v1",
            "pid": pid,
            "uid": os.getuid(),
            "start_ticks": int(process_fields[19]),
            "pgid": pid if os.getpgid(pid) == pid else None,
            "cmdline_sha256": hashlib.sha256(read(Path(f"/proc/{pid}/cmdline"))).hexdigest(),
            "config_path": str(configuration_path) if configuration_path is not None else None,
            "output": str(output),
            "owner": config.get("owner"),
            "image": config.get("image"),
            "attempt": number,
            "state": "running",
        }
        write_control(directory / "control.json", control)
        # EOF makes the child exit if this parent dies before durable publication.
        os.write(ready_write, b"1")
        os.close(ready_write)
        ready_write = None
        while True:
            if control["pgid"] is None and os.getpgid(pid) == pid:
                control["pgid"] = pid
                write_control(directory / "control.json", control)
            reaped, status, usage = os.wait4(pid, os.WNOHANG)
            if reaped:
                child_reaped = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                kill_child(pid)
                _, status, usage = os.wait4(pid, 0)
                child_reaped = True
                break
            time.sleep(0.05)
    except BaseException:
        kill_child(pid)
        os.wait4(pid, 0)
        child_reaped = True
        raise
    finally:
        if ready_write is not None:
            os.close(ready_write)
        if control is not None:
            control["state"] = "reaped" if child_reaped else "running"
            write_control(directory / "control.json", control)
    record = {
        "attempt": number,
        "returncode": os.waitstatus_to_exitcode(status),
        "watchdog_expired": timed_out,
        "wall_seconds": time.monotonic() - started,
        "driver_child_user_cpu_seconds": usage.ru_utime,
        "driver_child_system_cpu_seconds": usage.ru_stime,
        "driver_child_max_rss_kib": usage.ru_maxrss,
        "accounting_scope": "wait4 child usage; excludes Docker daemon and container cgroup usage",
        "trajectory_exists": (directory / "trajectory.json").is_file(),
        "crash_boundary_exists": (directory / "crash-boundary.json").is_file(),
    }
    if record["trajectory_exists"]:
        trajectory_bytes = read(directory / "trajectory.json")
        trajectory = json.loads(trajectory_bytes)
        record["trajectory"] = {
            "path": str(directory / "trajectory.json"),
            "sha256": hashlib.sha256(trajectory_bytes).hexdigest(),
            "saved_model_calls": trajectory["info"]["model_stats"]["api_calls"],
            "saved_message_count": len(trajectory["messages"]),
            "saved_exit_status": trajectory["info"]["exit_status"],
        }
    if (directory / "agent-result.json").is_file():
        record["agent_result"] = json.loads(read(directory / "agent-result.json"))
    write(directory / "outcome.json", record)
    return record


def kill_child(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        # The child may not have reached setsid(), or may already have exited.
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def run(config, configuration_path=None):
    started = time.monotonic()
    output = Path(config["output"])
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    private_environment(output, config["endpoint"])
    from minisweagent import __version__, package_dir
    from minisweagent.environments.docker import DockerEnvironment

    if __version__ != "2.4.6":
        raise ValueError("The baseline requires the installed mini-swe-agent 2.4.6")
    report = {
        "schema": "chio.mini-swe.upstream-comparison.v1",
        "scenario": config["scenario"],
        "source_commit": config["revision"],
        "configuration": config,
        "mini_swe_agent_version": __version__,
        "litellm_version": importlib.metadata.version("litellm"),
        "upstream_module_sha256": {
            name: hashlib.sha256(read(package_dir / name)).hexdigest()
            for name in ("agents/default.py", "environments/docker.py", "models/litellm_model.py")
        },
        "architecture": "one retained upstream DockerEnvironment; no per-command container lease",
        "rerun_policy": (
            "explicit parent rerun with a fresh DefaultAgent and LitellmModel; "
            "no trajectory restore"
        ),
        "upstream_automatic_recovery": False,
        "completed": False,
        "attempts": [],
    }
    environment = None
    owns_label = False
    try:
        source = Path(config["source"])
        if command(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source)[1]:
            raise ValueError("Baseline requires the clean committed comparison fixture")
        revision = command(["git", "rev-parse", "HEAD"], cwd=source)[1].decode().strip()
        if revision != config["revision"]:
            raise ValueError("Baseline source HEAD differs from the selected commit")
        entries = command(["git", "ls-tree", "-rz", revision], cwd=source)[1].split(b"\0")
        names = set()
        for entry in filter(None, entries):
            metadata, name = entry.split(b"\t", 1)
            mode, kind, _ = metadata.split(b" ")
            if mode not in {b"100644", b"100755"} or kind != b"blob":
                raise ValueError("The comparison fixture must contain only regular source files")
            names.add(name)
        if names != {b"calculator.py", b"test_calculator.py"}:
            raise ValueError("Unexpected comparison fixture files")
        archive = command(["git", "archive", "--format=tar", revision], cwd=source)[1]
        (output / "source.tar").write_bytes(archive)
        report["source_archive_sha256"] = hashlib.sha256(archive).hexdigest()
        image = json.loads(docker("image", "inspect", config["image"]))[0]
        if image["Id"] != config["image"] or image["Config"].get("Volumes"):
            raise ValueError("Execution image differs or declares additional writable volumes")
        if owned_containers(config["owner"]):
            raise ValueError("Comparison ownership label already exists")
        owns_label = True
        environment_logger = logging.getLogger("comparison.upstream.environment")
        environment_logger.setLevel(logging.CRITICAL)
        environment_logger.propagate = False
        environment_logger.addHandler(logging.NullHandler())
        environment = DockerEnvironment(
            logger=environment_logger,
            image=config["image"],
            cwd="/workspace",
            timeout=20,
            interpreter=["/bin/bash", "--noprofile", "--norc", "-c"],
            executable=DOCKER,
            forward_env=[],
            env={"HOME": "/workspace", "TMPDIR": "/tmp", "PYTHONDONTWRITEBYTECODE": "1"},
            run_args=run_arguments(config["owner"]),
            container_timeout="600s",
            pull_timeout=60,
        )
        record = container_record(environment.container_id, config["owner"], config["image"])
        if not record["State"]["Running"]:
            raise RuntimeError("Baseline execution container did not remain running")
        write_control(
            output / "container-control.json",
            {
                "schema": "chio.mini-swe.comparison-container.v1",
                "id": record["Id"],
                "owner": config["owner"],
                "image": config["image"],
                "output": str(output),
                "config_path": (
                    str(configuration_path) if configuration_path is not None else None
                ),
            },
        )
        report["container"] = {
            "id": record["Id"],
            "image": record["Image"],
            "owner": record["Config"]["Labels"][LABEL],
            "user": record["Config"]["User"],
            "host_config": record["HostConfig"],
            "environment_configuration": environment.config.model_dump(mode="json"),
        }
        docker(
            "exec",
            "-i",
            environment.container_id,
            "/bin/tar",
            "--extract",
            "--no-same-owner",
            "--file=-",
            "--directory=/workspace",
            data=archive,
        )
        report["setup_seconds"] = time.monotonic() - started
        execution_started = time.monotonic()
        first = attempt(environment, config, 1, output, started + 600, configuration_path)
        report["attempts"].append(first)
        if config["scenario"] == "patch-return-crash":
            if first["returncode"] != -signal.SIGKILL or not first["crash_boundary_exists"]:
                raise RuntimeError("The requested upstream execution-return crash was not observed")
            report["stopped_process_outcome"] = {
                "returncode": first["returncode"],
                "upstream_resumed": False,
                "saved_trajectory": first.get("trajectory"),
                "workspace_retained_by": "comparison parent retaining DockerEnvironment",
                "effects_after_stop": docker(
                    "exec", environment.container_id, "/bin/cat", "/workspace/effects.txt"
                )
                .decode()
                .splitlines(),
                "calculator_sha256_after_stop": hashlib.sha256(
                    docker("exec", environment.container_id, "/bin/cat", "/workspace/calculator.py")
                ).hexdigest(),
            }
            report["attempts"].append(
                attempt(environment, config, 2, output, started + 600, configuration_path)
            )
        report["execution_seconds"] = time.monotonic() - execution_started
        last = report["attempts"][-1]
        report["agent_submitted"] = (
            last["returncode"] == 0
            and last.get("agent_result", {}).get("exit_status") == "Submitted"
        )
        export_started = time.monotonic()
        final = output / "final"
        final.mkdir(mode=0o700)
        report["files"] = {}
        for name in FILES:
            status_code, content = command(
                [DOCKER, "exec", environment.container_id, "/bin/cat", "/workspace/" + name],
                accepted=(0, 1),
            )
            if status_code == 0:
                (final / name).write_bytes(content)
                report["files"][name] = {
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
        baseline = output / "baseline"
        baseline.mkdir(mode=0o700)
        for name in ("calculator.py", "test_calculator.py"):
            (baseline / name).write_bytes(
                command(["git", "show", revision + ":" + name], cwd=source)[1]
            )
        patch = command(
            ["git", "diff", "--no-index", "--", "baseline/calculator.py", "final/calculator.py"],
            cwd=output,
            accepted=(0, 1),
        )[1]
        (output / "patch.diff").write_bytes(patch)
        report["patch_sha256"] = hashlib.sha256(patch).hexdigest()
        report["effects"] = (
            read(final / "effects.txt").decode().splitlines()
            if (final / "effects.txt").is_file()
            else []
        )
        report["test_output"] = (
            read(final / "test-output.txt").decode()
            if (final / "test-output.txt").is_file()
            else None
        )
        report["export_seconds"] = time.monotonic() - export_started
    except BaseException as error:
        report["error_type"] = type(error).__name__
        (output / "failure.txt").write_text(traceback.format_exc()[-MAX_DIAGNOSTICS:])
        raise
    finally:
        try:
            if owns_label:
                report["cleanup"] = cleanup(config["owner"], config["image"], environment)
            report["completed"] = (
                report.get("agent_submitted", False) and "error_type" not in report
            )
        except BaseException as error:
            report["cleanup"] = {"verified": False, "error_type": type(error).__name__}
            report["error_type"] = type(error).__name__
            (output / "cleanup-failure.txt").write_text(traceback.format_exc()[-MAX_DIAGNOSTICS:])
            raise
        finally:
            report["total_seconds"] = time.monotonic() - started
            write(output / "result.json", report)
    if not report["completed"]:
        raise RuntimeError("Upstream baseline did not submit the fixture task")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    value = run(configuration(arguments.config), arguments.config.resolve(strict=True))
    print(json.dumps({"result": str(Path(value["configuration"]["output"]) / "result.json")}))


if __name__ == "__main__":
    main()
