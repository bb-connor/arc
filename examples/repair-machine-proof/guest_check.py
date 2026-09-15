"""Trusted Linux guest checker for the existing seven-case repair contract.

This executable run is not itself a cryptographic proof. The surrounding
machine state, inputs, completion and output must all be covered by a verifier.
"""

# Reproducible fixture entropy unblocks Python/OpenSSL initialization. It is
# public and must never be used to generate production secrets or exchange keys.
import fcntl
import os
import struct

with open("/dev/random", "wb") as entropy:
    fcntl.ioctl(entropy, 0x40085203, struct.pack("ii", 256, 32) + bytes(range(32)))

import hashlib
import json
from pathlib import Path
import resource
import shutil
import subprocess
import sys

ROOT = Path("/opt/chio")
WORK = Path("/work")
JAIL = Path("/candidate")
MESSAGE = "test: checked repository repair"
HOOKS = [
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "reference-transaction",
]
FILES = [
    "sdks/python/chio-adapter-base/src/chio_adapter_base/security.py",
    "sdks/python/chio-hermes/src/chio_hermes/executors.py",
]
ENV = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/nonexistent",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_AUTHOR_NAME": "repair-check",
    "GIT_AUTHOR_EMAIL": "repair@invalid",
    "GIT_COMMITTER_NAME": "repair-check",
    "GIT_COMMITTER_EMAIL": "repair@invalid",
    "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    "HOOK_TEST_PATH": "/work/hooks",
    "PYTHONHASHSEED": "0",
}


def normalize(argv):
    result, cursor, commit = [], 0, False
    while cursor < len(argv):
        if not commit and argv[cursor : cursor + 2] == [
            "-c",
            "core.hooksPath=/dev/null",
        ]:
            cursor += 2
            continue
        if argv[cursor] == "commit":
            commit = True
        if not (commit and argv[cursor] == "--no-verify"):
            result.append(argv[cursor])
        cursor += 1
    return result


def confine_candidate():
    os.chroot(JAIL)
    os.chdir("/work")
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2, 128 * 1024**2))


def git(argv):
    result = subprocess.run(
        ["/usr/bin/git", *argv],
        cwd=WORK,
        env=ENV,
        capture_output=True,
        text=True,
        check=False,
    )
    return {"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def git_ok(argv):
    result = git(argv)
    if result["code"] != 0:
        raise ValueError(f"Git setup failed: {result}")


def main():
    artifact_bytes = (ROOT / "artifact.json").read_bytes()
    artifact = json.loads(artifact_bytes)
    contract = json.loads((ROOT / "contract.json").read_bytes())
    if (
        set(artifact) != {"baseSha256", "files"}
        or artifact["baseSha256"] != contract["baseSha256"]
        or set(artifact["files"]) != set(FILES)
    ):
        raise ValueError("unselected base or paths")
    if any(len(s.encode()) > 256 * 1024 for s in artifact["files"].values()):
        raise ValueError("source exceeds contract limit")
    for name, short in zip(FILES, ["security.py", "executors.py"]):
        (JAIL / short).write_text(artifact["files"][name])
    requests = contract["requests"]
    (JAIL / "requests.json").write_text(json.dumps(requests))
    child = subprocess.run(
        ["/usr/bin/python3.12", "-I", "-S", "-B", "/driver.py"],
        env=ENV,
        preexec_fn=confine_candidate,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    if child.returncode or len(child.stdout) > 1024 * 1024:
        raise ValueError(f"candidate failed: {child.returncode}: {child.stderr[:1024]}")
    calls = json.loads(child.stdout)
    if not isinstance(calls, list) or len(calls) != 7:
        raise ValueError("wrong invocation count")
    rows = []
    for index, argv in enumerate(calls):
        expected = (
            requests[index]["argv"]
            if index < 5
            else [
                "git",
                "-C",
                "/work",
                "--git-dir",
                "/work/.git",
                "--work-tree",
                "/work",
                "commit",
                "-m",
                MESSAGE,
            ]
        )
        if (
            not isinstance(argv, list)
            or len(argv) > 64
            or any(not isinstance(a, str) or len(a) > 4096 or "\0" in a for a in argv)
            or normalize(argv) != normalize(expected)
        ):
            raise ValueError("candidate changed the requested operation")
        if WORK.exists():
            shutil.rmtree(WORK)
        WORK.mkdir()
        git_ok(["init", "-q"])
        (WORK / "change.txt").write_text("checked change\n")
        git_ok(["add", "change.txt"])
        (WORK / "hooks").mkdir()
        for name in HOOKS:
            path = WORK / "hooks" / name
            path.write_text(f"#!/bin/sh\nprintf ran >> /work/{name}.observed\n")
            path.chmod(0o700)
        git_ok(["config", "core.hooksPath", "/work/hooks"])
        execution = git(argv[1:])
        observed = [name for name in HOOKS if (WORK / f"{name}.observed").exists()]
        message = git(["log", "-1", "--format=%s"])
        committed = git(["show", "HEAD:change.txt"])
        passed = (
            execution["code"] == 0
            and not observed
            and message["code"] == 0
            and message["stdout"].strip() == MESSAGE
            and committed["code"] == 0
            and committed["stdout"] == "checked change\n"
        )
        rows.append(
            {
                "case": index,
                "argv": argv,
                "execution": execution,
                "hooksObserved": observed,
                "commitReadback": message,
                "committedFile": committed,
                "passed": passed,
            }
        )
    result = {
        "artifactSha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "passed": all(r["passed"] for r in rows),
        "cases": rows,
        "cryptographicProofVerified": False,
    }
    print("CHIO_CHECK_RESULT " + json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
