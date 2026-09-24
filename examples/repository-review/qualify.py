"""Exercise the real CLI application with two commits, failures and a model stub."""

import argparse
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from chio_process import ProcessClient
from review import host

HERE = Path(__file__).resolve().parent
PROFILES = {"inventory": "inventory", "scripted-model": "model_fixture:create"}
LIMITED_PROFILE = "limited"


def command(*args, success=True, env=None):
    result = subprocess.run(
        list(map(str, args)), capture_output=True, text=True, timeout=180, env=env
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result


def commits(directory):
    repo = directory / "repo"
    repo.mkdir()
    command("git", "init", "-q", repo)

    def commit(message):
        command("git", "-C", repo, "add", ".")
        command(
            "git",
            "-C",
            repo,
            "-c",
            "user.name=Review Test",
            "-c",
            "user.email=review@example.invalid",
            "commit",
            "--no-verify",
            "-qm",
            message,
            # These commits reproduce a digest containing a compact-SSN match.
            env={
                **os.environ,
                "GIT_AUTHOR_DATE": "1788636360 -0400",
                "GIT_COMMITTER_DATE": "1788636360 -0400",
            },
        )
        return command("git", "-C", repo, "rev-parse", "HEAD").stdout.strip()

    (repo / "app.py").write_text("value = 1\n")
    base = commit("base")
    (repo / "app.py").write_text("value = 2\n")
    (repo / "test_app.py").write_text("assert value == 2\n")
    head = commit("head")
    return repo, base, head


def exercise(binary, output, temporary):
    repo, base, head = commits(temporary)
    reports = {}
    for name, profile in PROFILES.items():
        directory = temporary / name
        app = [sys.executable, HERE / "review.py"]
        command(
            *app,
            "prepare",
            "--repo",
            repo,
            "--base",
            base,
            "--head",
            head,
            "--run-dir",
            directory,
            "--chio",
            binary,
            "--model-factory",
            profile,
        )
        # Editing the checkout cannot redirect either worker's reads.
        (repo / "app.py").write_text("uncommitted = 'must not be reviewed'\n")
        handoff_failure = command(
            *app,
            "run",
            "--run-dir",
            directory,
            "--crash-after-handoff",
            "changes",
            success=False,
        )
        assert "('changes', 77)" in handoff_failure.stderr
        first_handoff = json.loads(
            (directory / "changes/first-handoff.json").read_text()
        )
        (directory / "changes/first-handoff.json").unlink()
        failure = command(
            *app,
            "run",
            "--run-dir",
            directory,
            "--crash-after-publication",
            success=False,
        )
        assert "('publisher', 76)" in failure.stderr
        first = json.loads((directory / "publisher/first-publication.json").read_text())
        # Erase the oracle to prove recovery does not consume it.
        (directory / "publisher/first-publication.json").unlink()
        assert len(list((directory / "sockets").glob("*.sock"))) == 1
        with sqlite3.connect(directory / "publications.db") as db:
            assert db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 1
        if profile == "inventory":
            config = json.loads((directory / "run.json").read_text())
            socket = directory / "sockets/probe.sock"
            connection_path = directory / "connections/probe-changes.json"
            command(
                binary,
                "process",
                "credential",
                "--state",
                directory / "host",
                "--process",
                "changes",
                "--socket",
                socket,
                "--out",
                connection_path,
            )
            reader = json.loads(connection_path.read_text())
            with host(config, directory, socket):
                client = ProcessClient(str(socket), reader["credential"])
                forbidden = client.invoke(
                    "forbidden-publication",
                    "repo",
                    "publish_report",
                    {"report": "forbidden", "snapshot_hash": config["snapshot_hash"]},
                )
                assert forbidden["verdict"] == "deny"
                forbidden_read = client.invoke(
                    "forbidden-mailbox-read",
                    "chio-ipc",
                    "receive_tests",
                    {"after_sequence": "0", "limit": 1},
                )
                assert forbidden_read["verdict"] == "deny"
        command(*app, "run", "--run-dir", directory)
        evidence = json.loads((directory / "evidence.json").read_text())
        assert evidence["publications"] == 1
        assert evidence["publication"] == {"report_id": 1}
        if profile == "inventory":
            assert (
                evidence["report_hash"]
                == "09499777cf86e8a1e7858e4001f276e8ff79af1658e411840211a25eeba57c55"
            )
        assert len({worker["pid"] for worker in evidence["workers"].values()}) == 3
        assert evidence["base"] == base and evidence["head"] == head
        assert first in evidence["workers"]["publisher"]["receipts"]
        assert first_handoff in evidence["workers"]["changes"]["receipts"]
        assert evidence["receipt_verification"]["receipts_verified"] == (
            9 if profile == "inventory" else 13
        )
        with sqlite3.connect(directory / "host/mailboxes.db") as db:
            assert db.execute(
                "SELECT id, last_sequence, acknowledged_through FROM mailboxes ORDER BY id"
            ).fetchall() == [("changes", 1, 1), ("tests", 1, 1)]
            assert db.execute(
                "SELECT channel, payload, payload_bytes FROM mailbox_messages ORDER BY channel"
            ).fetchall() == [("changes", None, 0), ("tests", None, 0)]
        # Completed graph replay must also leave publication history unchanged.
        command(*app, "run", "--run-dir", directory)
        repeated = json.loads((directory / "evidence.json").read_text())
        assert repeated["publications"] == 1
        for role in ("changes", "tests", "publisher"):
            assert (
                repeated["workers"][role]["receipts"]
                == evidence["workers"][role]["receipts"]
            )
        # The local publication row is not itself signed. Its full report must
        # still match the parameters of the verified original invocation.
        with sqlite3.connect(directory / "publications.db") as db:
            original_report = db.execute(
                "SELECT report FROM reports WHERE id=1"
            ).fetchone()[0]
            db.execute(
                "UPDATE reports SET report=? WHERE id=1",
                (original_report + "\ntampered",),
            )
        try:
            rejected = command(*app, "run", "--run-dir", directory, success=False)
            assert (
                "published report does not match its signed invocation"
                in rejected.stderr
            )
            with sqlite3.connect(directory / "publications.db") as db:
                assert db.execute("SELECT count(*) FROM reports").fetchone()[0] == 1
                assert (
                    db.execute("SELECT report FROM reports WHERE id=1").fetchone()[0]
                    == original_report + "\ntampered"
                )
        finally:
            with sqlite3.connect(directory / "publications.db") as db:
                db.execute("UPDATE reports SET report=? WHERE id=1", (original_report,))
        command(*app, "run", "--run-dir", directory)
        secrets = [
            json.loads(p.read_text())["credential"]
            for p in (directory / "connections").glob("*.json")
        ]
        for role in ("changes", "tests", "publisher"):
            for path in (directory / role).iterdir():
                data = path.read_bytes()
                assert all(secret.encode() not in data for secret in secrets)
        source = (directory / "snapshot.json").read_text()
        (directory / "snapshot.json").write_text(
            source.replace('"value = 2', '"value = 9')
        )
        rejected = command(*app, "run", "--run-dir", directory, success=False)
        assert "snapshot changed" in rejected.stderr
        (directory / "snapshot.json").write_text(source)
        command(
            binary,
            "process",
            "cancel",
            "--state",
            directory / "host",
            "--process",
            "editor",
        )
        command(*app, "run", "--run-dir", directory, success=False)
        with sqlite3.connect(directory / "publications.db") as db:
            assert db.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 1
        destination = output / name
        destination.mkdir(mode=0o700)
        for filename in ("report.md", "evidence.json", "receipts.ndjson", "kernel.pub"):
            (destination / filename).write_bytes((directory / filename).read_bytes())
        reports[name] = {
            "publications": 1,
            "receipts_verified": evidence["receipt_verification"]["receipts_verified"],
            "host_init_seconds": evidence["host_init_seconds"],
            "recovery_attempt_seconds": evidence["attempt_seconds"],
        }
    limited = temporary / LIMITED_PROFILE
    command(
        sys.executable,
        HERE / "review.py",
        "prepare",
        "--repo",
        repo,
        "--base",
        base,
        "--head",
        head,
        "--run-dir",
        limited,
        "--chio",
        binary,
        "--max-calls",
        "6",
    )
    command(
        sys.executable, HERE / "review.py", "run", "--run-dir", limited, success=False
    )
    assert not (limited / "publications.db").exists()
    assert "limit_reached" in (limited / "publisher/worker.log").read_text()
    summary = {
        "profiles": reports,
        "live_model": False,
        "handoffs_replayed_without_duplicate_messages": True,
        "shared_call_limit_rejected_publication": True,
    }
    (output / "qualification.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


def work_directory(requested):
    # Reserve the longest profile and socket suffix before preparing any host.
    suffix = max(
        (
            Path(name) / "sockets/123456789012.sock"
            for name in (*PROFILES, LIMITED_PROFILE)
        ),
        key=lambda path: len(os.fsencode(path)),
    )
    parent = (requested.parent if requested else Path(tempfile.gettempdir())).resolve(
        strict=True
    )
    if (
        requested is None
        and len(os.fsencode(parent / "chio-rv-xxxxxxxx" / suffix)) >= 104
    ):
        parent = Path("/tmp").resolve(strict=True)
    for ancestor in (parent, *parent.parents):
        metadata = ancestor.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or (
                metadata.st_mode & 0o022
                and not (metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX)
            )
        ):
            raise ValueError("qualification work parent is not protected")
    candidate = parent / (requested.name if requested else "chio-rv-xxxxxxxx")
    if len(os.fsencode(candidate / suffix)) >= 104:
        raise ValueError("qualification work directory exceeds the socket path budget")
    if requested is not None:
        candidate.mkdir(mode=0o700, exist_ok=False)
        return candidate
    return Path(tempfile.mkdtemp(prefix="chio-rv-", dir=parent))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="new short private work directory with an existing protected parent",
    )
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    temporary = work_directory(args.work_dir)
    try:
        exercise(args.chio.resolve(strict=True), args.output, temporary)
    except BaseException:
        print(f"Preserved private failure state: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    main()
