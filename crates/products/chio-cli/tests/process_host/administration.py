"""Real host administration refusals preserve authority and caller files."""

import fcntl
import hashlib
import json
import os
import select
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from runner import command, prepare, write


def init_nonempty(binary, directory):
    state, _, _ = prepare(binary, directory / "prepared")
    unrelated = directory / "unrelated"
    unrelated.mkdir(mode=0o700)
    (unrelated / "sentinel").write_bytes(b"unrelated private state\x00")
    before = {p.name: p.read_bytes() for p in unrelated.iterdir()}
    command(
        binary,
        "init",
        "--config",
        directory / "prepared/host.json",
        "--state",
        unrelated,
        success=False,
    )
    assert {p.name: p.read_bytes() for p in unrelated.iterdir()} == before
    command(binary, "revoke", "--state", state, "--process", "absent", success=False)


def relocation_files(binary, directory):
    state, _, _ = prepare(binary, directory / "prepared")
    command(binary, "export", "--state", state)
    for name in [
        "extra",
        "extra.tmp",
        "receipts.db-wal",
        "authority.db-wal",
        "unknown.db-wal",
    ]:
        moved = directory / name.replace(".", "-")
        shutil.copytree(state, moved)
        before = (moved / "authority.db").read_bytes()
        foreign = moved / name
        foreign.write_bytes(b"unverified bytes")
        command(binary, "import", "--state", moved, success=False)
        assert (moved / "authority.db").read_bytes() == before
        assert foreign.read_bytes() == b"unverified bytes"
    for variant in ["missing-manifest-abi", "incompatible-host"]:
        moved = directory / variant
        shutil.copytree(state, moved)
        manifest_path = moved / "relocation.json"
        manifest = json.loads(manifest_path.read_text())
        if variant == "missing-manifest-abi":
            manifest.pop("abi")
            manifest["written_by"] = None
        else:
            host = moved / "host.json"
            record = json.loads(host.read_text())
            record["abi"] = "chio.process.abi.v1"
            record["written_by"] = None
            write(host, record)
            manifest["files"]["host.json"] = hashlib.sha256(
                host.read_bytes()
            ).hexdigest()
        write(manifest_path, manifest)
        before = (moved / "authority.db").read_bytes()
        command(binary, "import", "--state", moved, success=False)
        assert (moved / "authority.db").read_bytes() == before
        status = json.loads(command(binary, "status", "--state", moved).stdout)
        if variant == "incompatible-host":
            assert status["abi"]["host"] == "chio.process.abi.v1"
            assert status["abi"]["written_by"] is None


def busy_reader(binary, directory):
    state, _, _ = prepare(binary, directory / "prepared")
    database = state / "receipts.db"
    with sqlite3.connect(database) as writer, sqlite3.connect(database) as reader:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE busy_export(value INTEGER)")
        writer.commit()
        reader.execute("BEGIN")
        reader.execute("SELECT * FROM busy_export").fetchall()
        writer.execute("INSERT INTO busy_export VALUES(1)")
        writer.commit()
        before = (state / "authority.db").read_bytes()
        result = command(binary, "export", "--state", state, success=False)
        assert "checkpoint is busy" in result.stderr
        assert (state / "authority.db").read_bytes() == before
        reader.rollback()
    command(binary, "export", "--state", state)


def orphan_sidecar(binary, directory):
    state, _, _ = prepare(binary, directory / "prepared")
    assert not (state / "runner.db").exists()
    orphan = state / "runner.db-wal"
    orphan.write_bytes(b"foreign orphan WAL")
    authority = state / "authority.db"
    before = authority.read_bytes()
    locks = {p.name: p.read_bytes() for p in (state / "authority.db.locks").iterdir()}
    command(binary, "export", "--state", state, success=False)
    assert authority.read_bytes() == before, "orphan WAL refusal retired authority"
    assert orphan.read_bytes() == b"foreign orphan WAL"
    assert {
        p.name: p.read_bytes() for p in (state / "authority.db.locks").iterdir()
    } == locks
    orphan.unlink()
    assert json.loads(command(binary, "export", "--state", state).stdout)["exported"]


def committed_import_wal(binary, directory):
    state, _, _ = prepare(binary, directory / "prepared")
    command(binary, "export", "--state", state)
    moved = directory / "moved"
    shutil.copytree(state, moved)
    authority = moved / "authority.db"
    original = authority.read_bytes()
    manifest = (moved / "relocation.json").read_bytes()
    # Pin the exported snapshot across the real import commit. Connection
    # teardown cannot fold that commit into the main file while this reader lives.
    with sqlite3.connect(authority) as reader:
        reader.execute("BEGIN")
        assert reader.execute(
            "SELECT state FROM chio_serving_relocation"
        ).fetchone() == ("exported",)
        imported = json.loads(command(binary, "import", "--state", moved).stdout)
        wal = moved / "authority.db-wal"
        assert wal.stat().st_size > 32
        assert authority.read_bytes() == original, (
            "fixture must retain the import only in WAL"
        )
        (moved / "relocation.json").write_bytes(manifest)
        # The same committed WAL at another location is foreign recovery state.
        foreign = directory / "foreign"
        shutil.copytree(state, foreign)
        shutil.copyfile(wal, foreign / "authority.db-wal")
        before = {
            p.name: p.read_bytes() for p in foreign.glob("authority.db*") if p.is_file()
        }
        locks = {
            p.name: p.read_bytes() for p in (foreign / "authority.db.locks").iterdir()
        }
        command(binary, "import", "--state", foreign, success=False)
        assert all(
            (foreign / name).read_bytes() == value for name, value in before.items()
        ), "foreign WAL refusal changed authority bytes"
        assert {
            p.name: p.read_bytes() for p in (foreign / "authority.db.locks").iterdir()
        } == locks
        anchor = {
            p.name: p.read_bytes() for p in (moved / "authority.db.locks").iterdir()
        }
        host = moved / "host.json"
        host_bytes = host.read_bytes()
        wal_bytes = wal.read_bytes()
        host.write_bytes(host_bytes + b"\n")
        command(binary, "import", "--state", moved, success=False)
        assert authority.read_bytes() == original
        assert wal.read_bytes() == wal_bytes
        assert {
            p.name: p.read_bytes() for p in (moved / "authority.db.locks").iterdir()
        } == anchor
        host.write_bytes(host_bytes)
        assert (
            json.loads(command(binary, "import", "--state", moved).stdout) == imported
        )
        assert {
            p.name: p.read_bytes() for p in (moved / "authority.db.locks").iterdir()
        } == anchor
        assert authority.read_bytes() == original
        assert not (moved / "relocation.json").exists()
        reader.rollback()


def diagnostic_pipe(binary, directory):
    state, _, _ = prepare(binary, directory / "prepared")
    logs = state / "run-logs"
    logs.mkdir(mode=0o700)
    for stream in ["stdout", "stderr"]:
        path = logs / f"reader-1.{stream}"
        path.write_text("x" * 65536)
        path.chmod(0o600)
    snapshot = {
        "schema": "chio.process.run-status.v1",
        "run_id": "test",
        "observed_at_ms": 1,
        "plan_binding": "x",
        "max_parallel": 1,
        "workers": [
            {
                "process": "reader",
                "state": "completed",
                "attempts": 1,
                "max_attempts": 1,
                "outcome": "x" * 65536,
                "waiting_on": [],
            }
        ],
    }
    write(state / "run-status.json", snapshot)
    (state / "run-status.json").chmod(0o600)
    with sqlite3.connect(state / "process.db") as db:
        db.execute(
            "UPDATE processes SET checkpoint=? WHERE id='reader'",
            (json.dumps("x" * 65536),),
        )
    for args in [
        ["status"],
        ["logs", "--process", "reader", "--attempt", "1"],
        ["state", "--process", "reader"],
    ]:
        process = subprocess.Popen(
            [binary, "process", *args, "--state", str(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert select.select([process.stdout], [], [], 30)[0], (
                "no diagnostic output"
            )
            assert os.read(process.stdout.fileno(), 1), "no diagnostic bytes"
            assert process.poll() is None, "fixture must block on a full stdout pipe"
            with (state / "host.lock").open("rb") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            out, err = process.communicate(timeout=30)
            assert process.returncode == 0, (out, err)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)


def legacy_suspensions(binary, directory):
    from failures import prepare as prepare_failure
    from failures import run, states

    path = directory / "prepared"
    prepare_failure(binary, path, policy="continue_independent")
    completed = run(binary, path)
    database = path / "host/runner.db"
    with sqlite3.connect(database) as db:
        db.execute("ALTER TABLE run_workers DROP COLUMN suspensions")
        db.execute(
            "UPDATE run_workers SET state='running',outcome=NULL WHERE process='first'"
        )
        assert "suspensions" not in [
            row[1] for row in db.execute("PRAGMA table_info(run_workers)")
        ]
    started = {p.name: p.read_bytes() for p in path.glob("*-started.json")}
    recovered = run(binary, path)
    with sqlite3.connect(database) as db:
        assert "suspensions" in [
            row[1] for row in db.execute("PRAGMA table_info(run_workers)")
        ]
        assert db.execute(
            "SELECT suspensions,outcome FROM run_workers WHERE process='first'"
        ).fetchone() == (0, "host_interrupted")
    assert {p.name: p.read_bytes() for p in path.glob("*-started.json")} == started
    expected = states(completed)
    expected["first"]["outcome"] = "host_interrupted"
    assert states(recovered) == expected


if __name__ == "__main__":
    cases = {
        "init": init_nonempty,
        "relocation": relocation_files,
        "busy": busy_reader,
        "orphan": orphan_sidecar,
        "committed-wal": committed_import_wal,
        "diagnostics": diagnostic_pipe,
        "legacy": legacy_suspensions,
    }
    for name, case in cases.items():
        if len(sys.argv) > 2 and sys.argv[2] != name:
            continue
        with tempfile.TemporaryDirectory(prefix=f"chio-admin-{name}-") as temporary:
            case(sys.argv[1], Path(temporary))
        print(f"{name}: passed", flush=True)
