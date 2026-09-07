import io
import json
import os
import sqlite3
import tarfile

import pytest
from chio_mini_swe import repository_store as store
from chio_mini_swe.repository import export, serve
from chio_mini_swe.repository_archive import (
    canonical,
    entries,
    git,
    import_revision,
    materialize,
    patch,
)
from chio_mini_swe.repository_transport import run


def archive(*members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as stream:
        for name, kind, data in members:
            member = tarfile.TarInfo(name)
            member.type = kind
            if kind == tarfile.SYMTYPE:
                member.linkname = data
            elif kind == tarfile.REGTYPE:
                member.size = len(data)
            stream.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


@pytest.mark.parametrize(
    "members",
    [
        [("../outside", tarfile.REGTYPE, b"x")],
        [("/outside", tarfile.REGTYPE, b"x")],
        [(".git/config", tarfile.REGTYPE, b"x")],
        [("nested/.GIT/config", tarfile.REGTYPE, b"x")],
        [("file", tarfile.REGTYPE, b"x"), ("file", tarfile.REGTYPE, b"y")],
        [("link", tarfile.SYMTYPE, "/etc/passwd")],
        [("link", tarfile.SYMTYPE, "../outside")],
        [("link", tarfile.SYMTYPE, "inside"), ("link/file", tarfile.REGTYPE, b"x")],
        [("fifo", tarfile.FIFOTYPE, b"")],
        [("hardlink", tarfile.LNKTYPE, b"")],
        [("control\nname", tarfile.REGTYPE, b"x")],
        [
            ("deep/alias", tarfile.SYMTYPE, "../shallow"),
            ("start", tarfile.SYMTYPE, "deep/alias/../../outside"),
        ],
        [("a", tarfile.SYMTYPE, "b"), ("b", tarfile.SYMTYPE, "a")],
    ],
)
def test_unsafe_archive_never_materializes(tmp_path, members):
    with pytest.raises(ValueError):
        materialize(archive(*members), tmp_path)
    assert not list(tmp_path.iterdir())


def commit(repo):
    git("add", "--force", "--all", cwd=repo)
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost",
        "commit",
        "--quiet",
        "-m",
        "fixture",
        cwd=repo,
    )


@pytest.fixture
def repository(tmp_path, monkeypatch):
    prior = os.umask(0o077)
    tmp_path.chmod(0o700)
    root = tmp_path / "source"
    root.mkdir()
    git("init", "--quiet", cwd=root)
    (root / "file").write_bytes(b"committed\n")
    commit(root)
    monkeypatch.setattr(store, "engine", lambda: "fixture-engine")
    monkeypatch.setattr(store, "qualify_image", lambda _: None)
    try:
        yield root
    finally:
        os.umask(prior)


def test_selected_revision_and_patch_roundtrip_preserve_binary_links_modes(repository, tmp_path):
    (repository / "link").symlink_to("file")
    (repository / "binary").write_bytes(bytes(range(256)))
    (repository / "executable").write_text("#!/bin/sh\nexit 0\n")
    (repository / "executable").chmod(0o755)
    (repository / ".gitignore").write_text("ignored\n")
    (repository / "ignored").write_text("tracked despite ignore\n")
    commit(repository)
    source_commit, before = import_revision(repository, "HEAD")
    (repository / "file").write_text("dirty working tree must stay private\n")
    (repository / "untracked").write_text("untracked working tree\n")
    assert import_revision(repository, source_commit)[1] == before
    changed = entries(before)
    changed["file"] = ("file", 0o644, b"repaired\n")
    changed["binary"] = ("file", 0o644, b"\x00new binary\xff")
    changed["ignored"] = ("file", 0o644, b"new tracked contents\n")
    changed.pop("executable")
    changed["new-file"] = ("file", 0o644, b"new\n")
    after = archive(
        *[
            (
                name,
                tarfile.SYMTYPE if kind == "symlink" else tarfile.REGTYPE,
                content.decode() if kind == "symlink" else content,
            )
            for name, (kind, _, content) in changed.items()
        ]
    )
    difference = patch(before, after)
    copy = tmp_path / "apply"
    copy.mkdir()
    materialize(before, copy)
    git("init", "--quiet", cwd=copy)
    git("add", "--force", "--all", cwd=copy)
    run(["/usr/bin/git", "apply", "--check", "-"], cwd=copy, data=difference)
    run(["/usr/bin/git", "apply", "-"], cwd=copy, data=difference)
    assert (copy / "binary").read_bytes() == b"\x00new binary\xff"
    assert (copy / "file").read_bytes() == b"repaired\n"
    assert (copy / "ignored").read_text() == "new tracked contents\n"
    assert (copy / "new-file").read_text() == "new\n"
    assert not (copy / "executable").exists()
    assert (copy / "link").is_symlink()
    assert (repository / "file").read_text().startswith("dirty")
    assert b"untracked working tree" not in before


def test_canonical_snapshot_ignores_tar_metadata():
    data = archive(("file", tarfile.REGTYPE, b"content"))
    assert canonical(canonical(data)) == canonical(data)
    assert entries(canonical(data))["file"][2] == b"content"


def initialized(repository, tmp_path):
    state = tmp_path / "state"
    store.initialize(repository, "HEAD", "image", "helper", state, 1)
    return state


def test_cleanup_failure_does_not_promote_snapshot_and_recovery_blocks_reexecution(
    repository, tmp_path, monkeypatch
):
    state = initialized(repository, tmp_path)
    calls = []

    class Simulated:
        fail = True

        def execute(self, *_):
            calls.append("effect")
            return canonical(archive(("file", tarfile.REGTYPE, b"changed\n"))), {
                "output": "",
                "returncode": 0,
                "exception_info": "",
            }

        def cleanup(self):
            if self.fail:
                raise RuntimeError("cleanup unavailable")

    control = Simulated()
    monkeypatch.setattr(store.Workspace, "containers", lambda *_: control)
    with store.Workspace(state) as workspace:
        before = workspace.status()["snapshot"]
        with pytest.raises(RuntimeError, match="cleanup"):
            workspace.execute("change the file")
        assert workspace.status()["revision"] == 0
        assert workspace.status()["snapshot"] == before
        with pytest.raises(ValueError, match="Recover pending"):
            export(workspace, tmp_path / "forbidden-export")
    control.fail = False
    with store.Workspace(state) as workspace:
        workspace.recover()
        assert workspace.status()["commands"][0]["status"] == "interrupted"
        with pytest.raises(ValueError, match="stopped"):
            workspace.execute("change again")
        result = export(workspace, tmp_path / "last-known")
        assert result["interrupted"] and result["revision"] == 0
        assert (
            entries((tmp_path / "last-known/workspace.tar").read_bytes())["file"][2]
            == b"committed\n"
        )
    assert calls == ["effect"]


def test_private_workspace_serialization_and_version_gate(repository, tmp_path):
    state = initialized(repository, tmp_path)
    with store.Workspace(state):
        with pytest.raises(BlockingIOError):
            store.Workspace(state)
    with sqlite3.connect(state / "journal.db") as db:
        db.execute("PRAGMA user_version=999")
    with pytest.raises(ValueError, match="journal version"):
        store.Workspace(state)
    assert not (state / "journal.db-wal").exists()


def test_discovery_has_no_command_effect_and_rejects_extra_arguments(
    repository, tmp_path, monkeypatch
):
    state = initialized(repository, tmp_path)
    monkeypatch.setattr(store.Workspace, "execute", lambda *_: pytest.fail("unexpected execution"))
    messages = [
        {"id": 1, "method": "tools/list"},
        {
            "id": 2,
            "method": "tools/call",
            "params": {"name": "execute", "arguments": {"command": "ls", "container": "foreign"}},
        },
    ]
    outgoing = io.StringIO()
    with store.Workspace(state) as workspace:
        serve(
            workspace,
            io.BytesIO(b"".join(json.dumps(message).encode() + b"\n" for message in messages)),
            outgoing,
        )
    results = [json.loads(line)["result"] for line in outgoing.getvalue().splitlines()]
    assert results[0]["tools"][0]["annotations"]["readOnlyHint"] is False
    assert results[1]["isError"] is True


def test_control_process_limits_output_and_time():
    with pytest.raises(ValueError, match="output bound"):
        run(["/usr/bin/python3", "-c", "print('x'*100000)"], limit=1024)
    with pytest.raises(TimeoutError):
        run(["/bin/sleep", "5"], timeout=0.05)


def test_total_operation_budget_spans_control_calls():
    from chio_mini_swe.repository_transport import operation_budget

    with operation_budget(0.1), pytest.raises(TimeoutError):
        run(["/bin/sleep", "0.06"], timeout=5)
        run(["/bin/sleep", "0.06"], timeout=5)
    assert run(["/bin/true"])[0] == 0


@pytest.mark.parametrize("output", ["x" * (512 * 1024), "\0" * 81000, "\ufffd" * 81000])
def test_serialized_output_overflow_never_promotes(repository, tmp_path, monkeypatch, output):
    class Completed:
        def execute(self, snapshot, _command):
            return snapshot, {"output": output, "returncode": 0, "exception_info": ""}

        def cleanup(self):
            pass

    state = initialized(repository, tmp_path)
    monkeypatch.setattr(store.Workspace, "containers", lambda *_: Completed())
    with store.Workspace(state) as workspace:
        before = workspace.status()["snapshot"]
        with pytest.raises(ValueError, match="serialized frame bound"):
            workspace.execute("produce large output")
        assert workspace.status()["revision"] == 0
        assert workspace.status()["snapshot"] == before
        assert workspace.status()["commands"][0]["status"] == "interrupted"


@pytest.mark.parametrize("output", ["x" * 500000, "\0" * 79000, "\ufffd" * 79000])
def test_large_valid_output_roundtrips_inside_host_frame(repository, tmp_path, monkeypatch, output):
    from chio_mini_swe.repository_wire import MAX_FRAME, MAX_REQUEST_ID

    class Completed:
        def execute(self, snapshot, _command):
            return snapshot, {"output": output, "returncode": 0, "exception_info": ""}

        def cleanup(self):
            pass

    state = initialized(repository, tmp_path)
    monkeypatch.setattr(store.Workspace, "containers", lambda *_: Completed())
    message = {
        "id": "\0" * MAX_REQUEST_ID,
        "method": "tools/call",
        "params": {"name": "execute", "arguments": {"command": "produce valid output"}},
    }
    outgoing = io.StringIO()
    with store.Workspace(state) as workspace:
        serve(workspace, io.BytesIO(json.dumps(message).encode() + b"\n"), outgoing)
        assert workspace.status()["revision"] == 1
    encoded = outgoing.getvalue().encode()
    assert len(encoded) <= MAX_FRAME
    assert json.loads(encoded)["result"]["structuredContent"]["output"] == output


def test_signal_after_committing_does_not_rewrite_completed_state(
    repository, tmp_path, monkeypatch
):
    class Completed:
        def execute(self, snapshot, _command):
            return snapshot, {"output": "done", "returncode": 0, "exception_info": ""}

        def cleanup(self):
            pass

    original = store.Workspace.complete

    def interrupted(self, *args):
        original(self, *args)
        raise KeyboardInterrupt

    state = initialized(repository, tmp_path)
    monkeypatch.setattr(store.Workspace, "containers", lambda *_: Completed())
    monkeypatch.setattr(store.Workspace, "complete", interrupted)
    with store.Workspace(state) as workspace:
        with pytest.raises(KeyboardInterrupt):
            workspace.execute("committed before signal")
    with store.Workspace(state) as workspace:
        workspace.recover()
        assert workspace.status()["revision"] == 1
        assert not workspace.status()["interrupted"]
        assert workspace.status()["commands"][0]["status"] == "completed"


def test_container_git_configuration_is_never_used_for_host_patch(repository, tmp_path):
    from chio_mini_swe.repository_archive import contents, encode_entries, with_git

    _, source = import_revision(repository, "HEAD")
    snapshot = with_git(source)
    files = entries(snapshot, allow_git=True)
    marker = tmp_path / "host-command-must-not-run"
    files[".git/config"] = (
        "file",
        0o644,
        f'[filter "evil"]\n clean = touch {marker}\n required = true\n'.encode(),
    )
    files[".gitattributes"] = ("file", 0o644, b"* filter=evil\n")
    files[".git/hooks/pre-commit"] = ("file", 0o755, f"#!/bin/sh\ntouch {marker}\n".encode())
    files["file"] = ("file", 0o644, b"repaired\n")
    exported = contents(encode_entries(files))
    assert all(".git" not in name.split("/") for name in entries(exported))
    assert b"repaired" in patch(contents(snapshot), exported)
    assert not marker.exists()


def test_snapshot_fifo_and_configuration_drift_fail_closed(repository, tmp_path):
    from chio_mini_swe.repository import tool

    state = initialized(repository, tmp_path)
    with store.Workspace(state) as workspace:
        original = tool(workspace.config)
        assert tool(dict(workspace.config, timeout_seconds=2)) != original
        sha = "1" * 64
        os.mkfifo(state / "snapshots" / sha, 0o600)
        with pytest.raises(ValueError, match="regular file"):
            workspace.snapshot(sha)


@pytest.mark.parametrize(
    "mutation", ["output", "command", "server", "unknown", "duplicate", "configuration"]
)
def test_receipt_binding_refuses_mismatched_evidence(repository, tmp_path, monkeypatch, mutation):
    import copy

    from chio_mini_swe.repository_proof import bindings, output_digest

    class Completed:
        def execute(self, snapshot, _command):
            return snapshot, {"output": "verified 🚀\n", "returncode": 0, "exception_info": ""}

        def cleanup(self):
            pass

    state = initialized(repository, tmp_path)
    monkeypatch.setattr(store.Workspace, "containers", lambda *_: Completed())
    with store.Workspace(state) as workspace:
        output = workspace.execute("print result")
        receipt = {
            "id": "receipt",
            "tool_server": "sandbox",
            "tool_name": "execute",
            "content_hash": output_digest(output),
            "action": {"parameters": {"command": "print result"}},
            "decision": {"verdict": "allow"},
            "metadata": {"admission_operation": {"projected_state": "completed"}},
        }
        assert len(bindings(workspace, [receipt], "sandbox")) == 1
        changed = copy.deepcopy(receipt)
        if mutation == "output":
            changed["content_hash"] = "0" * 64
        elif mutation == "command":
            changed["action"]["parameters"]["command"] = "another command"
        elif mutation == "server":
            changed["tool_server"] = "other"
        elif mutation == "unknown":
            changed["metadata"]["admission_operation"]["projected_state"] = "unknown"
        elif mutation == "configuration":
            workspace.config["timeout_seconds"] += 1
        receipts = [changed, changed] if mutation == "duplicate" else [changed]
        with pytest.raises(ValueError):
            bindings(workspace, receipts, "sandbox")
