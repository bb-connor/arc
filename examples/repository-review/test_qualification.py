"""The legacy qualifier chooses an owned short root before launching workers."""

import importlib.util
import os
import socket
import tempfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "legacy_qualify", Path(__file__).with_name("qualify.py")
)
qualifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualifier)


@pytest.mark.parametrize("explicit", [False, True])
def test_long_temporary_root_uses_validated_short_work_directory(
    tmp_path, monkeypatch, explicit
):
    long_root = tmp_path / ("long" * 35)
    long_root.mkdir()
    monkeypatch.setattr(qualifier.tempfile, "tempdir", str(long_root))
    chosen = []

    def exercise(binary, output, work):
        assert len(os.fsencode(work / "scripted-model/sockets/123456789012.sock")) < 104
        assert work.stat().st_uid == os.getuid()
        assert work.stat().st_mode & 0o077 == 0
        chosen.append(work)

    monkeypatch.setattr(qualifier, "exercise", exercise)
    arguments = [
        "qualify.py",
        "--chio",
        "/usr/bin/true",
        "--output",
        str(tmp_path / "evidence"),
    ]
    if explicit:
        # The explicit root is independently owned and short even under long TMPDIR.
        short = Path(qualifier.tempfile.mkdtemp(prefix="chio-qtest-", dir="/tmp"))
        work = short / "work"
        arguments += ["--work-dir", str(work)]
    monkeypatch.setattr(qualifier.sys, "argv", arguments)
    try:
        qualifier.main()
        assert len(chosen) == 1
        if explicit:
            assert chosen == [work]
        assert not chosen[0].exists()
    finally:
        if explicit:
            short.rmdir()


@pytest.fixture
def short_root():
    with tempfile.TemporaryDirectory(prefix="chio-q-", dir="/tmp") as directory:
        yield Path(directory).resolve()


def path_with_bytes(parent, length):
    path = parent / ("x" * (length - len(os.fsencode(parent)) - 1))
    assert len(os.fsencode(path)) == length
    return path


@pytest.mark.parametrize("work_bytes", range(63, 68))
def test_explicit_root_refuses_before_creation_when_only_inventory_fits(
    short_root, monkeypatch, work_bytes
):
    work = path_with_bytes(short_root, work_bytes)
    assert len(os.fsencode(work / "inventory/sockets/123456789012.sock")) < 104
    assert len(os.fsencode(work / "scripted-model/sockets/123456789012.sock")) >= 104
    monkeypatch.setattr(
        qualifier.sys,
        "argv",
        [
            "qualify.py",
            "--chio",
            "/usr/bin/true",
            "--output",
            str(short_root / "evidence"),
            "--work-dir",
            str(work),
        ],
    )

    def no_workload(*args):
        pytest.fail("qualification workload started before socket-path refusal")

    monkeypatch.setattr(qualifier, "exercise", no_workload)
    with pytest.raises(ValueError, match="exceeds the socket path budget"):
        qualifier.main()
    assert not work.exists()


@pytest.mark.parametrize("work_bytes", range(63, 68))
def test_default_root_falls_back_when_only_inventory_fits(
    short_root, monkeypatch, work_bytes
):
    # The generated /chio-rv-<eight random characters> needs 17 bytes.
    parent = path_with_bytes(short_root, work_bytes - 17)
    parent.mkdir(mode=0o700)
    monkeypatch.setattr(qualifier.tempfile, "tempdir", str(parent))
    work = qualifier.work_directory(None)
    try:
        assert work.parent == Path("/tmp").resolve()
        assert not list(parent.iterdir())
        assert len(os.fsencode(work / "scripted-model/sockets/123456789012.sock")) < 104
    finally:
        work.rmdir()


@pytest.mark.parametrize("explicit", [False, True])
def test_maximum_valid_root_is_private_and_binds_longest_profile_socket(
    short_root, monkeypatch, explicit
):
    if explicit:
        requested = path_with_bytes(short_root, 62)
    else:
        parent = path_with_bytes(short_root, 45)
        parent.mkdir(mode=0o700)
        monkeypatch.setattr(qualifier.tempfile, "tempdir", str(parent))
        requested = None
    work = qualifier.work_directory(requested)
    try:
        assert len(os.fsencode(work)) == 62
        assert work.stat().st_uid == os.getuid()
        assert work.stat().st_mode & 0o077 == 0
        path = work / "scripted-model/sockets/123456789012.sock"
        assert len(os.fsencode(path)) == 103
        path.parent.mkdir(parents=True)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
        path.unlink()
        path.parent.rmdir()
        path.parent.parent.rmdir()
    finally:
        work.rmdir()


def test_unprotected_parent_still_refuses_before_work_creation(short_root):
    parent = short_root / "writable"
    parent.mkdir(mode=0o700)
    parent.chmod(0o777)
    work = parent / "work"
    with pytest.raises(ValueError, match="parent is not protected"):
        qualifier.work_directory(work)
    assert not work.exists()


@pytest.mark.parametrize("kind", ["directory", "file", "symlink"])
def test_existing_final_entry_is_refused_without_following_or_replacing(
    short_root, kind
):
    work = short_root / "existing"
    target = short_root / "target"
    target.mkdir()
    marker = target / "retained"
    marker.write_bytes(b"unchanged")
    if kind == "directory":
        work.mkdir()
    elif kind == "file":
        work.write_bytes(b"unchanged")
    else:
        work.symlink_to(target, target_is_directory=True)
    before = work.lstat()
    with pytest.raises(FileExistsError):
        qualifier.work_directory(work)
    assert work.lstat() == before
    assert marker.read_bytes() == b"unchanged"
    if kind == "file":
        assert work.read_bytes() == b"unchanged"
    elif kind == "directory":
        assert not list(work.iterdir())
    else:
        assert work.readlink() == target
