"""The legacy qualifier chooses an owned short root before launching workers."""

import importlib.util
import os
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
        assert len(os.fsencode(work / "inventory/sockets/123456789012.sock")) < 104
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
