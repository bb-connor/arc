import pytest
from chio_mini_swe.repository_archive import entries, git, import_revision, with_git


def commit(repository):
    git("add", "--all", cwd=repository)
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost",
        "commit",
        "--quiet",
        "-m",
        "fixture",
        cwd=repository,
    )
    return git("rev-parse", "HEAD", cwd=repository).decode().strip()


@pytest.mark.parametrize("filter_kind", ["smudge", "process"])
def test_import_does_not_execute_source_filters(tmp_path, filter_kind):
    git("init", "--quiet", "--template=", cwd=tmp_path)
    (tmp_path / ".gitattributes").write_text("file filter=source-command\n")
    (tmp_path / "file").write_bytes(b"committed bytes\n")
    selected = commit(tmp_path)
    git(
        "config", "filter.source-command." + filter_kind, "touch executed-filter; cat", cwd=tmp_path
    )
    git("config", "filter.source-command.required", "true", cwd=tmp_path)
    imported, data = import_revision(tmp_path, "HEAD")
    seeded = with_git(data)
    assert imported == selected
    assert entries(data)["file"][2] == b"committed bytes\n"
    assert entries(seeded, allow_git=True)["file"][2] == b"committed bytes\n"
    assert not (tmp_path / "executed-filter").exists()


@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
def test_import_resolves_refs_and_history_with_export_attributes(tmp_path, object_format):
    git("init", "--quiet", "--template=", "--object-format=" + object_format, cwd=tmp_path)
    (tmp_path / ".gitattributes").write_text("omitted export-ignore\n")
    (tmp_path / "file").write_bytes(b"first\n")
    (tmp_path / "omitted").write_bytes(b"excluded by committed attributes\n")
    first = commit(tmp_path)
    git("tag", "selected", cwd=tmp_path)
    (tmp_path / "file").write_bytes(b"second\n")
    commit(tmp_path)
    (tmp_path / "file").write_bytes(b"dirty\n")
    for revision in (first, "selected", "refs/tags/selected", "HEAD~1"):
        selected, data = import_revision(tmp_path, revision)
        assert selected == first
        assert entries(data)["file"][2] == b"first\n"
        assert "omitted" not in entries(data)
    assert (tmp_path / "file").read_bytes() == b"dirty\n"


def test_import_supports_worktree_object_storage(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    git("init", "--quiet", "--template=", cwd=source)
    (source / "file").write_bytes(b"selected\n")
    selected = commit(source)
    worktree = tmp_path / "checkout with spaces"
    git("worktree", "add", "--quiet", "--detach", str(worktree), selected, cwd=source)
    imported, data = import_revision(worktree, "HEAD")
    assert imported == selected
    assert entries(data)["file"][2] == b"selected\n"


def test_import_ignores_local_object_replacements(tmp_path):
    git("init", "--quiet", "--template=", cwd=tmp_path)
    (tmp_path / "file").write_bytes(b"selected commit\n")
    selected = commit(tmp_path)
    (tmp_path / "file").write_bytes(b"local replacement\n")
    replacement = commit(tmp_path)
    git("replace", selected, replacement, cwd=tmp_path)
    imported, data = import_revision(tmp_path, selected)
    assert imported == selected
    assert entries(data)["file"][2] == b"selected commit\n"


def test_import_rejects_submodules(tmp_path):
    git("init", "--quiet", "--template=", cwd=tmp_path)
    (tmp_path / "file").write_bytes(b"selected\n")
    selected = commit(tmp_path)
    git("update-index", "--add", "--cacheinfo", "160000," + selected + ",module", cwd=tmp_path)
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost",
        "commit",
        "--quiet",
        "-m",
        "submodule",
        cwd=tmp_path,
    )
    with pytest.raises(ValueError, match="submodules"):
        import_revision(tmp_path, "HEAD")


def test_missing_objects_do_not_invoke_source_promisor_remote(tmp_path):
    git("init", "--quiet", "--template=", cwd=tmp_path)
    (tmp_path / "file").write_bytes(b"missing\n")
    selected = commit(tmp_path)
    blob = git("rev-parse", selected + ":file", cwd=tmp_path).decode().strip()
    (tmp_path / ".git" / "objects" / blob[:2] / blob[2:]).unlink()
    remote = tmp_path / "remote-command"
    remote.write_text("#!/bin/sh\ntouch '" + str(tmp_path / "executed-remote") + "'\nexit 1\n")
    remote.chmod(0o700)
    git("config", "extensions.partialClone", "source", cwd=tmp_path)
    git("config", "remote.source.promisor", "true", cwd=tmp_path)
    git("config", "remote.source.url", "ext::" + str(remote), cwd=tmp_path)
    git("config", "protocol.ext.allow", "always", cwd=tmp_path)
    with pytest.raises(RuntimeError):
        import_revision(tmp_path, "HEAD")
    assert not (tmp_path / "executed-remote").exists()
