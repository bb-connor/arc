import json

import pytest
from chio_mini_swe import repository_archive
from chio_mini_swe import repository_store as store
from chio_mini_swe.repository_archive import encode_entries, entries, git, import_revision
from chio_mini_swe.repository_scope import SCOPED_SCHEMA, normalize_source_paths, require_scope
from test_repository import commit
from test_repository import repository as repository


@pytest.mark.parametrize(
    "paths",
    [
        [],
        {},
        [True],
        [""],
        ["."],
        ["./file"],
        ["file/"],
        ["../file"],
        ["/file"],
        ["a/../file"],
        ["a//file"],
        [".git"],
        ["a/.GIT/config"],
        ["a\\b"],
        ["line\nend"],
        ["file", "file"],
        ["parent", "parent/file"],
        [str(i) for i in range(65)],
        ["a" * 1025],
        [str(i) + "x" * 1000 for i in range(20)],
    ],
)
def test_invalid_selection_is_refused_before_source_access(paths):
    with pytest.raises(ValueError):
        import_revision("/does-not-exist", "HEAD", source_paths=paths)


def test_source_paths_are_literal_and_keep_repository_relative_names(repository):
    for name in ("-option", ":(glob)*", "literal*", "literalX", "space name"):
        (repository / name).write_text(name)
    (repository / "nested").mkdir()
    (repository / "nested/file").write_bytes(b"selected committed contents")
    commit(repository)
    revision = git("rev-parse", "HEAD", cwd=repository).decode().strip()
    (repository / "nested/file").write_text("dirty must stay private")
    (repository / "nested/untracked").write_text("untracked must stay private")
    chosen = ["nested", "literal*", "-option", ":(glob)*", "space name"]
    actual, data = import_revision(repository, revision, source_paths=chosen)
    files = entries(data)
    assert actual == revision
    assert set(files) == {"nested", "nested/file", *chosen[1:]}
    assert files["nested/file"][2] == b"selected committed contents"
    assert "file" not in files and "literalX" not in files
    assert normalize_source_paths(chosen) == sorted(chosen)
    for missing in (["nested/file/absent"], ["nested", "absent"]):
        with pytest.raises(ValueError, match="must exist"):
            import_revision(repository, revision, source_paths=missing)


def test_unselected_content_does_not_consume_the_archive_limit(repository, monkeypatch):
    (repository / "large-unselected").write_bytes(b"x" * 4096)
    commit(repository)
    monkeypatch.setattr(repository_archive, "MAX_CONTENT", 1024)
    with pytest.raises(ValueError, match="byte limit"):
        import_revision(repository, "HEAD")
    _, data = import_revision(repository, "HEAD", source_paths=["file"])
    assert set(entries(data)) == {"file"}


def test_unselected_submodule_is_not_imported_and_selected_submodule_is_refused(repository):
    revision = git("rev-parse", "HEAD", cwd=repository).decode().strip()
    git("update-index", "--add", "--cacheinfo", "160000," + revision + ",module", cwd=repository)
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost",
        "commit",
        "--quiet",
        "-m",
        "submodule",
        cwd=repository,
    )
    _, data = import_revision(repository, "HEAD", source_paths=["file"])
    assert set(entries(data)) == {"file"}
    with pytest.raises(ValueError, match="submodules"):
        import_revision(repository, "HEAD", source_paths=["module"])


def test_scope_allows_parent_directories_but_not_other_files_or_directory_aliases():
    safe = {"a": ("directory", 0o755, b""), "a/b": ("file", 0o644, b"selected")}
    require_scope(encode_entries(safe), ["a/b"])
    for name, value in [
        ("a/other", ("file", 0o644, b"outside")),
        ("another", ("directory", 0o755, b"")),
        ("alias", ("symlink", 0o777, b"a/b")),
    ]:
        with pytest.raises(ValueError, match="outside"):
            require_scope(encode_entries(safe | {name: value}), ["a/b"])


def test_outside_output_is_not_published_as_a_completed_revision(repository, tmp_path, monkeypatch):
    state = tmp_path / "scoped-state"
    store.initialize(repository, "HEAD", "image", "helper", state, 1, source_paths=["file"])
    cleaned = []

    class Outside:
        def execute(self, snapshot, command):
            files = entries(snapshot, allow_git=True)
            files["file"] = ("file", 0o644, b"partial change")
            files["outside"] = ("file", 0o644, b"must not publish")
            return encode_entries(files), {"output": "done", "returncode": 0, "exception_info": ""}

        def cleanup(self):
            cleaned.append(True)

    monkeypatch.setattr(store.Workspace, "containers", lambda *_: Outside())
    with store.Workspace(state) as workspace:
        assert workspace.config["schema"] == SCOPED_SCHEMA
        original = workspace.status()["snapshot"]
        with pytest.raises(ValueError, match="outside"):
            workspace.execute("create outside file")
        current = workspace.status()
        assert cleaned and current["interrupted"] and current["revision"] == 0
        assert current["snapshot"] == original
        assert current["commands"][0]["status"] == "interrupted"
        assert entries(workspace.snapshot(original), allow_git=True)["file"][2] == b"committed\n"
        with pytest.raises(ValueError, match="stopped"):
            workspace.execute("retry is refused")
    assert (repository / "file").read_bytes() == b"committed\n"


def test_workspace_cannot_change_scope_version_or_accept_unsorted_scope(repository, tmp_path):
    for i, mutation in enumerate(("missing", "wrong-version", "unsorted")):
        state = tmp_path / str(i)
        store.initialize(repository, "HEAD", "image", "helper", state, 1, source_paths=["file"])
        path = state / "workspace.json"
        config = json.loads(path.read_text())
        if mutation == "missing":
            del config["source_paths"]
        elif mutation == "wrong-version":
            config["schema"] = "chio.repository.workspace.v2"
        else:
            config["source_paths"] = ["z", "a"]
        path.write_text(json.dumps(config))
        with pytest.raises(ValueError):
            store.Workspace(state)


def test_retained_snapshot_must_match_scope_before_any_container_starts(
    repository, tmp_path, monkeypatch
):
    state = tmp_path / "mismatched-snapshot"
    store.initialize(repository, "HEAD", "image", "helper", state, 1, source_paths=["file"])
    path = state / "workspace.json"
    config = json.loads(path.read_text())
    config["source_paths"] = ["different-path"]
    path.write_text(json.dumps(config))
    monkeypatch.setattr(store.Workspace, "containers", lambda *_: pytest.fail("container started"))
    with store.Workspace(state) as workspace:
        with pytest.raises(ValueError, match="outside"):
            workspace.execute("read mismatched retained data")
        assert workspace.status()["revision"] == 0
        assert workspace.status()["commands"] == []
