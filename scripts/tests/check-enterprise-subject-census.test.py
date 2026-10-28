#!/usr/bin/env python3
"""Self-test for scripts/check-enterprise-subject-census.py."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SCRIPTS_DIR.parent
SCRIPT = SCRIPTS_DIR / "check-enterprise-subject-census.py"

CONTROL_PLANE = "crates/platform/chio-control-plane/src/"
PENDING_FILES = (
    CONTROL_PLANE + "scim_lifecycle.rs",
    CONTROL_PLANE + "trust_control/config_and_public.rs",
    "crates/protocol/chio-mcp-remote/src/remote_mcp/session_identity.rs",
)
CONFIG = CONTROL_PLANE + "trust_control/config_and_public.rs"
EXISTING_CAPABILITY_ID = 'capability_id: format!("scim-user:{}", record.user_id),'
SECOND_FUNCTION = '\nfn another_scim_capability_id(user_id: &str) -> String { format!("scim-user:{user_id}") }\n'


def tree(scratch: Path) -> Path:
    root = scratch / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy2(SCRIPT, root / "scripts" / SCRIPT.name)
    for path in PENDING_FILES:
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / path, root / path)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    return root


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", str(root / "scripts" / SCRIPT.name)],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )


def edit(root: Path, path: str, old: str, new: str) -> None:
    target = root / path
    text = target.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"{path} does not hold exactly one {old!r}"
    target.write_text(text.replace(old, new), encoding="utf-8")


def test_pinned_sites_pass(scratch: Path) -> None:
    result = run(tree(scratch))
    assert result.returncode == 0, result.stderr
    assert "5 pending unkeyed site(s)" in result.stdout, result.stdout


def test_new_function_in_pending_file_fails(scratch: Path) -> None:
    root = tree(scratch)
    with (root / CONFIG).open("a", encoding="utf-8") as handle:
        handle.write(SECOND_FUNCTION)
    result = run(root)
    assert result.returncode != 0, result.stdout
    assert "unkeyed scim capability id in `another_scim_capability_id`" in result.stderr, result.stderr


def test_second_site_in_pinned_owner_fails(scratch: Path) -> None:
    root = tree(scratch)
    edit(root, CONFIG, EXISTING_CAPABILITY_ID, EXISTING_CAPABILITY_ID + "\n" + EXISTING_CAPABILITY_ID)
    result = run(root)
    assert result.returncode != 0, result.stdout
    assert "2 `unkeyed scim capability id` sites in `build_scim_deprovision_receipt`, pinned at 1" in result.stderr, result.stderr


def test_removed_site_fails_until_unpinned(scratch: Path) -> None:
    root = tree(scratch)
    edit(root, CONFIG, EXISTING_CAPABILITY_ID, 'capability_id: record.user_id.clone(),')
    result = run(root)
    assert result.returncode != 0, result.stdout
    assert "pending entry `unkeyed scim capability id` in `build_scim_deprovision_receipt` has no site" in result.stderr, result.stderr


def test_renamed_derivation_fails(scratch: Path) -> None:
    root = tree(scratch)
    path = "crates/protocol/chio-mcp-remote/src/remote_mcp/session_identity.rs"
    edit(root, path, "fn derive_enterprise_subject_key(", "fn derive_subject_key_unkeyed(")
    result = run(root)
    assert result.returncode != 0, result.stdout
    assert f"{path}: pending entry `unkeyed enterprise subject derivation`" in result.stderr, result.stderr


def main() -> int:
    tests = [
        test_pinned_sites_pass,
        test_new_function_in_pending_file_fails,
        test_second_site_in_pinned_owner_fails,
        test_removed_site_fails_until_unpinned,
        test_renamed_derivation_fails,
    ]
    for test in tests:
        with tempfile.TemporaryDirectory() as scratch:
            test(Path(scratch))
    print(f"check-enterprise-subject-census self-test: {len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
