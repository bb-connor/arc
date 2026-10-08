#!/usr/bin/env python3
"""Self-test for scripts/check-private-file-custody.py."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(
    os.environ.get(
        "CHECK_PRIVATE_FILE_CUSTODY",
        Path(__file__).resolve().parent.parent / "check-private-file-custody.py",
    )
)
BASELINE = "scripts/private-file-custody-baseline.txt"
HEADER = "# pinned\n"

failures: list[str] = []


def run(
    files: dict[str, str], *arguments: str
) -> tuple[subprocess.CompletedProcess[str], str | None]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        baseline = root / BASELINE
        return result, baseline.read_text(encoding="utf-8") if baseline.is_file() else None


def expect(
    name: str,
    outcome: tuple[subprocess.CompletedProcess[str], str | None],
    exit_code: int,
    mentions: str = "",
) -> None:
    result, _ = outcome
    output = result.stdout + result.stderr
    if result.returncode != exit_code:
        failures.append(f"{name}: expected exit {exit_code}, got {result.returncode}\n{output}")
    elif mentions and mentions not in output:
        failures.append(f"{name}: expected {mentions!r} in\n{output}")


def pinned(*entries: str) -> dict[str, str]:
    return {BASELINE: HEADER + "".join(f"{entry}\n" for entry in entries)}


PRODUCTION = "crates/demo/chio-demo/src/lib.rs"
OPEN_WITH_MODE = """
use std::os::unix::fs::OpenOptionsExt;
pub fn create(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
}
"""

expect("clean source passes", run({PRODUCTION: "pub fn ok() {}\n", **pinned()}), 0)

expect(
    "new creation mode fails",
    run({PRODUCTION: OPEN_WITH_MODE, **pinned()}),
    1,
    "1 new creation-mode site(s)",
)

expect(
    "missing baseline fails every site",
    run({PRODUCTION: OPEN_WITH_MODE}),
    1,
    "new creation-mode",
)

expect(
    "pinned creation mode passes",
    run({PRODUCTION: OPEN_WITH_MODE, **pinned(f"1\tcreation-mode\t{PRODUCTION}")}),
    0,
)

expect(
    "multi-line directory mode fails",
    run(
        {
            PRODUCTION: "pub fn d(b: &mut std::fs::DirBuilder) { b\n    .mode(\n        0o700,\n    ); }\n",
            **pinned(),
        }
    ),
    1,
    "new creation-mode",
)

expect(
    "permission reads are not sites",
    run(
        {
            PRODUCTION: "pub fn m(x: &std::fs::Metadata) -> u32 { x.permissions().mode() & 0o077 }\n",
            **pinned(),
        }
    ),
    0,
)

for flag in ("libc::O_NOFOLLOW", "rustix::fs::OFlags::NOFOLLOW", "nix::fcntl::OFlag::O_NOFOLLOW"):
    expect(
        f"{flag} fails",
        run({PRODUCTION: f"pub fn f() {{ let _ = {flag}; }}\n", **pinned()}),
        1,
        "new no-follow",
    )

expect(
    "stat no-follow flags are not open sites",
    run({PRODUCTION: "pub fn f() { let _ = rustix::fs::AtFlags::SYMLINK_NOFOLLOW; }\n", **pinned()}),
    0,
)

expect(
    "set_permissions fails",
    run(
        {
            PRODUCTION: "pub fn p(f: &std::fs::File, m: std::fs::Permissions) { let _ = f.set_permissions(m); }\n",
            **pinned(),
        }
    ),
    1,
    "new set-permissions",
)

expect(
    "comments and strings are not sites",
    run(
        {
            PRODUCTION: '// O_NOFOLLOW and .mode(0o600)\npub const DOC: &str = "set_permissions(path)";\n',
            **pinned(),
        }
    ),
    0,
)

expect(
    "test-only items are not sites",
    run(
        {
            PRODUCTION: "pub fn ok() {}\n#[cfg(test)]\nmod tests {\n    fn f() { let _ = libc::O_NOFOLLOW; }\n}\n",
            **pinned(),
        }
    ),
    0,
)

for exempt in (
    "crates/security/chio-secure-fs/src/walk.rs",
    "crates/tooling/chio-test-support/src/lib.rs",
    "crates/demo/chio-demo/tests/custody.rs",
    "crates/demo/chio-demo/src/custody_tests.rs",
):
    expect(
        f"{exempt} is exempt",
        run({exempt: "pub fn f() { let _ = libc::O_NOFOLLOW; }\n", **pinned()}),
        0,
    )

expect(
    "a stale pin fails until ratcheted",
    run({PRODUCTION: OPEN_WITH_MODE, **pinned(f"2\tcreation-mode\t{PRODUCTION}")}),
    1,
    "run --ratchet",
)

lowered = run(
    {PRODUCTION: OPEN_WITH_MODE, **pinned(f"2\tcreation-mode\t{PRODUCTION}")},
    "--ratchet",
)
expect("ratchet lowers a stale pin", lowered, 0)
if lowered[1] is None or f"1\tcreation-mode\t{PRODUCTION}\n" not in lowered[1]:
    failures.append(f"ratchet lowers a stale pin: baseline was\n{lowered[1]}")

retired = run({PRODUCTION: "pub fn ok() {}\n", **pinned(f"1\tno-follow\t{PRODUCTION}")}, "--ratchet")
expect("ratchet drops a retired pin", retired, 0)
if retired[1] is None or PRODUCTION in retired[1]:
    failures.append(f"ratchet drops a retired pin: baseline was\n{retired[1]}")

raised = run({PRODUCTION: OPEN_WITH_MODE, **pinned()}, "--ratchet")
expect("ratchet never raises a pin", raised, 1, "never raises a pin")
if raised[1] != HEADER:
    failures.append(f"ratchet never raises a pin: baseline changed to\n{raised[1]}")

recorded = run({PRODUCTION: OPEN_WITH_MODE}, "--ratchet")
expect("first ratchet records the debt", recorded, 0)
if recorded[1] is None or f"1\tcreation-mode\t{PRODUCTION}\n" not in recorded[1]:
    failures.append(f"first ratchet records the debt: baseline was\n{recorded[1]}")

expect(
    "malformed baseline fails",
    run({PRODUCTION: "pub fn ok() {}\n", BASELINE: "one\tcreation-mode\tx.rs\n"}),
    1,
    "expected count<TAB>rule<TAB>path",
)

if failures:
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    raise SystemExit(1)
print("check-private-file-custody self-test passed")
