#!/usr/bin/env python3
"""Type-check and lint Linux-only Rust. This never proves kernel confinement."""
from pathlib import Path
import os
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[6]
zig = shutil.which("zig")
if zig is None:
    raise SystemExit("Zig is required for the retained Linux cross compilation gate")
def main():
    scratch = ROOT / "target/recovery-p5-cross-tools"
    scratch.mkdir(parents=True, exist_ok=True)
    for name, arguments in {"cc": "cc -target x86_64-linux-musl", "ar": "ar"}.items():
        wrapper = scratch / name
        # cc-rs detects Clang and adds the Rust triple, which Zig names without
        # the vendor. Translate that one known target, preserving all C flags.
        if name == "cc":
            wrapper.write_text('#!/bin/bash\nargs=()\nfor arg in "$@"; do\n'
                ' if [[ "$arg" != --target=x86_64-unknown-linux-musl ]]; then args+=("$arg"); fi\n'
                f'done\nexec {shlex.quote(zig)} {arguments} "${{args[@]}}"\n')
        else:
            wrapper.write_text(f'#!/bin/sh\nexec {shlex.quote(zig)} {arguments} "$@"\n')
        wrapper.chmod(0o700)
    environment = {
        **os.environ,
        "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
        "TMPDIR": str(Path(os.environ.get("TMPDIR", "/tmp")).resolve()),
        "ZIG_LOCAL_CACHE_DIR": str(ROOT / "target/recovery-p5-zig-local"),
        "ZIG_GLOBAL_CACHE_DIR": str(ROOT / "target/recovery-p5-zig-global"),
        "CC_x86_64_unknown_linux_musl": str(scratch / "cc"),
        "AR_x86_64_unknown_linux_musl": str(scratch / "ar"),
    }
    command = ["cargo", "clippy", "--offline", "--locked", "-p", "chio-cage",
               "-p", "chio-control-plane", "--all-targets", "--features", "chio-cage/enforcement-mutants",
               "--target", "x86_64-unknown-linux-musl", "--", "-D", "warnings"]
    print("Cross compilation only:", " ".join(command), flush=True)
    raise SystemExit(subprocess.run(command, cwd=ROOT, env=environment, check=False).returncode)

if __name__ == "__main__":
    main()
