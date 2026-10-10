#!/usr/bin/env python3
"""Exercise real Cargo package graphs, including forbidden transitive edges."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts/check-dependency-budget.py"


def package(root: Path, relative: str, name: str, dependencies: str = "") -> None:
    path = root / relative
    (path / "src").mkdir(parents=True)
    (path / "src/lib.rs").write_text("")
    (path / "Cargo.toml").write_text(
        f'[package]\nname = "{name}"\nversion = "0.1.0"\nedition = "2021"\n'
        '[features]\nreal-linux-enforcement = []\n[dependencies]\n' + dependencies
    )


def fixture(root: Path, denied: str | None = None, *, transitive: bool = False) -> None:
    members = ["crates/security/chio-cage-init", "crates/security/chio-secret-broker"]
    dependencies = ""
    if denied:
        package(root, "vendor/" + denied, denied)
        members.append("vendor/" + denied)
        carrier = denied
        if transitive:
            package(root, "vendor/carrier", "carrier", f'{denied} = {{ path = "../{denied}" }}\n')
            members.append("vendor/carrier")
            carrier = "carrier"
        dependencies = f'{carrier} = {{ path = "../../../vendor/{carrier}" }}\n'
    package(root, members[0], "chio-cage-init", dependencies)
    package(root, members[1], "chio-secret-broker")
    (root / "Cargo.toml").write_text('[workspace]\nresolver = "2"\nmembers = ' + repr(members).replace("'", '"') + "\n")
    subprocess.run(["cargo", "generate-lockfile", "--offline", "--quiet"], cwd=root, check=True)


def check(root: Path, expected: int, needle: str, checker: Path = CHECKER) -> None:
    result = subprocess.run(["python3", str(checker), "--root", str(root)], capture_output=True, text=True)
    assert result.returncode == expected, (result.returncode, result.stdout, result.stderr)
    assert needle in result.stdout + result.stderr, (needle, result.stdout, result.stderr)


with tempfile.TemporaryDirectory(prefix="chio-dependency-budget-") as temporary:
    work = Path(temporary)
    compliant = work / "compliant"
    fixture(compliant)
    check(compliant, 0, "chio-cage-init (chio-cage-init)")
    for name in ("tokio", "hyper", "reqwest", "rustls", "regex", "tracing", "openssl"):
        root = work / name
        fixture(root, name)
        check(root, 1, f"chio-cage-init carries denied package {name}")
    transitive = work / "transitive"
    fixture(transitive, "tokio", transitive=True)
    check(transitive, 1, "denied package tokio v0.1.0 through carrier")
    # The plan/status wire format requires JSON; it is the one explicit codec exception.
    codec = work / "codec"
    fixture(codec, "serde_json")
    check(codec, 0, "0 denied")
    checker = work / "lowered.py"
    source = CHECKER.read_text()
    assert "ceiling=72," in source
    checker.write_text(source.replace("ceiling=72,", "ceiling=71,", 1))
    check(ROOT, 1, "chio-cage-init has 72 packages", checker)
    check(ROOT, 0, "72 packages, ceiling 72")
print("dependency budget: 12 real Cargo graph cases passed")
