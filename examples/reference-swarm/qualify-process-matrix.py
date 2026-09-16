"""Run all seven local Enforced process scenarios and verify one portable bundle."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

from process_matrix_evidence import (
    SCENARIOS,
    SCHEMA,
    collect_case,
    digest,
    require,
    verify_bundle,
    verify_negative_cases,
    write,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser(
        "verify", help="Verify offline against separately retained operator pins"
    )
    for name in ("chio", "artifact", "trusted-pins"):
        verify.add_argument("--" + name, type=Path, required=True)
    negative = subparsers.add_parser(
        "test-evidence",
        help="Check rejection of capture, signature and semantic substitutions",
    )
    for name in ("chio", "artifact", "trusted-pins"):
        negative.add_argument("--" + name, type=Path, required=True)
    run = subparsers.add_parser(
        "run",
        help="Execute the real local scenario matrix (supported Linux x86_64 only)",
    )
    for name in (
        "chio",
        "cage-init",
        "probe",
        "reader",
        "output",
        "receipt-rollback-anchor-root",
    ):
        run.add_argument("--" + name, type=Path, required=True)
    run.add_argument("--worker-image", required=True)
    run.add_argument(
        "--runtime-source",
        required=True,
        help="Full source commit used to build the selected CLI",
    )
    args = parser.parse_args()
    os.umask(0o077)
    chio = args.chio.resolve(strict=True)
    if args.command in ("verify", "test-evidence"):
        verify = verify_bundle if args.command == "verify" else verify_negative_cases
        print(json.dumps(verify(chio, args.artifact, args.trusted_pins)))
        return
    require(
        platform.system() == "Linux" and platform.machine() == "x86_64",
        "requires supported Linux x86_64 cage profile",
    )
    require(os.getuid() != 0 and os.getgid() != 0, "requires non-root operator")
    require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", args.worker_image),
        "worker image must be an immutable local image ID",
    )
    require(
        re.fullmatch(r"[0-9a-f]{40}", args.runtime_source),
        "runtime source must be a full commit ID",
    )
    anchor = args.receipt_rollback_anchor_root.resolve(strict=True)
    require(
        anchor.is_dir() and not anchor.stat().st_mode & 0o077,
        "anchor must be an existing private directory",
    )
    binaries = {
        name: getattr(args, name).resolve(strict=True)
        for name in ("chio", "cage_init", "probe", "reader")
    }
    root = args.output.absolute()
    root.mkdir(parents=True, mode=0o700, exist_ok=False)
    root = root.resolve(strict=True)
    scripts = Path(__file__).resolve().parent
    repository = scripts.parents[1]
    source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    require(
        not subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=repository,
            text=True,
        ).strip(),
        "qualification source has tracked modifications",
    )
    identity = {
        "qualifier_source": source,
        "runtime_source": args.runtime_source,
        "platform": platform.platform(),
        "worker_image": args.worker_image,
        "binaries": {name: digest(path) for name, path in binaries.items()},
        "scripts": {path.name: digest(path) for path in scripts.glob("*.py")},
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    write(root / "identity.json", identity)
    commands = []

    def execute(label, command):
        command = list(map(str, command))
        record = {"label": label, "command": command, "exit": None}
        try:
            with (root / (label + ".stdout")).open("x") as stdout, (
                root / (label + ".stderr")
            ).open("x") as stderr:
                result = subprocess.run(
                    command, stdout=stdout, stderr=stderr, timeout=1200, check=False
                )
            record["exit"] = result.returncode
        finally:
            commands.append(record)
            (root / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        require(
            result.returncode == 0,
            f"{label} failed; inspect {root / (label + '.stderr')}",
        )
        print(f"passed {label}", file=sys.stderr, flush=True)

    execute("worker-image", ["docker", "image", "inspect", args.worker_image])
    image = json.loads((root / "worker-image.stdout").read_text())
    require(
        len(image) == 1
        and image[0]["Id"] == args.worker_image
        and image[0]["Architecture"] == "amd64"
        and image[0]["Os"] == "linux",
        "worker image identity or platform differs",
    )
    scenarios, pins = {}, {}
    for name in SCENARIOS:
        folder = root / name
        case_anchor = anchor / name
        case_anchor.mkdir(mode=0o700, exist_ok=False)
        if name == "reference":
            inputs = root / "reference-inputs"
            inputs.mkdir(mode=0o700)
            for filename in ("README.md", "PROCESS.md"):
                (inputs / filename).write_bytes((scripts / filename).read_bytes())
            execute(
                "reference-prepare",
                [
                    sys.executable,
                    scripts / "process-prepare.py",
                    "--chio",
                    chio,
                    "--cage-init",
                    binaries["cage_init"],
                    "--reader",
                    binaries["reader"],
                    "--input-dir",
                    inputs,
                    "--file",
                    "README.md",
                    "--file",
                    "PROCESS.md",
                    "--max-artifact-bytes",
                    "2097152",
                    "--output",
                    folder,
                    "--receipt-rollback-anchor-root",
                    case_anchor,
                ],
            )
            execute(
                "reference-workers",
                [
                    sys.executable,
                    scripts / "process-run.py",
                    "--chio",
                    chio,
                    "--state",
                    folder / "state",
                    "--output",
                    folder / "evidence",
                    "--worker-image",
                    args.worker_image,
                ],
            )
            execute(
                "reference-result",
                [
                    sys.executable,
                    scripts / "process-collect.py",
                    "--chio",
                    chio,
                    "--evidence",
                    folder / "evidence",
                    "--inputs",
                    folder / "inputs.json",
                    "--trusted-kernel-pubkey",
                    folder / "state/authority.db.kernel.pub",
                    "--output",
                    folder / "repository-report.json",
                ],
            )
            plan = folder / "state/reference-run-plan.json"
        else:
            execute(
                name,
                [
                    sys.executable,
                    scripts / f"qualify-process-{name}.py",
                    "--chio",
                    chio,
                    "--cage-init",
                    binaries["cage_init"],
                    "--probe",
                    binaries["probe"],
                    "--output",
                    folder,
                    "--receipt-rollback-anchor-root",
                    case_anchor,
                    "--worker-image",
                    args.worker_image,
                ],
            )
            plan = folder / (
                "state/reference-run-plan.json"
                if name == "filesystem"
                else "run-plan.json"
            )
        scenarios[name], pins[name] = collect_case(chio, name, folder, plan)
        print(f"collected {name}", file=sys.stderr, flush=True)
    require(
        identity["binaries"] == {name: digest(path) for name, path in binaries.items()},
        "executable changed during qualification",
    )
    require(
        identity["scripts"]
        == {path.name: digest(path) for path in scripts.glob("*.py")},
        "qualification scripts changed during run",
    )
    artifact, trusted_pins = root / "matrix.json", root / "operator-pins.json"
    write(artifact, {"schema": SCHEMA, "identity": identity, "scenarios": scenarios})
    write(
        trusted_pins,
        {
            "schema": SCHEMA + ".pins",
            "bundle_sha256": digest(artifact),
            "identity": identity,
            "scenarios": pins,
        },
    )
    report = verify_bundle(chio, artifact, trusted_pins)
    write(root / "verification.json", report)
    negative = verify_negative_cases(chio, artifact, trusted_pins)
    write(root / "negative-verification.json", negative)
    print(
        json.dumps(
            {
                "artifact": str(artifact),
                "operator_pins": str(trusted_pins),
                "bundle_sha256": digest(artifact),
                "local_matrix_verified": True,
                "rejected_substitutions": len(negative["checks"]),
                "m5_acceptance_complete": False,
            }
        )
    )


if __name__ == "__main__":
    main()
