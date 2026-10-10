"""Install a pinned AI SDK consumer with the two packed Chio process packages."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
TYPESCRIPT = REPOSITORY / "sdks/typescript"
sys.path.insert(0, str(TYPESCRIPT / "packages/ai-sdk-process/qualification"))
from qualify import installed_consumer  # noqa: E402


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=("ai6", "ai7"), default="ai7")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    packages = output / "packages"
    packages.mkdir()
    subprocess.run(
        ["npm", "run", "build", "--workspace", "@chio-protocol/ai-sdk-process"],
        cwd=TYPESCRIPT,
        check=True,
        timeout=120,
    )
    archives = []
    for name in ("process", "ai-sdk-process"):
        result = subprocess.check_output(
            ["npm", "pack", "--pack-destination", str(packages), "--json"],
            cwd=TYPESCRIPT / "packages" / name,
            timeout=120,
        )
        archives.append(packages / json.loads(result)[0]["filename"])
    consumer = installed_consumer(args.profile, output, archives)
    manifest = {
        "profile": args.profile,
        "consumer": str(consumer),
        "packages": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in archives
        },
        "lock_sha256": hashlib.sha256(
            (consumer / "package-lock.json").read_bytes()
        ).hexdigest(),
    }
    (output / "installation.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
