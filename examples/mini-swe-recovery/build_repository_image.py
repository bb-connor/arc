"""Build the local Python/Git qualification image and record its immutable ID."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    record = json.loads(args.worker_image_file.read_text())
    if "@sha256:" not in record["base"]:
        raise ValueError("Repository qualification requires a pinned base image")
    dockerfile = HERE / "Repository.Dockerfile"
    with tempfile.TemporaryDirectory(prefix="chio-repository-image-") as temporary:
        identifier = Path(temporary) / "image-id"
        subprocess.run(
            [
                *DOCKER,
                "build",
                "--file",
                str(dockerfile),
                "--build-arg",
                "BASE=" + record["base"],
                "--iidfile",
                str(identifier),
                str(HERE),
            ],
            check=True,
        )
        record["execution_image"] = identifier.read_text().strip()
    record["execution_dockerfile_sha256"] = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    record["execution_git_version"] = subprocess.check_output(
        [
            *DOCKER,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--entrypoint=/usr/bin/git",
            record["execution_image"],
            "--version",
        ],
        text=True,
    ).strip()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))


if __name__ == "__main__":
    main()
