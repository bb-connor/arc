"""Build a local worker image from locked dependencies and Chio wheels."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]


def run(*arguments, **kwargs):
    return subprocess.run([str(value) for value in arguments], check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="python:3.11-slim")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    inspected = json.loads(
        run(
            *DOCKER,
            "image",
            "inspect",
            args.base,
            capture_output=True,
            text=True,
        ).stdout
    )[0]
    digests = inspected.get("RepoDigests", [])
    if not digests:
        raise ValueError("Base image needs a registry digest; pull it before building")
    with tempfile.TemporaryDirectory(prefix="chio-mini-image-") as temporary:
        context = Path(temporary)
        requirements = context / "requirements.txt"
        run(
            "uv",
            "export",
            "--project",
            ROOT / "sdks/python/chio-mini-swe",
            "--locked",
            "--no-dev",
            "--no-header",
            "--no-emit-project",
            "--no-emit-package",
            "chio-process",
            "--output-file",
            requirements,
            stdout=subprocess.DEVNULL,
        )
        for package in ("chio-process", "chio-mini-swe"):
            run("uv", "build", ROOT / "sdks/python" / package, "--wheel", "--out-dir", context)
        (context / "Dockerfile").write_text("""ARG PYTHON_IMAGE=python:3.11-slim
FROM ${PYTHON_IMAGE}
COPY requirements.txt /opt/chio/requirements.txt
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes \\
    -r /opt/chio/requirements.txt
COPY *.whl /opt/chio/wheels/
RUN python -m pip install --no-cache-dir --no-deps /opt/chio/wheels/*.whl
RUN mkdir -p /run/chio /app /work
ENV PYTHONDONTWRITEBYTECODE=1 MSWEA_SILENT_STARTUP=1
USER 65534:65534
""")
        content = (
            digests[0].encode() + requirements.read_bytes() + (context / "Dockerfile").read_bytes()
        )
        content += b"".join(path.read_bytes() for path in sorted(context.glob("*.whl")))
        tag = "chio-mini-worker:" + hashlib.sha256(content).hexdigest()[:24]
        run(
            *DOCKER,
            "build",
            "--tag",
            tag,
            "--build-arg",
            f"PYTHON_IMAGE={digests[0]}",
            "--iidfile",
            context / "image-id",
            context,
        )
        result = {
            "local_tag": tag,
            "image": (context / "image-id").read_text().strip(),
            "base": digests[0],
            "requirements_sha256": hashlib.sha256(requirements.read_bytes()).hexdigest(),
            "wheels": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in context.glob("*.whl")
            },
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))


if __name__ == "__main__":
    main()
