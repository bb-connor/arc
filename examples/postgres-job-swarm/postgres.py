"""Create a dedicated TLS PostgreSQL fixture using the real store's role checks."""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATABASE = "chio_agent_jobs"


def command(arguments, directory, *, input=None, env=None, timeout=90):
    result = subprocess.run(
        arguments, input=input, capture_output=True, env=env, timeout=timeout
    )
    if result.returncode:
        with (directory / "setup-errors.log").open("ab") as log:
            log.write(result.stderr)
        raise RuntimeError("fixture command failed; inspect private setup-errors.log")
    return result.stdout


def database_env(state, role):
    return {
        **{
            name: os.environ[name]
            for name in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT")
            if name in os.environ
        },
        "CHIO_JOB_DATABASE_URL": state["urls"][role],
        "CHIO_JOB_DATABASE_CA": state["ca"],
    }


def start(args):
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    tls = directory / "tls"
    tls.mkdir(mode=0o700)
    identity = "chio-agent-jobs-" + secrets.token_hex(6)
    binary = args.binary.resolve(strict=True)
    passwords = {
        role: secrets.token_hex(24)
        for role in ("admin", "migrator", "runtime", "worker")
    }
    password_file = directory / "postgres-password"
    password_file.write_text(passwords["admin"] + "\n")
    openssl = args.openssl
    command(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "3",
            "-subj",
            "/CN=Chio temporary PostgreSQL CA",
            "-keyout",
            str(tls / "ca.key"),
            "-out",
            str(tls / "ca.crt"),
        ],
        directory,
    )
    command(
        [
            openssl,
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(tls / "server.key"),
            "-out",
            str(tls / "server.csr"),
        ],
        directory,
    )
    (tls / "server.ext").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
    )
    command(
        [
            openssl,
            "x509",
            "-req",
            "-in",
            str(tls / "server.csr"),
            "-CA",
            str(tls / "ca.crt"),
            "-CAkey",
            str(tls / "ca.key"),
            "-CAcreateserial",
            "-days",
            "3",
            "-sha256",
            "-extfile",
            str(tls / "server.ext"),
            "-out",
            str(tls / "server.crt"),
        ],
        directory,
    )
    image = json.loads(command(["docker", "image", "inspect", args.image], directory))[
        0
    ]
    # Freeze the local image by ID before creating any database state.
    image_id = image["Id"]
    volume = identity + "-data"
    state = {
        "container": identity,
        "volume": volume,
        "image_id": image_id,
        "repo_digests": image.get("RepoDigests", []),
        "ca": str(tls / "ca.crt"),
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    # Preserve identity even if readiness or migrations fail, so cleanup remains
    # bounded to this fixture. Database credentials stay in this private file.
    path = directory / "state.json"
    path.write_text(json.dumps(state))
    command(
        ["docker", "volume", "create", "--label", "chio.fixture=" + identity, volume],
        directory,
    )
    command(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            identity,
            "--label",
            "chio.fixture=" + identity,
            "--publish",
            "127.0.0.1::5432",
            "--env",
            "POSTGRES_DB=" + DATABASE,
            "--env",
            "POSTGRES_PASSWORD_FILE=/run/postgres-password",
            "--mount",
            f"type=volume,src={volume},dst=/var/lib/postgresql/data",
            "--mount",
            f"type=bind,src={password_file},dst=/run/postgres-password,readonly",
            "--mount",
            f"type=bind,src={tls / 'server.key'},dst=/tls/server.key,readonly",
            "--mount",
            f"type=bind,src={tls / 'server.crt'},dst=/tls/server.crt,readonly",
            "--user",
            "0",
            "--entrypoint",
            "bash",
            image_id,
            "-c",
            "install -o postgres -g postgres -m 600 /tls/server.key /var/lib/postgresql/server.key && "
            "install -o postgres -g postgres -m 644 /tls/server.crt /var/lib/postgresql/server.crt && "
            "exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/var/lib/postgresql/server.crt "
            "-c ssl_key_file=/var/lib/postgresql/server.key",
        ],
        directory,
    )
    deadline = time.monotonic() + 90
    while True:
        probe = subprocess.run(
            [
                "docker",
                "exec",
                identity,
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
                "-d",
                DATABASE,
            ],
            capture_output=True,
            timeout=10,
        )
        if probe.returncode == 0:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("PostgreSQL did not become ready")
        time.sleep(0.2)
    port = (
        command(["docker", "port", identity, "5432/tcp"], directory)
        .decode()
        .strip()
        .rsplit(":", 1)[1]
    )
    state["urls"] = {
        role: f"postgresql://chio_jobs_{role}:{passwords[role]}@localhost:{port}/{DATABASE}"
        for role in ("migrator", "runtime", "worker")
    }
    path.write_text(json.dumps(state))

    def sql(body):
        return command(
            [
                "docker",
                "exec",
                "-i",
                identity,
                "psql",
                "-X",
                "-v",
                "ON_ERROR_STOP=1",
                "-U",
                "postgres",
                "-d",
                DATABASE,
            ],
            directory,
            input=body.encode(),
        )

    sql(
        f"REVOKE ALL ON SCHEMA public FROM PUBLIC; REVOKE CREATE, TEMPORARY ON DATABASE {DATABASE} FROM PUBLIC;"
    )
    sql(
        (HERE / "migrator-role.sql")
        .read_text()
        .replace("__PASSWORD__", passwords["migrator"])
    )
    command([str(binary), "migrate"], directory, env=database_env(state, "migrator"))
    for role in ("runtime", "worker"):
        sql(
            (HERE / f"{role}-role.sql")
            .read_text()
            .replace("__PASSWORD__", passwords[role])
        )
    state["postgres_version"] = (
        command(["docker", "exec", identity, "postgres", "--version"], directory)
        .decode()
        .strip()
    )
    path.write_text(json.dumps(state))
    print(
        json.dumps(
            {
                "ready": True,
                "state": str(path),
                "postgres": state["postgres_version"],
                "image_id": image_id,
            }
        )
    )


def stop(args):
    path = args.state.resolve(strict=True)
    state = json.loads(path.read_text())
    inspected = json.loads(
        command(["docker", "inspect", state["container"]], path.parent)
    )[0]
    if inspected["Config"]["Labels"].get("chio.fixture") != state["container"]:
        raise ValueError("fixture container identity changed")
    command(["docker", "stop", "--time", "15", state["container"]], path.parent)
    print(json.dumps({"stopped": True, "data_retained": True}))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("start")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--binary", type=Path, required=True)
    create.add_argument("--image", default="postgres:17.11")
    create.add_argument("--openssl", default="openssl")
    close = subparsers.add_parser("stop")
    close.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    start(args) if args.command == "start" else stop(args)


if __name__ == "__main__":
    main()
