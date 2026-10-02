#!/usr/bin/env python3
"""Exercise native TLS, public enrollment and the complete Python buyer fault suite."""
import argparse
import contextlib
import copy
import io
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
from urllib.parse import urlsplit

import python_smoke
from smoke import write


class HttpsScenario(python_smoke.PythonScenario):
    def __init__(self, binary, root):
        super().__init__(binary, root)
        command = self.python_command("provider", "init", "/state")
        command[command.index("/client/client.py"):] = ["/client/tls_fixture.py", "/state", "127.0.0.1"]
        created = subprocess.run(command, capture_output=True, text=True, timeout=30)
        assert created.returncode == 0, created.stderr

    def command(self, role, *args):
        if role == "provider" and args[0] == "grant":
            # Even the inherited launcher's initial unused session is public and
            # proof-of-possession-bound in this transport profile.
            args = ("grant-session", *args[1:])
        if role == "provider" and args[0] == "serve-work":
            origin = getattr(self, "url", "https://127.0.0.1:0")
            port = urlsplit(origin).port
            args = ("serve-https", "/state", f"127.0.0.1:{port}", origin,
                    "/state/tls-cert.pem", "/state/tls-key.pem", args[-1])
        cmd = super().command(role, *args)
        # DNS is operator-provided infrastructure, not data returned by discovery.
        offset = cmd.index("/venv/bin/python") if "/venv/bin/python" in cmd else cmd.index("/app", cmd.index("--chdir"))
        for file in ("/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf"):
            if Path(file).exists():
                cmd[offset:offset] = ["--ro-bind", file, file]
        return cmd

    def start(self, fault="none"):
        super().start(fault)
        if not (self.root / "buyer/connection.json").exists():
            self.activate(self.url, "/state/tls-cert.pem")
            # Subsequent work depends only on this party's key and locally
            # activated public enrollment, without a shared bearer secret.
            (self.root / "buyer/session.json").unlink()
            (self.root / "buyer/peers.json").unlink()
        assert (self.root / "provider/https-backend.sock").is_socket()
        for path in ("/state/tls-key.pem", str(self.root / "provider/https-backend.sock"),
                     str(self.root / "provider/tls-key.pem")):
            assert not self.call("buyer", "probe", path)["readable"]

    def activate(self, origin, ca):
        enrollment = self.call("provider", "enrollment", "/state", self.keys["buyer"], origin, ca)
        write(self.root / "buyer/enrollment.json", enrollment)
        result = self.call("buyer", "enroll", "/state", self.keys["provider"], origin, "/state/enrollment.json")
        write(self.root / "enrollment.json", enrollment)
        write(self.root / "activation.json", result)
        return enrollment


def transport_denials(binary, root):
    case = HttpsScenario(binary, root)
    other = HttpsScenario(binary, root.with_name("untrusted-tls-authority"))
    try:
        case.start()
        case.snapshot()
        before = case.counts()
        original = (root / "buyer/connection.json").read_bytes()
        enrollment = json.loads((root / "enrollment.json").read_text())
        denials = []
        combined = root / "provider/combined.pem"
        combined.write_bytes((root / "provider/tls-cert.pem").read_bytes() + (root / "provider/tls-key.pem").read_bytes())
        result = case.invoke("provider", "enrollment", "/state", case.keys["buyer"], case.url, "/state/combined.pem")
        assert result.returncode != 0 and not result.stdout, "private key escaped in enrollment"
        denials.append({"case": "combined-certificate-and-private-key", "rejected": True})
        marker = "CA-comment-should-not-be-exported"
        (root / "provider/commented-ca.pem").write_text(marker + "\n" + (root / "provider/tls-cert.pem").read_text())
        normalized = case.call("provider", "enrollment", "/state", case.keys["buyer"], case.url, "/state/commented-ca.pem")
        assert marker not in normalized["body"]["caPem"]
        for label, provider, origin, change in (
            ("wrong-provider-key", "a" * 64, case.url, lambda v: None),
            ("wrong-selected-origin", case.keys["provider"], "https://unselected.invalid", lambda v: None),
            ("substituted-trust-root", case.keys["provider"], case.url, lambda v: v["body"].update(caPem="untrusted")),
            ("substituted-buyer", case.keys["provider"], case.url, lambda v: v["body"].update(buyer="a" * 64)),
        ):
            altered = copy.deepcopy(enrollment)
            change(altered)
            write(root / "buyer/altered.json", altered)
            result = case.invoke("buyer", "enroll", "/state", provider, origin, "/state/altered.json")
            assert result.returncode != 0, label
            assert (root / "buyer/connection.json").read_bytes() == original
            denials.append({"case": label, "error": result.stderr.strip()})
        for label, url in (("plaintext-downgrade", case.url.replace("https:", "http:")),
                           ("unselected-origin", "https://unselected.invalid")):
            result = case.invoke("buyer", "work", "/state", url)
            assert result.returncode != 0, label
            denials.append({"case": label, "error": result.stderr.strip()})
        # A signed configuration mistake is distinct from tampering: signature
        # checks succeed, but the real TLS handshake must still fail closed.
        (root / "provider/wrong-ca.pem").write_bytes((other.root / "provider/tls-cert.pem").read_bytes())
        case.activate(case.url, "/state/wrong-ca.pem")
        result = case.invoke("buyer", "work", "/state", case.url)
        assert result.returncode != 0 and "SSLCertVerificationError" in result.stderr
        denials.append({"case": "untrusted-serving-certificate", "error": result.stderr.strip()})
        wrong_host = case.url.replace("127.0.0.1", "localhost")
        case.activate(wrong_host, "/state/tls-cert.pem")
        result = case.invoke("buyer", "work", "/state", wrong_host)
        assert result.returncode != 0 and "SSLCertVerificationError" in result.stderr, result.stderr
        denials.append({"case": "certificate-hostname-mismatch", "error": result.stderr.strip()})
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=(root / "provider/tls-cert.pem").read_text())
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        try:
            with socket.create_connection(("127.0.0.1", urlsplit(case.url).port), timeout=5) as stream:
                with context.wrap_socket(stream, server_hostname="127.0.0.1"):
                    raise AssertionError("provider accepted TLS 1.2")
        except ssl.SSLError:
            denials.append({"case": "tls-version-downgrade", "rejected": True})
        with socket.create_connection(("127.0.0.1", urlsplit(case.url).port), timeout=5) as stream:
            stream.sendall(b"GET /.well-known/agent-card.json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            try:
                response = stream.recv(128)
                assert not response.startswith(b"HTTP/"), "public listener answered plaintext HTTP"
            except ConnectionResetError:
                pass
        denials.append({"case": "plaintext-on-tls-listener", "rejected": True})
        case.activate(case.url, "/state/tls-cert.pem")
        attacker = root / "attacker"
        attacker.mkdir(mode=0o700)
        write(attacker / "enrollment.json", json.loads((root / "enrollment.json").read_text()))
        with sqlite3.connect(root / "buyer/buyer.sqlite") as db:
            quote = json.loads(db.execute("SELECT quote FROM jobs").fetchone()[0])
        write(attacker / "quote.json", quote)
        # This caller has only the public enrollment and signed quote. Its mount
        # namespace has neither party's application key or provider TLS key.
        for mode in ("missing", "wrong-key"):
            command = case.python_command("attacker", "probe", "/state/key.seed")
            code = """
import sys
sys.path.insert(0, '/client')
import client, protocol as p
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
body = client.read('/state/enrollment.json')['body']
identity = Ed25519PrivateKey.generate() if sys.argv[1] == 'wrong-key' else None
output = client.Transport(body['origin'], body).invoke('quote', client.read('/state/quote.json'),
    body['session'], {name:body[name] for name in ('buyer','provider')}, identity)
sys.stdout.buffer.write(p.canonical(output))
"""
            command[command.index("/client/client.py"):] = ["-c", code, mode]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, result.stderr
            denied = json.loads(result.stdout)
            assert denied["task"]["status"]["state"] == "TASK_STATE_FAILED"
            assert not case.call("attacker", "probe", "/state/key.seed")["readable"]
            denials.append({"case": "public-enrollment-" + mode + "-proof", "response": denied})
        assert case.counts() == before == {"reviews": 0, "payments": {}, "buyerExpenses": 0}
        assert case.snapshot()["reserved"] == 0
        assert case.provider_snapshot()["acceptanceEvents"] == 0
        assert case.provider_snapshot()["jobs"] == []
        case.activate(case.url, "/state/tls-cert.pem")
        public = case.call("buyer", "work", "/state", case.url)
        assert public["buyerVerified"] and public["spent"] == 100
        write(root / "public.json", {"denials": denials, "workAfterRepair": public})
        return {"scenario": root.name, "denials": len(denials), "beforeRepair": before,
                "afterRepair": case.counts(), "plaintextBackend": "private Unix socket"}
    finally:
        case.stop()
        other.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/debug/chio-federated-work"))
    parser.add_argument("--python-env", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--normal-only", action="store_true")
    args = parser.parse_args()
    python_smoke.PythonScenario = HttpsScenario
    with contextlib.redirect_stdout(io.StringIO()):
        python_smoke.main()
    summary_file = args.output.resolve() / "summary.json"
    summary = json.loads(summary_file.read_text())
    if not args.normal_only:
        summary["scenarios"].append(transport_denials(args.binary.resolve(), args.output.resolve() / "transport-denials"))
    summary.update(passed=len(summary["scenarios"]), transport="TLS 1.3", negotiationCredential="proof of possession",
                   enrollment="provider-signed and locally activated", independentOperators=False)
    write(summary_file, summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
