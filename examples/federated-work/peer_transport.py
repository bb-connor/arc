"""Owned-host transport qualification driver; never used to authorize a decision."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import selectors
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
from urllib.parse import urlsplit

from peer_tls_fixture import create


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def run(binary, root, request_id, observer):
    root = Path(root)
    state = root / "verifier"
    python = os.environ["CHIO_FUNDED_PYTHON"]
    denials = []
    running = None
    logs = []

    def invoke(*args, success=True):
        result = subprocess.run([binary, *map(str, args)], capture_output=True, timeout=45)
        if success:
            assert result.returncode == 0, result.stderr.decode()
        else:
            assert result.returncode != 0, result.stdout
        return result

    def custody():
        with sqlite3.connect(f"file:{state / 'verifier-custody.sqlite3'}?mode=ro", uri=True) as db:
            return db.execute("SELECT request,observation,decision FROM custody").fetchone()

    def stop(kill=False):
        nonlocal running
        if running is not None:
            running.kill() if kill else running.terminate()
            code = running.wait(timeout=10)
            running.stdout.close()
            running = None
            if kill:
                assert code == -9

    def start(origin="https://127.0.0.1:0", source=observer, checker=python, cert=None):
        nonlocal running
        port = urlsplit(origin).port
        log = (root / f"peer-service-{len(logs)}.log").open("wb")
        logs.append(log)
        running = subprocess.Popen([binary, "experimental-verifier-serve", str(state), str(source),
            f"127.0.0.1:{port}", origin, str((cert or state) / "tls-cert.pem"), str((cert or state) / "tls-key.pem")],
            env=dict(os.environ, CHIO_FUNDED_PYTHON=str(checker)), stdout=subprocess.PIPE, stderr=log)
        with selectors.DefaultSelector() as selector:
            selector.register(running.stdout, selectors.EVENT_READ)
            assert selector.select(15), "verifier service readiness timeout"
            line = running.stdout.readline(1025)
        assert line.endswith(b"\n") and len(line) <= 1024, "invalid service readiness: " + log.name
        return json.loads(line)["origin"]

    def send(label, endpoint=None, call=None, success=False, error_contains=None):
        output = root / f"peer-{label}.json"
        result = invoke("experimental-verifier-send", endpoint or root / "peer-endpoint.json",
               root / "verifier-enrollment.json", call or root / "peer-call.json", output, success=success)
        if error_contains:
            assert error_contains.encode() in result.stderr, result.stderr
        if not success:
            assert not output.exists(), label
            denials.append(label)
        return output

    def connect(origin, ca):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=ca)
        url = urlsplit(origin)
        return context.wrap_socket(socket.create_connection((url.hostname, url.port), timeout=5), server_hostname=url.hostname)

    def wire(origin, ca, body, *, content_type="application/json", method="POST", host=None, extra="", lose=False, expected_status=None):
        url = urlsplit(origin)
        try:
            with connect(origin, ca) as stream:
                request = (f"{method} /v1/funded-work/verify HTTP/1.1\r\nHost: {host or url.netloc}\r\n"
                           f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n{extra}\r\n").encode() + body
                stream.sendall(request)
                if lose:
                    assert stream.recv(1) == b"H", "no HTTP response after commit"
                    return
                response = bytearray()
                while b"\r\n" not in response and len(response) < 1024:
                    part = stream.recv(1)
                    if not part:
                        break
                    response.extend(part)
                assert not response.startswith(b"HTTP/1.1 200 "), response
                if expected_status:
                    assert response.startswith(f"HTTP/1.1 {expected_status} ".encode()), response
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError):
            if lose or expected_status:
                raise

    def impostor(origin, response):
        """A valid TLS endpoint still cannot forge a verifier decision."""
        url = urlsplit(origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(state / "tls-cert.pem", state / "tls-key.pem")
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((url.hostname, url.port))
        listener.listen(1)
        listener.settimeout(10)
        errors = []

        def reply():
            try:
                with listener, context.wrap_socket(listener.accept()[0], server_side=True) as stream:
                    stream.settimeout(10)
                    header = bytearray()
                    while not header.endswith(b"\r\n\r\n") and len(header) < 8192:
                        part = stream.recv(1)
                        assert part, "truncated client header"
                        header.extend(part)
                    size = next(int(line.split(b":", 1)[1]) for line in header.split(b"\r\n") if line.lower().startswith(b"content-length:"))
                    while size:
                        part = stream.recv(min(size, 65536))
                        assert part, "truncated client body"
                        size -= len(part)
                    stream.sendall(response)
            except Exception as error:
                errors.append(repr(error))
        worker = threading.Thread(target=reply)
        worker.start()
        return worker, errors

    try:
        with contextlib.redirect_stdout(io.StringIO()):
            create(state, "127.0.0.1")
            wrong = root / "wrong-tls"
            wrong.mkdir()
            create(wrong, "other.example")
        origin = start(source=root / "missing-observer")
        endpoint = {"schema": "chio.experimental.funded-verifier-endpoint.v1", "origin": origin,
                    "address": f"127.0.0.1:{urlsplit(origin).port}", "caPem": (state / "root-cert.pem").read_text()}
        (root / "peer-endpoint.json").write_bytes(canonical(endpoint))
        invoke("experimental-verifier-call", root / "provider", request_id, observer, origin, root / "peer-call.json")
        call = (root / "peer-call.json").read_bytes()
        parsed = json.loads(call)
        shifted = root / "changed-destination.json"
        rejected = invoke("experimental-verifier-call", root / "provider", request_id, observer,
                          "https://other.example", shifted, success=False)
        assert b"selected origin" in rejected.stderr and not shifted.exists()
        assert (root / "peer-call.json").read_bytes() == call
        denials.append("retained-destination-substitution")
        send("missing-observer", error_contains="peer did not return a decision")
        wire(origin, endpoint["caPem"], call, expected_status=503)
        assert custody() == (None, None, None)
        invoke("experimental-verifier-serve", state, observer, "127.0.0.1:0", "https://127.0.0.1:0",
               state / "tls-cert.pem", state / "tls-key.pem", success=False)
        denials.append("concurrent-service-lock")
        stop()
        start(origin, checker=root / "missing-checker")
        send("missing-checker", error_contains="peer did not return a decision")
        wire(origin, endpoint["caPem"], call, expected_status=503)
        assert custody() == (None, None, None)
        stop()
        start(origin)
        mutations = [call + b"\n", b'{"signature":"duplicate",' + call[1:], b" " * (256 * 1024 + 1)]
        for field, value in (("origin", "https://unselected.invalid"), ("enrollmentSha256", "ab" * 32)):
            changed = copy.deepcopy(parsed)
            changed["body"][field] = value
            mutations.append(canonical(changed))
        for field in ("input", "output", "claim", "observation"):
            changed = copy.deepcopy(parsed)
            changed["body"]["request"][field] = "substituted"
            mutations.append(canonical(changed))
        changed = copy.deepcopy(parsed)
        changed["signature"] = "00" * 64
        mutations.append(canonical(changed))
        for index, raw in enumerate(mutations):
            wire(origin, endpoint["caPem"], raw)
            denials.append(f"unauthenticated-body-{index}")
            assert custody() == (None, None, None)
        for label, options in (("wrong-host", {"host": "other.example"}), ("wrong-method", {"method": "PUT"}),
                               ("wrong-content-type", {"content_type": "text/plain"}),
                               ("content-encoding", {"extra": "Content-Encoding: gzip\r\n"}),
                               ("duplicate-host", {"extra": "Host: other.example\r\n"}),
                               ("duplicate-length", {"extra": f"Content-Length: {len(call)}\r\n"}),
                               ("transfer-encoding", {"extra": "Transfer-Encoding: chunked\r\n"}),
                               ("expect-continue", {"extra": "Expect: 100-continue\r\n"}),
                               ("oversized-headers", {"extra": "X-Large: " + "a" * 8192 + "\r\n"})):
            wire(origin, endpoint["caPem"], call, **options)
            denials.append(label)
            assert custody() == (None, None, None)
        wrong_endpoint = dict(endpoint, caPem=(wrong / "root-cert.pem").read_text())
        (root / "wrong-endpoint.json").write_bytes(canonical(wrong_endpoint))
        send("wrong-ca", endpoint=root / "wrong-endpoint.json", error_contains="invalid peer certificate:")
        stop()
        start(origin, cert=wrong)
        # Trust this certificate but require the independently selected hostname.
        send("wrong-tls-hostname", endpoint=root / "wrong-endpoint.json", error_contains="NotValidForName")
        stop()
        start(origin)
        url = urlsplit(origin)
        with socket.create_connection((url.hostname, url.port), timeout=5) as plaintext:
            plaintext.sendall(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")
            try:
                assert not plaintext.recv(1024).startswith(b"HTTP/")
            except ConnectionResetError:
                pass
        denials.append("plaintext-tls-downgrade")
        assert custody() == (None, None, None)
        wire(origin, endpoint["caPem"], call, lose=True)
        original = custody()
        assert all(part is not None for part in original)
        assert original[0] == canonical(parsed["body"]["request"])
        stop(kill=True)
        (state / "key.seed").unlink()
        start(origin, source=root / "missing-observer", checker=root / "missing-checker")
        decision = send("recovered", success=True).read_bytes()
        assert decision == original[2]
        assert send("repeated", success=True).read_bytes() == decision
        assert custody() == original
        occupied = root / "occupied-output.json"
        occupied.write_bytes(b"preserve original output")
        invoke("experimental-verifier-send", root / "peer-endpoint.json", root / "verifier-enrollment.json",
               root / "peer-call.json", occupied, success=False)
        assert occupied.read_bytes() == b"preserve original output" and custody() == original
        denials.append("existing-output-preserved")
        stop()
        altered = json.loads(decision)
        altered["body"]["accepted"] = not altered["body"]["accepted"]
        raw = canonical(altered)
        for label, response in (("forged-decision", f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n".encode() + raw),
                                ("redirect", b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://unselected.invalid\r\nContent-Length: 0\r\n\r\n")):
            worker, errors = impostor(origin, response)
            try:
                send(label)
            finally:
                worker.join(timeout=15)
            assert not worker.is_alive() and not errors, errors
        (root / "decision.json").write_bytes(decision)
        (root / "decision-replay.json").write_bytes(decision)
        report = dict(denials=denials, responseLossRecovered=True,
                      replayWithoutSignerObserverChecker=True, killedSignal=9,
                      origin=origin, serviceUsesReceiverConfiguredObserver=True)
        (root / "peer-report.json").write_bytes(canonical(report))
        return report
    finally:
        stop()
        for log in logs:
            log.close()


if __name__ == "__main__":
    print(json.dumps(run(*sys.argv[1:])))
