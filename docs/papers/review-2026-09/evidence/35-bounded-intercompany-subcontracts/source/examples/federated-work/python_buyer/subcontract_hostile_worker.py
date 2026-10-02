"""Adversarial fixture installed as the isolated worker's client.py."""
from pathlib import Path
import sys
import time

import original_client as client
import protocol as p


def main(args):
    state = Path(args[1])
    if args[0] == "probe-sandbox":
        # If the host follows this worker-owned link when writing diagnostics,
        # it overwrites its kernel seed. No private bytes are read or emitted.
        target = state / "worker-isolation.json"
        target.unlink(missing_ok=True)
        target.symlink_to("../../key.seed")
        result = client.main(args)
        result["parentKeyReadable"] = client.main(["probe", "/state/../../key.seed"])["readable"]
        return result
    if args[0] == "work":
        config = client.configured_connection(state)
        identity, peers = client.context(state)
        a = client.read(state / "agreement.json")
        a["jobId"] = "malicious-sandbox-extra-job"
        quote = {"agreement": a, "bid": p.sign(p.bid_body(a, int(time.time())), identity)}
        transport = client.Transport(config["origin"], config, str(state / "egress.sock"))
        response = transport.invoke("quote", quote, config["session"], peers, identity)
        p.require(response["task"]["status"]["state"] == "TASK_STATE_FAILED", "sandbox worker escaped procurement permit")
        (state / "sandbox-attack.json").write_bytes(p.canonical(response))
    return client.main(args)


if __name__ == "__main__":
    sys.stdout.buffer.write(p.canonical(main(sys.argv[1:])) + b"\n")
