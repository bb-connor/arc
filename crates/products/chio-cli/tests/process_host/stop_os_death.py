"""REST-1 TEST-03 for the non-recovery native lifecycle: durable stop crossed with OS death.

A released fixture hold first completes as allow, so a held tool is live.
C7 kills the host right after a durable stop: the restarted host is
`ready_stopped`, refuses its first call and keeps the epoch until an offline
resume. C8 refuses a call while stopped, kills the host and resumes: the same
request identity then dispatches exactly once, so the refusal burned nothing.
"""

import json
import sys
import tempfile
import threading
from pathlib import Path

from chio_process import WorkerError
from os_death import Host, cli, kill, wait_for_hold

STOPPED = "guard denied the request: kernel emergency stop active"


class Serving:
    def __init__(self, node, name):
        self.node = node
        socket = node.socket(name)
        _, self.client = node.credential(socket)
        self.host = node.start(socket)
        node.ready(self.host)

    def readiness(self):
        return cli(self.node.binary, "stop-status", "--state", self.node.state)


def invoke(client, key, tool, arguments):
    try:
        return client.invoke(key, "reports", tool, arguments)
    except WorkerError as failure:
        raise AssertionError(f"{key} surfaced {failure.code} instead of a signed verdict") from None


def ready_state(serving):
    status = serving.readiness()
    assert status["via"] == "control_socket", status
    return status["response"]["status"]


def stop(node):
    stopped = cli(node.binary, "stop", "--state", node.state, "--reason", "os death drill")
    assert stopped["via"] == "control_socket", stopped
    status = stopped["response"]["status"]
    assert status["durability"] == "durable" and status["stopped"], stopped
    assert status["head"]["epoch"] == 1, stopped
    return status["head"]["epoch"]


def resume_offline(node, epoch):
    resumed = cli(node.binary, "resume", "--state", node.state, "--expected-epoch", epoch)
    assert resumed["via"] == "offline", resumed
    assert not resumed["response"]["status"]["stopped"], resumed


def refused(response):
    assert response["verdict"] == "deny", response
    assert response["reason"] == STOPPED, response
    assert response["output"] is None, response
    return response


def released_hold(binary, root):
    """A released hold completes normally, so the cutpoints hold a live tool."""
    node = Host(binary, root / "hold")
    control = node.publications.with_suffix(".control")
    control.write_text("hold-after")
    first = Serving(node, "first")
    outcome = {}
    caller = threading.Thread(
        target=lambda: outcome.update(
            response=invoke(first.client, "held", "append", {"report": "held"})
        )
    )
    caller.start()
    wait_for_hold(node.publications.with_suffix(".held"), first.host)
    control.write_text("ready")
    caller.join(timeout=90)
    assert not caller.is_alive(), "released hold never returned"
    response = outcome["response"]
    assert response["verdict"] == "allow", response
    assert response["output"] is not None, response
    node.stop(first.host)
    assert node.lines() == 1
    return {
        "cutpoint": "hold",
        "receipts": [response["receipt_json"]],
        "kernel_key": node.kernel_key,
        "publications": node.lines(),
    }


def c7(binary, root):
    node = Host(binary, root / "C7")
    first = Serving(node, "first")
    epoch = stop(node)
    kill(first.host)
    second = Serving(node, "second")
    status = ready_state(second)
    assert status["readiness"] == {"state": "ready_stopped"}, status
    assert status["stopped"] and status["head"]["epoch"] == epoch, status
    deny = refused(invoke(second.client, "c7-read", "read", {"path": "source.txt"}))
    node.stop(second.host)
    resume_offline(node, epoch)
    third = Serving(node, "third")
    assert ready_state(third)["readiness"] == {"state": "ready"}
    allowed = invoke(third.client, "c7-after", "read", {"path": "source.txt"})
    assert allowed["verdict"] == "allow", allowed
    node.stop(third.host)
    assert node.lines() == 0
    return {
        "cutpoint": "C7",
        "receipts": [deny["receipt_json"], allowed["receipt_json"]],
        "kernel_key": node.kernel_key,
        "publications": node.lines(),
    }


def c6(binary, root):
    """A call that returns while stopped stays Finalizing with its output withheld."""
    node = Host(binary, root / "C6")
    control = node.publications.with_suffix(".control")
    control.write_text("hold-after")
    first = Serving(node, "first")
    outcome = {}
    caller = threading.Thread(
        target=lambda: outcome.update(
            response=invoke(first.client, "c6-append", "append", {"report": "C6"})
        )
    )
    caller.start()
    wait_for_hold(node.publications.with_suffix(".held"), first.host)
    epoch = stop(node)
    control.write_text("ready")
    caller.join(timeout=90)
    assert not caller.is_alive(), "held call never returned under the stop"
    during = outcome["response"]
    assert during["verdict"] != "allow" and during["output"] is None, during
    assert ready_state(first)["withheld_operations"] == 1
    kill(first.host)
    assert node.lines() == 1
    second = Serving(node, "second")
    status = ready_state(second)
    assert status["readiness"] == {"state": "ready_stopped"}, status
    assert status["withheld_operations"] == 1, status
    retried = invoke(second.client, "c6-append", "append", {"report": "C6"})
    assert retried["verdict"] != "allow" and retried["output"] is None, retried
    node.stop(second.host)
    resume_offline(node, epoch)
    third = Serving(node, "third")
    released = invoke(third.client, "c6-append", "append", {"report": "C6"})
    assert released["verdict"] == "allow" and released["output"] is not None, released
    again = invoke(third.client, "c6-append", "append", {"report": "C6"})
    assert again["receipt_json"] == released["receipt_json"]
    node.stop(third.host)
    assert node.lines() == 1
    return {
        "cutpoint": "C6",
        "receipts": [during["receipt_json"], released["receipt_json"]],
        "kernel_key": node.kernel_key,
        "publications": node.lines(),
    }


def c8(binary, root):
    node = Host(binary, root / "C8")
    first = Serving(node, "first")
    epoch = stop(node)
    deny = refused(invoke(first.client, "c8-append", "append", {"report": "C8"}))
    assert node.lines() == 0
    kill(first.host)
    resume_offline(node, epoch)
    second = Serving(node, "second")
    dispatched = invoke(second.client, "c8-append", "append", {"report": "C8"})
    assert dispatched["verdict"] == "allow", dispatched
    assert dispatched["output"] is not None, dispatched
    again = invoke(second.client, "c8-append", "append", {"report": "C8"})
    assert again["receipt_json"] == dispatched["receipt_json"]
    node.stop(second.host)
    assert node.lines() == 1, "the refused id dispatched other than once"
    return {
        "cutpoint": "C8",
        "receipts": [deny["receipt_json"], dispatched["receipt_json"]],
        "kernel_key": node.kernel_key,
        "publications": node.lines(),
    }


def exercise(binary, root):
    return {
        "cases": [released_hold(binary, root), c7(binary, root), c6(binary, root), c8(binary, root)]
    }


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="chio-process-stop-os-death-") as temporary:
        print(json.dumps(exercise(sys.argv[1], Path(temporary))))
