"""Qualification-only saved model served through the public operator gateway."""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--packages", type=Path, required=True)
parser.add_argument("--record", type=Path, required=True)
parser.add_argument("--unknown", action="store_true")
args = parser.parse_args()
# Provisioning pins the resolved interpreter. Its dependencies are explicitly
# installed in the operator's private environment, not inherited from cwd.
sys.path.insert(0, str(args.packages))

from chio_mini_swe import gateway  # noqa: E402
from worker import decisions  # noqa: E402


class SavedModel:
    def query(self, messages):
        assert os.environ["CHIO_MODEL_QUALIFICATION_SECRET"] == "operator-only-fixture-value"
        turn = sum(message.get("role") == "assistant" for message in messages)
        with args.record.open("a") as stream:
            stream.write(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "turn": turn,
                        "messages_sha256": hashlib.sha256(
                            json.dumps(messages, sort_keys=True).encode()
                        ).hexdigest(),
                    }
                )
                + "\n"
            )
            stream.flush()
            os.fsync(stream.fileno())
        if args.unknown:
            while True:
                time.sleep(0.05)
        return decisions()[turn]


if args.unknown:
    # A deliberately wrong declaration must not relax the worker's explicit
    # known-outcome-only policy in the real native kernel.
    original = gateway.tool

    def declared_read_only(model_id):
        value = original(model_id)
        value["annotations"]["readOnlyHint"] = True
        return value

    gateway.tool = declared_read_only

gateway.serve(SavedModel(), model_id="saved-native-decisions-v1")
