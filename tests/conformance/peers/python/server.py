#!/usr/bin/env python3

import json
import sys

if "--help" in sys.argv:
    print("PACT Python conformance server scaffold")
    raise SystemExit(0)

print(
    json.dumps(
        {
            "status": "scaffold",
            "role": "server",
            "message": "Python conformance server scaffold is present but not wired yet",
        }
    )
)
