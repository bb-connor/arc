#!/usr/bin/env python3
"""Check finite propagation liveness, its original-action quotient and witnesses.

The historical 4-authority/8-capability length-24 SMT timeout remains
unverified. This gate checks a declared finite reduction, not that old bound.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT_SECONDS = 60
CASES = (
    ("RevocationPropagationPairLiveness", 0, "Model checking completed. No error has been found."),
    ("RevocationPropagationEpochQuotient", 0, "Model checking completed. No error has been found."),
    ("RevocationPropagationPairWitness", 0, "Model checking completed. No error has been found."),
    ("RevocationPropagationUnfairWitness", 13, "Temporal properties were violated."),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", default=os.environ.get("TLA2TOOLS_JAR"))
    parser.add_argument("--java", default="java")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.jar or not Path(args.jar).is_file():
        parser.error("--jar must name a TLC or Apalache jar containing tlc2.TLC")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    modules = {name for name, _, _ in CASES} | {
        "RevocationPropagation", "RevocationPropagationPairRefinement"
    }
    sources = [ROOT / f"formal/tla/{name}.tla" for name in sorted(modules)]
    sources += [ROOT / f"formal/tla/MC{name}.cfg" for name, _, _ in CASES]
    report = {
        "scope": "finite epoch-order quotient; epoch relabeling and fairness transfer are documented arguments",
        "historical_bound": "4 authorities, 8 capabilities, length 24: timeout, unverified",
        "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "results": [],
    }
    with tempfile.TemporaryDirectory(prefix="chio-propagation-") as temp:
        work = Path(temp)
        for source in sources:
            (work / source.name).write_bytes(source.read_bytes())
        for module, expected_exit, expected_text in CASES:
            command = [args.java, "-XX:+UseParallelGC", "-Xmx2048m", "-cp",
                       str(Path(args.jar).resolve()), "tlc2.TLC", "-workers", "2",
                       "-deadlock", "-metadir", str(work / module),
                       "-config", f"MC{module}.cfg", f"{module}.tla"]
            timed_out = False
            with (output / f"{module}.log").open("w") as log:
                try:
                    result = subprocess.run(command, cwd=work, stdout=log,
                                            stderr=subprocess.STDOUT,
                                            timeout=TIMEOUT_SECONDS, check=False)
                    code = result.returncode
                except subprocess.TimeoutExpired:
                    code, timed_out = None, True
            log_text = (output / f"{module}.log").read_text()
            passed = not timed_out and code == expected_exit and expected_text in log_text
            # The witness must actually explore issuance, delivery and its fair suffix.
            if module == "RevocationPropagationPairWitness":
                passed = passed and "3 distinct states found" in log_text
            report["results"].append({"module": module, "passed": passed,
                                      "exit_code": code, "timed_out": timed_out,
                                      "expected_exit": expected_exit})
            print(f"{module}: {'PASS' if passed else 'FAIL'}", flush=True)
            if not passed:
                break
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    if len(report["results"]) != len(CASES) or not all(r["passed"] for r in report["results"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
