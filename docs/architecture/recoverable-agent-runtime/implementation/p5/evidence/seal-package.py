#!/usr/bin/env python3
"""Seal verified local work without converting missing Linux evidence to success."""
import datetime
import importlib.util
import json
from pathlib import Path
import re
import sys
import tarfile
from inventory import ROOT, PHASE, sha, sources, source_binding

def load_runner():
    spec=importlib.util.spec_from_file_location("p5_gates",PHASE/"evidence/run-gates.py")
    if spec is None or spec.loader is None: raise ValueError("gate runner missing")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def counts(text):
    rust=re.findall(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored",text)
    out={"rust_tests_passed":sum(int(r[0]) for r in rust),"rust_tests_failed":sum(int(r[1]) for r in rust),"rust_tests_ignored":sum(int(r[2]) for r in rust)} if rust else {}
    for key,pattern in [("python_tests_passed",r"(\d+) passed in [\d.]+s"),("typescript_tests_passed",r"Tests\s+(\d+) passed")]:
        match=re.search(pattern,text)
        if match: out[key]=int(match.group(1))
    return out

def baseline_check():
    baseline=json.loads((PHASE/"source-baseline.json").read_text())
    for row in baseline["artifacts"]:
        if sha(ROOT/row["path"])!=row["sha256"]: raise ValueError("sealed P4 artifact changed: "+row["path"])
    archive=PHASE/"evidence/p4-source-baseline.tar.gz"
    if sha(archive)!=baseline["archive_sha256"]: raise ValueError("P4 archive hash changed")
    expected={row["path"]:row["sha256"] for row in baseline["sources"]}
    with tarfile.open(archive,"r:gz") as tar:
        observed={}
        import hashlib
        for entry in tar.getmembers():
            if not entry.isfile() or entry.name in observed: raise ValueError("invalid P4 archive member")
            data=tar.extractfile(entry)
            if data is None: raise ValueError("missing P4 archive bytes")
            observed[entry.name]=hashlib.sha256(data.read()).hexdigest()
        if observed!=expected: raise ValueError("P4 archive inventory differs")
    return baseline

def build_record():
    baseline=baseline_check();runner=load_runner();binding=source_binding();checks=[]
    for name,(command,cwd,_) in runner.GATES.items():
        row=json.loads((PHASE/"evidence"/(name+".result.json")).read_text())
        if (row["actual_command"]!=command or row["cwd"]!=cwd or row["status"]!="passed" or row["exit_code"]!=0
            or row.get("source_binding")!=binding or sha(PHASE/row["log"])!=row["log_sha256"]):
            raise ValueError("local gate absent, failed or stale: "+name)
        if command[0] == "cargo" or name in {"python", "ts", "vector-recompute"}:
            row.update(counts((PHASE/row["log"]).read_text()))
        if name in {"cage-inventory-mutations", "cage-script-mutations", "guard-mutations"}:
            row["evidence_class"] = "gate_harness_mutation_checks"
        if name in {"native","contracts","p1-native","p2-native","p3-native","p4-native","owning-tests",
                    "store-native","store-ordering","store-schema","store-regression","kernel-lib","conformance-lib"} and not row.get("rust_tests_passed"):
            raise ValueError("filtered gate had no passing tests: "+name)
        checks.append(row)
    linux=json.loads((PHASE/"evidence/linux-acceptance.result.json").read_text())
    if linux.get("source_binding")!=binding or sha(PHASE/linux["log"])!=linux["log_sha256"]:
        raise ValueError("Linux acceptance record drifted")
    if linux["status"] not in {"passed","blocked"}: raise ValueError("Linux acceptance failed and needs repair")
    if linux["status"]=="passed":
        if (linux["exit_code"]!=0 or linux.get("linux_tests")!=10 or len(linux.get("measured_images",[]))!=11
            or linux.get("host")!={"system":"Linux","machine":"x86_64"}
            or re.fullmatch(r"[a-f0-9]{64}",linux.get("cage_challenge","")) is None):
            raise ValueError("Linux acceptance inventory incomplete")
        text=(PHASE/linux["log"]).read_text()
        if "test result: ok. 10 passed; 0 failed; 0 ignored" not in text:
            raise ValueError("Linux useful-decision/channel/restart suite did not pass")
        for image in linux["measured_images"]:
            if sha(ROOT/image["path"])!=image["sha256"]: raise ValueError("measured Linux image changed")
    current=sources();old={r["path"]:r["sha256"] for r in baseline["sources"]}
    delta=[r for r in current if old.get(r["path"])!=r["sha256"]]
    authored=[r for r in delta if Path(r["path"]).suffix in {".rs",".inc"} and "_generated" not in Path(r["path"]).parts]
    other=[r for r in delta if Path(r["path"]).suffix not in {".rs",".inc"} and "_generated" not in Path(r["path"]).parts]
    review=json.loads((PHASE/"review-manifest.json").read_text())
    if (review["source_binding"]!=binding or review["authored_rust"]!=authored
        or review["authored_other_sources"]!=other or review["open_p0"] or review["open_p1"]):
        raise ValueError("source review incomplete or stale")
    coverage=json.loads((PHASE/"requirements-coverage.json").read_text())
    architecture=json.loads((ROOT/"docs/architecture/recoverable-agent-runtime/requirements.json").read_text())
    obligations={r["id"] for r in architecture["requirements"] if r["phase"]=="P5"}
    if {r["id"] for r in coverage["requirements"]}!=obligations or len(obligations)!=10:
        raise ValueError("P5 obligation crosswalk incomplete")
    for requirement in coverage["requirements"]:
        for anchor in requirement["sources"]+requirement["acceptance_tests"]:
            if anchor["anchor"] not in (ROOT/anchor["path"]).read_text(): raise ValueError("crosswalk anchor drifted")
    for name in ["sdks/typescript/node_modules","sdks/typescript/scripts/node_modules","sdks/typescript/packages/node-http/node_modules","sdks/typescript/packages/conformance/node_modules"]:
        path=ROOT/name
        if path.exists() or path.is_symlink(): raise ValueError("temporary Node overlay remains: "+name)
    complete=linux["status"]=="passed"
    return {"schema":"chio.recovery-p5-verification.v1","phase":"P5","phase_accomplished":complete,
        "status":"locally_verified_pending_linux_acceptance" if not complete else "locally_and_linux_verified",
        "created_at_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"source_binding":binding,
        "local_gates":checks,"linux_acceptance":linux,"joined_sources":current,"phase_delta":delta,
        "reviewed_authored_rust":authored,"review":review,"requirements":coverage,
        "preserved_p4_artifacts":len(baseline["artifacts"]),"prior_source_count":len(baseline["sources"]),
        "p4_source_count":baseline["p4_source_count"],
        "preexisting_cage_source_count":len(baseline["cage_baseline_sources"]),
        "next_phase":"P6" if complete else "P5 Linux acceptance, then P6",
        "limits":["No hosted CI or deployment qualification","Node lifecycle scripts were disabled during the isolated lockfile installation","Cross compilation proves types and lint only"]}

def main():
    record=build_record()
    (PHASE/"verification.json").write_text(json.dumps(record,indent=2)+"\n")
    paths=sorted(p for p in PHASE.rglob("*") if p.is_file() and p.name!="package-integrity.json" and "__pycache__" not in p.parts)
    integrity={"schema":"chio.recovery-p5-package-integrity.v1","artifacts":[{"path":str(p.relative_to(PHASE)),"sha256":sha(p)} for p in paths]}
    (PHASE/"package-integrity.json").write_text(json.dumps(integrity,indent=2)+"\n")
    print(f"SEALED P5 local work: {len(record['local_gates'])} gates, {len(record['reviewed_authored_rust'])} reviewed Rust sources; phase accomplished={record['phase_accomplished']}")

if __name__=="__main__": main()
