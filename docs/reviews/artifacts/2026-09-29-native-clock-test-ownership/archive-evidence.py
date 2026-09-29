from pathlib import Path
import json,shutil,hashlib,re
w=Path(__file__).parent
out=Path("docs/reviews/artifacts/2026-09-29-native-clock-test-ownership")
out.mkdir(parents=True,exist_ok=True)
names=[
 "progress.md","final-review.md","kernel-tests-before.txt","kernel-tests-after.txt",
 "kernel-source-before.json","kernel-path-mapping.json","kernel-scenario-relocations.json",
 "kernel-test-body-preservation.json","kernel-inventory-preservation.json","live-selectors.json",
 "declaration-relocations.json","shared-identity-pins.json","binaries.json","run-targets.py",
 "verify_kernel_bodies.py","verify_kernel_inventory.py","rust_items.py",
 "native-flow-exit.json","native-flow-tests.log","clock-red-case.log","clock-red.log",
 "native-clock-green.log","native-clock-stale-binary.log","native-deadline-red.log",
 "native-deadline-green.log","native-issuance-green.log","native-live-clock.log",
 "native-broker-clock-red.log","native-broker-connection-red.log","native-runtime-expiry-red.log",
 "native-caller-red.log","native-future-clock-red.log","native-flow-superseded.log",
 "native-flow-superseded-result.json","kernel-superseded.log","kernel-superseded-result.json",
 "admission-injected-clock.log","emergency-stop-red.log","emergency-stop-green.log",
 "native-fixes-final.log","native-fixes-final-result.json","kernel-final-2.log","kernel-final-2-result.json",
 "clippy-final.log","clippy-final-2.log","clippy-final-3.log","clippy-final-4.log","format-final.log",
 "format-final-2.log","format-fix-final.log","format-last-final.log","format-last-fix.log",
 "native-campaign-executable.json","native-tests-after.txt","native-qualification.json",
 "runtime-expiry-stale-observation.log","runtime-expiry-stale-observation-result.json",
 "verification-index.json","archive-evidence.py",
 "hygiene-final-ratchet.log","negative-final-ratchet.log","kernel-bodies-final.log",
 "selector-live-check.log","flow-selector-final.log","response-selector-final.log",
]
names += [p.name for p in w.glob("*.log")]+[p.name for p in w.glob("*-result.json")]
for name in sorted(set(names)):
 p=w/name
 if p.exists():shutil.copyfile(p,out/name)
# Compiler diagnostics and terminal metadata retain failures without megabytes
# of Cargo artifact/fingerprint rows. Human build logs preserve command context.
builds=[]
for p in sorted(list(w.glob("batch-build*.jsonl")) + list(w.glob("kernel-visibility-build.jsonl"))):
 rows=[json.loads(line) for line in p.read_text().splitlines()]
 messages=[r["message"] for r in rows if r.get("reason")=="compiler-message"]
 terminal=[r for r in rows if r.get("reason")=="build-finished"]
 builds.append({"log":p.stem+".log","terminal":terminal,"diagnostics":messages})
 log=p.with_suffix(".log")
 if log.exists():shutil.copyfile(log,out/log.name)
(out/"build-results.json").write_text(json.dumps(builds,indent=2)+"\n")
manifest={str(p.relative_to(out)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob("*")) if p.is_file() and p.name!="sha256.json"}
(out/"sha256.json").write_text(json.dumps(manifest,indent=2)+"\n")
print("Archived",len(manifest),"files at",out)
