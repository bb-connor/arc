"""Synthetic primary-probe records for the maintained qualification decoder.

All execution observations are modeled, including native identities. No process,
compiler, controller, provider, or isolation probe is run by this fixture.
These golden bytes use the historical authorization and six-tool roster still
explicitly supported by the current production decoder. The controller is
inert retained bytes required by that supported archive contract;
it is never imported or executed. Keep these approved bytes and the explicit
six-tool roster independent of the verifier constants under test.
"""
import hashlib
import json
from pathlib import Path

SOURCE_NAME = "scripts/record-rust-compilation.py"
AUTHORIZATION_SHA256 = "90659258cf73681a01780b0e83018bd418b1cbf3207fa29c2e0454af0a5bac41"
CONTROLLER_SHA256 = "35735f7d03fa1030155b076cad5fe5e0d66ac653a2458708750aaf09a3a4d26a"
REVIEWED_TOOLS = {
    "consumer/verify_public_compilation_probes.py": "21f92a7d36cf5a4709addda7e3394c8e4cd0a1f919c8895a7fd8e43b42acc60e",
    "consumer/scope-record-functions.py": "f92309385f1eba536d88cd9adbd4eb02943a02a1be84efc808e8d0e29b724471",
    "consumer/physical_publication_functions.py": "35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564",
    "consumer/probe-observation-functions.py": "8ac9b9822c09e629c81d458207cf8f1b0af8a3161bf81dd045dc9b098172403e",
    "inventory-collector.py": "1f35d0a4c6462d30fecc995e68b55e8a7ef4db10dac44ced9023974d4b3c279d",
    "run-public-compiler-campaign-current.py": CONTROLLER_SHA256,
}

FIXTURES = Path(__file__).with_name("fixtures") / "qualification-primary"
AUTHORIZATION_BYTES = (FIXTURES / "authorization.json").read_bytes()
CONTROLLER_BYTES = (FIXTURES / "controller.txt").read_bytes()


class PrimaryProbePackage:
    """Build ordinary files only, with modeled process and publication records."""
    def __init__(self, audit, root, source_root):
        self.audit = audit
        self.root = root.resolve()
        self.candidate = Path("/var/tmp/chio-public-model-not-executed")
        self.sources = [{"path":SOURCE_NAME,"sha256":hashlib.sha256((source_root/SOURCE_NAME).read_bytes()).hexdigest()}]
        self.binding = self.audit.binding(self.sources,None)
        self.authorization = json.loads(AUTHORIZATION_BYTES)
        self.cases = []
        self.results = []
        self.configs = []
        self.controller = self.ref("controller.py",CONTROLLER_BYTES,
            str(self.candidate/"target/metadata/run-public-compiler-campaign-current.py"),size=True)
        self.authorization_ref = self.ref("authorization.json",AUTHORIZATION_BYTES,
            str(self.candidate/"target/metadata/public-probe-authorization.json"),size=True)
        self.tools = [{"path":str(self.candidate/"target/metadata"/name),"sha256":sha}
                      for name,sha in REVIEWED_TOOLS.items()]
        for approved in self.authorization["cases"]:
            self.case(approved)

    def ref(self, name, value, original=None, *, size=False):
        raw = value if type(value) is bytes else self.audit.compilation_canonical(value)+b"\n"
        path = self.root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        ref = {"path":name,"sha256":hashlib.sha256(raw).hexdigest()}
        if original is not None:
            ref["original_path"] = original
        if size:
            ref["size"] = len(raw)
        return ref

    def original_ref(self, name, raw, original):
        retained = self.ref(name,raw,str(original),size=True)
        return retained,{"path":str(original),"sha256":retained["sha256"],"size":len(raw)}

    def sample(self, name):
        if name == "allowed-read": value = {"public_bytes":20}
        elif name in {"outside-read","outside-write","evidence-read","evidence-write"}:
            value = {"expected_denial":True,"observed_errno":13}
        elif name == "network": value = {key:{"expected_denial":True,"observed_errno":1} for key in ["1","2"]}
        elif name == "forged-ipc": value = {"observed_refusal_exit":86}
        elif name == "gnu-native": value = {"commands":[["modeled-rustc-1"],["modeled-rustc-2"]],
            "program_exit":0,"public_stdout":"14","compiler_child_ipc":{
                "observation":"proc-macro-checked-original-pipe-identities-not-inherited"}}
        else: value = {"command":["modeled-musl-rustc"],"program_exit":0,"elf_machine":62,
            "elf_type":3,"interpreter_present":False,"target":"x86_64-unknown-linux-musl"}
        return {"schema":"chio.public-linux-compilation-probe.v1","mode":name,"result":value}

    def sync(self, count):
        units = {}
        for index in range(count):
            identifier = f"{index+1:032x}"
            reference = {"path":"records/"+identifier+".json","sha256":"a"*64,"size":100,"identity":{"device":1,"inode":2}}
            value = {"schema":"chio.rust-unit-publication-outcome.v1","source_binding":self.binding,
                "invocation_id":identifier,"kind":"compilation","record_status":"success","compiler_exit":0,
                "record":reference,"completion":{**reference,"path":"completions/"+identifier+".json"},
                "unit_images_sha256":"b"*64,"physical_status":"complete"}
            units[identifier] = value
        publication = {"source_binding":self.binding,"retention_batches":[],"unit_publications":units}
        stderr = b"".join(b"compilation_recorder.unit_publication_outcome="+self.audit.compilation_canonical(
            {**value,"durability":{"status":"confirmed","phase":"completion-directory-fsync","errno":None}})+b"\n"
            for value in units.values())
        sync = self.audit.current_required_sync_observations(publication,stderr)
        return stderr,hashlib.sha256(self.audit.compilation_canonical(sync)).hexdigest()

    def case(self, approved):
        name = approved["name"]
        case_root = self.candidate/"target/metadata/primary-observations"/name
        scope = self.candidate/"target/evidence"/name/("1"*32)/"scope.json"
        configuration = self.candidate/approved["configuration_relative_path"]
        command = [value.format(candidate=str(self.candidate),configuration=str(configuration))
                   for value in approved["command_template"]]
        prefix = "cases/"+name+"/"
        count = 2 if name == "gnu-native" else 1 if name == "musl-static-pie" else 0
        stderr,sync = self.sync(count)
        outer_out,capture_out = self.original_ref(prefix+"launcher.stdout.log",b"",case_root/"launcher.stdout.log")
        outer_err,capture_err = self.original_ref(prefix+"launcher.stderr.log",stderr,case_root/"launcher.stderr.log")
        sample = self.sample(name)
        inner_out,inner_capture_out = self.original_ref(prefix+"scope.stdout.log",self.audit.compilation_canonical(sample)+b"\n",scope.with_name("stdout.log"))
        inner_err,inner_capture_err = self.original_ref(prefix+"scope.stderr.log",b"",scope.with_name("stderr.log"))
        observation = {"schema":"chio.public-linux-launcher-observation.v1","candidate":str(self.candidate),
            "source_binding":self.binding,"name":name,"command":command,"actual_exit":0,
            "command_timeout_seconds":approved["timeout_seconds"],"elapsed_seconds":0.5,"pid":101,"process_group":101,
            "launcher_capture":{"stdout":capture_out,"stderr":capture_err}}
        observation_ref = self.ref(prefix+"launcher-observation.json",observation,
            str(case_root/"launcher-observation.json"),size=True)
        observed_ref = {"path":observation_ref["original_path"],"sha256":observation_ref["sha256"],"size":observation_ref["size"]}
        runtime = {"source_inventory_version":self.audit.INVENTORY_VERSION,"base_commit":None,
                   "sources":self.sources,"source_binding":self.binding}
        runtime_refs = {key:self.ref(prefix+filename,runtime,str(case_root/filename))
                        for key,filename in [("runtime_before","runtime-before.json"),("runtime_after","runtime-after.json")]}
        inner_command = command[command.index("--")+1:]
        audit_command = ["/usr/bin/python3.12","-I","-B",str(self.candidate/"target/metadata/consumer/verify_public_compilation_probes.py"),
            "--auditor",str(self.candidate/"target/metadata/inventory-collector.py"),"--scope",str(scope),
            "--runtime-before",str(case_root/"runtime-before.json"),"--runtime-after",str(case_root/"runtime-after.json"),
            "--command",str(case_root/"command.json"),"--launcher-observation",str(case_root/"launcher-observation.json"),
            "--authorization",str(self.candidate/"target/metadata/public-probe-authorization.json")]
        original = {"schema":"chio.original-public-compilation-probe-verification.v2","source_binding":self.binding,
            "scope_id":"c"*64,"original_namespace":str(self.candidate/"target/records"/name),"scope_path":str(scope),
            "verified_publications":count,"verified_dispatches":count,"verified_compilations":count,"verified_inventory_images":1,
            "coverage":"original-namespace-public-microprobe-record-joins-only","qualified":False,
            "compiled_closure_status":"not-established","primary_probe_result_coverage":"separate actual whole controller execution required",
            "authorization_sha256":self.authorization_ref["sha256"],"launcher_observation":observed_ref,
            "launcher_capture":observation["launcher_capture"],"scope_stdout_capture":inner_capture_out,
            "scope_stderr_capture":inner_capture_err,"probe_observation":sample,"required_sync_observation_sha256":sync}
        original_ref = self.ref(prefix+"self.audit.stdout.json",original,str(case_root/"original-namespace-self.audit.stdout.json"))
        audit_stderr = self.ref(prefix+"self.audit.stderr.log",b"",str(case_root/"original-namespace-self.audit.stderr.log"))
        observed = {key:observation[key] for key in ["name","command","actual_exit","command_timeout_seconds","elapsed_seconds",
                                                    "pid","process_group","launcher_capture"]}
        observed.update(status="passed-command-and-original-namespace-audit",qualified=False,
            compiled_closure_status="not-established",launcher_observation=observed_ref,
            original_namespace_audit={"command":audit_command,"actual_exit":0,"stdout_sha256":original_ref["sha256"],
                "stderr_sha256":audit_stderr["sha256"],"scope":str(scope)})
        for key,ref in runtime_refs.items():
            observed[key] = {"command":["/usr/bin/python3.12","-I","-B",str(self.candidate/"target/metadata/inventory-collector.py"),
                "--inventory","--source-root",str(self.candidate)],"actual_exit":0,"path":ref["original_path"],"sha256":ref["sha256"]}
        result_ref = self.ref(prefix+"result.json",observed)
        self.cases.append({"name":name,"result":result_ref,**runtime_refs,"command":self.ref(prefix+"command.json",inner_command),
            "original_audit_stdout":original_ref,"original_audit_stderr":audit_stderr,"launcher_stdout":outer_out,
            "launcher_stderr":outer_err,"launcher_observation":observation_ref,"scope_stdout":inner_out,"scope_stderr":inner_err})
        self.results.append(observed)
        self.configs.append({"name":name,"command":command,"guest_path":str(configuration),"sha256":"f"*64})

    def read(self, ref):
        return json.loads((self.root/ref["path"]).read_bytes())

    def replace(self, ref, value):
        new = self.ref(ref["path"],value,ref.get("original_path"),size="size" in ref)
        ref.clear();ref.update(new)

    def change_result(self,index,change):
        change(self.results[index])
        self.replace(self.cases[index]["result"],self.results[index])

    def change_original(self,index,change):
        ref = self.cases[index]["original_audit_stdout"]
        value = self.read(ref);change(value);self.replace(ref,value)
        self.change_result(index,lambda row:row["original_namespace_audit"].update(stdout_sha256=ref["sha256"]))

    def change_observation(self,index,change):
        ref = self.cases[index]["launcher_observation"]
        value = self.read(ref);change(value);self.replace(ref,value)
        capture = {"path":ref["original_path"],"sha256":ref["sha256"],"size":ref["size"]}
        self.change_result(index,lambda row:row.update({key:value[key] for key in [
            "name","command","actual_exit","command_timeout_seconds","elapsed_seconds","pid","process_group","launcher_capture"]},
            launcher_observation=capture))
        self.change_original(index,lambda row:row.update(launcher_observation=capture,launcher_capture=value["launcher_capture"]))

    def bundle(self):
        caps = {"total_seconds":900,"ordinary_seconds":120,"compiler_seconds":180,"retry":False}
        plan = {"schema":"chio.public-linux-primary-plan.v2","candidate":str(self.candidate),"expected_uid":1001,
            "source_location":{"schema":"chio.source-location.v1","repository":str(self.candidate),
                "host":{"system":"Linux","machine":"x86_64","node":"public-model-not-executed"},
                "root":{"device":1,"inode":2,"uid":1001,"mode":0o700}},
            "source_binding":self.binding,"authorization_sha256":self.authorization_ref["sha256"],"caps":caps,
            "tools":self.tools,"configs":self.configs}
        plan_ref = self.ref("plan.json",plan,str(self.candidate/"target/metadata/plan.json"))
        summary = {"schema":"chio.public-linux-primary-result.v2","candidate":str(self.candidate),"expected_uid":1001,
            "source_binding":self.binding,"authorization_sha256":self.authorization_ref["sha256"],"caps":caps,
            "results":self.results,"status":"passed-public-microprobes","qualified":False,"compiled_closure_status":"not-established",
            "elapsed_from_first_dispatch_seconds":9.0,"artifacts_exported":False}
        dispatch = {"schema":"chio.public-probe-dispatch-start.v1","candidate":str(self.candidate),"source_binding":self.binding,
            "caps":caps,"plan_sha256":plan_ref["sha256"],"unix_seconds":1.0,"monotonic_seconds":1.0}
        command = ["/usr/bin/python3.12","-I","-B",str(Path(self.controller["original_path"]).relative_to(self.candidate)),
            str(Path(plan_ref["original_path"]).relative_to(self.candidate)),plan_ref["sha256"],
            str(Path(self.authorization_ref["original_path"]).relative_to(self.candidate))]
        pins = [{"purpose":"compiler-primary-controller","path":self.controller["original_path"],"observed":{"sha256":self.controller["sha256"]}},
            {"purpose":"compiler-primary-plan","path":plan_ref["original_path"],"observed":{"sha256":plan_ref["sha256"]}},
            {"purpose":"compiler-primary-authorization","path":self.authorization_ref["original_path"],"observed":{"sha256":self.authorization_ref["sha256"]}},
            *[{"purpose":"compiler-primary-tool","path":row["path"],"observed":{"sha256":row["sha256"]}} for row in self.tools]]
        snapshot = {"format":"chio.local-command-provenance.v1","git":{"head":None},"entries":{SOURCE_NAME:{
            "membership":"tracked","state":"file","content_coverage":"sha256-bytes","sha256":self.sources[0]["sha256"]}},
            "explicit_file_pins":pins}
        snapshot["content_manifest_sha256"] = hashlib.sha256(json.dumps({key:snapshot[key] for key in ["git","entries","explicit_file_pins"]},
            sort_keys=True,ensure_ascii=True,separators=(",",":"),allow_nan=False).encode()).hexdigest()
        log = self.ref("controller.log",b"".join(self.audit.compilation_canonical(value)+b"\n" for value in self.results))
        runtime = {"source_inventory_version":self.audit.INVENTORY_VERSION,"base_commit":None,"sources":self.sources,"source_binding":self.binding}
        provenance = {"start":self.ref("start.json",{"repository":str(self.candidate),"cwd":str(self.candidate),"command":command,"environment":{}}),
            "before":self.ref("before.json",snapshot),"after":self.ref("after.json",snapshot),
            "runtime_sources_before":self.ref("runtime-before.json",runtime),"runtime_sources_after":self.ref("runtime-after.json",runtime),
            "result":self.ref("execution-result.json",{"format":"chio.local-command-provenance.v1","actual_command_exit":0,"runner_exit":0,
                "inventories_complete":True,"output_pipe_completed":True,"provenance_error":None,"source_drift":{"detected":False},
                "before_manifest_sha256":snapshot["content_manifest_sha256"],"after_manifest_sha256":snapshot["content_manifest_sha256"],
                "log":{"sha256":log["sha256"]}})}
        self.evidence = {"schema":"chio.linux-compiler-primary-probes.v2","plan":plan_ref,"summary":self.ref("summary.json",summary),
            "dispatch_start":self.ref("dispatch-start.json",dispatch),"execution":{"command":command,"cwd":".","log":log,"provenance":provenance},
            "controller":self.controller,"authorization":self.authorization_ref,"cases":self.cases}
        return self.ref("evidence.json",self.evidence)


