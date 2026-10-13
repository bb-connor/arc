#!/usr/bin/env python3
"""Owning production contracts and original copy joins, without a Rust run."""
from copy import deepcopy
from contextlib import ExitStack, redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT/"scripts/compiled-dimension-profiles.py"
spec = importlib.util.spec_from_file_location("compiled_dimension_profiles",TOOL)
profiles = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = profiles
spec.loader.exec_module(profiles)


class CompiledDimensionProfilesTest(unittest.TestCase):
    def owning_capture_fixture(self, root):
        """Actual recorder/inspector/exporter composition with simulated unit rows.

        The publisher and original filesystem custody are real. No Rust or
        Cargo command is executed, and these controls never claim qualification.
        """
        subprocess.run(["git","init","--quiet"],cwd=root,check=True)
        for name in ["compiled-dimension-profiles.py","record-rust-compilation.py","verify-recovery-qualification.py"]:
            path = root/"scripts"/name;path.parent.mkdir(exist_ok=True);path.write_bytes((ROOT/"scripts"/name).read_bytes())
        def module(name):
            spec = importlib.util.spec_from_file_location("owning_control_"+name.replace("-","_"),root/"scripts"/(name+".py"))
            loaded = importlib.util.module_from_spec(spec);spec.loader.exec_module(loaded);return loaded
        auditor,recorder = module("verify-recovery-qualification"),module("record-rust-compilation")
        source = root/"crates/public/src/lib.rs";source.parent.mkdir(parents=True);source.write_bytes(b"pub struct SimulatedCompilerUnit;\n")
        (root/"target").mkdir()
        for name in ["cargo","rustc"]:
            path = root/"tools"/name;path.parent.mkdir(exist_ok=True);path.write_bytes(("PUBLIC-NONEXECUTED-TOOL-"+name+"\n").encode())
        def image(path):
            raw = path.read_bytes();return {"path":str(path),"sha256":hashlib.sha256(raw).hexdigest(),"size":len(raw)}
        tools = {"helper":image(root/"scripts/compiled-dimension-profiles.py"),"inspector":image(root/"scripts/verify-recovery-qualification.py"),
            "recorder":image(root/"scripts/record-rust-compilation.py"),"python":image(Path(sys.executable).resolve()),
            "cargo":image(root/"tools/cargo"),"rustc":image(root/"tools/rustc")}
        captured = profiles.DimensionCompilerCapture.__new__(profiles.DimensionCompilerCapture)
        captured.repository,captured.output,captured.auditor = root,root/"target/capture",auditor
        captured.dimension,captured.stack,captured.actions = "live_provider",ExitStack(),{}
        captured.output.mkdir(mode=0o700)
        self.addCleanup(captured.close)
        inventory = captured.runtime_inventory();captured.inventory = inventory
        environment = {"PATH":"/usr/bin:/bin","HOME":"/nonexistent","CARGO_HOME":str(root/"target/public-cargo"),
            "TMPDIR":str(root/"target/tmp"),"CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"2",
            "CARGO_NET_OFFLINE":"true","CARGO_TERM_COLOR":"never","LC_ALL":"C"}
        target,namespace = root/"target/compiled",root/"target/publications"
        namespace.mkdir(mode=0o700)
        output = target/"debug/deps/chio_control_plane-public";output.parent.mkdir(parents=True)
        output.write_bytes(b"SIMULATED-UNIT-IMAGE-NEVER-EXECUTED\n");output.chmod(0o500)
        options = {"schema":"chio.compiled-dimension-capture-options.v2","dimension":"live_provider",
            "source_binding":inventory["source_binding"],"mode":"host-trusted-fresh","tools":tools,"environment":environment,
            "actions":{"native-host-library":{"namespace":str(namespace),"target":str(target),"launch_configuration":None}},
            "source_origin":None,"primary_probes":None}
        captured.options = options
        options_ref = captured.publish_json("options.json",options)
        captured.configuration = {**options_ref,"path":str(root/options_ref["path"])}
        public_log = io.StringIO()
        campaign = recorder.Campaign(namespace,inventory["source_binding"])
        try:
            with redirect_stderr(public_log):
                def retained(path,role=None):
                    item = {**image(path),**campaign.retain(path.read_bytes())}
                    if role is not None:item["role"] = role
                    return item
                row = recorder.row_for([],{},inventory["source_binding"])
                with campaign.retention_batch():
                    row.update(kind="compilation",status="success",compiler_exit=0,inputs=[retained(source,"source")],
                        outputs=[retained(output,"unit")],compiler=retained(root/"tools/rustc"),
                        semantics={"source":str(source),"cwd":str(root)})
                campaign.publish(row)
        finally:campaign.close()
        before_ref = captured.publish_json("before.json",inventory)
        contract = profiles.compilation_contract("live_provider","native-host-library",root)
        action = options["actions"]["native-host-library"]
        producer = {"schema":"chio.compiled-dimension-command-production.v2","dimension":"live_provider","label":"native-host-library",
            "contract":contract,"command":[tools["cargo"]["path"],*contract["command"][1:]],
            "environment":{**environment,"CARGO_TARGET_DIR":str(target),"RUSTC":tools["rustc"]["path"],"RUSTC_WRAPPER":tools["recorder"]["path"],
                "CHIO_COMPILATION_RECORDS":str(namespace),"CHIO_COMPILATION_SOURCE_ROOT":str(root),"CHIO_COMPILATION_SOURCE_BINDING":inventory["source_binding"]},
            "namespace":str(namespace),"source_binding":inventory["source_binding"],"runtime_inventory_before":before_ref,
            "runtime_inventory_after":before_ref,"toolchain_probe":{"command":[tools["rustc"]["path"],"-Vv"],"actual_exit":0,
                "stdout":captured.publish("version.log",b"release: 1.95.0\n"),"compiler":tools["rustc"]},
            "tools":tools,"options":captured.configuration,"launch_configuration":None,"source_origin":None,
            "actual_exit":0,"duration_seconds":1.0,"completed":True,"log":captured.publish("production.log",public_log.getvalue().encode()),
            "qualified":False,"compiled_closure_status":"not-established"}
        captured.actions["native-host-library"] = {"producer":producer,"reference":captured.publish_json("producer.json",producer),
                                                   "namespace":namespace,"target":target}
        return captured,image(output),auditor

    def test_real_publication_through_original_inspector_and_unbound_export_remains_unqualified(self):
        with tempfile.TemporaryDirectory() as temporary:
            captured,image,auditor = self.owning_capture_fixture(Path(temporary).resolve())
            name = "dimension/live_provider/native-host-library"
            observation = captured.observe("native-host-library",{name:[image]},{name:[image]},[])
            report = auditor.artifact_json(captured.repository,observation["report"])
            self.assertEqual(report["schema"],"chio.compiler-profile-custody-observation.v2")
            self.assertFalse(report["qualified"])
            index = auditor.artifact_json(captured.repository,captured.finish())
            template = auditor.artifact_json(captured.repository,index["templates"][0])
            self.assertEqual(template["schema"],"chio.unbound-compiled-profile-evidence.v2")
            self.assertIsNone(template["dimension_binding"]["record"])
            self.assertIsNone(template["subject_export"])
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_profile_record$"):
                auditor.audit_compiled_profile(captured.repository,template,captured.inventory["source_binding"],captured.inventory["sources"],None)

    def test_real_inspector_refuses_a_failed_simulated_producer_before_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            captured,image,auditor = self.owning_capture_fixture(Path(temporary).resolve())
            action = captured.actions["native-host-library"]
            action["producer"]["actual_exit"] = 1
            action["reference"] = captured.publish_json("failed-producer.json",action["producer"])
            name = "dimension/live_provider/native-host-library"
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_custody$"):
                captured.observe("native-host-library",{name:[image]},{name:[image]},[])
            self.assertNotIn("observation",action)
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_custody$"):
                captured.finish()

    def test_full_custody_export_joins_the_final_owner_and_refuses_a_different_executed_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            captured,image,auditor = self.owning_capture_fixture(Path(temporary).resolve())
            root = captured.repository
            name = "dimension/live_provider/native-host-library"
            captured.observe("native-host-library",{name:[image]},{name:[image]},[])
            index = auditor.artifact_json(root,captured.finish())
            template = auditor.artifact_json(root,index["templates"][0])
            def reference(name,value):
                item = captured.publish_json(name,value)
                return {key:item[key] for key in ["path","sha256"]}
            logical = str(Path(image["path"]).relative_to(root))
            executable = {"path":logical,"sha256":image["sha256"],"size":image["size"]}
            rows = [{"id":"simulated-owner-row-"+str(i),"native_executable":executable} for i in range(96)]
            row_ref = captured.publish("native-rows.jsonl",b"".join((json.dumps(row)+"\n").encode() for row in rows))
            cohort = reference("cohort.json",{"rows":row_ref,"trials":{row["id"]:{"native_executable":executable} for row in rows}})
            attempts = reference("attempts.json",[{"primary":cohort}])
            owner = reference("owner.json",{"schema":"chio.recovery-live-provider-evidence.v1","cohort_attempts":attempts})
            bound = profiles.bind_profile_to_owner(auditor,root,template,owner)
            result = auditor.audit_compiled_profile(root,bound,captured.inventory["source_binding"],captured.inventory["sources"],None,
                                                   dimension_records={"live_provider":owner})
            self.assertEqual(result["subjects"],{name:[image]})
            self.assertEqual(result["coverage"],"owning-dimension-action-and-original-produced-to-executed-image-custody")
            self.assertEqual(template["schema"],"chio.unbound-compiled-profile-evidence.v2")
            self.assertIsNone(template["dimension_binding"]["record"])
            changed = deepcopy(rows)
            changed[0]["native_executable"]["path"] = "target/another-native-executable"
            changed_ref = captured.publish("changed-native-rows.jsonl",b"".join((json.dumps(row)+"\n").encode() for row in changed))
            wrong_cohort = reference("wrong-cohort.json",{"rows":changed_ref,
                "trials":{row["id"]:{"native_executable":executable} for row in rows}})
            wrong_attempts = reference("wrong-attempts.json",[{"primary":wrong_cohort}])
            wrong_owner = reference("wrong-owner.json",{"schema":"chio.recovery-live-provider-evidence.v1","cohort_attempts":wrong_attempts})
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_executed_subject$"):
                profiles.bind_profile_to_owner(auditor,root,template,wrong_owner)
            borrowed = reference("borrowed-owner.json",{"schema":"chio.recovery-formal-evidence.v1"})
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_owner_record$"):
                profiles.bind_profile_to_owner(auditor,root,template,borrowed)

    def test_original_inspector_refuses_a_failed_publication_excluded_from_selected_units(self):
        with tempfile.TemporaryDirectory() as temporary:
            captured,image,auditor = self.owning_capture_fixture(Path(temporary).resolve())
            name = "dimension/live_provider/native-host-library"
            observation = captured.observe("native-host-library",{name:[image]},{name:[image]},[])
            path = captured.repository/observation["request"]["path"]
            source = captured.repository/"scripts/record-rust-compilation.py"
            spec = importlib.util.spec_from_file_location("extra_failed_publication",source)
            recorder = importlib.util.module_from_spec(spec);spec.loader.exec_module(recorder)
            campaign = recorder.Campaign(captured.actions["native-host-library"]["namespace"],captured.inventory["source_binding"])
            try:
                row = recorder.row_for([],{},captured.inventory["source_binding"])
                row.update(kind="compilation",status="compiler_failed",compiler_exit=1)
                with redirect_stderr(io.StringIO()):campaign.publish(row)
            finally:campaign.close()
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_rows$"):
                auditor.inspect_compiler_profile_request(path)



    def test_new_output_refuses_replacement_of_an_original_intermediate_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            boundary = root/"target";boundary.mkdir()
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_output$"):
                with profiles.fresh_owned_directory(boundary/"private/result",boundary):
                    (boundary/"private").rename(boundary/"original-private")
                    (boundary/"private/result").mkdir(parents=True)

    def test_owned_linux_commands_match_the_actual_maintained_caller(self):
        source = ROOT/"scripts/run-confined-return-linux-acceptance.py"
        spec = importlib.util.spec_from_file_location("owned_linux_compilation_caller",source)
        caller = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = caller
        spec.loader.exec_module(caller)
        commands = caller.compilation_commands()
        self.assertEqual(len(commands),len({row["name"] for row in commands}))
        for row in commands:
            observed = profiles.compilation_contract("linux",row["name"],ROOT)
            self.assertEqual(observed["command"],row["command"])
            self.assertEqual(observed["environment"],{"CHIO_CONFINED_CANARY_MODE":row["mode"]} if "mode" in row else {})
            self.assertEqual(observed["caller_source"],"scripts/run-confined-return-linux-acceptance.py")
        for name in ["contracts","kernel","linux","canary-unlisted"]:
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_producer$"):
                profiles.compilation_contract("linux",name,ROOT)

    def test_formal_contract_pins_the_actual_entry_and_separate_input_snapshot(self):
        root = "/var/tmp/owned-model"
        for name,entry in {"ownership":"recovery.rs","review":"review.rs","third":"third.rs"}.items():
            row = profiles.compilation_contract("formal",name,root,
                captured_inputs=root+"/target/run/inputs",output_root=root+"/target/run/compiled")
            self.assertEqual(row["command"],["rustc","+1.94.1","--edition","2021","-D","warnings",entry,
                "--emit","dep-info,link","-o",root+"/target/run/compiled/"+name])
            self.assertEqual(row["cwd"],root+"/target/run/inputs")
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_projection$"):
            profiles.compilation_contract("formal","ownership",root,
                captured_inputs=root+"/target/run/inputs",output_root=root+"/target/run")

    def test_live_compile_contract_preserves_the_independent_ignored_execution_command(self):
        expected = ["cargo","test","--offline","--locked","-p","chio-control-plane","--lib",
                    "live_comparative_native_host","--no-run"]
        self.assertEqual(profiles.compilation_contract("live_provider","native-host-library",ROOT)["command"],expected)
        self.assertEqual(profiles.LIVE_NATIVE_COMMAND,expected[:-1]+["--","--ignored","--test-threads=1"])
        with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_producer$"):
            profiles.compilation_contract("live_provider","contracts",ROOT)

    def fixture(self, temporary):
        root = Path(temporary).resolve()
        source = root/"produced-test-image"
        body = b"PUBLIC-EXECUTABLE-COPY-CONTROL\n"
        source.write_bytes(body)
        source.chmod(0o500)
        image = {"path":str(source),"sha256":hashlib.sha256(body).hexdigest(),"size":len(body)}
        # This is only a unit row composition fixture. No compiler was executed.
        rows = [{"invocation_id":"a"*32,"kind":"compilation","status":"success","compiler_exit":0,
                 "outputs":[{**image,"role":"unit"}]}]
        record = {"path":"owning-dimension.json","sha256":"b"*64}
        binding = {"schema":"chio.compiled-dimension-production-binding.v2","dimension":"linux",
                   "label":"control-plane-library","record":record}
        return root,source,image,rows,record,binding

    def test_actual_original_copy_and_owned_output_export_are_unqualified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,source,image,rows,record,binding = self.fixture(temporary)
            destination = root/"executed-test-image"
            receipt = profiles.capture_subject_copy(image,destination)
            self.assertEqual(destination.read_bytes(),source.read_bytes())
            self.assertEqual(receipt["source_identity"][1],source.stat().st_ino)
            self.assertEqual(receipt["destination_identity"][1],destination.stat().st_ino)
            self.assertNotEqual(receipt["source_identity"][1],receipt["destination_identity"][1])
            name = "dimension/linux/control-plane-library"
            export = profiles.export_dimension_bindings(binding,record,rows,{name:[image]},
                {name:[receipt["destination"]]},[receipt])
            self.assertEqual(export["produced_subjects"][name][0]["invocation_id"],"a"*32)
            self.assertEqual(export["compiled_closure_status"],"not-established")
            self.assertFalse(export["qualified"])

    def test_forged_failed_missing_or_unrelated_producers_never_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,source,image,rows,record,binding = self.fixture(temporary)
            name = "dimension/linux/control-plane-library"
            for mutation in ["missing","failed","null_exit","bool_exit","probe","depfile","missing_output_role","other_output","duplicate","unhashable_kind"]:
                changed = deepcopy(rows)
                if mutation == "missing":changed = []
                elif mutation == "failed":changed[0]["status"] = "compiler_failed";changed[0]["compiler_exit"] = 1
                elif mutation == "null_exit":changed[0]["compiler_exit"] = None
                elif mutation == "bool_exit":changed[0]["compiler_exit"] = False
                elif mutation == "probe":changed[0]["kind"] = "probe";changed[0]["outputs"] = []
                elif mutation == "depfile":changed[0]["outputs"][0]["role"] = "depfile"
                elif mutation == "missing_output_role":changed[0]["outputs"][0].pop("role")
                elif mutation == "other_output":changed[0]["outputs"][0]["sha256"] = "c"*64
                elif mutation == "duplicate":changed.append(deepcopy(changed[0]))
                else:changed[0]["kind"] = []
                with self.subTest(mutation=mutation):
                    with self.assertRaises(ValueError):
                        profiles.export_dimension_bindings(binding,record,changed,{name:[image]},{name:[image]},[])
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_binding$"):
                profiles.export_dimension_bindings(binding,{**record,"sha256":"c"*64},rows,{name:[image]},{name:[image]},[])

    def test_every_copy_row_is_checked_and_missing_or_cross_subject_receipts_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,source,image,rows,record,binding = self.fixture(temporary)
            receipt = profiles.capture_subject_copy(image,root/"executed-test-image")
            name = "dimension/linux/control-plane-library"
            for mutation in ["missing","extra_invalid","changed_source","changed_destination","changed_digest","bool_identity"]:
                copies = [deepcopy(receipt)]
                if mutation == "missing":copies = []
                elif mutation == "extra_invalid":copies.append(None)
                elif mutation == "changed_source":copies[0]["source"]["path"] = str(root/"unrelated-root")
                elif mutation == "changed_destination":copies[0]["destination"]["path"] = str(root/"unrelated-image")
                elif mutation == "changed_digest":copies[0]["destination_sha256"] = "c"*64
                else:copies[0]["source_identity"][0] = True
                with self.subTest(mutation=mutation):
                    with self.assertRaises(ValueError):
                        profiles.export_dimension_bindings(binding,record,rows,{name:[image]},
                            {name:[receipt["destination"]]},copies)

    def test_destination_mutation_during_copy_is_refused_and_only_own_partial_file_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,source,image,*_ = self.fixture(temporary)
            destination = root/"executed-test-image"
            original = profiles.os.write
            def corrupt(descriptor,body):
                written = original(descriptor,body)
                os.pwrite(descriptor,b"MUTATED",0)
                return written
            with patch.object(profiles.os,"write",side_effect=corrupt):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_copy_destination$"):
                    profiles.capture_subject_copy(image,destination)
            self.assertFalse(destination.exists())
            self.assertEqual(source.read_bytes(),b"PUBLIC-EXECUTABLE-COPY-CONTROL\n")

    def test_secret_shaped_copy_source_is_refused_without_opening_its_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = {"path":str(root/"credentials.toml"),"sha256":"a"*64,"size":10}
            with patch.object(profiles.os,"open",side_effect=AssertionError("secret original opened")):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_copy_policy$"):
                    profiles.capture_subject_copy(source,root/"copied-image")

    def test_actual_readonly_model_snapshot_projects_every_current_owned_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            model = root/"docs/architecture/recoverable-agent-runtime/model"
            model.mkdir(parents=True)
            captured = root/"target/model/inputs"
            captured.mkdir(parents=True)
            sources,receipts = [],[]
            for name in ["recovery.rs","review.rs","third.rs","run.py"]:
                body = ("PUBLIC-CAPTURED-MODEL-SOURCE-"+name+"\n").encode()
                original,copy = model/name,captured/name
                original.write_bytes(body);copy.write_bytes(body);copy.chmod(0o444)
                digest = hashlib.sha256(body).hexdigest()
                image = {"path":str(original),"sha256":digest,"size":len(body)}
                receipt = profiles.capture_source_projection(image,{**image,"path":str(copy)})
                self.assertEqual(receipt["source_identity"][1],original.stat().st_ino)
                sources.append({"path":str(original.relative_to(root)),"sha256":digest})
                receipts.append(receipt)
            inputs = profiles.checked_source_projections(receipts,sources,root,captured)
            self.assertEqual({item["path"] for item in inputs},{str(captured/name) for name in ["recovery.rs","review.rs","third.rs","run.py"]})
            self.assertTrue(all(item["role"] == "campaign-produced" for item in inputs))
            for changed in [receipts[:-1],[*receipts,None],[*receipts,deepcopy(receipts[0])]]:
                with self.assertRaises(ValueError):
                    profiles.checked_source_projections(changed,sources,root,captured)
            changed = deepcopy(receipts);changed[0]["source"]["path"] = str(root/"unrelated.rs")
            with self.assertRaises(ValueError):
                profiles.checked_source_projections(changed,sources,root,captured)
            (captured/"recovery.rs").chmod(0o600)
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_projection_readonly$"):
                profiles.capture_source_projection(receipts[0]["source"],receipts[0]["captured"])

    def test_secret_shaped_projection_is_refused_before_any_original_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            image = {"path":str(root/".npmrc"),"sha256":"a"*64,"size":10}
            with patch.object(profiles.os,"open",side_effect=AssertionError("secret opened")):
                with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_projection_policy$"):
                    profiles.capture_source_projection(image,{**image,"path":str(root/"captured-source")})

    def test_actual_two_name_cargo_hardlink_becomes_one_produced_inode_and_a_fresh_observed_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,source,image,*_ = self.fixture(temporary)
            alias = root/"public-cargo-alias"
            os.link(source,alias)
            self.assertEqual(source.stat().st_nlink,2)
            receipt = profiles.replace_owned_output_alias(image,{**image,"path":str(alias)},root)
            self.assertEqual(source.stat().st_nlink,1)
            self.assertEqual(alias.stat().st_nlink,1)
            self.assertNotEqual(source.stat().st_ino,alias.stat().st_ino)
            self.assertEqual(receipt["source_identity"][1],source.stat().st_ino)
            self.assertEqual(receipt["destination_identity"][1],alias.stat().st_ino)
            self.assertEqual(alias.read_bytes(),source.read_bytes())

    def test_foreign_third_link_and_outside_alias_are_refused_without_deletion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,source,image,*_ = self.fixture(temporary)
            alias,third = root/"public-cargo-alias",root/"foreign-hardlink"
            os.link(source,alias);os.link(source,third)
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_output_alias$"):
                profiles.replace_owned_output_alias(image,{**image,"path":str(alias)},root)
            self.assertTrue(alias.is_file());self.assertEqual(source.stat().st_nlink,3)
            with self.assertRaisesRegex(ValueError,"^qualification.compiled_dimension_output_alias$"):
                profiles.replace_owned_output_alias(image,{**image,"path":str(alias)},root/"bounded-child")
            self.assertTrue(alias.is_file())

    def options_fixture(self, dimension="linux", label="control-plane-library"):
        # Pure decoded producer controls. No tool from this fixture is executed.
        root = Path("/var/tmp/current-owned-dimension")
        tools = {name:{"path":str(root/path),"sha256":"d"*64,"size":10} for name,path in {
            "helper":"scripts/compiled-dimension-profiles.py","inspector":"scripts/verify-recovery-qualification.py",
            "recorder":"scripts/record-rust-compilation.py","cargo":"tools/cargo","rustc":"tools/rustc",
            "python":"tools/python3"}.items()}
        environment = {"PATH":"/usr/bin:/bin","HOME":"/nonexistent","CARGO_HOME":str(root/"target/public-cargo"),
            "TMPDIR":str(root/"target/tmp"),"CARGO_INCREMENTAL":"0","CARGO_BUILD_JOBS":"2",
            "CARGO_NET_OFFLINE":"true","CARGO_TERM_COLOR":"never","LC_ALL":"C"}
        options = {"schema":"chio.compiled-dimension-capture-options.v2","dimension":dimension,
            "source_binding":"c"*64,"mode":"host-trusted-fresh","tools":tools,"environment":environment,
            "actions":{label:{"namespace":str(root/"target/publications"),"target":str(root/"target/compiled"),
                "launch_configuration":None}},"source_origin":None,"primary_probes":None}
        contract = profiles.compilation_contract(dimension,label,root,captured_inputs=root/"target/inputs",
                                                output_root=root/"target/compiled")
        actual = [tools["cargo"]["path"],*contract["command"][1:]] if dimension != "formal" else \
            [tools["python"]["path"],"-B",tools["recorder"]["path"],tools["rustc"]["path"],*contract["command"][2:]]
        action = options["actions"][label]
        env = {**environment,**contract["environment"],"CARGO_TARGET_DIR":action["target"],
            "RUSTC":tools["rustc"]["path"],"RUSTC_WRAPPER":tools["recorder"]["path"],
            "CHIO_COMPILATION_RECORDS":action["namespace"],"CHIO_COMPILATION_SOURCE_ROOT":str(root),
            "CHIO_COMPILATION_SOURCE_BINDING":"c"*64}
        ref = {"path":"target/public-fixture.json","sha256":"a"*64,"size":10}
        producer = {"schema":"chio.compiled-dimension-command-production.v2","dimension":dimension,"label":label,
            "contract":contract,"command":actual,"environment":env,"namespace":action["namespace"],"source_binding":"c"*64,
            "runtime_inventory_before":ref,"runtime_inventory_after":ref,"tools":tools,
            "toolchain_probe":{"command":[tools["rustc"]["path"],"-Vv"],"actual_exit":0,"stdout":ref,"compiler":tools["rustc"]},
            "options":{"path":str(root/"target/options.json"),"sha256":"a"*64,"size":10},"launch_configuration":None,
            "source_origin":None,"actual_exit":0,"duration_seconds":1.0,"completed":True,"log":ref,
            "qualified":False,"compiled_closure_status":"not-established"}
        return root,options,producer

    def test_fixed_producer_options_reject_hidden_selectors_and_every_unused_wrong_action(self):
        root,options,_ = self.options_fixture()
        self.assertEqual(profiles.checked_capture_options(options,root,"linux","c"*64),options)
        for mutation in ["extra","wrapper","token","borrowed_action","foreign_tool","overlapping_target","unknown_mode","bool_size"]:
            changed = deepcopy(options)
            if mutation == "extra":changed["covered_all_compilation"] = True
            elif mutation == "wrapper":changed["environment"]["RUSTC_WRAPPER"] = "/foreign/wrapper"
            elif mutation == "token":changed["environment"]["API_TOKEN"] = "SYNTHETIC-UNUSED-CREDENTIAL"
            elif mutation == "borrowed_action":changed["actions"]["contracts"] = deepcopy(next(iter(changed["actions"].values())))
            elif mutation == "foreign_tool":changed["tools"]["helper"]["path"] = "/foreign/helper.py"
            elif mutation == "overlapping_target":changed["actions"]["control-plane-library"]["target"] = str(root/"target")
            elif mutation == "unknown_mode":changed["mode"] = []
            else:changed["tools"]["rustc"]["size"] = True
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                profiles.checked_capture_options(changed,root,"linux","c"*64)

    def test_every_owned_dimension_producer_refuses_wrong_command_failed_or_untyped_outcomes(self):
        for dimension,label,release in [("linux","control-plane-library","1.95.0"),
                ("formal","ownership","1.94.1"),("live_provider","native-host-library","1.95.0")]:
            root,options,producer = self.options_fixture(dimension,label)
            context = profiles.checked_producer_record(producer,{"source_binding":"c"*64},root,options,"release: "+release+"\n")
            self.assertEqual(context["contract"],producer["contract"])
            for mutation in ["extra","wrong_command","failed","bool_exit","missing_exit","not_complete","borrowed_contract","wrong_version","nonfinite_duration","bool_duration","extra_environment","unhashable_path"]:
                changed = deepcopy(producer);version = "release: "+release+"\n"
                if mutation == "extra":changed["compiler_verified"] = True
                elif mutation == "wrong_command":changed["command"].append("--unreviewed")
                elif mutation == "failed":changed["actual_exit"] = 1
                elif mutation == "bool_exit":changed["actual_exit"] = False
                elif mutation == "missing_exit":changed["actual_exit"] = None
                elif mutation == "not_complete":changed["completed"] = False
                elif mutation == "borrowed_contract":changed["contract"]["command"] = ["cargo","test","-p","chio-core"]
                elif mutation == "wrong_version":version = "release: 1.93.0\n"
                elif mutation == "nonfinite_duration":changed["duration_seconds"] = float("nan")
                elif mutation == "bool_duration":changed["duration_seconds"] = True
                elif mutation == "extra_environment":changed["environment"]["RUSTC_WORKSPACE_WRAPPER"] = "/foreign/wrapper"
                else:changed["log"]["path"] = []
                with self.subTest(dimension=dimension,mutation=mutation),self.assertRaises(ValueError):
                    profiles.checked_producer_record(changed,{"source_binding":"c"*64},root,options,version)

    def test_actual_owned_target_creation_never_follows_a_symbolic_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            boundary = root/"target";boundary.mkdir()
            outside = root/"outside";outside.mkdir()
            (boundary/"alias").symlink_to(outside,target_is_directory=True)
            with self.assertRaises(OSError):
                with profiles.fresh_owned_directory(boundary/"alias/new-target",boundary):pass
            self.assertEqual(list(outside.iterdir()),[])
            with profiles.fresh_owned_directory(boundary/"owned/new-target",boundary) as created:
                self.assertTrue(created.is_dir())
                self.assertEqual(created.stat().st_mode & 0o777,0o700)
            with self.assertRaises(FileExistsError):
                with profiles.fresh_owned_directory(boundary/"owned/new-target",boundary):pass


if __name__ == "__main__":
    unittest.main()
