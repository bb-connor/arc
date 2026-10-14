"""Maintained host discovery regressions. Synthetic model callbacks only.

Complete original cohort promoted from the target-resident evidence programs:
original initial five, held alias positives, root/output/parent replacement,
late membership, same-inode/identical-byte artifact mutation and bootstrap
primary+secondary close controls. Fixtures are disposable public files under
the worktree evidence directory (target/), never historical paths. No actual
SDK/toolchain inventory collection or real tool subprocess ever runs here.
"""
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import types
import unittest
from unittest import mock
import uuid

MAINTAINED=Path(__file__).absolute().parents[2]
SCRIPTS=MAINTAINED/'scripts'
SOURCE=SCRIPTS/'capture-host-toolchain-metadata.py'
DEPENDENCY=SCRIPTS/'record-rust-compilation.py'
DEPENDENCY_SHA='7185939c7576e2ae0129190831b2eaf777a8c42c8d9f081dc9bf52dc1c0a7f47'
FIXTURES=MAINTAINED/'target/host-metadata-test-fixtures'

# Deny every real tool subprocess; synthetic callbacks alone supply observations.
# The single permitted exception is the exact local Python bootstrap-close fault
# process spawned by BootstrapCloseProcess, in the same interpreter mode.
_REAL_POPEN=subprocess.Popen
def _permitted_fault_process(argv):
 args=list(argv)
 return (len(args) in (4,5) and args[0]==sys.executable and args[1]=='-B'
         and args[-1]=='--bootstrap-close-fault-process'
         and Path(args[-2]).absolute()==Path(__file__).absolute()
         and args[2:-2]==([] if not sys.flags.optimize else ['-O']))
def forbidden(argv=None,*args,**kwargs):
 if argv is not None and _permitted_fault_process(argv):
  return _REAL_POPEN(argv,*args,**kwargs)
 raise RuntimeError('real subprocess forbidden')
subprocess.Popen=forbidden

def strict_profile_request(driver,sdk):
 # Satisfies the maintained CLI's non-model validate() contract exactly.
 # Paths are declared strings; validate performs no host file open. The profile
 # is the current supported one: selector and installed sysroot are 1.95.0.
 def digest(value):return hashlib.sha256(value).hexdigest()
 return {'schema':'chio.host-toolchain-discovery-request.v1','toolchain_selector':'1.95.0','host_target':'aarch64-apple-darwin',
  'images':{'rustup':{'path':'/usr/local/bin/rustup','sha256':digest(b'PUBLIC-rustup')},
            'rustc':{'path':'/Users/connor/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc','sha256':digest(b'PUBLIC-rustc')},
            'clang':{'path':driver,'sha256':digest(b'PUBLIC-clang')},
            'ld':{'path':'/usr/bin/ld','sha256':digest(b'PUBLIC-ld')},
            'xcrun':{'path':'/usr/bin/xcrun','sha256':digest(b'PUBLIC-xcrun')}},
  'roots':{'sdk':sdk,'rust-sysroot':'/Users/connor/.rustup/toolchains/1.95.0-aarch64-apple-darwin','native-runtime':['/usr/lib']},
  'aliases':[],'environment':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','DEVELOPER_DIR':'/Applications/Xcode.app/Contents/Developer'},
  'prior_discovery':None}

class DiscoveryTest(unittest.TestCase):
 def setUp(self):
  self.assertTrue(SOURCE.is_file(),'maintained metadata helper is not implemented')
  spec=importlib.util.spec_from_file_location('metadata_model_'+uuid.uuid4().hex,SOURCE)
  self.m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=self.m;spec.loader.exec_module(self.m)
  self.root=FIXTURES/uuid.uuid4().hex;self.root.mkdir(parents=True)
  self.addCleanup(shutil.rmtree,self.root,ignore_errors=True)
  images={}
  for name in ['rustup','rustc','clang','ld','xcrun']:
   p=self.root/name;p.write_bytes(b'PUBLIC-MODEL-'+name.encode());images[name]={'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
  roots={}
  for name in ['sdk','rust-sysroot','native-runtime']:
   p=self.root/(name+'-root');p.mkdir();(p/'public-input').write_bytes(b'PUBLIC-'+name.encode());roots[name]=str(p)
  self.request={'schema':'chio.host-toolchain-discovery-request.v1','toolchain_selector':'1.95.0','host_target':'aarch64-apple-darwin',
   'images':images,'roots':{'sdk':roots['sdk'],'rust-sysroot':roots['rust-sysroot'],'native-runtime':[roots['native-runtime']]},
   'aliases':[],'environment':{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','DEVELOPER_DIR':'/Applications/Xcode.app/Contents/Developer'},
   'prior_discovery':None}
  self.contract={'driver':images['clang']['path'],'sdk':roots['sdk'],'public_roots':[str(self.root)]}
 def fake(self,argv,environment,descriptor,timeout):
  return {'exit':0,'stdout':b'PUBLIC-SYNTHETIC-DISCOVERY\n','stderr':b''}
 def collect(self,runner=None):
  return self.m.collect(self.request,self.root/'result',command_runner=runner or self.fake,model_contract=self.contract)
 def test_complete_before_after_and_image_custody_are_discovery_only(self):
  result=self.collect()
  self.assertEqual(result['observation_kind'],'synthetic-model')
  self.assertEqual(len(result['probes']),10)
  self.assertEqual(result['before'],result['after'])
  self.assertEqual(result['compiler_coverage'],'not-established')
  self.assertTrue((self.root/'result/discovery.json').is_file())
 def test_changed_input_and_boolean_probe_exit_cannot_complete(self):
  def changed(argv,environment,descriptor,timeout):
   (Path(self.request['roots']['sdk'])/'public-input').write_bytes(b'PUBLIC-CHANGED')
   return self.fake(argv,environment,descriptor,timeout)
  with self.assertRaises(self.m.m.Refusal):self.collect(changed)
  self.assertFalse((self.root/'result/discovery.json').exists())
  other=self.root/'result-bool'
  with self.assertRaises(self.m.m.Refusal):self.m.collect(self.request,other,command_runner=lambda *args:{'exit':False,'stdout':b'PUBLIC','stderr':b''},model_contract=self.contract)
  self.assertFalse((other/'discovery.json').exists())
 def test_metadata_only_secret_exclusions_and_no_overwrite(self):
  secret=Path(self.request['roots']['sdk'])/'credentials.toml';secret.write_bytes(b'SYNTHETIC-EXCLUDED')
  original=self.m.m.HeldPath.read
  def read(held,*args,**kwargs):
   if held.path==secret:raise RuntimeError('excluded synthetic body opened')
   return original(held,*args,**kwargs)
  self.m.m.HeldPath.read=read
  try:result=self.collect()
  finally:self.m.m.HeldPath.read=original
  exclusions=[item for root in result['before']['roots'] for item in root['members'] if item['kind']=='excluded']
  self.assertEqual(len(exclusions),1)
  self.assertNotIn('sha256',exclusions[0])
  with self.assertRaises(self.m.m.Refusal):self.collect()
 def test_unknown_env_and_incomplete_request_refuse(self):
  self.request['environment']['DYLD_INSERT_LIBRARIES']='PUBLIC-UNDECLARED'
  with self.assertRaises(self.m.m.Refusal):self.collect()
  del self.request['environment']['DYLD_INSERT_LIBRARIES']
  self.request['images']['rustup']=None
  with self.assertRaises(self.m.m.Refusal):self.collect()
 def test_unused_declared_sdk_alias_retarget_cannot_complete(self):
  alias=self.root/'selected-sdk';sdk=Path(self.request['roots']['sdk']);alias.symlink_to(sdk.name)
  self.request['aliases']=[{'path':str(alias),'text':sdk.name,'target':str(sdk)}]
  changed=[]
  def runner(argv,environment,descriptor,timeout):
   if not changed:
    alias.rename(self.root/'original-selected-sdk');alias.symlink_to('native-runtime-root');changed.append(True)
   return self.fake(argv,environment,descriptor,timeout)
  with self.assertRaises(self.m.m.Refusal):self.collect(runner)
  self.assertTrue((self.root/'original-selected-sdk').is_symlink())
  self.assertFalse((self.root/'result/discovery.json').exists())

class RunControls(DiscoveryTest):
 def test_held_descriptor_alias_positive(self):
  actual=Path(self.request['images']['rustc']['path'])
  alias=self.root/'rustc-selected';alias.symlink_to(actual.name)
  self.request['images']['rustc']['path']=str(alias)
  self.request['aliases']=[{'path':str(alias),'text':actual.name,'target':str(actual)}]
  seen=[]
  def runner(argv,env,fd,timeout):
   expected=next(entry for entry in self.request['images'].values() if entry['path']==argv[0])
   seen.append(argv)
   self.assertEqual(hashlib.sha256(os.pread(fd,1024,0)).hexdigest(),expected['sha256'])
   return self.fake(argv,env,fd,timeout)
  result=self.collect(runner)
  self.assertEqual(len(seen),10)
  self.assertEqual(result['images']['rustc']['physical_path'],str(actual))
 def test_root_directory_replacement_refuses(self):
  sdk=Path(self.request['roots']['sdk'])
  (sdk/'public-input').rename(self.root/'retained-sdk-input')
  changed=[]
  def runner(*args):
   if not changed:
    before=sdk.stat().st_ino;sdk.rename(self.root/'original-sdk');sdk.mkdir();changed.append([before,sdk.stat().st_ino])
   return self.fake(*args)
  error=None
  try:result=self.collect(runner)
  except self.m.m.Refusal as exc:error=str(exc)
  (self.root/'observation.json').write_text(json.dumps({'replacement':changed,'error':error,'published':(self.root/'result/discovery.json').exists()}))
  self.assertIsNotNone(error,'replacement SDK root completed with no identity refusal')
 def test_output_directory_replacement_refuses(self):
  changed=[]
  def runner(*args):
   if not changed:
    output=self.root/'result';prior=self.root/'original-result';before=output.stat().st_ino
    output.rename(prior);output.mkdir();(prior/'artifacts').rename(output/'artifacts')
    changed.append([before,output.stat().st_ino])
   return self.fake(*args)
  error=None
  try:result=self.collect(runner)
  except self.m.m.Refusal as exc:error=str(exc)
  (self.root/'observation.json').write_text(json.dumps({'replacement':changed,'error':error,'published':(self.root/'result/discovery.json').exists()}))
  self.assertIsNotNone(error,'replacement output directory completed with no custody refusal')

class MembershipControl(DiscoveryTest):
 def test_final_walk_membership_addition_refuses(self):
  sdk=Path(self.request['roots']['sdk']);original=self.m.m.HeldPath.read;reads=[]
  def read(held,*a,**kw):
   data=original(held,*a,**kw)
   if held.path==sdk/'public-input':
    reads.append(True)
    if len(reads)==2:(sdk/'late-public-input').write_bytes(b'PUBLIC-LATE-MEMBER')
   return data
  self.m.m.HeldPath.read=read
  error=None;result=None
  try:
   try:result=self.collect()
   except self.m.m.Refusal as exc:error=str(exc)
  finally:self.m.m.HeldPath.read=original
  obs={'error':error,'source_reads':len(reads),'late_member_exists':(sdk/'late-public-input').exists(),'published':(self.root/'result/discovery.json').exists(),'after_paths':None if result is None else [x['path'] for x in result['after']['roots'][0]['members']]}
  (self.root/'observation.json').write_text(json.dumps(obs,indent=2)+'\n')
  self.assertEqual(len(reads),2)
  self.assertIsNotNone(error,'new public member omitted while final inventory completed')

class CustodyTest(DiscoveryTest):
 def test_empty_root_positive_records_original_terminal_identity(self):
  sdk=Path(self.request['roots']['sdk']);(sdk/'public-input').rename(self.root/'retained-input')
  result=self.collect();root=result['before']['roots'][0]
  self.assertEqual(root['root_identity'][0:2],[sdk.stat().st_dev,sdk.stat().st_ino])
  self.assertEqual(root['root_identity'],result['after']['roots'][0]['root_identity'])
 def test_output_parent_substitution_refuses(self):
  parent=self.root/'publication';parent.mkdir();changed=[]
  def runner(*args):
   if not changed:
    parent.rename(self.root/'original-publication');parent.mkdir()
    (self.root/'original-publication/result').rename(parent/'result');changed.append(True)
   return self.fake(*args)
  with self.assertRaises(self.m.m.Refusal):
   self.m.collect(self.request,parent/'result',command_runner=runner,model_contract=self.contract)
  self.assertFalse((parent/'result/discovery.json').exists())
 def test_late_input_membership_during_publication_refuses_return(self):
  publish=self.m.m.publish_file;changed=[];sdk=Path(self.request['roots']['sdk'])
  def late(directory,name,payload,*args,**kwargs):
   result=publish(directory,name,payload,*args,**kwargs)
   if name=='discovery.json':(sdk/'late-after-publication').write_bytes(b'PUBLIC-LATE');changed.append(True)
   return result
  self.m.m.publish_file=late
  try:
   with self.assertRaises(self.m.m.Refusal):self.collect()
  finally:self.m.m.publish_file=publish
  self.assertTrue(changed)
 def test_late_output_root_substitution_during_publication_refuses_return(self):
  publish=self.m.m.publish_file;changed=[]
  def late(directory,name,payload,*args,**kwargs):
   result=publish(directory,name,payload,*args,**kwargs)
   if name=='discovery.json':
    output=self.root/'result';output.rename(self.root/'original-result');output.mkdir()
    (self.root/'original-result/artifacts').rename(output/'artifacts');changed.append(True)
   return result
  self.m.m.publish_file=late
  try:
   with self.assertRaises(self.m.m.Refusal):self.collect()
  finally:self.m.m.publish_file=publish
  self.assertTrue(changed)
 def test_unenumerated_leaf_after_final_directory_iteration_refuses(self):
  sdk=Path(self.request['roots']['sdk']);read=self.m.m.HeldPath.read;seen=[]
  def changed(file,*args,**kwargs):
   body=read(file,*args,**kwargs)
   if file.path==sdk/'public-input':
    seen.append(True)
    if len(seen)==2:(sdk/'late-leaf').write_bytes(b'PUBLIC-LATE')
   return body
  self.m.m.HeldPath.read=changed
  try:
   with self.assertRaises(self.m.m.Refusal):self.collect()
  finally:self.m.m.HeldPath.read=read
  self.assertEqual(len(seen),2)

class LateArtifact(DiscoveryTest):
 def test_late_retained_body_change_refuses_successful_return(self):
  publish=self.m.m.publish_file;changed=[];expected=hashlib.sha256(b'PUBLIC-sdk').hexdigest()
  def late(directory,name,payload,*a,**kw):
   result=publish(directory,name,payload,*a,**kw)
   if name=='discovery.json':
    target=self.root/'result/artifacts'/expected
    original=target.read_bytes();(self.root/'retained-original-artifact').write_bytes(original)
    target.write_bytes(b'CHANGEDsdk');changed.append(str(target))
   return result
  self.m.m.publish_file=late;error=None;result=None
  try:
   try:result=self.collect()
   except self.m.m.Refusal as exc:error=str(exc)
  finally:self.m.m.publish_file=publish
  artifact=self.root/'result/artifacts'/expected
  observation={'mutations':len(changed),'refusal':error,'returned_success':result is not None,'physical_discovery':(self.root/'result/discovery.json').exists(),'expected_sha256':expected,'actual_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'fixture':str(self.root)}
  (self.root/'late-artifact-observation.json').write_text(json.dumps(observation,indent=2)+'\n')
  self.assertEqual(len(changed),1)
  self.assertNotEqual(observation['actual_sha256'],expected)
  self.assertIsNotNone(error,'collector returned successful discovery after retained referenced CAS bytes changed')

class ArtifactCustody(DiscoveryTest):
 def test_late_same_byte_replacement_inode_refuses_successful_return(self):
  publish=self.m.m.publish_file;changed=[];expected=hashlib.sha256(b'PUBLIC-sdk').hexdigest()
  def late(directory,name,payload,*args,**kwargs):
   result=publish(directory,name,payload,*args,**kwargs)
   if name=='discovery.json':
    target=self.root/'result/artifacts'/expected;body=target.read_bytes();previous=target.stat().st_ino
    target.rename(self.root/'retained-original-artifact');target.write_bytes(body)
    changed.append((previous,target.stat().st_ino))
   return result
  self.m.m.publish_file=late
  try:
   with self.assertRaises(self.m.m.Refusal):self.collect()
  finally:self.m.m.publish_file=publish
  self.assertEqual(len(changed),1);self.assertNotEqual(*changed[0])
  self.assertTrue((self.root/'result/discovery.json').is_file())

class DiagnosticTest(DiscoveryTest):
 def strict_profile_request(self):
  return strict_profile_request(self.m.DRIVER,self.m.SDK)
 def test_generic_io_failure_has_only_closed_numeric_phase_diagnostic(self):
  request=self.root/'request.json';request.write_text(json.dumps(self.strict_profile_request()))
  collect=self.m.collect;calls=[]
  def failed(*args,**kwargs):
   calls.append(True)
   diagnostics=kwargs.get('diagnostics')
   if diagnostics is not None:
    diagnostics.phase(7);diagnostics.probe_index=3
   raise PermissionError(errno.EACCES,'SYNTHETIC_OPAQUE_MESSAGE_DO_NOT_RETAIN','SYNTHETIC_PRIVATE_PATH_DO_NOT_RETAIN')
  self.m.collect=failed;stream=io.StringIO()
  try:
   with contextlib.redirect_stderr(stream):code=self.m.main(['--collect',str(request),'--output',str(self.root/'result')])
  finally:self.m.collect=collect
  self.assertEqual(code,86);self.assertEqual(len(calls),1)
  text=stream.getvalue();self.assertNotIn('SYNTHETIC_',text)
  prefix='host_toolchain_discovery.diagnostic='
  diagnostics=[json.loads(line[len(prefix):]) for line in text.splitlines() if line.startswith(prefix)]
  self.assertEqual(len(diagnostics),1,'generic failure has no static phase/errno diagnostic')
  value=diagnostics[0]
  self.assertEqual(set(value),{'schema','phase_id','probe_index','root_index','entries_examined','artifact_count','unique_bytes','elapsed_millis','exception_class','errno'})
  self.assertEqual((value['phase_id'],value['probe_index'],value['exception_class'],value['errno']),(7,3,'PermissionError',13))
  for key in ['phase_id','probe_index','root_index','entries_examined','artifact_count','unique_bytes','elapsed_millis']:
   self.assertIs(type(value[key]),int);self.assertGreaterEqual(value[key],0)
 def test_before_inventory_fault_reports_phase_root_and_retained_progress(self):
  tracker=self.m.Diagnostics();read=self.m.m.HeldPath.read
  leaf=Path(self.request['roots']['sdk'])/'public-input'
  def failed(held,*args,**kwargs):
   if held.path==leaf:raise OSError(errno.EMFILE,'SYNTHETIC_OPAQUE_MESSAGE',str(leaf))
   return read(held,*args,**kwargs)
  self.m.m.HeldPath.read=failed
  try:
   with self.assertRaises(OSError) as caught:
    self.m.collect(self.request,self.root/'result',command_runner=self.fake,model_contract=self.contract,diagnostics=tracker)
  finally:self.m.m.HeldPath.read=read
  value=tracker.value(caught.exception)
  self.assertEqual((value['phase_id'],value['root_index'],value['probe_index'],value['errno']),(6,1,0,24))
  self.assertEqual(value['artifact_count'],5);self.assertEqual(value['entries_examined'],1)
  self.assertGreater(value['unique_bytes'],0);self.assertFalse((self.root/'result/discovery.json').exists())
 def test_third_probe_fault_reports_actual_callback_index(self):
  tracker=self.m.Diagnostics();calls=[]
  def failed(*args):
   calls.append(True)
   if len(calls)==3:raise TimeoutError(errno.ETIMEDOUT,'SYNTHETIC_OPAQUE_MESSAGE')
   return self.fake(*args)
  with self.assertRaises(TimeoutError) as caught:
   self.m.collect(self.request,self.root/'result',command_runner=failed,model_contract=self.contract,diagnostics=tracker)
  value=tracker.value(caught.exception)
  self.assertEqual((value['phase_id'],value['root_index'],value['probe_index'],value['exception_class'],value['errno']),
                   (7,0,3,'TimeoutError',errno.ETIMEDOUT))
  self.assertEqual(len(calls),3);self.assertGreater(value['artifact_count'],5)
  self.assertFalse((self.root/'result/discovery.json').exists())
 def test_final_artifact_directory_sync_fault_has_no_discovery_completion(self):
  tracker=self.m.Diagnostics();fsync=self.m.os.fsync;faults=[]
  def failed(descriptor):
   if tracker.phase_id==11:
    faults.append(True);raise OSError(errno.EIO,'SYNTHETIC_PRIVATE_ERROR')
   return fsync(descriptor)
  self.m.os.fsync=failed
  try:
   with self.assertRaises(OSError) as caught:
    self.m.collect(self.request,self.root/'result',command_runner=self.fake,model_contract=self.contract,diagnostics=tracker)
  finally:self.m.os.fsync=fsync
  value=tracker.value(caught.exception)
  self.assertEqual((value['phase_id'],value['errno']),(11,5));self.assertEqual(len(faults),1)
  self.assertFalse((self.root/'result/discovery.json').exists());self.assertGreater(value['artifact_count'],5)
 def test_late_byte_refusal_reports_final_phase_and_preserves_physical_evidence(self):
  tracker=self.m.Diagnostics();publish=self.m.m.publish_file
  sha=self.m.hashlib.sha256(b'PUBLIC-sdk').hexdigest();changes=[]
  def late(directory,name,payload,*args,**kwargs):
   result=publish(directory,name,payload,*args,**kwargs)
   if name=='discovery.json':
    leaf=self.root/'result/artifacts'/sha;leaf.write_bytes(b'CHANGEDsdk');changes.append(True)
   return result
  self.m.m.publish_file=late
  try:
   with self.assertRaises(self.m.m.Refusal) as caught:
    self.m.collect(self.request,self.root/'result',command_runner=self.fake,model_contract=self.contract,diagnostics=tracker)
  finally:self.m.m.publish_file=publish
  value=tracker.value(caught.exception)
  self.assertEqual((value['phase_id'],value['exception_class'],value['errno']),(13,'Refusal',None))
  self.assertEqual(len(changes),1);self.assertTrue((self.root/'result/discovery.json').is_file())
 def test_unknown_exception_and_invalid_numeric_values_are_not_formatted(self):
  class SYNTHETIC_PRIVATE_CLASS(OSError):
   @property
   def errno(self):raise RuntimeError('exception property accessed')
   def __str__(self):raise RuntimeError('exception message formatted')
  tracker=self.m.Diagnostics();stream=io.StringIO()
  with contextlib.redirect_stderr(stream):tracker.emit(SYNTHETIC_PRIVATE_CLASS('SYNTHETIC_PRIVATE_VALUE'))
  value=json.loads(stream.getvalue().split('=',1)[1])
  self.assertEqual(value['exception_class'],'OtherException');self.assertIsNone(value['errno'])
  self.assertNotIn('SYNTHETIC_',stream.getvalue())
  error=OSError('SYNTHETIC_PRIVATE_VALUE')
  for invalid in [False,-1,4096,'5']:
   error.errno=invalid;self.assertIsNone(tracker.value(error)['errno'])
  tracker.phase_id=False;tracker.probe_index=11;tracker.root_index=-1
  tracker.store=type('LocalCounters',(),{'entries':False,'artifacts':{},'bytes':16*1024**3+1})()
  value=tracker.value(error)
  for key in ['phase_id','probe_index','root_index','entries_examined','unique_bytes']:self.assertIsNone(value[key])
 def test_success_is_unchanged_discovery_only_without_error_diagnostic(self):
  tracker=self.m.Diagnostics();stream=io.StringIO()
  with contextlib.redirect_stderr(stream):
   result=self.m.collect(self.request,self.root/'result',command_runner=self.fake,model_contract=self.contract,diagnostics=tracker)
  self.assertEqual(stream.getvalue(),'');self.assertEqual(tracker.phase_id,13)
  self.assertEqual(result['schema'],'chio.host-toolchain-discovery.v2')
  self.assertEqual(result['compiler_coverage'],'not-established');self.assertEqual(len(result['probes']),10)
  self.assertNotIn('diagnostic',result)
 def test_unknown_cli_exception_is_closed_and_does_not_format_message(self):
  class SYNTHETIC_PRIVATE_CLASS(Exception):
   def __str__(self):raise RuntimeError('exception message formatted')
  stream=io.StringIO();require=self.m.m.require
  def failed(*args):raise SYNTHETIC_PRIVATE_CLASS('SYNTHETIC_PRIVATE_VALUE')
  self.m.m.require=failed
  try:
   with contextlib.redirect_stderr(stream):code=self.m.main(['SYNTHETIC_PRIVATE_ARGV'])
  finally:self.m.m.require=require
  self.assertEqual(code,86);lines=stream.getvalue().splitlines()
  self.assertEqual(lines[0],'host_toolchain_discovery.io_or_format')
  value=json.loads(lines[1].split('=',1)[1])
  self.assertEqual((value['phase_id'],value['exception_class'],value['errno']),(1,'OtherException',None))
  self.assertNotIn('SYNTHETIC_',stream.getvalue());self.assertEqual(len(lines),2)
 def test_dependency_compile_failure_has_closed_bootstrap_diagnostic(self):
  source=SOURCE.read_text()
  invalid=b'SYNTHETIC_OPAQUE_DEPENDENCY_SOURCE ::'
  old="DEPENDENCY_SHA='"+DEPENDENCY_SHA+"'"
  self.assertEqual(source.count(old),1)
  # Only a synthetic source-read callback and expected synthetic digest are
  # substituted. This exercises error handling, never dependency authority.
  source=source.replace(old,"DEPENDENCY_SHA='"+hashlib.sha256(invalid).hexdigest()+"'")
  read=self.m.os.read;stream=io.StringIO();module=types.ModuleType('bootstrap_public_model')
  module.__file__=str(SOURCE)
  self.m.os.read=lambda descriptor,count:invalid
  try:
   with contextlib.redirect_stderr(stream):
    with self.assertRaises(SystemExit) as caught:exec(compile(source,module.__file__,'exec'),module.__dict__)
  finally:self.m.os.read=read
  self.assertEqual(caught.exception.code,86)
  lines=stream.getvalue().splitlines();self.assertEqual(len(lines),2)
  self.assertEqual(lines[0],'host_toolchain_discovery.io_or_format')
  value=json.loads(lines[1].split('=',1)[1])
  self.assertEqual((value['phase_id'],value['exception_class'],value['errno']),(0,'OtherException',None))
  self.assertNotIn('SYNTHETIC_',stream.getvalue());self.assertNotIn(str(SCRIPTS),stream.getvalue())

def bootstrap_close_fault_process():
 # Exact original extra real-Python fault process: the real dependency FD is
 # opened, really closed once, then a synthetic EIO is raised at that close.
 # The collector's guarded bootstrap projects it as the closed phase0 record
 # and SystemExit(86); the uncaught SystemExit is the actual process exit.
 spec=importlib.util.spec_from_file_location('bootstrap_fault_process_model',SOURCE)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 FIXTURES.mkdir(parents=True,exist_ok=True)
 request=FIXTURES/('bootstrap-close-process-request-'+uuid.uuid4().hex+'.json')
 request.write_text(json.dumps(strict_profile_request(module.DRIVER,module.SDK)))
 actual_open=os.open;actual_close=os.close;target=[]
 def opening(path,*a,**k):
  fd=actual_open(path,*a,**k)
  if Path(path)==DEPENDENCY:target.append(fd)
  return fd
 def closing(fd):
  actual_close(fd)
  if fd in target:raise OSError(errno.EIO,'SYNTHETIC_OPAQUE_CLOSE_DETAIL','SYNTHETIC_PRIVATE_CLOSE_FILENAME')
 sys.argv=[str(SOURCE),'--validate-request',str(request)]
 with mock.patch.object(os,'open',opening),mock.patch.object(os,'close',closing):
  exec(compile(SOURCE.read_bytes(),str(SOURCE),'exec'),{'__file__':str(SOURCE),'__name__':'__main__'})
 return 0

class BootstrapCloseProcess(unittest.TestCase):
 def test_bootstrap_close_fault_process_exit86_closed_diagnostics(self):
  flags=['-O'] if sys.flags.optimize else []
  argv=[sys.executable,'-B',*flags,str(Path(__file__).absolute()),'--bootstrap-close-fault-process']
  started=time.monotonic();completed=subprocess.run(argv,capture_output=True,timeout=60)
  elapsed=time.monotonic()-started;text=completed.stderr.decode()
  FIXTURES.mkdir(parents=True,exist_ok=True)
  record={'argv':argv,'interpreter_optimization':sys.flags.optimize,'exit':completed.returncode,
   'stdout':completed.stdout.decode(),'stderr':text,'elapsed_seconds':elapsed,
   'collector_source':{'path':str(SOURCE),'sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest()},
   'test_source':{'path':str(Path(__file__).absolute()),'sha256':hashlib.sha256(Path(__file__).absolute().read_bytes()).hexdigest()},
   'dependency_sha256':hashlib.sha256(DEPENDENCY.read_bytes()).hexdigest()}
  (FIXTURES/('bootstrap-close-process-'+('optimized' if sys.flags.optimize else 'normal')+'.execution.json')).write_text(json.dumps(record,indent=2)+'\n')
  self.assertEqual(completed.returncode,86,'fault process did not exit 86')
  self.assertEqual(completed.stdout,b'')
  lines=text.splitlines();self.assertEqual(len(lines),2)
  self.assertEqual(lines[0],'host_toolchain_discovery.io_or_format')
  value=json.loads(lines[1].split('=',1)[1])
  self.assertEqual((value['phase_id'],value['errno']),(0,5))
  self.assertNotIn('SYNTHETIC_',text);self.assertNotIn(str(SCRIPTS),text);self.assertNotIn('Traceback',text)

class SelectedCwdControl(DiscoveryTest):
 def test_ambient_cwd_change_cannot_change_selected_execution_cwd(self):
  elsewhere=self.root/'ambient-elsewhere';elsewhere.mkdir()
  previous=os.getcwd();os.chdir(elsewhere)
  try:
   result=self.collect();ambient=os.getcwd()
   self.assertEqual(ambient,str(elsewhere),'ambient cwd did not actually change during collection')
   self.assertNotEqual(str(elsewhere),str(self.m.ROOT))
   self.assertEqual({probe['cwd'] for probe in result['probes']},{str(self.m.ROOT)})
   for probe in result['probes']:
    self.assertEqual(probe['cwd'],str(self.m.ROOT))
    self.assertTrue(os.path.isabs(probe['cwd']) and 'cwd' in probe)
   self.assertEqual(len(result['probes']),10)
   self.assertTrue((self.root/'result/discovery.json').is_file())
   # Exercise the actual_probe implementation itself through a fake Popen
   # boundary: no real tool process is created, but the pipe read ends are
   # real local descriptors, so selector draining and wait run for real.
   observed=[]
   def fake_popen(argv,*args,**kwargs):
    read_end,write_end=os.pipe();os.write(write_end,b'PUBLIC-SYNTHETIC-DISCOVERY\n');os.close(write_end)
    error_read,error_write=os.pipe();os.close(error_write)
    observed.append((list(argv),kwargs.get('cwd')))
    class stream:
     def __init__(self,fd):self.fd=fd
     def fileno(self):return self.fd
     def close(self):os.close(self.fd)
    class process:
     pid=4242;stdout=stream(read_end);stderr=stream(error_read)
     @staticmethod
     def poll():return 0
     @staticmethod
     def wait(timeout=None):return 0
    return process()
   image=os.open(self.root/'rustc',os.O_RDONLY)
   real_popen=self.m.subprocess.Popen
   self.m.subprocess.Popen=fake_popen
   try:
    with self.m.m.HeldPath(self.m.ROOT,directory=True) as held_directory:
     for probe in result['probes']:
      outcome=self.m.actual_probe(probe['argv'],self.request['environment'],image,30,held_directory)
      self.assertEqual(outcome,{'exit':0,'stdout':b'PUBLIC-SYNTHETIC-DISCOVERY\n','stderr':b''})
   finally:
    self.m.subprocess.Popen=real_popen;os.close(image)
   self.assertEqual(len(observed),10)
   for (argv,cwd),probe in zip(observed,result['probes']):
    self.assertEqual(argv,probe['argv'])
    self.assertEqual(cwd,probe['cwd'])
    self.assertEqual(cwd,str(self.m.ROOT))
  finally:os.chdir(previous)

class BootstrapClose(unittest.TestCase):
 def test_bootstrap_close_io_failure_retains_safe_phase_zero_and_exit86(self):
  actual_open=os.open;actual_close=os.close;target=[];closed=[];stream=io.StringIO();caught=None
  def opened(path,*args,**kwargs):
   fd=actual_open(path,*args,**kwargs)
   if Path(path)==DEPENDENCY:target.append(fd)
   return fd
  def closing(fd):
   actual_close(fd)
   if fd in target:
    closed.append(fd)
    raise OSError(errno.EIO,'SYNTHETIC_OPAQUE_CLOSE_DETAIL','SYNTHETIC_PRIVATE_CLOSE_FILENAME')
  module=types.ModuleType('actual_bootstrap_close_model');module.__file__=str(SOURCE)
  with mock.patch.object(os,'open',opened),mock.patch.object(os,'close',closing),contextlib.redirect_stderr(stream):
   try:exec(compile(SOURCE.read_bytes(),str(SOURCE),'exec'),module.__dict__)
   except BaseException as error:caught=error
  text=stream.getvalue();lines=text.splitlines()
  observation={'dependency_fds_opened':len(target),'dependency_fds_actually_closed':len(closed),'exception_type':None if caught is None else type(caught).__name__,'exit_code':caught.code if type(caught) is SystemExit else None,'stderr':text,'raw_marker_in_stderr':'SYNTHETIC_' in text,'source_override':False,'fault':'real ordinary Python dependency descriptor closed, then synthetic OSError EIO raised at that cleanup call'}
  (FIXTURES/('bootstrap-close-observation-'+uuid.uuid4().hex+'.json')).write_text(json.dumps(observation,indent=2)+'\n')
  self.assertEqual(len(target),1);self.assertEqual(len(closed),1)
  self.assertEqual(observation['exit_code'],86,'bootstrap close failure escaped the safe diagnostic handler')
  self.assertEqual(len(lines),2)
  self.assertEqual(lines[0],'host_toolchain_discovery.io_or_format')
  diagnostic=json.loads(lines[1].split('=',1)[1]);self.assertEqual((diagnostic['phase_id'],diagnostic['errno']),(0,5))
  self.assertFalse(observation['raw_marker_in_stderr'])

class CleanupTest(unittest.TestCase):
 def run_bootstrap(self,read_error=None,close_error=None,open_error=None,invalid_source=False):
  actual_open=os.open;actual_read=os.read;actual_close=os.close;opened=[];closed=[];stream=io.StringIO();caught=None
  source=SOURCE.read_text();invalid=b'SYNTHETIC_OPAQUE_BAD_SOURCE ::'
  if invalid_source:
   old="DEPENDENCY_SHA='"+DEPENDENCY_SHA+"'"
   self.assertEqual(source.count(old),1)
   source=source.replace(old,"DEPENDENCY_SHA='"+hashlib.sha256(invalid).hexdigest()+"'")
  def opening(path,*a,**k):
   if Path(path)==DEPENDENCY and open_error is not None:raise open_error
   fd=actual_open(path,*a,**k)
   if Path(path)==DEPENDENCY:opened.append(fd)
   return fd
  def reading(fd,count):
   if fd in opened:
    if read_error is not None:raise read_error
    if invalid_source:return invalid
   return actual_read(fd,count)
  def closing(fd):
   actual_close(fd)
   if fd in opened:
    closed.append(fd)
    if close_error is not None:raise close_error
  module=types.ModuleType('local_bootstrap_cleanup');module.__file__=str(SOURCE)
  with mock.patch.object(os,'open',opening),mock.patch.object(os,'read',reading),mock.patch.object(os,'close',closing),contextlib.redirect_stderr(stream):
   try:exec(compile(source,str(SOURCE),'exec'),module.__dict__)
   except BaseException as error:caught=error
  self.assertNotIn('SYNTHETIC_',stream.getvalue());self.assertNotIn(str(SCRIPTS),stream.getvalue())
  return module,caught,stream.getvalue(),opened,closed
 def diagnostic(self,error,text):
  self.assertIs(type(error),SystemExit);self.assertEqual(error.code,86)
  lines=text.splitlines();self.assertEqual(len(lines),2);self.assertEqual(lines[0],'host_toolchain_discovery.io_or_format')
  value=json.loads(lines[1].split('=',1)[1]);self.assertEqual(value['phase_id'],0)
  return value
 def test_read_failure_wins_over_cleanup_failure_with_one_close(self):
  _,error,text,opened,closed=self.run_bootstrap(read_error=PermissionError(13,'SYNTHETIC_READ'),close_error=OSError(5,'SYNTHETIC_CLOSE'))
  value=self.diagnostic(error,text);self.assertEqual((value['exception_class'],value['errno']),('PermissionError',13))
  self.assertEqual(len(opened),1);self.assertEqual(closed,opened)
 def test_synthetic_compile_failure_wins_over_cleanup_failure(self):
  _,error,text,opened,closed=self.run_bootstrap(invalid_source=True,close_error=OSError(5,'SYNTHETIC_CLOSE'))
  value=self.diagnostic(error,text);self.assertEqual((value['exception_class'],value['errno']),('OtherException',None))
  self.assertEqual(len(opened),1);self.assertEqual(closed,opened)
 def test_failed_open_does_not_close_an_unowned_descriptor(self):
  _,error,text,opened,closed=self.run_bootstrap(open_error=FileNotFoundError(2,'SYNTHETIC_OPEN','SYNTHETIC_FILENAME'))
  value=self.diagnostic(error,text);self.assertEqual((value['exception_class'],value['errno']),('FileNotFoundError',2))
  self.assertEqual(opened,[]);self.assertEqual(closed,[])
 def test_successful_bootstrap_has_one_real_close_and_no_error_diagnostic(self):
  module,error,text,opened,closed=self.run_bootstrap()
  self.assertIsNone(error);self.assertEqual(text,'');self.assertEqual(len(opened),1);self.assertEqual(closed,opened)
  self.assertTrue(callable(module.collect));self.assertEqual(module.PROBE_SECONDS,30);self.assertEqual(module.TOTAL_SECONDS,900)

CONTROL_CLASSES=(DiscoveryTest,RunControls,MembershipControl,CustodyTest,LateArtifact,ArtifactCustody,
 DiagnosticTest,BootstrapClose,BootstrapCloseProcess,SelectedCwdControl,CleanupTest)

def load_tests(loader,tests,pattern):
 # Select each distinct control exactly once: subclass-inherited fixtures are
 # not re-run, so the suite count is the distinct method count per mode.
 suite=unittest.TestSuite()
 for cls in CONTROL_CLASSES:
  for name,member in sorted(cls.__dict__.items()):
   if name.startswith('test_') and callable(member):suite.addTest(cls(name))
 return suite

if __name__=='__main__':
 if len(sys.argv)==2 and sys.argv[1]=='--bootstrap-close-fault-process':
  bootstrap_close_fault_process()
 else:
  unittest.main(verbosity=2)
