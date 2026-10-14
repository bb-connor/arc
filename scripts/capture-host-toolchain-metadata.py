#!/usr/bin/env python3
"""Bounded public host discovery only. No compilation or producer authority."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import stat
import subprocess
import sys
import time
import types

class Diagnostics:
 """Closed static phases and numeric progress. Never format exception text."""
 def __init__(self):
  self.phase_id=0;self.probe_index=0;self.root_index=0;self.store=None;self.started=time.monotonic()
 def phase(self,value):
  if type(value) is not int or not 0<=value<=13:raise ValueError('diagnostic_phase')
  self.phase_id=value
 def value(self,error):
  names={OSError:'OSError',PermissionError:'PermissionError',FileNotFoundError:'FileNotFoundError',
    NotADirectoryError:'NotADirectoryError',IsADirectoryError:'IsADirectoryError',TimeoutError:'TimeoutError',
    BlockingIOError:'BlockingIOError',InterruptedError:'InterruptedError',BrokenPipeError:'BrokenPipeError',
    ValueError:'ValueError',TypeError:'TypeError',KeyError:'KeyError',RuntimeError:'RuntimeError',MemoryError:'MemoryError',
    UnicodeError:'UnicodeError',UnicodeDecodeError:'UnicodeDecodeError',UnicodeEncodeError:'UnicodeEncodeError',
    UnicodeTranslateError:'UnicodeTranslateError'}
  kind=names.get(type(error),'OtherException')
  if 'm' in globals() and type(error) is m.__dict__.get('Refusal'):kind='Refusal'
  number=error.errno if type(error) in names and isinstance(error,OSError) else None
  if type(number) is not int or not 0<=number<=4095:number=None
  def bounded(value,maximum):return value if type(value) is int and 0<=value<=maximum else None
  entries=0 if self.store is None else self.store.entries
  artifacts=0 if self.store is None else len(self.store.artifacts)
  size=0 if self.store is None else self.store.bytes
  elapsed=int(max(0,time.monotonic()-self.started)*1000)
  return {'schema':'chio.host-toolchain-diagnostic.v1','phase_id':bounded(self.phase_id,13),
    'probe_index':bounded(self.probe_index,10),'root_index':bounded(self.root_index,34),
    'entries_examined':bounded(entries,200000),'artifact_count':bounded(artifacts,100000),
    'unique_bytes':bounded(size,16*1024*1024*1024),'elapsed_millis':bounded(elapsed,2**63-1),
    'exception_class':kind,'errno':number}
 def emit(self,error):
  print('host_toolchain_discovery.diagnostic='+json.dumps(self.value(error),sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)

ROOT=Path(__file__).absolute().parents[1]
DEPENDENCY=ROOT/'scripts/record-rust-compilation.py'
DEPENDENCY_SHA='7185939c7576e2ae0129190831b2eaf777a8c42c8d9f081dc9bf52dc1c0a7f47'
bootstrap_diagnostics=Diagnostics();descriptor=None;bootstrap_error=None
try:
 descriptor=os.open(DEPENDENCY,os.O_RDONLY|os.O_NOFOLLOW)
 source=os.read(descriptor,512*1024)
 if hashlib.sha256(source).hexdigest()!=DEPENDENCY_SHA:
  raise RuntimeError('discovery_dependency_image_mismatch')
 m=types.ModuleType('held_discovery_dependency');m.__file__=str(DEPENDENCY)
 exec(compile(source,str(DEPENDENCY),'exec'),m.__dict__)
except Exception as error:
 bootstrap_error=error
finally:
 if descriptor is not None:
  # Close once. Cleanup failure is projected through the same closed handler,
  # and cannot replace an earlier read/hash/compile refusal.
  try:os.close(descriptor)
  except Exception as error:
   if bootstrap_error is None:bootstrap_error=error
if bootstrap_error is not None:
 print('host_toolchain_discovery.io_or_format',file=sys.stderr)
 bootstrap_diagnostics.emit(bootstrap_error);raise SystemExit(86) from None

DRIVER='/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang'
SDK='/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk'
PUBLIC_ROOTS=['/Applications/Xcode.app','/usr/lib','/System/Library']
MAX_ENTRIES=200000
MAX_UNIQUE_BYTES=16*1024*1024*1024
MAX_ARTIFACTS=100000
TOTAL_SECONDS=900
PROBE_SECONDS=30

def strict_path(value):
 m.require(type(value) is str and os.path.isabs(value),'discovery_absolute_path')
 path=m.absolute(value)
 m.require(str(path)==value,'discovery_path_syntax')
 return path

def validate(request,model_contract=None):
 fields={'schema','toolchain_selector','host_target','images','roots','aliases','environment','prior_discovery'}
 m.require(type(request) is dict and set(request)==fields and request['schema']=='chio.host-toolchain-discovery-request.v1'
           and request['toolchain_selector']=='1.95.0' and request['host_target'] in {'aarch64-apple-darwin','x86_64-apple-darwin'},'discovery_request')
 images=request['images']
 m.require(type(images) is dict and set(images)=={'rustup','rustc','clang','ld','xcrun'},'discovery_images')
 for image in images.values():
  m.require(type(image) is dict and set(image)=={'path','sha256'} and type(image['sha256']) is str
            and m.DIGEST.fullmatch(image['sha256']),'discovery_image_metadata_required')
  strict_path(image['path'])
 contract={'driver':DRIVER,'sdk':SDK,'public_roots':PUBLIC_ROOTS} if model_contract is None else model_contract
 roots=request['roots']
 m.require(type(roots) is dict and set(roots)=={'sdk','rust-sysroot','native-runtime'} and images['clang']['path']==contract['driver']
           and roots['sdk']==contract['sdk'],'discovery_declared_profile')
 for role in ['sdk','rust-sysroot']:strict_path(roots[role])
 m.require(type(roots['native-runtime']) is list and 1<=len(roots['native-runtime'])<=32,'discovery_runtime_metadata_required')
 permitted=[Path(root) for root in contract['public_roots']]+[strict_path(roots['rust-sysroot'])]
 for root in roots['native-runtime']:
  path=strict_path(root)
  m.require(any(path.is_relative_to(parent) for parent in permitted) and (model_contract is not None or not path.is_relative_to(ROOT)),'discovery_public_runtime_root')
 if model_contract is None:
  m.require(Path(images['rustc']['path']).parent.parent==Path(roots['rust-sysroot'])
            and Path(roots['rust-sysroot']).name=='1.95.0-'+request['host_target'],'discovery_rust_sysroot')
 aliases=request['aliases']
 m.require(type(aliases) is list and len(aliases)<=128,'discovery_aliases')
 for alias in aliases:
  m.require(type(alias) is dict and set(alias)=={'path','text','target'},'discovery_alias')
  path,target=strict_path(alias['path']),strict_path(alias['target'])
  m.require(type(alias['text']) is str and m.absolute(alias['text'],path.parent)==target,'discovery_alias')
 m.require(len({alias['path'] for alias in aliases})==len(aliases),'discovery_alias')
 environment=request['environment']
 allowed={'PATH','HOME','RUSTUP_HOME','CARGO_HOME','LANG','LC_ALL','DEVELOPER_DIR'}
 m.require(type(environment) is dict and set(environment)<=allowed and all(type(value) is str and '\x00' not in value
            and '\n' not in value and not m.SECRET_WORD.search(value) for value in environment.values())
            and environment.get('PATH')=='/usr/bin:/bin' and environment.get('DEVELOPER_DIR')=='/Applications/Xcode.app/Contents/Developer',
            'discovery_environment')
 for name in ['HOME','RUSTUP_HOME','CARGO_HOME']:
  if name in environment:strict_path(environment[name])
 prior=request['prior_discovery']
 m.require(prior is None or type(prior) is dict and set(prior)=={'path','sha256'} and type(prior['path']) is str
           and type(prior['sha256']) is str and m.DIGEST.fullmatch(prior['sha256']),'discovery_prior_reference')
 return request

def probe_catalog(request):
 paths={name:entry['path'] for name,entry in request['images'].items()}
 return [('selector-resolution','rustup',[paths['rustup'],'which','--toolchain',request['toolchain_selector'],'rustc']),
         ('rustup-version','rustup',[paths['rustup'],'--version']),
         ('rustc-version','rustc',[paths['rustc'],'-vV']),
         ('rustc-sysroot','rustc',[paths['rustc'],'--print','sysroot']),
         ('selected-ld','xcrun',[paths['xcrun'],'--find','ld']),
         ('clang-version','clang',[paths['clang'],'--version']),
         ('selected-sdk','xcrun',[paths['xcrun'],'--show-sdk-path']),
         ('sdk-version','xcrun',[paths['xcrun'],'--show-sdk-version']),
         ('ld-version','ld',[paths['ld'],'-v']),
         ('clang-resource-directory','clang',[paths['clang'],'-print-resource-dir'])]

def actual_probe(argv,environment,descriptor,timeout,directory):
 # The executable is the still-held regular image. argv[0] stays the declared
 # logical command name. Discovery makes no default-linker or compilation claim.
 # Actual execution runs in the explicitly selected held working directory;
 # ambient process cwd is never inherited.
 process=subprocess.Popen(argv,executable='/dev/fd/'+str(descriptor),env=environment,
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True,
   pass_fds=(descriptor,),start_new_session=True,cwd=str(directory.path))
 streams={'stdout':bytearray(),'stderr':bytearray()};deadline=time.monotonic()+timeout
 try:
  with selectors.DefaultSelector() as selector:
   for name,stream in [('stdout',process.stdout),('stderr',process.stderr)]:
    os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
   while selector.get_map():
    remaining=deadline-time.monotonic();m.require(remaining>0,'discovery_probe_timeout')
    for key,_ in selector.select(min(remaining,0.25)):
     payload=os.read(key.fd,65536)
     if not payload:selector.unregister(key.fileobj);continue
     m.require(len(streams[key.data])+len(payload)<=m.MAX_JSON,'discovery_probe_output_limit')
     streams[key.data].extend(payload)
  remaining=deadline-time.monotonic();m.require(remaining>0,'discovery_probe_timeout')
  code=process.wait(timeout=remaining)
  return {'exit':code,**{name:bytes(body) for name,body in streams.items()}}
 finally:
  if process.poll() is None:
   os.killpg(process.pid,signal.SIGKILL);process.wait()
  process.stdout.close();process.stderr.close()

class Store:
 def __init__(self,output,parent,directory,artifacts,custody,diagnostics):
  self.output=output;self.parent=parent;self.directory=directory;self.artifact_directory=artifacts
  self.custody=custody;self.root_bindings=[];self.directory_guards={};self.diagnostics=diagnostics;diagnostics.store=self
  self.bytes=0;self.artifacts={};self.artifact_identities={};self.entries=0;self.started=time.monotonic()
 def verify_output(self):
  # Output membership legitimately changes, but the original directory chain
  # and its mode remain authoritative until the caller receives completion.
  for held in [self.parent,self.directory,self.artifact_directory]:
   held.verify(content=False)
   m.require(m.identity(os.fstat(held.fd))[:3]==held.initial[:3],'discovery_output_identity_changed')
 def verify_artifact_membership(self):
  self.verify_output()
  m.require(sorted(os.listdir(self.artifact_directory.fd))==sorted(self.artifacts),'discovery_artifact_membership_changed')
 def bind_roots(self,request):
  roots=[('sdk',request['roots']['sdk']),('rust-sysroot',request['roots']['rust-sysroot'])]
  roots += [('native-runtime',root) for root in request['roots']['native-runtime']]
  for role,logical in roots:
   hops=[];root=m.declared_component_path(logical,Path('/'),{'aliases':request['aliases']},hops=hops)
   permitted=[Path(path) for path in PUBLIC_ROOTS]+[Path(request['roots']['rust-sysroot'])]
   m.require(not root.is_relative_to(ROOT) or self.model,'discovery_project_cache_root')
   m.require(self.model or any(root.is_relative_to(parent) for parent in permitted),'discovery_public_physical_root')
   m.require(not (self.output.is_relative_to(root) or root.is_relative_to(self.output)),'discovery_output_overlap')
   held=self.custody.enter_context(m.HeldPath(root,directory=True))
   self.root_bindings.append((role,logical,root,hops,held))
 def verify_inputs(self,complete=False):
  for _,_,_,_,held in self.root_bindings:held.verify()
  if complete:
   for path,(expected,names) in self.directory_guards.items():
    with m.HeldPath(path,directory=True) as held:
     m.require(m.identity(os.fstat(held.fd))==expected and sorted(os.listdir(held.fd))==names,
               'discovery_directory_changed')
     held.verify()
   for _,_,_,_,held in self.root_bindings:held.verify()
 def bound(self):
  m.require(time.monotonic()-self.started<TOTAL_SECONDS,'discovery_deadline')
 def artifact_bytes(self,sha,expected):
  # Reopen one leaf at a time through the original held directory. The original
  # publication identity remains bound even when identical bytes are replaced.
  self.bound();self.verify_output()
  before=os.stat(sha,dir_fd=self.artifact_directory.fd,follow_symlinks=False)
  m.require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and m.identity(before)==expected,
            'discovery_artifact_identity_changed')
  descriptor=os.open(sha,os.O_RDONLY|m.NOFOLLOW,dir_fd=self.artifact_directory.fd)
  try:
   m.require(m.identity(os.fstat(descriptor))==expected,'discovery_artifact_identity_changed')
   m.require(expected[3]<=m.MAX_INPUT,'discovery_payload_limit')
   chunks=[];total=0
   while True:
    self.bound();part=os.read(descriptor,min(1024*1024,m.MAX_INPUT+1-total))
    if not part:break
    total+=len(part);m.require(total<=m.MAX_INPUT,'discovery_payload_limit');chunks.append(part)
   body=b''.join(chunks)
   m.require(total==expected[3] and hashlib.sha256(body).hexdigest()==sha,'discovery_artifact_changed')
   m.require(m.identity(os.fstat(descriptor))==expected and
             m.identity(os.stat(sha,dir_fd=self.artifact_directory.fd,follow_symlinks=False))==expected,
             'discovery_artifact_identity_changed')
   self.verify_output();return body
  finally:os.close(descriptor)
 def verify_artifact_bytes(self):
  self.verify_artifact_membership()
  m.require(set(self.artifact_identities)==set(self.artifacts),'discovery_artifact_binding')
  for sha,size in self.artifacts.items():
   body=self.artifact_bytes(sha,self.artifact_identities[sha])
   m.require(len(body)==size,'discovery_artifact_changed')
  self.verify_artifact_membership()
 def put(self,payload):
  self.bound();self.verify_output();self.verify_inputs();m.require(type(payload) is bytes and len(payload)<=m.MAX_INPUT,'discovery_payload_limit')
  sha=hashlib.sha256(payload).hexdigest()
  if sha not in self.artifacts:
   m.require(len(self.artifacts)<MAX_ARTIFACTS and self.bytes+len(payload)<=MAX_UNIQUE_BYTES,'discovery_quota')
   temporary='.pending-'+m.uuid.uuid4().hex
   with m.HeldPath(self.artifact_directory.path/temporary,create=True) as staged:
    m.publish_held(self.artifact_directory,sha,payload,staged,synchronize=False)
    expected=m.identity(os.fstat(staged.fd))
    m.require(self.artifact_bytes(sha,expected)==payload,'discovery_artifact_changed')
   self.bytes+=len(payload);self.artifacts[sha]=len(payload);self.artifact_identities[sha]=expected
  else:
   m.require(self.artifact_bytes(sha,self.artifact_identities[sha])==payload,'discovery_artifact_changed')
  self.verify_output();self.verify_inputs()
  return {'artifact':'artifacts/'+sha,'sha256':sha,'size':len(payload)}
 def snapshot(self,request):
  self.verify_inputs(complete=True);result=[]
  for root_index,(role,logical,root,hops,root_held) in enumerate(self.root_bindings,1):
   self.diagnostics.root_index=root_index
   members=[]
   def walk(directory):
    self.bound()
    with m.HeldPath(directory,directory=True) as held:
     names=sorted(os.listdir(held.fd));initial=m.identity(os.fstat(held.fd))
     for name in names:
      self.entries+=1;m.require(self.entries<=MAX_ENTRIES,'discovery_entry_limit')
      path=directory/name;value=os.stat(name,dir_fd=held.fd,follow_symlinks=False)
      entry={'path':str(path.relative_to(root)),'identity':list(m.identity(value))}
      if m.secret_path(path):entry.update(kind='excluded',reason='secret-path-policy')
      elif stat.S_ISDIR(value.st_mode):entry['kind']='directory';walk(path)
      elif stat.S_ISREG(value.st_mode):
       with m.HeldPath(path) as file:entry.update(kind='regular',**self.put(file.read()))
      elif stat.S_ISLNK(value.st_mode):
       text=os.readlink(name,dir_fd=held.fd)
       m.require(m.identity(value)==m.identity(os.stat(name,dir_fd=held.fd,follow_symlinks=False)),'discovery_alias_changed')
       entry.update(kind='link',text=text,target_binding='not-established')
      else:raise m.Refusal('discovery_special_input')
      members.append(entry)
     m.require(initial==m.identity(os.fstat(held.fd)) and names==sorted(os.listdir(held.fd)),
               'discovery_directory_changed');held.verify()
     prior=self.directory_guards.get(directory)
     m.require(prior is None or prior==(initial,names),'discovery_directory_changed')
     self.directory_guards[directory]=(initial,names)
   walk(root)
   result.append({'role':role,'logical_root':logical,'physical_root':str(root),'origin':'public-system-or-toolchain-distribution',
                  'root_hops':hops,'root_identity':list(root_held.initial),'members':sorted(members,key=lambda item:item['path'])})
  self.verify_inputs(complete=True)
  return {'schema':'chio.host-toolchain-input-inventory.v2','roots':result}

def collect(request,output,command_runner=None,model_contract=None,diagnostics=None):
 diagnostics=Diagnostics() if diagnostics is None else diagnostics
 m.require(type(diagnostics) is Diagnostics,'discovery_diagnostics');diagnostics.phase(2)
 validate(request,model_contract)
 m.require((platform.system()=='Darwin') if command_runner is None and model_contract is None else True,'discovery_darwin_required')
 m.require((command_runner is None)==(model_contract is None),'discovery_model_boundary')
 output=strict_path(str(output))
 m.require(output.is_relative_to(ROOT/'target') and output!=ROOT/'target','discovery_output_namespace')
 roots=[strict_path(request['roots'][key]) for key in ['sdk','rust-sysroot']]+[strict_path(root) for root in request['roots']['native-runtime']]
 m.require(not any(output.is_relative_to(root) or root.is_relative_to(output) for root in roots),'discovery_output_overlap')
 diagnostics.phase(3)
 runner=actual_probe if command_runner is None else command_runner
 with contextlib.ExitStack() as custody:
  # Actual probe execution uses an explicitly selected held working directory:
  # the verified repository root, bound and validated like every other
  # custody descriptor. Ambient process cwd is never consulted or inherited.
  execution=custody.enter_context(m.HeldPath(ROOT,directory=True))
  if command_runner is None:
   runner=lambda argv,environment,descriptor,timeout: actual_probe(argv,environment,descriptor,timeout,execution)
  parent=custody.enter_context(m.HeldPath(output.parent,directory=True))
  try:os.mkdir(output.name,0o700,dir_fd=parent.fd)
  except FileExistsError:raise m.Refusal('discovery_output_exists') from None
  parent.verify(content=False)
  directory=custody.enter_context(m.HeldPath(output,directory=True))
  artifacts=custody.enter_context(m.mkdir(directory,'artifacts'))
  store=Store(output,parent,directory,artifacts,custody,diagnostics);store.model=command_runner is not None
  store.verify_output();store.bind_roots(request)
  diagnostics.phase(4)
  alias_originals=m.linux_alias_bindings({'aliases':request['aliases']})
  diagnostics.phase(5)
  images={};held_images={}
  for name,expected in request['images'].items():
   physical=m.declared_path(expected['path'],{'aliases':request['aliases']})
   m.require(command_runner is not None or not physical.is_relative_to(ROOT),'discovery_project_cache_image')
   held=custody.enter_context(m.HeldPath(physical));held_images[name]=held
   body=held.read();m.require(hashlib.sha256(body).hexdigest()==expected['sha256'],'discovery_image_changed')
   images[name]={'logical_path':expected['path'],'physical_path':str(physical),'identity':list(held.initial),**store.put(body)}
  diagnostics.phase(6)
  before=store.snapshot(request);before_image=store.put(m.canonical(before));probes=[]
  diagnostics.phase(7);diagnostics.root_index=0
  for probe_index,(identifier,image_name,argv) in enumerate(probe_catalog(request),1):
   diagnostics.probe_index=probe_index
   store.bound();held=held_images[image_name];held.verify();execution.verify();started=time.monotonic()
   timeout=min(PROBE_SECONDS,TOTAL_SECONDS-(started-store.started));m.require(timeout>0,'discovery_deadline')
   result=runner(argv,request['environment'],held.fd,timeout)
   m.require(type(result) is dict and set(result)=={'exit','stdout','stderr'} and type(result['exit']) is int
             and type(result['stdout']) is bytes and type(result['stderr']) is bytes,'discovery_probe_observation')
   probes.append({'id':identifier,'argv':argv,'argv_sha256':m.digest(argv),'cwd':str(execution.path),'image':images[image_name],
     'execution_method':'held-fd-executable-discovery-only','environment_sha256':m.digest(request['environment']),
     'exit':result['exit'],'stdout':store.put(result['stdout']),'stderr':store.put(result['stderr']),
     'elapsed_seconds':time.monotonic()-started})
   held.verify();m.require(result['exit']==0,'discovery_probe_failed')
   if command_runner is None:
    # Discovery projections are exact path/host joins, not compilation or cfg
    # registration. No lexical normalization or implicit alias lookup is used.
    text=result['stdout'].decode('utf-8',errors='strict').strip()
    if identifier in {'selector-resolution','rustc-sysroot','selected-ld','selected-sdk'}:
     expected={'selector-resolution':request['images']['rustc']['path'],'rustc-sysroot':request['roots']['rust-sysroot'],
               'selected-ld':request['images']['ld']['path'],'selected-sdk':request['roots']['sdk']}[identifier]
     strict_path(text)
     m.require(m.declared_path(text,{'aliases':request['aliases']})==m.declared_path(expected,{'aliases':request['aliases']}),
               'discovery_probe_projection')
    if identifier=='rustc-version':
     m.require(text.startswith('rustc '+request['toolchain_selector']+' ') and '\nhost: '+request['host_target']+'\n' in '\n'+text+'\n',
               'discovery_probe_projection')
  diagnostics.phase(8);diagnostics.probe_index=0
  after=store.snapshot(request);after_image=store.put(m.canonical(after))
  m.require(m.canonical(before)==m.canonical(after),'discovery_scope_changed')
  diagnostics.phase(9);diagnostics.root_index=0
  for name,held in held_images.items():
   held.verify();m.require(hashlib.sha256(held.read()).hexdigest()==images[name]['sha256'],'discovery_image_changed')
  m.verify_linux_aliases({'aliases':request['aliases']},alias_originals)
  diagnostics.phase(10)
  # Recheck original CAS leaf identities and bytes before physical completion.
  store.verify_artifact_bytes()
  result={'schema':'chio.host-toolchain-discovery.v2','observation_kind':'host-discovery' if command_runner is None else 'synthetic-model',
    'request_sha256':m.digest(request),'platform':{'system':platform.system(),'machine':platform.machine()},
    'collector_dependency_sha256':DEPENDENCY_SHA,'images':images,'probes':probes,'before':before,'after':after,
    'declared_alias_observations':alias_originals,
    'before_inventory':before_image,'after_inventory':after_image,'compiler_coverage':'not-established',
    'alias_target_coverage':'not-established-for-inventory-link-members','unique_bytes':store.bytes,
    'artifact_count':len(store.artifacts),'entries_examined':store.entries,'elapsed_seconds':time.monotonic()-store.started}
  store.verify_inputs(complete=True);store.verify_artifact_membership();store.bound()
  diagnostics.phase(11)
  os.fsync(store.artifact_directory.fd)
  diagnostics.phase(12)
  m.publish_file(store.directory,'discovery.json',m.canonical(result)+b'\n')
  diagnostics.phase(13)
  # A late failure may leave physical evidence. It never grants successful
  # completion or compilation authority, and is not represented as rollback.
  store.verify_inputs(complete=True);store.verify_artifact_membership();store.bound()
  for held in held_images.values():held.verify()
  execution.verify()
  m.verify_linux_aliases({'aliases':request['aliases']},alias_originals)
  store.verify_artifact_bytes()
  store.verify_inputs(complete=True);store.verify_output();store.bound()
  return result

def main(argv):
 diagnostics=Diagnostics()
 try:
  diagnostics.phase(1)
  m.require(len(argv) in {2,4} and argv[0] in {'--validate-request','--collect'},'discovery_cli')
  path=strict_path(argv[1])
  with m.HeldPath(path) as held:
   body=held.read(m.MAX_JSON);request=json.loads(body);diagnostics.phase(2);validate(request)
   if argv[0]=='--validate-request':
    m.require(len(argv)==2,'discovery_cli');print(json.dumps({'request_sha256':hashlib.sha256(body).hexdigest(),'probes':probe_catalog(request)}));return 0
   m.require(len(argv)==4 and argv[2]=='--output','discovery_cli')
   result=collect(request,strict_path(argv[3]),diagnostics=diagnostics);held.verify()
   print(json.dumps({'discovery_sha256':m.digest(result),'compiler_coverage':'not-established'}));return 0
 except Exception as error:
  print('host_toolchain_discovery.io_or_format',file=sys.stderr)
  diagnostics.emit(error);return 86

if __name__=='__main__':raise SystemExit(main(sys.argv[1:]))
