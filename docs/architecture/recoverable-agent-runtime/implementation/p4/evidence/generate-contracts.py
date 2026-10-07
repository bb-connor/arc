#!/usr/bin/env python3
"""Generate the closed P4 catalog from the authored portable contract fields."""
import copy
import json
from pathlib import Path
root=Path('spec/schemas/chio-wire/v1/recovery'); base='https://chio.computer/schemas/chio-wire/v1/recovery/'
old=json.loads((root/'action-intent.schema.json').read_text())['$defs']
defs={key:copy.deepcopy(old[key]) for key in ['opaqueId','recoveryDigest32','safeInteger','scope']}
r=lambda name:{'$ref':'#/$defs/'+name}
obj=lambda fields:{'type':'object','additionalProperties':False,'required':list(fields),'properties':fields}
arr=lambda item,n,minimum=0:{'type':'array','items':item,'minItems':minimum,'maxItems':n}
en=lambda *values:{'type':'string','enum':list(values)}
text=lambda n:{'type':'string','minLength':1,'maxLength':n,'x-utf8-max-bytes':n}
id=r('opaqueId');d=r('recoveryDigest32');integer=r('safeInteger');boolean={'type':'boolean'};ver={'const':1};scope=r('scope')
label={'$ref':json.loads(Path('spec/schemas/chio-wire/v1/security/information-label.schema.json').read_text())['$id']}
ref=lambda name:{'$ref':name+'.schema.json'}
defs['artifactReference']=obj({'scope':scope,'artifact':id,'version':id,'provenance':d})
defs['artifactInfluence']=obj({'commitment':d,'externally_influenced':boolean,'unknown':boolean})
defs['artifactProducer']={'oneOf':[obj({'kind':{'const':name},**fields}) for name,fields in [
 ('native_operation',{'operation':id}),('checkpoint',{'checkpoint':id}),('derivation',{'operation':id}),('adoption',{'evidence':id}),('import',{'manifest':d,'origin':r('artifactReference')})]]}
defs['modelContext']=obj({'context':id,'provider':id,'account':id,'conversation':text(128),'cache':text(128),'side_files':arr(r('artifactReference'),8),'contract':d})
defs['artifactSink']={'oneOf':[obj({'kind':{'const':'agent'}}),obj({'kind':{'const':'model'},'context':r('modelContext')}),obj({'kind':{'const':'archive'}})]}
defs['artifactRecipient']=obj({'recipient':id,'scope':scope,'runtime':text(128),'principal':text(256),'lineage':id,'isolation_epoch':text(128),'context_generation':integer,'clearance':label,'sink':r('artifactSink')})
contracts={
'artifact-reference':r('artifactReference'),
'artifact-influence':r('artifactInfluence'),
'artifact-producer':r('artifactProducer'),
'model-context':r('modelContext'),
'artifact-recipient':r('artifactRecipient'),
'artifact-handle':obj({'handle':id,'recipient':id}),
'artifact-version':obj({'domain_version':ver,'scope':scope,'artifact':id,'version':id,'content':d,'size_bytes':{'type':'integer','minimum':0,'maximum':1048576},'media_type':text(128),'schema':d,'producer':r('artifactProducer'),
 'dependencies':arr(r('artifactReference'),16),'label':label,'influence':r('artifactInfluence'),'lineage':id,'isolation_epoch':text(128),'evidence':arr(id,8),'policy':d,'contract':d,'creation_sequence':{'type':'integer','minimum':1,'maximum':9007199254740991},'retention':en('ephemeral','checkpoint','evidence')}),
'artifact-certificate':obj({'domain_version':ver,'evidence':id,'scope':scope,'kind':en('classification','projection'),'artifact':id,'version':id,'producer':r('artifactProducer'),'content':d,'size_bytes':{'type':'integer','minimum':0,'maximum':1048576},'schema':d,
 'dependencies':arr(r('artifactReference'),16),'implementation':d,'configuration':d,'output_label':label,'influence':r('artifactInfluence'),'issued_at_unix_ms':integer,'valid_until_unix_ms':integer}),
'artifact-archive-manifest':obj({'domain_version':ver,'scope':scope,'root':r('artifactReference'),'versions':arr(ref('artifact-version'),16,1),'total_bytes':{'type':'integer','minimum':0,'maximum':1048576}}),
'labeled-checkpoint':obj({'domain_version':ver,'checkpoint':id,'revision':{'type':'integer','minimum':1,'maximum':9007199254740991},'scope':scope,'runtime':text(128),'artifacts':arr(r('artifactReference'),8,1),'model_contexts':arr(r('modelContext'),8),'label':label,'influence':r('artifactInfluence'),'lineage':id,'isolation_epoch':text(128),'native_evidence_sequence':{'type':'integer','minimum':1,'maximum':9007199254740991},'policy':d}),
'artifact-release-intent':obj({'domain_version':ver,'release':id,'kind':{'oneOf':[obj({'kind':{'const':'captured_output'},'operation':id}),obj({'kind':{'const':'independently_admitted'},'request':id})]},'artifact':r('artifactReference'),'source_label':label,'admitted_label':label,'influence':r('artifactInfluence'),
 'recipient':r('artifactRecipient'),'policy':d,'authorization':d,'observation_transition':id,'observation_generation':integer,'state':en('admitted','uncertain','delivered')}),
}
signedprops=json.loads((root/'signed-explanation-report.schema.json').read_text())['properties']
for body in ['artifact-certificate','artifact-archive-manifest']:
 props=copy.deepcopy(signedprops);props['body']=ref(body);contracts['signed-'+body]=obj(props)
def used_defs(shape):
 needed=set()
 def walk(value):
  if isinstance(value,dict):
   for key,item in value.items():
    if key=='$ref' and isinstance(item,str) and item.startswith('#/$defs/'):
     name=item.removeprefix('#/$defs/')
     if name not in needed:needed.add(name);walk(defs[name])
    else:walk(item)
  elif isinstance(value,list):
   for item in value:walk(item)
 walk(shape);return {key:defs[key] for key in sorted(needed)}
for name,shape in contracts.items():
 if shape.get('$ref','').startswith('#/$defs/'):
  shape=copy.deepcopy(defs[shape['$ref'].removeprefix('#/$defs/')])
 document={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':base+name+'.schema.json','title':name.replace('-',' ').title()+' V1',**shape,'$defs':used_defs(shape)}
 (root/(name+'.schema.json')).write_text(json.dumps(document,indent=2)+'\n')
registry_path=Path('spec/schemas/registry.json');registry=json.loads(registry_path.read_text())
for name in contracts:
 entry={'schema':'chio.'+name.replace('-','.')+'.v1','artifactKind':name.replace('-','_'),'version':1,'schemaFile':str(root/(name+'.schema.json')),'introducedBy':'recovery-runtime-p4'}
 if name.startswith('signed-'):entry['payloadSchemaFile']=str(root/(name.removeprefix('signed-')+'.schema.json'))
 if not any(old['schema']==entry['schema'] for old in registry['artifacts']):registry['artifacts'].append(entry)
registry_path.write_text(json.dumps(registry,indent=2)+'\n')
print(f'Wrote {len(contracts)} closed P4 schemas with local catalog references')
