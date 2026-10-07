import json,copy
from pathlib import Path
root=Path('spec/schemas/chio-wire/v1/recovery'); base='https://chio.computer/schemas/chio-wire/v1/recovery/'
old=json.loads((root/'action-intent.schema.json').read_text())['$defs']
defs={k:copy.deepcopy(old[k]) for k in ['opaqueId','recoveryDigest32','safeInteger','scope']}
r=lambda x:{'$ref':'#/$defs/'+x}
obj=lambda p:{'type':'object','additionalProperties':False,'required':list(p),'properties':p}
arr=lambda i,n,minimum=0:{'type':'array','items':i,'minItems':minimum,'maxItems':n}
en=lambda *v:{'type':'string','enum':list(v)}
text=lambda n:{'type':'string','minLength':1,'maxLength':n,'x-utf8-max-bytes':n}
id=r('opaqueId'); d=r('recoveryDigest32'); integer=r('safeInteger'); boolean={'type':'boolean'}; ver={'const':1}; scope=r('scope')
label={'$ref':json.loads(Path('spec/schemas/chio-wire/v1/security/information-label.schema.json').read_text())['$id']}
fields=arr(id,16); digests=arr(d,16); interval={'issued_at_unix_ms':integer,'valid_until_unix_ms':integer}
kind=en('support_read','issue_write','field_projection'); output=en('return_value','withhold'); prereqkind=en('historical_fact','current_predicate','held_reservation')
defs['semanticValue']={'oneOf':[obj({'kind':{'const':k},'value':v}) for k,v in [('text',text(4096)),('integer',integer),('boolean',boolean)]]}
defs['semanticField']=obj({'field':id,'value':r('semanticValue')})
defs['semanticSelector']={'oneOf':[obj({'kind':{'const':'present'},'field':id}),obj({'kind':{'const':'equals'},'field':id,'value':r('semanticValue')}),obj({'kind':{'const':'text_bytes_at_most'},'field':id,'bytes':integer})]}
defs['semanticChannel']=obj({'channel':en('input','success','error','no_value','nested','batch','pagination','redirect','stream','file','log','shell','model'),'enabled':boolean})
defs['semanticNativeSource']=obj({'key':d,'generation':integer,'principal_label':label,'lineage_label':label,'session_label':label})
defs['semanticInputVersion']=obj({'resource':id,'version':d,'content':d})
defs['semanticPrerequisiteRequirement']=obj({'fact':id,'kind':prereqkind,'resource':id})
defs['semanticOperation']=obj({'operation':id,'kind':kind,'input_schema':d,'output_schema':d,'implementation':d,'channels':arr(r('semanticChannel'),13,1),'input_fields':fields,'selectors':arr(r('semanticSelector'),16),'required_assertions':arr(id,8),'prerequisites':arr(r('semanticPrerequisiteRequirement'),8),'projection_fields':arr(id,8),'source_label':label,'external_influence':boolean})
defs['semanticDestination']=obj({'destination':id,'provider':id,'account':id,'resource':id,'endpoint':text(2048),'audience':label,'purpose':text(256),'subject_mapping':d,'acl_query':d,'require_provider_precondition':boolean})
defs['semanticAnnotator']=obj({'key':d,'facts':arr(id,8),'may_attest_facts':boolean})
defs['semanticOverride']=obj({'selector_index':integer,'reason':text(512),'fixture_digests':arr(d,8,1)})
defs['semanticRoute']=obj({'server':text(128),'tool':text(128),'package':d,'operation':id,'implementation':d,'input_schema':d,'output_schema':d,'destinations':arr(r('semanticDestination'),16,1),'operator_selectors':arr(r('semanticSelector'),16),'reviewed_overrides':arr(r('semanticOverride'),16),'resolver_key':d,'endorsement_key':d,'prerequisite_key':d,'transformation_key':d,'annotators':arr(r('semanticAnnotator'),16)})
defs['semanticPlanInput']={'oneOf':[obj({'kind':{'const':'exact'},'resource':id,'version':d,'material':d}),obj({'kind':{'const':'future_output'},'step':id})]}
defs['semanticPlanStep']=obj({'step':id,'operation':id,'destination':id,'dependencies':arr(id,8),'inputs':arr(r('semanticPlanInput'),16,1),'output':output})
contracts={
'semantic-package':obj({'domain_version':ver,'package':id,'dependencies':digests,'operations':arr(r('semanticOperation'),16,1)}),
'semantic-deployment':obj({'domain_version':ver,'scope':scope,'generation':{'type':'integer','minimum':1,'maximum':9007199254740991},'native_binding':d,'context_binding':d,'exposure_binding':d,'packages':arr(d,16,1),'routes':arr(r('semanticRoute'),16,1)}),
'semantic-action':obj({'domain_version':ver,'scope':scope,'registry':d,'generation':integer,'operation':id,'destination':id,'request_id':id,'request_namespace':d,'capability':d,'request_semantics':d,'payload':d,'inputs':arr(r('semanticInputVersion'),16,1),'source_label':label,'native_source':r('semanticNativeSource'),'influence':d,'externally_influenced':boolean,'plan':d,'step':id,'output':output,**interval}),
'semantic-payload':obj({'fields':arr(r('semanticField'),16,1)}),
'semantic-plan':obj({'domain_version':ver,'scope':scope,'registry':d,'steps':arr(r('semanticPlanStep'),16,1)}),
'semantic-audience':obj({'domain_version':ver,'scope':scope,'provider':id,'account':id,'resource':id,'audience':label,'subject_mapping':d,'query':d,'provider_version':text(128),'completeness':en('complete','partial','ambiguous','outage','rate_limited'),'pagination':obj({'pages_observed':integer,'pages_expected':integer,'cursor':en('complete','pending')}),'observed_at_unix_ms':integer,'valid_until_unix_ms':integer}),
'scoped-endorsement':obj({'domain_version':ver,'evidence':id,'scope':scope,'target':{'oneOf':[obj({'kind':{'const':'exact_action'},'action':d}),obj({'kind':{'const':'persistent_artifact'},'artifact':d})]},'influence':d,'assertions':arr(id,8,1),'destination':id,'purpose':text(256),**interval}),
'semantic-annotation':obj({'domain_version':ver,'scope':scope,'input':r('semanticInputVersion'),'restrictions':label,'externally_influenced':boolean,'facts':arr(id,8),'confidence_basis_points':{'type':'integer','minimum':0,'maximum':10000},**interval}),
'semantic-transformation':obj({'domain_version':ver,'scope':scope,'producer':id,'producer_action':d,'inputs':arr(r('semanticInputVersion'),16,1),'implementation':d,'configuration':d,'output_schema':d,'output':d,'output_label':label,'influence':d,'destination':id,'purpose':text(256),'disposition':output,**interval}),
'semantic-prerequisite':obj({'domain_version':ver,'evidence':id,'scope':scope,'action':d,'fact':id,'kind':prereqkind,'resource':id,'version':d,'material':d,'producer':id,'lease':{'oneOf':[id,{'type':'null'}]},'purpose':text(256),**interval}),
}
signedprops=json.loads((root/'signed-explanation-report.schema.json').read_text())['properties']
for body in ['semantic-package','semantic-deployment','semantic-audience','scoped-endorsement','semantic-annotation','semantic-transformation','semantic-prerequisite']:
 props=copy.deepcopy(signedprops);props['body']={'$ref':body+'.schema.json'}
 contracts['signed-'+body]=obj(props)
ref=lambda x:{'$ref':x+'.schema.json'}
contracts['semantic-invocation']=obj({'schema':{'const':'chio.semantic.invocation.v1'},'action':ref('semantic-action'),'payload':ref('semantic-payload'),'audience':ref('signed-semantic-audience'),'endorsements':arr(ref('signed-scoped-endorsement'),8),'annotations':arr(ref('signed-semantic-annotation'),8),'transformation':{'oneOf':[ref('signed-semantic-transformation'),{'type':'null'}]},'prerequisites':arr(ref('signed-semantic-prerequisite'),8)})
contracts['semantic-provider-request']=obj({'domain_version':ver,'kind':kind,'provider':id,'account':id,'resource':id,'provider_version':text(128),'operation':id,'attempt':text(128),'payload':ref('semantic-payload')})
contracts['semantic-provider-response']=obj({'provider':id,'account':id,'resource':id,'checked_provider_version':text(128),'operation':id,'attempt':text(128),'payload':ref('semantic-payload')})
def used_defs(shape):
 needed=set()
 def walk(value):
  if isinstance(value,dict):
   for key,v in value.items():
    if key=='$ref' and isinstance(v,str) and v.startswith('#/$defs/'):
     name=v.removeprefix('#/$defs/')
     if name not in needed:
      needed.add(name);walk(defs[name])
    else:walk(v)
  elif isinstance(value,list):
   for v in value:walk(v)
 walk(shape)
 return {key:defs[key] for key in sorted(needed)}
for name,shape in contracts.items():
 doc={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':base+name+'.schema.json','title':name.replace('-',' ').title()+' V1',**shape,'$defs':used_defs(shape)}
 (root/(name+'.schema.json')).write_text(json.dumps(doc,indent=2)+'\n')
regpath=Path('spec/schemas/registry.json');reg=json.loads(regpath.read_text())
for name in contracts:
 entry={'schema':'chio.'+name.replace('-','.')+'.v1','artifactKind':name.replace('-','_'),'version':1,'schemaFile':str(root/(name+'.schema.json')),'introducedBy':'recovery-runtime-p3'}
 if name.startswith('signed-'):entry['payloadSchemaFile']=str(root/(name.removeprefix('signed-')+'.schema.json'))
 if not any(e['schema']==entry['schema'] for e in reg['artifacts']):reg['artifacts'].append(entry)
regpath.write_text(json.dumps(reg,indent=2)+'\n')
print(f'Wrote {len(contracts)} closed P3 schemas with local catalog references')
