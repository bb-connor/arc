from pathlib import Path
import re,sys
sys.path.insert(0,'docs/reviews/artifacts/2026-09-29-native-clock-test-ownership')
from rust_items import mask
root=Path('crates/platform/chio-store-sqlite/src')
def span(s,name):
 m=re.search(r'\bfn '+name+r'\(',s);assert m,name
 masked=mask(s);start=masked.index('{',m.end());depth=1;i=start+1
 while depth:
  depth+=(masked[i]=='{')-(masked[i]=='}');i+=1
 return m.start(),i

def edit_fn(path,name,edit):
 p=root/path;s=p.read_text();a,b=span(s,name);old=s[a:b];new=edit(old);assert old!=new,(path,name);p.write_text(s[:a]+new+s[b:])

def reuse_hold(s):
 a=s.index('        if let Some(hold_id) = hold_id {'); b=s.index('\n\n        let current',a)
 guard=s[a:b].replace('        if let Some(hold_id)', '        let validated_hold = if let Some(hold_id)',1)
 guard=guard.replace('            SqliteBudgetStore::validate_hold_authority(', '            let next_authority = SqliteBudgetStore::validate_hold_authority(',1)
 assert guard.endswith('        }')
 guard=guard[:-9]+'''            Some((hold_id, hold, next_authority))
        } else {
            None
        };'''
 s=s[:a]+guard+s[b:]
 a=s.index('        if let Some(hold_id) = hold_id {',a+len(guard))
 release='let remaining = ExposureUnits::new(hold.remaining_exposure_units)' in s[a:]
 b=s.index('            let remaining =' if release else '            self.update_hold(',a)
 binding='hold' if release else '_'
 s=s[:a]+f'        if let Some((hold_id, {binding}, next_authority)) = validated_hold {{\n'+s[b:]
 return s
for name in ['reverse_charge_cost_with_ids_and_authority','reduce_charge_cost_with_ids_and_authority','settle_charge_cost_with_ids_and_authority']:
 edit_fn(Path('budget_store/trait_impl.rs'),name,reuse_hold)

def cache_queries(s,mapped=False):
 err='.map_err(sqlite_error)?' if mapped else '?'
 pattern=r'\.query_row\(\s*(r#"[\s\S]*?"#|"(?:[^"\\]|\\.)*"),\s*'
 s=re.sub(pattern,lambda m:'.prepare_cached('+m[1]+')'+err+'.query_row(',s)
 return s.replace('.prepare(','.prepare_cached(')
for path,names,mapped in [
 ('budget_store/store.rs',['load_hold','has_captured_hold','has_live_hold','load_mutation_event'],False),
 ('budget_store/trait_impl.rs',['get_usage','capture_invocation_reservations','reverse_charge_cost_with_ids_and_authority','reduce_charge_cost_with_ids_and_authority','settle_charge_cost_with_ids_and_authority'],False),
 ('budget_store/joint_guard.rs',['reject_structured_hold_from_legacy_writer'],False),
 ('admission_operation_store.rs',['load_by_operation_id_tx','load_by_replay_key_tx'],True),
 ('security_state/capability_set_suspension.rs',['load_binding','load_members','load_snapshot','evaluate_capability_suspension'],True),
]:
 for name in names:edit_fn(Path(path),name,lambda s:cache_queries(s,mapped))
# Capacities belong to each owning connection. Shared authority connections
# initialize the budget owner through this same function before serving.
p=root/'budget_store/store.rs';s=p.read_text();needle='''    ) -> Result<(), BudgetStoreError> {
        if !allow_provisioned {''';assert needle in s
s=s.replace(needle,'''    ) -> Result<(), BudgetStoreError> {
        // Bounded bytecode reuse for budget and shared admission lookups.
        // Rows and authorization decisions are always read in their transaction.
        connection.set_prepared_statement_cache_capacity(64);
        if !allow_provisioned {''',1);p.write_text(s)
p=root/'security_state.rs';s=p.read_text();needle='        let connection = Connection::open(path).map_err(sqlite_error)?;';assert needle in s
s=s.replace(needle,needle+'\n        // Reuse suspension lookup bytecode, never the observed authority state.\n        connection.set_prepared_statement_cache_capacity(32);',1);p.write_text(s)
print('Applied16 hot-reader conversions, explicit cache capacities and3 in-transaction hold reuses.')
