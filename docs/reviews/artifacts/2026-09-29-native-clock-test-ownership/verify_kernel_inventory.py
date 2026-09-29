from pathlib import Path
import json,re,subprocess
w=Path(__file__).parent
mapping=json.loads((w/'kernel-path-mapping.json').read_text())
old={line[:-6] for line in (w/'kernel-tests-before.txt').read_text().splitlines() if line.endswith(': test')}
b=json.loads((w/'binaries.json').read_text())
s=subprocess.check_output([b['chio_kernel'],'--list'],text=True);(w/'kernel-tests-after.txt').write_text(s)
new={line[:-6] for line in s.splitlines() if line.endswith(': test')}
def moved(name):
 if name in mapping:return mapping[name]
 for src,dst in sorted(mapping.items(),key=lambda x:len(x[0]),reverse=True):
  if src.endswith('::') and name.startswith(src):return dst+name[len(src):]
 return name
missing=sorted({moved(n) for n in old}-new);added=sorted(new-{moved(n) for n in old})
report={'before':len(old),'after':len(new),'missing':missing,'added':added}
(w/'kernel-inventory-preservation.json').write_text(json.dumps(report,indent=2)+'\n');print(report);assert not missing and added == ['kernel::tests::emergency::clock::clock_failure_during_emergency_stop_cannot_resume_execution']
selectors=set()
for name in ['scripts/check-flow-security.sh','scripts/check-response-recovery.sh','.github/workflows/chio-tee-fips.yml']:
 selectors.update(re.findall(r'kernel::tests::[A-Za-z0-9_:]+',Path(name).read_text()))
absent=sorted(s for s in selectors if not any(n==s or n.startswith(s.rstrip(':')+'::') for n in new))
pq_prefixes=('kernel::tests::boot_receipts::','kernel::tests::threshold_crypto_floor::','kernel::tests::threshold_issuance::','kernel::tests::session_reports::report_refuses_classical_signer_below_boot_floor')
pq=[s for s in absent if s.startswith(pq_prefixes)]
absent=[s for s in absent if s not in pq]
report={'live_selectors':len(selectors),'default_feature_selectors_verified':len(selectors)-len(pq),'pq_selectors_not_compiled':pq,'absent':absent};(w/'live-selectors.json').write_text(json.dumps(report,indent=2)+'\n');print(report);assert not absent
