from pathlib import Path
import sys,re,json,hashlib,collections
sys.path.insert(0,str(Path(__file__).parent));from rust_items import mask,noise
W=Path(__file__).parent
before=json.loads((W/'kernel-source-before.json').read_text())
after={str(p):p.read_text() for p in Path('crates/kernel/chio-kernel/src/kernel/tests').rglob('*.rs')}
def tokens(s):
 m=mask(s)
 spans=[(x.start(),m.index(";",x.end())+1) for x in re.finditer(r"\buse\s",m)]
 for a,b in reversed(spans):s=s[:a]+s[b:]
 # Preserve literals exactly; discard comments and formatting outside them.
 parts=[];pos=0
 for m in noise.finditer(s):
  if m.start()<pos:continue
  parts.extend(re.findall(r'\w+|[^\w\s]',s[pos:m.start()]))
  if m[0].startswith('//'):pos=m.end();continue
  if m[0]=='/*':
   pos=s.find('*/',m.end())+2;continue
  end=m.end()
  if m[1] is not None:
   term='"'+m[1];end=s.find(term,end)+len(term)
  parts.append(s[m.start():end]);pos=end
 parts.extend(re.findall(r'\w+|[^\w\s]',s[pos:]));return parts
def tests(files):
 result=collections.Counter()
 for path,s in files.items():
  m=mask(s)
  # Attributes have no braces after masking. The declaration follows the test attribute.
  for t in re.finditer(r'#\[(?:tokio::)?test(?:\([^]]*\))?\]\s*(?:#\[[\s\S]*?\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)',s):
   start=m.index('{',t.end());i=start+1;depth=1
   while depth and i<len(m):depth+=(m[i]=='{')-(m[i]=='}');i+=1
   seq=tokens(s[start:i])
   # rustfmt may add trailing commas; separators do not affect these bodies.
   seq=[x for i,x in enumerate(seq) if not (x==',' and i+1<len(seq) and seq[i+1] in [')',']','}'])]
   digest=hashlib.sha256('\0'.join(seq).encode()).hexdigest()
   result[(t[1],digest)]+=1
 return result
b=tests(before);a=tests(after)
print('source test bodies:',sum(b.values()),'before,',sum(a.values()),'after')
missing=b-a;added=a-b
print('changed/missing:',list(missing));print('changed/added:',list(added));assert not missing and sum(added.values()) == 1 and {name for name,_ in added} == {'clock_failure_during_emergency_stop_cannot_resume_execution'}
(W/'kernel-test-body-preservation.json').write_text(json.dumps({'before':sum(b.values()),'after':sum(a.values()),'original_bodies_preserved':True,'new_regression_tests':[name for name,_ in added],'digests':[{'name':n,'sha256':h,'count':v} for (n,h),v in sorted(a.items())]},indent=2)+'\n')
