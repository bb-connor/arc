from pathlib import Path
import re,json,hashlib
R=Path('crates/kernel/chio-kernel/src/kernel'); W=Path('.superpowers/sdd/2026-09-29-native-clock-test-ownership')
# Mask literals/comments so brace depth and item ranges are lexical Rust, not SQL/JSON.
noise=re.compile(r'//[^\n]*|/\*|(?:b|c)?r(\#*)"|(?:b|c)?"(?:[^"\\]|\\[\s\S])*"|b?\'(?:\\[\s\S]|[^\\\'])\'')
def mask(s):
 out=list(s); pos=0
 while (m:=noise.search(s,pos)):
  end=m.end()
  if m[0]=='/*':
   d=1
   while d and end<len(s):
    a=s.find('/*',end);b=s.find('*/',end)
    if b<0: end=len(s);break
    if a>=0 and a<b:d+=1;end=a+2
    else:d-=1;end=b+2
  elif m[1] is not None:
   term='"'+m[1];e=s.find(term,end);end=len(s) if e<0 else e+len(term)
  out[m.start():end]=['\n' if c=='\n' else ' ' for c in s[m.start():end]];pos=end
 return ''.join(out)
def items(s,pattern):
 m=mask(s);depth=0;ds=[]
 for c in m: ds.append(depth);depth+= (c=='{')-(c=='}')
 return [x for x in re.finditer(pattern,m,re.M) if ds[x.start()]==0]
