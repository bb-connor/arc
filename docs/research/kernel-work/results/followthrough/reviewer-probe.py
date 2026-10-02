from pathlib import Path
root=Path("/tmp/chio-verifiable-work-paper")
modules={}
for name,relative in [("follow","docs/research/kernel-work/verify_followthrough.py"),("prior","labs/kernel-work-composition/verify.py")]:
 p=root/relative
 ns={"__file__":str(p),"__name__":"review_only_probe"}
 exec(compile(p.read_text(),str(p),"exec"),ns)
 modules[name]=ns
path=root/"docs/research/kernel-work/results/model/explorer.stdout"
original=Path.read_bytes
reads=[]
def altered_read(p):
 if p.absolute()==path:
  reads.append(str(p)); return b'{"violations":1,"divergences":0}\n'
 return original(p)
Path.read_bytes=altered_read
print("Probe: simulate changed prior-model explorer.stdout via read-only overlay")
try:
 modules["follow"]["check"]()
 print("AGGREGATE: ACCEPTED; changed prior artifact reads:",len(reads))
 try:
  modules["prior"]["check"]()
 except Exception as error:
  print("PRIOR: REJECTED:",type(error).__name__,str(error))
 else:
  print("PRIOR: ACCEPTED")
finally:
 Path.read_bytes=original
print("No checkout files changed by probe.")
