import json,re,subprocess
from pathlib import Path
R=Path(__file__).resolve().parent
CLI='/Users/venky/.agents/skills/archify/bin/archify.mjs'
for name in ['ciso','governance','technical']:
 p=R/('ai-security-lab-'+name+'.architecture.json')
 for n in range(12):
  result=subprocess.run(['node',CLI,'validate','architecture',str(p),'--quality','showcase','--json'],capture_output=True,text=True)
  receipt=json.loads(result.stdout);(R/('ai-security-lab-'+name+'.validation.json')).write_text(json.dumps(receipt,indent=2)+'\n')
  if receipt.get('ok'):print(name,'PASS',n,'repairs',flush=True);break
  d=json.loads(p.read_text());msg=receipt.get('error','');diags=receipt.get('diagnostics',[])
  print(name,n,len(diags),[x['code'] for x in diags],flush=True)
  if 'too short' in msg and name=='governance':
   for c in d['components']:c['pos'][0]*=1.32
   d['meta']['viewBox'][0]=1460
  elif (m:=re.search(r'Label "([^"]+)" overlaps component.*?labelDy ([+-]\d+)',msg,re.S)):
   e=next(e for e in d['connections'] if e.get('label')==m[1]);e['labelDy']=e.get('labelDy',0)+int(m[2])
  else:
   diag=diags[0];e=next(e for e in d['connections'] if e['id']==diag['subject'].get('id'))
   if diag['code']=='clean-flow/endpoint-side-direction':
    field=diag['evidence']['authoredField'];e[field]='top' if field=='fromSide' else 'bottom'
   elif diag['code']=='composition/short-interior-segment':e['route']='straight'
   elif diag['code']=='composition/proper-crossing':
    e['fromSide']='bottom';e['toSide']='top'
   elif diag['code']=='composition/label-route-clearance':e['labelDy']=e.get('labelDy',0)+22
   else:raise RuntimeError(json.dumps(receipt))
  p.write_text(json.dumps(d,indent=2)+'\n')
 else:raise RuntimeError('Repair budget exceeded '+name)
