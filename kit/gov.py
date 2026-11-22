#!/usr/bin/env python3
"""Loyalty governance local proposals. No approval/signing code is exposed by MCP."""
import argparse,csv,datetime,hashlib,json,os,pathlib,re,subprocess,sys,tempfile
class Denied(Exception): pass
def fail(code): raise Denied(code)
def canon(x): return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()
def digest(x): return hashlib.sha256(x).hexdigest()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def load(p): return json.loads(p.read_text(encoding='utf-8'))
def save(p,x,exclusive=False):
 p.parent.mkdir(parents=True,exist_ok=True)
 if exclusive:
  try:
   with p.open('x',encoding='utf-8',newline='\n') as f: f.write(canon(x).decode()+'\n')
  except FileExistsError: fail('LOCKED_BY_OTHER')
 else:
  with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',newline='\n',dir=p.parent,delete=False) as f: f.write(canon(x).decode()+'\n'); n=f.name
  os.replace(n,p)
def closed(x,required,optional=()):
 if not isinstance(x,dict) or set(x)-set(required)-set(optional) or set(required)-set(x): fail('NOT_ALLOWED')
def git(root,*args,check=True):
 p=subprocess.run(['git','-C',str(root),*args],capture_output=True)
 if check and p.returncode: fail('GIT_ERROR: '+p.stderr.decode(errors='replace')[:300])
 return p
class Gov:
 def __init__(self,root,trust=None,role='executor'):
  self.root=pathlib.Path(root).resolve(); self.g=self.root/'governance'; self.tasks={x['id']:x for x in load(self.g/'backlog.yaml')};self.policy=load(self.g/'policy.json');self.identity=load(self.g/'identities.yaml');self.role=role;self.trust=trust
 def task(self,i):
  if i not in self.tasks: fail('UNKNOWN_TASK')
  return self.tasks[i]
 def head(self): return git(self.root,'rev-parse','HEAD').stdout.decode().strip()
 def safe(self,path):
  if not isinstance(path,str) or pathlib.Path(path).is_absolute() or '..' in pathlib.Path(path).parts or path.startswith('.git'): fail('EVIDENCE_INVALID')
  p=self.root/path
  if not p.resolve().is_relative_to(self.root) or any(x.is_symlink() for x in [p,*p.parents] if x!=self.root and x.is_relative_to(self.root)): fail('EVIDENCE_INVALID')
  return p
 def file_at(self,commit,path): return git(self.root,'show',commit+':'+path).stdout
 def fingerprint(self,role):
  return (self.trust or {}).get(role,{}).get('fingerprint')
 def signed(self,tag,role):
  fp=self.fingerprint(role)
  if not fp or not re.fullmatch(r'[0-9A-Fa-f]{40,64}',fp): return None
  v=git(self.root,'verify-tag','--raw',tag,check=False)
  if v.returncode or not any(fp.upper() in line.split()[2:] for line in v.stderr.decode(errors='replace').upper().splitlines() if line.startswith('[GNUPG:] VALIDSIG ')): return None
  o=git(self.root,'cat-file','tag',tag,check=False)
  if o.returncode:return None
  try:
   raw=o.stdout.decode(); payload=json.loads(raw.split('\n\n',1)[1].split('-----BEGIN PGP SIGNATURE-----',1)[0]); sha=git(self.root,'rev-parse',tag+'^{commit}').stdout.decode().strip()
   if payload['commit_sha']!=sha or git(self.root,'merge-base','--is-ancestor',sha,self.head(),check=False).returncode:return None
   return payload
  except (ValueError,KeyError,Denied):return None
 def tag_for(self,i):
  t=self.task(i);return ('gate/'+t['gate'] if t['kind']=='gate' else 'task/'+i)+'/accepted'
 def evpath(self,i):return self.g/'evidence'/self.task(i)['gate']/(i+'.json')
 def validate(self,e,commit=None):
  errors=[]
  try:
   closed(e,['tarefa','gate','commit_sha','ambiente','testes','artefatos','produzido_por','criado_em','chave_idempotencia'],['substitui']); t=self.task(e['tarefa']); closed(e['produzido_por'],['sessao','ferramenta','modelo'])
   if e['gate']!=t['gate'] or e['ambiente'] not in ('local','homologacao','producao') or not re.fullmatch('[0-9a-f]{40}',e['commit_sha']): fail('EVIDENCE_INVALID')
   if not e['artefatos'] or not isinstance(e['testes'],list): fail('EVIDENCE_INVALID')
   ids=[]
   for a in e['artefatos']:
    closed(a,['caminho','sha256','bytes']); p=self.safe(a['caminho']); raw=self.file_at(commit,a['caminho']) if commit else p.read_bytes(); original=self.file_at(e['commit_sha'],a['caminho'])
    if len(raw)!=a['bytes'] or digest(raw)!=a['sha256'] or digest(original)!=a['sha256']: errors.append('HASH_MISMATCH:'+a['caminho'])
   for test in e['testes']:
    closed(test,['id','nome','resultado','registro_sha256']);ids.append(test['id'])
    if test['resultado']!='passou':errors.append('TEST_FAILED:'+test['id'])
    if test['registro_sha256'] not in [a['sha256'] for a in e['artefatos']]:errors.append('EVIDENCE_INVALID: test log')
   if not set(t['required_tests']).issubset(ids):errors.append('EVIDENCE_INVALID: missing required tests')
   if e['chave_idempotencia']!=digest(canon([e['tarefa'],e['artefatos']])):errors.append('EVIDENCE_INVALID: idempotency')
  except (Denied,KeyError,ValueError,TypeError,OSError) as ex:errors.append('EVIDENCE_INVALID:'+str(ex))
  return errors
 def accepted(self,i):
  p=self.signed(self.tag_for(i),'verifier')
  if not p or p.get('decision')!='accepted' or p.get('id')!=i:return False
  try:
   index=p['evidence_index'];
   if not index or digest(canon(index))!=p['index_sha256']:return False
   for taskid,h in index.items():
    path=self.evpath(taskid).relative_to(self.root).as_posix(); raw=self.file_at(p['commit_sha'],path)
    if digest(raw)!=h or digest(self.file_at(self.head(),path))!=h or self.validate(json.loads(raw),p['commit_sha']):return False
    if not self.evpath(taskid).exists() or digest(self.evpath(taskid).read_bytes())!=h:return False
    if self.validate(json.loads(raw)):return False
   return True
  except (Denied,OSError,ValueError,KeyError,TypeError):return False
 def p0(self,i,gate=False):
  t=self.task(i);out=[]
  for f in csv.DictReader((self.g/'findings.csv').read_text(encoding='utf-8-sig').splitlines()):
   if f['severidade']!='P0' or not f['status'].startswith('aberto'):continue
   ids=self.policy['p0_remediation'].get(f['id'],[])
   if ids and all(self.accepted(x) for x in ids):continue
   if gate or (f['id'] in t.get('achados_relacionados','') and i not in self.policy['p0_bootstrap_allowed']):out.append(f['id'])
  return out
 def deps(self,i):return [{'id':d,'accepted':self.accepted(d)} for d in self.task(i)['dependencies']]
 def claim(self,i):return self.g/'claims'/(i+'.json')
 def status(self,i):
  if self.accepted(i):return 'aceita'
  if self.task(i).get('deferred'):return 'adiada'
  if (self.g/'blocks'/(i+'.json')).exists():return 'bloqueada'
  if self.evpath(i).exists():
   try:
    h=self.head();base=self.tag_for(i).removesuffix('/accepted')
    if self.signed(base+'/rejected/'+h,'verifier'):return 'rejeitada'
    if self.signed('review/'+i+'/'+h,'reviewer'):return 'em_revisao'
   except Denied:pass
   return 'evidencia_enviada'
  if self.claim(i).exists():return 'em_execucao'
  return 'a_fazer'
 def ready(self,i):return self.status(i)=='a_fazer' and not self.p0(i) and all(x['accepted'] for x in self.deps(i)) and self.task(i)['kind']=='task'
 def report(self,gate):
  ts=[x for x in self.tasks.values() if x['gate']==gate];
  if not ts:fail('UNKNOWN_GATE')
  rows=[]
  for t in ts:
   i=t['id'];e=self.evpath(i); rows.append({'id':i,'state':self.status(i),'errors':self.validate(load(e)) if e.exists() else ['EVIDENCE_MISSING'],'dependencies':self.deps(i)})
  return {'gate':gate,'tasks':rows,'p0_open':self.p0(ts[0]['id'],True),'accepted':self.accepted(self.policy['gate_tasks'][gate]) if gate in self.policy['gate_tasks'] else False}
 def call(self,name,args):
  if name not in SCHEMAS:fail('NOT_ALLOWED')
  req,opt=SCHEMAS[name];closed(args,req,opt)
  for k,v in args.items():
   if k=='limite':
    if type(v)!=int or not 1<=v<=88:fail('NOT_ALLOWED')
   elif k in ['artefatos','testes']:
    if not isinstance(v,list):fail('NOT_ALLOWED')
   elif k=='depende_de_terceiro':
    if type(v)!=bool:fail('NOT_ALLOWED')
   elif not isinstance(v,str) or not v or len(v)>4000:fail('NOT_ALLOWED')
  if name in WRITE and self.role!='executor':fail('NOT_ALLOWED')
  if name=='gov_get_requirement':return next((x for x in load(self.g/'requirements.yaml') if x['id']==args['id']),None)
  if name=='gov_list_decisions':return [x for x in load(self.g/'decisions.yaml') if not args.get('status') or x['status']==args['status']]
  if name=='gov_get_task':return {**self.task(args['id']),'state':self.status(args['id']),'dependency_states':self.deps(args['id'])}
  if name=='gov_get_dependencies':return self.deps(args['id'])
  if name=='gov_next_tasks':return [t for i,t in self.tasks.items() if self.ready(i) and (not args.get('responsavel') or args['responsavel'].lower() in t['responsavel'].lower())][:args.get('limite',10)]
  if name=='gov_get_acceptance_criteria':return {k:self.task(args['id'])[k] for k in ('criterio_de_aceite','teste','evidencia','required_tests')}
  if name=='gov_list_evidence':
   i=args['tarefa'];p=self.evpath(i);return [{'evidence':load(x),'errors':self.validate(load(x))} for x in sorted(p.parent.glob(i+'*.json'))] if p.parent.exists() else []
  if name=='gov_validate_evidence':return self.validate(load(self.safe(args['caminho'])))
  if name=='gov_get_state':
   out={}
   for i,t in self.tasks.items():
    st=self.status(i);out.setdefault(t['gate'],{});out[t['gate']][st]=out[t['gate']].get(st,0)+1
   return {'waves':out,'identity_status':self.identity.get('status'),'trust_configured':bool(self.trust),'next':self.call('gov_next_tasks',{})}
  if name=='gov_gate_report':return self.report(args['gate'])
  i=args.get('id',args.get('tarefa'));t=self.task(i);p=self.safe(str(self.claim(i).relative_to(self.root)))
  if name=='gov_start_task':
   if t['kind']=='gate' or t['deferred'] or self.accepted(i):fail('NOT_ALLOWED')
   if not all(x['accepted'] for x in self.deps(i)):fail('DEP_NOT_ACCEPTED')
   if self.p0(i):fail('P0_OPEN')
   if p.exists():
    prev=load(p)
    if prev['sessao']==args['sessao'] and prev['chave_idempotencia']==args['chave_idempotencia']:return prev
    fail('LOCKED_BY_OTHER')
   data={**args,'created_at':now()};save(p,data,True);return data
  if not p.exists():fail('NOT_CLAIMED')
  if self.accepted(i):fail('NOT_ALLOWED')
  if name=='gov_report_block':save(self.safe('governance/blocks/'+i+'.json'),args);return args
  if name=='gov_submit_evidence':
   arts=[]
   for a in args['artefatos']:
    if not isinstance(a,str):fail('EVIDENCE_INVALID')
    try:raw=self.safe(a).read_bytes()
    except OSError:fail('EVIDENCE_INVALID')
    arts.append({'caminho':a,'sha256':digest(raw),'bytes':len(raw)})
   arts.sort(key=lambda x:x['caminho']); key=digest(canon([i,arts]))
   if args['chave_idempotencia']!=key:fail('EVIDENCE_INVALID: expected key '+key)
   pth=self.safe(str(self.evpath(i).relative_to(self.root)));prev=load(pth) if pth.exists() else None
   if prev and prev['chave_idempotencia']==key:
    if prev['testes']!=args['testes']:fail('EVIDENCE_INVALID: same key different tests')
    return prev
   e={'tarefa':i,'gate':t['gate'],'commit_sha':self.head(),'ambiente':'local','testes':args['testes'],'artefatos':arts,'produzido_por':{'sessao':load(p)['sessao'],'ferramenta':'MCP/CLI','modelo':'not attested by executor'},'criado_em':now(),'chave_idempotencia':key}
   if prev:e['substitui']=digest(canon(prev))
   errs=self.validate(e)
   if errs:fail(';'.join(errs))
   if prev:save(pth.with_name(i+'.'+digest(canon(prev))+'.json'),prev)
   save(pth,e);return e
  fail('NOT_ALLOWED')
SCHEMAS={'gov_get_requirement':(['id'],[]),'gov_list_decisions':([],['status']),'gov_get_task':(['id'],[]),'gov_get_dependencies':(['id'],[]),'gov_next_tasks':([],['responsavel','limite']),'gov_get_acceptance_criteria':(['id'],[]),'gov_list_evidence':(['tarefa'],[]),'gov_validate_evidence':(['caminho'],[]),'gov_get_state':([],[]),'gov_gate_report':(['gate'],[]),'gov_start_task':(['id','sessao','chave_idempotencia'],[]),'gov_submit_evidence':(['tarefa','artefatos','testes','chave_idempotencia'],[]),'gov_report_block':(['tarefa','motivo','depende_de_terceiro'],[])}
WRITE={'gov_start_task','gov_submit_evidence','gov_report_block'}
def schema(n):
 r,o=SCHEMAS[n];p={k:({'type':'integer','minimum':1,'maximum':88} if k=='limite' else {'type':'boolean'} if k=='depende_de_terceiro' else {'type':'array','items':{'type':'string'}} if k=='artefatos' else {'type':'array','items':{'type':'object','additionalProperties':False,'required':['id','nome','resultado','registro_sha256'],'properties':{a:{'type':'string'} for a in ['id','nome','resultado','registro_sha256']}}} if k=='testes' else {'type':'string'}) for k in r+o};return {'type':'object','properties':p,'required':r,'additionalProperties':False}
def mcp(g):
 for line in sys.stdin:
  rid=None
  try:
   q=json.loads(line);rid=q.get('id');method=q.get('method');p=q.get('params',{})
   if rid is None:continue
   if method=='initialize':result={'protocolVersion':'2025-11-25' if p.get('protocolVersion')=='2025-11-25' else '2025-03-26','capabilities':{'tools':{}},'serverInfo':{'name':'loyalty-governance','version':'2.1.0'}}
   elif method=='ping':result={}
   elif method=='tools/list':result={'tools':[{'name':n,'description':n.replace('_',' '),'inputSchema':schema(n),'annotations':{'readOnlyHint':n not in WRITE}} for n in SCHEMAS if g.role=='executor' or n not in WRITE]}
   elif method=='tools/call':
    try:result={'content':[{'type':'text','text':json.dumps(g.call(p['name'],p.get('arguments',{})),ensure_ascii=False)}]}
    except Denied as e:result={'isError':True,'content':[{'type':'text','text':str(e)}]}
   else:print(json.dumps({'jsonrpc':'2.0','id':rid,'error':{'code':-32601,'message':'Method not found'}}),flush=True);continue
   print(json.dumps({'jsonrpc':'2.0','id':rid,'result':result},ensure_ascii=False),flush=True)
  except Exception as e:print(json.dumps({'jsonrpc':'2.0','id':rid,'error':{'code':-32603,'message':type(e).__name__}}),flush=True)
def main():
 p=argparse.ArgumentParser();p.add_argument('--root',default=str(pathlib.Path(__file__).resolve().parents[1]));p.add_argument('--role',choices=['executor','reviewer'],default='executor');p.add_argument('--trust',default=os.environ.get('LOYALTY_PUBLIC_TRUST'));p.add_argument('command');p.add_argument('args',nargs='?',default='{}');a=p.parse_args();trust=None
 if a.trust:
  path=pathlib.Path(a.trust).resolve()
  if path.is_relative_to(pathlib.Path(a.root).resolve()):
   print('TRUST_MUST_BE_EXTERNAL',file=sys.stderr);sys.exit(1)
  trust=load(path)
 g=Gov(a.root,trust=trust,role=a.role)
 try:
  if a.command=='mcp':mcp(g)
  else:print(json.dumps(g.call(a.command,json.loads(a.args)),ensure_ascii=False,indent=2))
 except Denied as e:print(str(e),file=sys.stderr);sys.exit(1)
if __name__=='__main__':main()
