#!/usr/bin/env python3
"""Reference verifier for a SEPARATE trusted checkout. Not deployable until R0-03/06."""
import argparse, json, pathlib, sys, re, os
# In production install gov.py from ROOT-APPROVED external verifier repository, not target checkout.
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
try: from gov import Gov,Denied,fail,git,canon,digest,load,now,closed
except ImportError:
 sys.path.insert(0,str(HERE.parent/'tools'));from gov import Gov,Denied,fail,git,canon,digest,load,now,closed

import base64, binascii, subprocess, tempfile

# ---- 24/11, DP-45: aceite com override assinado pela RAIZ quando o revisor recusa SO por ponto coberto por DP registrada ----
# O documento de autorizacao (JSON canonico, formato ln-override/1) e assinado pela raiz FORA do CI (cerimonia do PM) e entra
# como entrada do workflow: "<base64 do documento>.<base64 da assinatura destacada>". A chave do verificador (CI) so assina a
# tag de aceite DEPOIS de conferir a assinatura da raiz; sem ela, nada e aceito. A tag de aceite leva o documento e a
# assinatura, para qualquer um reverificar fora do GitHub.
DPID=re.compile(r'^(DP-\d{2,3}|D\d{2})$')
GPG_BAD=('[GNUPG:] BADSIG','[GNUPG:] ERRSIG','[GNUPG:] EXPSIG','[GNUPG:] EXPKEYSIG','[GNUPG:] REVKEYSIG','[GNUPG:] NO_PUBKEY')

def root_signed_bytes(doc,sig,root_fpr):
 """True so se sig e UMA assinatura DESTACADA, valida, da raiz (primaria = root_fpr; subchave dela) sobre os bytes de doc."""
 with tempfile.TemporaryDirectory(prefix='ln-ovr-') as d:
  dp=pathlib.Path(d)/'doc';sp=pathlib.Path(d)/'sig';dp.write_bytes(doc);sp.write_bytes(sig)
  pk=subprocess.run(['gpg','--batch','--no-tty','--list-packets',str(sp)],capture_output=True)
  pkts=pk.stdout.decode(errors='replace')
  if pk.returncode or pkts.count(':signature packet:')!=1 or ':literal data packet:' in pkts or ':compressed packet:' in pkts:return False
  v=subprocess.run(['gpg','--batch','--no-tty','--status-fd','1','--verify',str(sp),str(dp)],capture_output=True)
 st=[l.strip() for l in v.stdout.decode(errors='replace').upper().splitlines()]
 valid=[l for l in st if l.startswith('[GNUPG:] VALIDSIG ')]
 return v.returncode==0 and len(valid)==1 and valid[0].split()[-1]==root_fpr.upper() and not any(l.startswith(GPG_BAD) for l in st)

def verify_override(g,trust,i,head,auth,dps_in):
 """Confere a autorizacao da raiz contra o parecer contrario EXISTENTE e o decisions.yaml do alvo. Devolve o bloco 'override'."""
 try:
  doc_b64,sig_b64=auth.strip().split('.');doc=base64.b64decode(doc_b64,validate=True);sig=base64.b64decode(sig_b64,validate=True)
 except (ValueError,binascii.Error):fail('OVERRIDE_INVALID: formato (esperado <doc_b64>.<sig_b64>)')
 if not root_signed_bytes(doc,sig,trust['root_fingerprint']):fail('OVERRIDE_ROOT_SIGNATURE_INVALID')
 try:d=json.loads(doc.decode('utf-8'))
 except ValueError:fail('OVERRIDE_INVALID: json')
 if not isinstance(d,dict) or canon(d)!=doc:fail('OVERRIDE_INVALID: documento nao canonico')
 try:closed(d,['formato','base','tarefa','alvo','dps','parecer','mapeamento'],['nota'])
 except Denied:fail('OVERRIDE_INVALID: campos')
 if d['formato']!='ln-override/1' or d['base']!='DP-45' or d['tarefa']!=i or d['alvo']!=head:fail('OVERRIDE_INVALID: formato/base/tarefa/alvo')
 dps=d['dps']
 if not isinstance(dps,list) or not dps or not all(isinstance(x,str) and DPID.match(x) for x in dps) or dps!=sorted(set(dps)):fail('OVERRIDE_WITHOUT_DP')
 if dps!=dps_in:fail('OVERRIDE_DP_MISMATCH: entrada dp difere do documento assinado')
 try:decs=json.loads(g.file_at(head,'governance/decisions.yaml'))
 except (Denied,ValueError):fail('OVERRIDE_DECISIONS_MISSING')
 ids={x.get('id') for x in decs if isinstance(x,dict)} if isinstance(decs,list) else set()
 if 'DP-45' not in ids:fail('OVERRIDE_DP45_NOT_IN_TARGET')
 unknown=[x for x in dps if x not in ids]
 if unknown:fail('OVERRIDE_DP_UNKNOWN:'+','.join(unknown))
 par=d['parecer'];rname='review/'+i+'/'+head
 try:closed(par,['tag','oid','payload_sha256'])
 except Denied:fail('OVERRIDE_INVALID: parecer')
 if par['tag']!=rname:fail('OVERRIDE_REVIEW_MISMATCH: tag')
 review=g.signed(rname,'reviewer')
 if not review:fail('OVERRIDE_REVIEW_MISSING')
 if git(g.root,'rev-parse','refs/tags/'+rname).stdout.decode().strip()!=par['oid'] or digest(canon(review))!=par['payload_sha256']:fail('OVERRIDE_REVIEW_MISMATCH: objeto/payload')
 if review.get('decision')!='unfavorable':fail('OVERRIDE_REVIEW_NOT_UNFAVORABLE')
 crit,probs=review.get('criterios'),review.get('problemas')
 if not isinstance(crit,list) or not isinstance(probs,list) or not all(isinstance(c,dict) for c in crit):fail('OVERRIDE_REVIEW_WITHOUT_CRITERIA')
 failed=[c.get('criterio') for c in crit if c.get('atendido') is not True]
 if not failed and not probs:fail('OVERRIDE_NOTHING_TO_COVER')
 m=d['mapeamento']
 try:closed(m,['criterios','problemas'])
 except Denied:fail('OVERRIDE_MAPPING_INVALID')
 used=set()
 for key,want in (('criterios',failed),('problemas',probs)):
  if not isinstance(m[key],list):fail('OVERRIDE_MAPPING_INVALID')
  got=[]
  for e in m[key]:
   try:closed(e,['texto','dps'])
   except Denied:fail('OVERRIDE_MAPPING_INVALID')
   if not isinstance(e['dps'],list) or not e['dps'] or not set(e['dps'])<=set(dps):fail('OVERRIDE_MAPPING_INVALID: dps')
   got.append(e['texto']);used|=set(e['dps'])
  # cada criterio NAO atendido e cada problema do parecer tem de estar mapeado a DP(s), exatamente (sem faltar nem sobrar)
  if sorted(got,key=str)!=sorted(want,key=str):fail('OVERRIDE_MAPPING_INCOMPLETE:'+key)
 if used!=set(dps):fail('OVERRIDE_DP_UNUSED')
 return {'base':'DP-45','dps':dps,'mapeamento':m,'parecer':par,'raiz':trust['root_fingerprint'],
         'autorizacao_sha256':digest(doc),'autorizacao_b64':doc_b64,'assinatura_raiz_b64':sig_b64}

def changed_protected(g,baseline,target,paths):
 changed=git(g.root,'diff','--name-only','-z',baseline,target).stdout.decode().split('\0')
 return [x for x in changed if x and any(x==p.rstrip('/') or x.startswith(p.rstrip('/')+'/') for p in paths)]
class Verifier:
 def __init__(self,root,trust):
  self.trust=trust; self.g=Gov(root,trust=trust,role='verifier');self.head=self.g.head()
  for k in ['root_fingerprint','baseline_commit','executor','reviewer','verifier','protected']:
   if k not in trust:fail('UNCONFIGURED_TRUST')
  fps=[trust[k]['fingerprint'] for k in ('executor','reviewer','verifier')]+[trust['root_fingerprint']]
  if len(set(fps))!=4 or not all(re.fullmatch(r'[0-9A-Fa-f]{40,64}',s or '') for s in fps):fail('UNCONFIGURED_TRUST')
  if trust['executor']['provider']==trust['reviewer']['provider']:fail('REVIEW_NOT_INDEPENDENT')
  if git(self.g.root,'status','--porcelain').stdout:fail('DIRTY_CHECKOUT')
  if not re.fullmatch('[0-9a-f]{40}',trust['baseline_commit']):fail('UNCONFIGURED_TRUST')
  if git(self.g.root,'merge-base','--is-ancestor',trust['baseline_commit'],self.head,check=False).returncode:fail('UNTRUSTED_BASELINE')
  # Pinned baseline is installed out of band by root. Require its signed commit.
  v=git(self.g.root,'verify-commit','--raw',trust['baseline_commit'],check=False)
  if v.returncode or not any(trust['root_fingerprint'].upper() in l.split()[2:] for l in v.stderr.decode(errors='replace').upper().splitlines() if l.startswith('[GNUPG:] VALIDSIG ')):fail('UNTRUSTED_BASELINE')
  if self.g.identity.get('status')!='configured' or any(self.g.identity.get(k)!=trust.get(k) for k in ('executor','reviewer','verifier','root_fingerprint')):fail('IDENTITY_MISMATCH')
 def sign(self,tag,payload):
  fp=self.trust['verifier']['fingerprint']; payload={**payload,'commit_sha':self.head,'por':fp,'em':now()}
  # No force; an accepted ref cannot be superseded locally. Rotation/revocation is explicit root procedure.
  git(self.g.root,'-c','user.name=Loyalty Verifier','-c','user.email=verifier@loyalty.invalid','-c','gpg.format=openpgp','tag','-s','-u',fp,'-m',canon(payload).decode(),tag,self.head)
  return payload
 def evaluate(self,i,override=False):
  g=self.g;t=g.task(i);errors=[];index={};wave=t['gate'];isgate=t['kind']=='gate'
  protected=changed_protected(g,self.trust['baseline_commit'],self.head,self.trust['protected'])
  if protected:errors.append('PROTECTED_CHANGED:'+','.join(protected))
  if not all(x['accepted'] for x in g.deps(i)):errors.append('DEP_NOT_ACCEPTED')
  if g.p0(i,isgate):errors.append('P0_OPEN:'+','.join(g.p0(i,isgate)))
  items=[x['id'] for x in g.tasks.values() if x['gate']==wave and x['kind']!='gate'] if isgate else [i]
  for j in items:
   if isgate and not g.accepted(j):errors.append('TASK_NOT_ACCEPTED:'+j)
   path=g.evpath(j).relative_to(g.root).as_posix()
   try:
    raw=g.file_at(self.head,path); errors+=g.validate(json.loads(raw),self.head);index[j]=digest(raw)
    if not git(g.root,'merge-base','--is-ancestor',json.loads(raw)['commit_sha'],self.head,check=False).returncode==0:errors.append('EVIDENCE_COMMIT_NOT_ANCESTOR:'+j)
   except (Denied,ValueError,KeyError):errors.append('EVIDENCE_MISSING:'+j)
  # Reviews and checks are signed external attestations against the exact target commit.
  # They must be produced by isolated reviewer and trusted clean runner respectively.
  # Git tags are immutable externally; use commit-qualified names.
  review=g.signed('review/'+i+'/'+self.head,'reviewer');checks=g.signed('checks/'+i+'/'+self.head,'verifier')
  # DP-45: com override (raiz ja conferida em verify_override) o parecer tem de existir, ser independente e CONTRARIO; o resto nao muda
  want='unfavorable' if override else 'favorable'
  if not review or review.get('decision')!=want or review.get('id')!=i or review.get('executor_provider')!=self.trust['executor']['provider'] or review.get('reviewer_provider')!=self.trust['reviewer']['provider'] or review.get('executor_fingerprint')!=self.trust['executor']['fingerprint'] or review.get('reviewer_fingerprint')!=self.trust['reviewer']['fingerprint']:errors.append('REVIEW_NOT_INDEPENDENT_OR_MISSING')
  required=set(t['required_tests'])
  if isgate:
   for j in items:required.update(g.task(j)['required_tests'])
  if not checks or checks.get('id')!=i or checks.get('clean_environment') is not True or checks.get('runner_policy_sha256')!=self.trust.get('runner_policy_sha256') or not required.issubset({x['id'] for x in checks.get('tests',[]) if x.get('result')=='pass'}):errors.append('REQUIRED_TESTS_FAILED_OR_MISSING')
  return errors,index
 def accept(self,i):
  t=self.g.task(i);errors,index=self.evaluate(i);ref=self.g.tag_for(i)
  if self.g.accepted(i):fail('ALREADY_ACCEPTED')
  if errors:
   # commit-qualified rejection preserves history; canonical rejected tag is not overwritten.
   self.reject(i,';'.join(errors));fail('CONDITION_FAILED: '+';'.join(errors))
  payload=self.sign(ref,{'id':i,'gate':t['gate'],'tasks':list(index),'decision':'accepted','evidence_index':index,'index_sha256':digest(canon(index)),'indice_evidencias_sha256':digest(canon(index))})
  mirror=self.trust.get('acceptance_dir')
  if mirror:
   path=pathlib.Path(mirror).resolve()
   if path.is_relative_to(self.g.root):fail('EXTERNAL_MIRROR_REQUIRED')
   from gov import save
   save(path/(i+'.yaml'),payload)
  return payload
 def accept_override(self,i,auth,dps_in):
  # DP-45: nenhuma tag de rejeicao aqui (a rejeicao normal ja registrou o parecer contrario); recusa = falha sem efeito
  t=self.g.task(i);ref=self.g.tag_for(i)
  if self.g.accepted(i):fail('ALREADY_ACCEPTED')
  ov=verify_override(self.g,self.trust,i,self.head,auth,dps_in)
  errors,index=self.evaluate(i,override=True)
  if errors:fail('OVERRIDE_REFUSED: '+';'.join(errors))
  return self.sign(ref,{'id':i,'gate':t['gate'],'tasks':list(index),'decision':'accepted','evidence_index':index,'index_sha256':digest(canon(index)),'indice_evidencias_sha256':digest(canon(index)),
                        'via':'override '+','.join(ov['dps'])+' (DP-45)','override':ov})
 def reject(self,i,motivo):
  ref=self.g.tag_for(i).removesuffix('/accepted')+'/rejected/'+self.head
  return self.sign(ref,{'id':i,'decision':'rejected','reason':motivo})
def main():
 p=argparse.ArgumentParser();p.add_argument('--repo',required=True);p.add_argument('--trust',required=True);p.add_argument('action',choices=['gov_accept_gate','gov_accept_override','gov_reject_gate','evaluate']);p.add_argument('id');p.add_argument('--reason')
 p.add_argument('--override-file');p.add_argument('--dp');a=p.parse_args()
 try:
  trust_path=pathlib.Path(a.trust).resolve();repo=pathlib.Path(a.repo).resolve()
  if trust_path.is_relative_to(repo):fail('TRUST_MUST_BE_EXTERNAL')
  v=Verifier(repo,load(trust_path));i=v.g.policy['gate_tasks'].get(a.id,a.id)
  if a.action=='gov_accept_override':
   if not a.override_file or not a.dp:fail('OVERRIDE_WITHOUT_DP')
   dps=a.dp.split(',')
   if not all(DPID.match(x) for x in dps) or dps!=sorted(set(dps)):fail('OVERRIDE_WITHOUT_DP')
   out=v.accept_override(i,pathlib.Path(a.override_file).read_text(encoding='ascii'),dps)
  else:out=v.evaluate(i) if a.action=='evaluate' else v.accept(i) if a.action=='gov_accept_gate' else v.reject(i,a.reason or 'rejected')
  print(json.dumps(out,ensure_ascii=False,indent=2))
 except Denied as e:print(str(e),file=sys.stderr);sys.exit(1)
if __name__=='__main__':main()
