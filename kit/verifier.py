#!/usr/bin/env python3
"""Reference verifier for a SEPARATE trusted checkout. Not deployable until R0-03/06."""
import argparse, json, pathlib, sys, re, os
# In production install gov.py from ROOT-APPROVED external verifier repository, not target checkout.
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
try: from gov import Gov,Denied,fail,git,canon,digest,load,now,closed
except ImportError:
 sys.path.insert(0,str(HERE.parent/'tools'));from gov import Gov,Denied,fail,git,canon,digest,load,now,closed

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
 def evaluate(self,i):
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
  if not review or review.get('decision')!='favorable' or review.get('id')!=i or review.get('executor_provider')!=self.trust['executor']['provider'] or review.get('reviewer_provider')!=self.trust['reviewer']['provider'] or review.get('executor_fingerprint')!=self.trust['executor']['fingerprint'] or review.get('reviewer_fingerprint')!=self.trust['reviewer']['fingerprint']:errors.append('REVIEW_NOT_INDEPENDENT_OR_MISSING')
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
 def reject(self,i,motivo):
  ref=self.g.tag_for(i).removesuffix('/accepted')+'/rejected/'+self.head
  return self.sign(ref,{'id':i,'decision':'rejected','reason':motivo})
def main():
 p=argparse.ArgumentParser();p.add_argument('--repo',required=True);p.add_argument('--trust',required=True);p.add_argument('action',choices=['gov_accept_gate','gov_reject_gate','evaluate']);p.add_argument('id');p.add_argument('--reason');a=p.parse_args()
 try:
  trust_path=pathlib.Path(a.trust).resolve();repo=pathlib.Path(a.repo).resolve()
  if trust_path.is_relative_to(repo):fail('TRUST_MUST_BE_EXTERNAL')
  v=Verifier(repo,load(trust_path));i=v.g.policy['gate_tasks'].get(a.id,a.id)
  out=v.evaluate(i) if a.action=='evaluate' else v.accept(i) if a.action=='gov_accept_gate' else v.reject(i,a.reason or 'rejected')
  print(json.dumps(out,ensure_ascii=False,indent=2))
 except Denied as e:print(str(e),file=sys.stderr);sys.exit(1)
if __name__=='__main__':main()
