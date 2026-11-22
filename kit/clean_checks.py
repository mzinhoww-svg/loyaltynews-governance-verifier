#!/usr/bin/env python3
"""Run root-approved checks; invoke ONLY in a disposable, unprivileged isolated job.
No signer keys, GitHub write token, project secrets or network in test execution.
Policy must be in trusted checkout. Output is not a signed attestation until trusted job seals it.
"""
import argparse,os,json,hashlib,pathlib,subprocess,sys,tempfile
p=argparse.ArgumentParser();p.add_argument('--checkout',required=True);p.add_argument('--target',required=True);p.add_argument('--policy',required=True);p.add_argument('--task',required=True);p.add_argument('--output',required=True);a=p.parse_args();root=pathlib.Path(a.checkout).resolve();policy=pathlib.Path(a.policy).resolve();output=pathlib.Path(a.output).resolve()
if policy.is_relative_to(root) or output.is_relative_to(root):raise SystemExit('external policy/output required')
if os.environ.get('GNUPGHOME') or any(k in os.environ for k in ['GITHUB_TOKEN','GH_TOKEN','VERIFIER_PRIVATE_KEY','OPENAI_API_KEY','ANTHROPIC_API_KEY','DEEPSEEK_API_KEY']):raise SystemExit('secret environment refused')
if subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip()!=a.target or subprocess.check_output(['git','-C',str(root),'status','--porcelain']):raise SystemExit('wrong or dirty checkout')
raw=policy.read_bytes();manifest=json.loads(raw); tests=manifest['checks'].get(a.task,[])
if not tests:raise SystemExit('no trusted tests configured')
results=[]
with tempfile.TemporaryDirectory() as home:
 for t in tests:
  command=t['argv'];
  if not isinstance(command,list) or not command or not all(isinstance(x,str) for x in command):raise SystemExit('argv array required')
  try:
   result=subprocess.run(command,cwd=root,env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':home,'LANG':'C.UTF-8'},capture_output=True,timeout=min(int(t.get('timeout_sec',300)),900));code=result.returncode;blob=result.stdout+result.stderr
  except subprocess.TimeoutExpired as e:code=124;blob=b'timeout'
  results.append({'id':t['id'],'result':'pass' if code==0 else 'fail','exit_code':code,'log_sha256':hashlib.sha256(blob).hexdigest()})
report={'id':a.task,'commit_sha':a.target,'clean_environment':True,'runner_policy_sha256':hashlib.sha256(raw).hexdigest(),'tests':results}
output.write_text(json.dumps(report,indent=2)+'\n');sys.exit(0 if all(x['result']=='pass' for x in results) else 1)
