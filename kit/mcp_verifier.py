#!/usr/bin/env python3
import argparse,pathlib,sys,json
from verifier import Verifier
from gov import load,closed,Denied
p=argparse.ArgumentParser();p.add_argument('--repo',required=True);p.add_argument('--trust',required=True);a=p.parse_args();repo=pathlib.Path(a.repo).resolve();trust=pathlib.Path(a.trust).resolve()
if trust.is_relative_to(repo):raise SystemExit('TRUST_MUST_BE_EXTERNAL')
def schema(reject=False):
 keys=['gate']+(['motivo'] if reject else []);return {'type':'object','properties':{k:{'type':'string'} for k in keys},'required':keys,'additionalProperties':False}
for line in sys.stdin:
 rid=None
 try:
  q=json.loads(line);rid=q.get('id');m=q.get('method');params=q.get('params',{})
  if rid is None:continue
  if m=='initialize':res={'protocolVersion':'2025-11-25','capabilities':{'tools':{}},'serverInfo':{'name':'loyalty-verifier-only','version':'2.1.0'}}
  elif m=='tools/list':res={'tools':[{'name':'gov_accept_gate','description':'Check independent signed proofs and sign acceptance','inputSchema':schema()},{'name':'gov_reject_gate','description':'Sign rejection','inputSchema':schema(True)}]}
  elif m=='tools/call':
   n=params['name'];args=params.get('arguments',{});reject=n=='gov_reject_gate'
   try:
    if n not in ('gov_accept_gate','gov_reject_gate'):raise Denied('NOT_ALLOWED')
    closed(args,['gate']+(['motivo'] if reject else []));v=Verifier(repo,load(trust));i=v.g.policy['gate_tasks'].get(args['gate'],args['gate']);r=v.reject(i,args['motivo']) if reject else v.accept(i);res={'content':[{'type':'text','text':json.dumps(r,ensure_ascii=False)}]}
   except Denied as e:res={'isError':True,'content':[{'type':'text','text':str(e)}]}
  elif m=='ping':res={}
  else:raise ValueError('unknown method')
  print(json.dumps({'jsonrpc':'2.0','id':rid,'result':res}),flush=True)
 except Exception as e:print(json.dumps({'jsonrpc':'2.0','id':rid,'error':{'code':-32603,'message':type(e).__name__}}),flush=True)
