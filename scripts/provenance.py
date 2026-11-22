#!/usr/bin/env python3
"""Validacao conjunta de proveniencia do relatorio do runner (03 v2 par.5 / 03 v3).
Uso: provenance.py <zip-baixado> <trust.json> <policy.json> <target_sha> <task>
Ambiente: GITHUB_TOKEN (actions:read), GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT,
GITHUB_WORKFLOW_REF, GITHUB_WORKFLOW_SHA, RUNNER_ARTIFACT_ID, RUNNER_ARTIFACT_DIGEST, RUNNER_REPORT_SHA256.
Sai 0 so se workflow, run, tentativa, job, artefato (ZIP), relatorio (JSON), politica e commit baterem entre si."""
import hashlib, io, json, os, sys, urllib.request, zipfile

E = os.environ
def api(path):
    req = urllib.request.Request('https://api.github.com' + path, headers={
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
        'Authorization': 'Bearer ' + E['GITHUB_TOKEN']})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)
def sha(b): return hashlib.sha256(b).hexdigest()

def main():
    zpath, trust_p, policy_p, target, task = sys.argv[1:6]
    trust = json.load(open(trust_p, encoding='utf-8'))
    repo, run_id, attempt = E['GITHUB_REPOSITORY'], E['GITHUB_RUN_ID'], E['GITHUB_RUN_ATTEMPT']
    err = []
    want_ref = f"{repo}/.github/workflows/verifier.yml@refs/heads/main"
    if E['GITHUB_WORKFLOW_REF'] != want_ref: err.append('workflow_ref')
    run = api(f'/repos/{repo}/actions/runs/{run_id}')
    if run.get('path') != '.github/workflows/verifier.yml': err.append('run.path')
    if run.get('head_sha') != E['GITHUB_WORKFLOW_SHA']: err.append('run.head_sha')
    if run.get('head_branch') != 'main': err.append('run.head_branch')
    if run.get('event') not in ('schedule', 'workflow_dispatch'): err.append('run.event')
    if str(run.get('run_attempt')) != str(attempt): err.append('run.attempt')
    jobs = api(f'/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')['jobs']
    rj = [j for j in jobs if j['name'].startswith('runner')]
    if len(rj) != 1 or rj[0]['conclusion'] != 'success' or rj[0]['head_sha'] != E['GITHUB_WORKFLOW_SHA']: err.append('job.runner')
    art = api(f"/repos/{repo}/actions/artifacts/{E['RUNNER_ARTIFACT_ID']}")
    if str(art.get('workflow_run', {}).get('id')) != str(run_id): err.append('artifact.run')
    if art.get('workflow_run', {}).get('head_sha') != E['GITHUB_WORKFLOW_SHA']: err.append('artifact.head_sha')
    if art.get('name') != f'runner-report-{task}-{target}': err.append('artifact.name')
    zbytes = open(zpath, 'rb').read()
    zd = 'sha256:' + sha(zbytes)
    if not (art.get('digest') == zd == E['RUNNER_ARTIFACT_DIGEST'] or (art.get('digest') == zd and E['RUNNER_ARTIFACT_DIGEST'] in (zd, zd[7:]))):
        err.append('artifact.digest(zip)')
    with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
        report_raw = z.read('runner-report.json')
    if sha(report_raw) != E['RUNNER_REPORT_SHA256']: err.append('report.sha256(json)')
    rep = json.loads(report_raw)
    pol_raw = open(policy_p, 'rb').read()
    if sha(pol_raw) != trust['runner_policy_sha256'] or rep.get('runner_policy_sha256') != trust['runner_policy_sha256']: err.append('policy')
    if rep.get('commit_sha') != target or rep.get('id') != task or rep.get('clean_environment') is not True: err.append('report.target')
    want_ids = {t['id'] for t in json.loads(pol_raw)['checks'].get(task, [])}
    got = {t['id']: t['result'] for t in rep.get('tests', [])}
    if not want_ids or set(got) != want_ids or any(v != 'pass' for v in got.values()): err.append('tests')
    for e in err: print('PROVENIENCIA FALHOU:', e)
    sys.exit(1 if err else 0)

if __name__ == '__main__':
    main()
