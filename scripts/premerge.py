#!/usr/bin/env python3
"""Status pre-merge do verificador (opcao B do PM, PM-2026-11-23-A; r0-preparacao/seguranca/16_decisao-status-pre-merge.md).

Dois status deterministicos em cada PR para main do produto, postados pela App LN Verifier (sem LLM por PR; o parecer do
revisor continua no aceite, sobre o merge commit Mi):
  ln-verifier/protected-paths  diff merge-base(origin/main, H)..H toca caminho protegido do trust.json (ou .gitattributes,
                               .gitmodules, .lfsconfig em qualquer nivel) => failure, salvo se TODO commit desse diff que toca
                               o caminho protegido for assinado pela RAIZ (ato raiz com novo baseline).
  ln-verifier/clean-checks     relatorio do runner limpo (politica 'PR', ambiente limpo, politica = trust) com todos os testes 'pass'.

Uso:
  premerge.py avaliar --product <clone com origin/main> --target <H> --trust trust.json --keys <dir *.asc> --runner-report r.json --out status.json
  premerge.py postar  --repo <owner/nome> --sha <H> --statuses status.json [--target-url URL] [--api-url URL]   (token da App em APP_TOKEN)
Falha fechada: qualquer duvida vira 'failure'; 'postar' so aceita os dois contextos acima e so estados success/failure.
"""
import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

SHA = re.compile(r'^[0-9a-f]{40}$')
REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
CONTEXTS = ('ln-verifier/protected-paths', 'ln-verifier/clean-checks')
BASENAMES = ('.gitattributes', '.gitmodules', '.lfsconfig')


def git(repo, *args, check=True, env=None):
    p = subprocess.run(['git', '-C', str(repo), '-c', 'core.hooksPath=' + os.devnull, *args], capture_output=True, env=env)
    if check and p.returncode:
        raise SystemExit(f'git {args[0]} falhou: {p.stderr.decode(errors="replace").strip()[:200]}')
    return p


def lines(repo, *args):
    return [x for x in git(repo, *args).stdout.decode('utf-8', 'replace').split('\n') if x]


def protected_hits(names, trust):
    pre = [p for p in trust.get('protected', [])]
    base = set(trust.get('protected_basenames', [])) | set(BASENAMES)
    out = []
    for n in names:
        if any((n.startswith(p) if p.endswith('/') else n == p) for p in pre) or n.split('/')[-1] in base:
            out.append(n)
    return out


def root_signed(repo, commit, root_fpr, gnupghome):
    env = {**os.environ, 'GNUPGHOME': gnupghome}
    v = git(repo, 'verify-commit', '--raw', commit, check=False, env=env)
    for ln in v.stderr.decode('utf-8', 'replace').splitlines():
        if ln.startswith('[GNUPG:] VALIDSIG ') and root_fpr.upper() in (f.upper() for f in ln.split()[2:]):
            return v.returncode == 0
    return False


def avaliar_paths(repo, target, trust, gnupghome):
    base = git(repo, 'merge-base', 'origin/main', target).stdout.decode().strip()
    hits = protected_hits(lines(repo, 'diff', '--name-only', base, target), trust)
    if not hits:
        return 'success', 'nenhum caminho protegido alterado'
    bad = []
    for c in lines(repo, 'rev-list', f'{base}..{target}'):
        touched = protected_hits(lines(repo, 'diff-tree', '--no-commit-id', '--name-only', '-r', '-m', '--root', c), trust)
        if touched and not root_signed(repo, c, trust['root_fingerprint'], gnupghome):
            bad.append(c[:12])
    if bad:
        return 'failure', f'caminho protegido sem ato raiz ({len(hits)}): ' + ', '.join(hits[:3]) + (' ...' if len(hits) > 3 else '')
    return 'success', f'mudanca protegida em commits assinados pela raiz ({len(hits)} caminho(s))'


def avaliar_checks(report, target, trust):
    if not report:
        return 'failure', 'relatorio do runner ausente'
    if report.get('id') != 'PR' or report.get('commit_sha') != target or report.get('clean_environment') is not True \
            or report.get('runner_policy_sha256') != trust.get('runner_policy_sha256'):
        return 'failure', 'relatorio do runner nao corresponde a PR/alvo/politica'
    tests = report.get('tests') or []
    falhos = [t.get('id') for t in tests if t.get('result') != 'pass']
    if not tests:
        return 'failure', 'nenhum teste no relatorio'
    if falhos:
        return 'failure', 'falhou: ' + ', '.join(str(x) for x in falhos[:4])
    return 'success', f'{len(tests)} teste(s) do runner limpo passaram'


def cmd_avaliar(a):
    repo = pathlib.Path(a.product).resolve()
    trust_path = pathlib.Path(a.trust).resolve()
    if trust_path.is_relative_to(repo):
        raise SystemExit('TRUST_MUST_BE_EXTERNAL')
    if not SHA.match(a.target):
        raise SystemExit('alvo invalido')
    trust = json.load(open(trust_path, encoding='utf-8'))
    report = None
    if a.runner_report and pathlib.Path(a.runner_report).is_file():
        try:
            report = json.load(open(a.runner_report, encoding='utf-8'))
        except ValueError:
            report = None
    home = tempfile.mkdtemp(prefix='ln-premerge-gnupg-')
    try:
        os.chmod(home, 0o700)
        for f in sorted(pathlib.Path(a.keys).glob('*.asc')):
            subprocess.run(['gpg', '--batch', '--quiet', '--import', str(f)], capture_output=True, env={**os.environ, 'GNUPGHOME': home})
        try:
            p_state, p_desc = avaliar_paths(repo, a.target, trust, home)
        except SystemExit as e:
            p_state, p_desc = 'failure', f'erro ao avaliar: {str(e)[:100]}'
    finally:
        subprocess.run(['gpgconf', '--homedir', home, '--kill', 'all'], capture_output=True)
        shutil.rmtree(home, ignore_errors=True)
    c_state, c_desc = avaliar_checks(report, a.target, trust)
    out = [{'context': CONTEXTS[0], 'state': p_state, 'description': p_desc[:140]},
           {'context': CONTEXTS[1], 'state': c_state, 'description': c_desc[:140]}]
    txt = json.dumps({'target': a.target, 'statuses': out}, ensure_ascii=False, indent=2)
    pathlib.Path(a.out).write_text(txt + '\n', encoding='utf-8')
    print(txt)
    return 0


def api(base, method, path, token, body=None):
    req = urllib.request.Request(base.rstrip('/') + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                                          'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def cmd_postar(a):
    token = os.environ.get('APP_TOKEN', '')
    if not token:
        raise SystemExit('APP_TOKEN ausente (falha fechada)')
    if not REPO.match(a.repo) or not SHA.match(a.sha):
        raise SystemExit('repo ou sha invalido')
    doc = json.load(open(a.statuses, encoding='utf-8'))
    if doc.get('target') != a.sha:
        raise SystemExit('status.json e de outro alvo')
    sts = doc.get('statuses') or []
    if sorted(s.get('context') for s in sts) != sorted(CONTEXTS) or any(s.get('state') not in ('success', 'failure') for s in sts):
        raise SystemExit('status.json fora do contrato (2 contextos, success/failure)')
    atuais = api(a.api_url, 'GET', f'/repos/{a.repo}/commits/{a.sha}/statuses?per_page=100', token)
    ultimo = {}
    for s in atuais:   # a API devolve do mais novo para o mais antigo
        ultimo.setdefault(s.get('context'), s)
    postados = 0
    for s in sts:
        u = ultimo.get(s['context'])
        if u and u.get('state') == s['state'] and u.get('description') == s['description']:
            print(f"[premerge] {s['context']}: ja {s['state']} (nada a fazer)")
            continue
        body = {'state': s['state'], 'context': s['context'], 'description': s['description'][:140]}
        if a.target_url:
            body['target_url'] = a.target_url
        r = api(a.api_url, 'POST', f'/repos/{a.repo}/statuses/{a.sha}', token, body)
        if r.get('state') != s['state'] or r.get('context') != s['context']:
            raise SystemExit(f"status nao confirmado pela API: {s['context']}")
        postados += 1
        print(f"[premerge] {s['context']} = {s['state']} ({s['description']})")
    print(f'[premerge] postados: {postados}')
    return 0


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    v = sp.add_parser('avaliar')
    for x in ('--product', '--target', '--trust', '--keys', '--out'):
        v.add_argument(x, required=True)
    v.add_argument('--runner-report')
    p = sp.add_parser('postar')
    for x in ('--repo', '--sha', '--statuses'):
        p.add_argument(x, required=True)
    p.add_argument('--target-url')
    p.add_argument('--api-url', default=os.environ.get('LN_GITHUB_API', 'https://api.github.com'))
    a = ap.parse_args()
    try:
        return cmd_avaliar(a) if a.cmd == 'avaliar' else cmd_postar(a)
    except urllib.error.HTTPError as e:
        print(f'[premerge] FALHOU: HTTP {e.code} na API', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
