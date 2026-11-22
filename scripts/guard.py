#!/usr/bin/env python3
"""Deteccao de desvio de configuracao (sem segredos). Falha (exit 1) se algo diverge do esperado no trust.json.
Le a API publica do GitHub com o GITHUB_TOKEN do proprio run (somente leitura). Nao corrige nada."""
import json, os, sys, urllib.request

def api(path):
    req = urllib.request.Request('https://api.github.com' + path, headers={
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
        'Authorization': 'Bearer ' + os.environ['GITHUB_TOKEN']})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

def main():
    trust = json.load(open(sys.argv[1], encoding='utf-8'))
    exp = trust['expected_config']
    errors = []
    stop = os.environ.get('LN_EMERGENCY_STOP')
    if stop is None or stop.strip() == '':
        errors.append('LN_EMERGENCY_STOP ausente (falha fechada)')
    elif stop.strip() != '0':
        errors.append('LN_EMERGENCY_STOP ativo')
    for repo, want in exp['repos'].items():
        r = api(f'/repos/{repo}')
        if r.get('visibility') != want['visibility']:
            errors.append(f'{repo}: visibilidade {r.get("visibility")} != {want["visibility"]}')
        if want.get('default_branch') and r.get('default_branch') != want['default_branch']:
            errors.append(f'{repo}: branch padrao {r.get("default_branch")}')
        active = {x['name']: x for x in api(f'/repos/{repo}/rulesets')}
        for name in want.get('rulesets_active', []):
            if name not in active:
                errors.append(f'{repo}: ruleset ausente {name}')
            elif api(f'/repos/{repo}/rulesets/{active[name]["id"]}').get('enforcement') != 'active':
                errors.append(f'{repo}: ruleset {name} nao ativo')
        for name in want.get('rulesets_disabled', []):
            if name in active and api(f'/repos/{repo}/rulesets/{active[name]["id"]}').get('enforcement') == 'active':
                errors.append(f'{repo}: {name} ATIVO (parada de emergencia acionada?)')
    for e in errors:
        print('DESVIO:', e)
    if errors:
        sys.exit(1)
    print('guard ok')

if __name__ == '__main__':
    main()
