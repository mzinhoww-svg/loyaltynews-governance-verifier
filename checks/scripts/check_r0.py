#!/usr/bin/env python3
"""Checks confiaveis das tarefas R0 (R0-06): rodam no runner, em container SEM rede, sobre o checkout limpo do produto.

Uso: check_r0.py <TAREFA> <raiz-do-produto> [--keys <dir com raiz.asc>]
Sai 0 so se todas as regras da tarefa passam. Cada regra imprime 'ok' ou 'FALHA'. Falha fechada: tarefa sem regra,
arquivo ausente, JSON invalido ou padrao de segredo => exit 1. So biblioteca padrao + git/gpg do container.
As regras conferem a FORMA verificavel da evidencia (o julgamento de merito e do revisor de outro provedor).
"""
import csv
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

SECRET = re.compile(
    r'-----BEGIN [A-Z ]*PRIVATE KEY-----|sk-or-v1-[0-9a-f]{16,}|sk-ant-[A-Za-z0-9_-]{16,}'
    r'|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}')
EVID = 'evidencias'
FAILS = []


def ok(cond, msg):
    print(('ok    ' if cond else 'FALHA ') + msg)
    if not cond:
        FAILS.append(msg)
    return cond


def read(root, rel):
    p = root / rel
    return p.read_bytes() if p.is_file() else None


def load_json(root, rel):
    raw = read(root, rel)
    if raw is None:
        ok(False, f'{rel}: ausente')
        return None
    try:
        return json.loads(raw.decode('utf-8-sig'))
    except (ValueError, UnicodeDecodeError) as e:
        ok(False, f'{rel}: JSON invalido ({type(e).__name__})')
        return None


def git(root, *args, check=True):
    p = subprocess.run(['git', '-C', str(root), '-c', 'core.hooksPath=/dev/null', '-c', 'safe.directory=*', *args], capture_output=True)
    if check and p.returncode:
        return None
    return p


def no_secrets(root, rels):
    for rel in rels:
        raw = read(root, rel)
        if raw is None:
            continue
        ok(not SECRET.search(raw.decode('utf-8', 'replace')), f'{rel}: sem padrao de segredo')


def require_files(root, rels):
    for rel in rels:
        raw = read(root, rel)
        ok(raw is not None and len(raw.strip()) > 0, f'{rel}: presente e nao vazio')
    no_secrets(root, rels)


def cases_file(root, rel, required_ids, field='resultado', expected=('recusado', 'passou')):
    data = load_json(root, rel)
    if data is None:
        return
    rows = data.get('casos') if isinstance(data, dict) else data
    if not ok(isinstance(rows, list), f'{rel}: lista "casos"'):
        return
    by = {str(r.get('id')): r for r in rows if isinstance(r, dict)}
    for cid in required_ids:
        r = by.get(cid)
        ok(r is not None and r.get(field) in expected and bool(r.get('registro')),
           f'{rel}: caso {cid} com {field} em {expected} e registro')
    no_secrets(root, [rel])


# ---------------- regras por tarefa ----------------
def r0_01(root, keys):
    # Inventario de credenciais SEM valores (matriz v2 + DP-19/20/21) e teste de escopo.
    require_files(root, [f'{EVID}/R0-01/inventario-credenciais.md', f'{EVID}/R0-01/teste-escopo.json'])
    data = load_json(root, f'{EVID}/R0-01/teste-escopo.json') or {}
    rows = data.get('casos', []) if isinstance(data, dict) else []
    ok(len(rows) >= 1 and all(r.get('resultado') == 'recusado' for r in rows),
       'teste-escopo: toda chave testada recusada fora do escopo')
    inv = (read(root, f'{EVID}/R0-01/inventario-credenciais.md') or b'').decode('utf-8', 'replace')
    ok('50' in inv and ('US$' in inv or 'USD' in inv), 'inventario: teto de US$ 50 registrado')


def r0_02(root, keys):
    data = load_json(root, 'governance/decisions.yaml')
    if data is None:
        return
    ok(isinstance(data, list) and len(data) >= 41, f'decisions.yaml: >= 41 decisoes (proposta R0-02 v2) — tem {len(data) if isinstance(data, list) else "?"}')
    if isinstance(data, list):
        ids = [d.get('id') for d in data if isinstance(d, dict)]
        ok(len(ids) == len(set(ids)) == len(data), 'decisions.yaml: ids unicos')
        ok(all(isinstance(d, dict) and d.get('id') and d.get('escolha') and d.get('referencia') for d in data),
           'decisions.yaml: cada decisao com id, escolha e referencia')
        ok({'D01', 'D09', 'D10', 'D11'}.issubset(set(ids)), 'decisions.yaml: decisoes de 21/11 (D01..D11) presentes')


def r0_03(root, keys):
    ident = load_json(root, 'governance/identities.yaml') or {}
    fps = [ident.get('root_fingerprint')] + [(ident.get(k) or {}).get('fingerprint') for k in ('executor', 'reviewer', 'verifier')]
    ok(ident.get('status') == 'configured' and all(re.fullmatch(r'[0-9A-F]{40}', f or '') for f in fps) and len(set(fps)) == 4,
       'identities.yaml: configured, 4 fingerprints distintas')
    ok((ident.get('executor') or {}).get('provider') != (ident.get('reviewer') or {}).get('provider'),
       'identities.yaml: executor e revisor de provedores distintos')
    # Matriz de recusas do 02 v3 par.6 (casos 1-9) com registro de cada tentativa.
    cases_file(root, f'{EVID}/R0-03/matriz-recusas.json', [str(i) for i in range(1, 10)],
               expected=('recusado', 'passou', 'conforme'))


def r0_04(root, keys):
    # Tags v1.0/v2.0 anotadas, assinadas pela raiz, arvores = manifestos (7 e 11), v1.0 contida na v2.0.
    raiz = pathlib.Path(keys) / 'raiz.asc' if keys else None
    for tag, prefix, n in (('v1.0', 'baseline-v1.0', 7), ('v2.0', 'spec-v2.0', 11)):
        t = git(root, 'cat-file', '-t', tag)
        if not ok(t is not None and t.stdout.decode().strip() == 'tag', f'{tag}: tag anotada presente'):
            continue
        if raiz and raiz.is_file():
            with tempfile.TemporaryDirectory() as gh:
                env = {**os.environ, 'GNUPGHOME': gh}
                subprocess.run(['gpg', '--batch', '--quiet', '--import', str(raiz)], env=env, capture_output=True)
                v = subprocess.run(['git', '-C', str(root), '-c', 'safe.directory=*', 'verify-tag', '--raw', tag], env=env, capture_output=True)
                fpr = subprocess.run(['gpg', '--batch', '--with-colons', '--list-keys'], env=env, capture_output=True).stdout.decode()
                root_fprs = {l.split(':')[9] for l in fpr.splitlines() if l.startswith('fpr:')}
                sig = [l for l in v.stderr.decode('utf-8', 'replace').splitlines() if l.startswith('[GNUPG:] VALIDSIG ')]
                ok(v.returncode == 0 and any(set(l.split()[2:]) & root_fprs for l in sig), f'{tag}: assinatura valida da raiz')
                subprocess.run(['gpgconf', '--kill', 'all'], env=env, capture_output=True)
        else:
            ok(False, f'{tag}: chave publica da raiz ausente em --keys')
        man = git(root, 'show', f'{tag}:{prefix}/manifest_sha256.json')
        if not ok(man is not None, f'{tag}: {prefix}/manifest_sha256.json'):
            continue
        try:
            m = json.loads(man.stdout.decode('utf-8-sig'))
        except ValueError:
            ok(False, f'{tag}: manifesto invalido')
            continue
        entries = m.get('files', m) if isinstance(m, dict) else {x['path']: x['sha256'] for x in m}
        if isinstance(entries, list):
            entries = {x.get('path') or x.get('caminho'): x.get('sha256') for x in entries}
        good = 0
        for rel, want in entries.items():
            blob = git(root, 'cat-file', 'blob', f'{tag}:{prefix}/{rel}')
            good += bool(blob is not None and hashlib.sha256(blob.stdout).hexdigest() == str(want).lower())
        ok(good == len(entries) and len(entries) >= n, f'{tag}: {good}/{len(entries)} blobs conferem com o manifesto (minimo {n})')
    v1 = git(root, 'ls-tree', '-r', 'v1.0', '--', 'baseline-v1.0')
    v2 = git(root, 'ls-tree', '-r', 'v2.0', '--', 'baseline-v1.0')
    ok(v1 is not None and v2 is not None and v1.stdout == v2.stdout and v1.stdout, 'v1.0 intacta dentro da arvore da v2.0')
    for name, want in (('agents.registry.json', 64), ('workflows.registry.json', 17), ('meetings.registry.json', 28)):
        files = git(root, 'ls-tree', '-r', '--name-only', 'v2.0', '--', 'spec-v2.0')
        path = next((f for f in (files.stdout.decode().splitlines() if files else []) if f.endswith('/' + name)), None)
        cnt = None
        if path:
            try:
                d = json.loads(git(root, 'show', f'v2.0:{path}').stdout.decode('utf-8-sig'))
                lst = next((v for v in (d.values() if isinstance(d, dict) else [d]) if isinstance(v, list)), d)
                cnt = len(lst) if isinstance(lst, list) else None
            except (ValueError, AttributeError):
                cnt = None
        ok(cnt == want, f'v2.0: {name} = {want} (achou {cnt})')


def r0_05(root, keys):
    ok(False, 'R0-05 usa R0-05-TEST (tests/test_governance.py) e R0-05-BYTES na politica; check_r0 nao se aplica')


def r0_06(root, keys):
    # Registro dos tres casos do verificador autonomo (backlog R0-06) com o run e o log de cada um.
    cases_file(root, f'{EVID}/R0-06/casos-verificador.json', ['tag-executor-invalida', 'gate-teste-falho-sem-tag', 'mudanca-executor-no-verificador'],
               expected=('passou', 'recusado'))


def r0_07(root, keys):
    require_files(root, [f'{EVID}/R0-07/inventario-vertra.md', f'{EVID}/R0-07/teste-escrita-negada.json'])
    cases_file(root, f'{EVID}/R0-07/teste-escrita-negada.json', ['escrita-com-chave-leitura'], expected=('recusado',))


def r0_08(root, keys):
    for n in range(1, 17):
        hits = sorted((root / 'docs' / 'adr').glob(f'ADR-{n:03d}*.md'))
        if ok(len(hits) == 1, f'docs/adr/ADR-{n:03d}*.md: exatamente um arquivo'):
            txt = hits[0].read_text(encoding='utf-8', errors='replace')
            ok(re.search(r'crit[eé]rio', txt, re.I) is not None, f'{hits[0].name}: tem criterio verificavel')
            no_secrets(root, [hits[0].relative_to(root).as_posix()])


def r0_09(root, keys):
    require_files(root, [f'{EVID}/R0-09/relatorio-marca-dominio.md'])


def r0_10(root, keys):
    data = load_json(root, 'governance/legal.yaml')
    if data is None:
        return
    pontos = data.get('pontos') if isinstance(data, dict) else None
    allowed = {'coberto_por_parecer', 'decidido_pelo_responsavel_sem_parecer', 'em_aberto'}
    ok(isinstance(pontos, list) and len(pontos) >= 18, f'legal.yaml: >= 18 pontos (proposta R0-10 v4)')
    if isinstance(pontos, list):
        ok(all(isinstance(p, dict) and p.get('id') and p.get('situacao') in allowed for p in pontos),
           f'legal.yaml: cada ponto com situacao em {sorted(allowed)}')
    no_secrets(root, ['governance/legal.yaml'])


def r0_11(root, keys):
    data = load_json(root, 'governance/backlog.yaml')
    if not isinstance(data, list):
        ok(False, 'backlog.yaml: lista')
        return
    ids = {t.get('id') for t in data}
    ok(len(ids) == len(data), 'backlog.yaml: ids unicos')
    ok(all(d in ids for t in data for d in t.get('dependencies', [])), 'backlog.yaml: toda dependencia existe')
    graph = {t['id']: list(t.get('dependencies', [])) for t in data}
    state, cyc = {}, []

    def visit(n, stack):
        if state.get(n) == 1:
            cyc.append(n)
            return
        if state.get(n) == 2:
            return
        state[n] = 1
        for d in graph.get(n, []):
            visit(d, stack + [n])
        state[n] = 2
    for n in graph:
        visit(n, [])
    ok(not cyc, 'backlog.yaml: sem ciclos')
    ok(sum(1 for t in data if t.get('kind') == 'gate') >= 7, 'backlog.yaml: gates de onda presentes (>= 7)')


def r0_12(root, keys):
    # Gate R0: todas as regras das tarefas da onda (R0-05 tem testes proprios na politica).
    for t in ('R0-01', 'R0-02', 'R0-03', 'R0-04', 'R0-06', 'R0-07', 'R0-08', 'R0-09', 'R0-10', 'R0-11'):
        print(f'--- {t}')
        RULES[t](root, keys)


RULES = {'R0-01': r0_01, 'R0-02': r0_02, 'R0-03': r0_03, 'R0-04': r0_04, 'R0-05': r0_05, 'R0-06': r0_06,
         'R0-07': r0_07, 'R0-08': r0_08, 'R0-09': r0_09, 'R0-10': r0_10, 'R0-11': r0_11, 'R0-12': r0_12}


def main(argv):
    if len(argv) < 3:
        print('uso: check_r0.py <TAREFA> <raiz> [--keys <dir>]')
        return 2
    task, root = argv[1], pathlib.Path(argv[2]).resolve()
    keys = argv[argv.index('--keys') + 1] if '--keys' in argv else None
    rule = RULES.get(task)
    if rule is None:
        print(f'FALHA tarefa sem regra: {task}')
        return 1
    if not (root / 'governance').is_dir():
        print('FALHA raiz do produto invalida')
        return 1
    rule(root, keys)
    print(f'RESULTADO {task}: ' + ('ok' if not FAILS else f'FALHOU ({len(FAILS)})'))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
