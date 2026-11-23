#!/usr/bin/env python3
"""Descoberta automatica de alvos do verificador (02 v3 par.2; frente 12 "verificador-gates").

Uso: discover.py --product <clone do produto com origin/main e tags> --trust trust.json --keys <dir com *.asc>
                 [--limit 1] [--out alvos.json]
Sem segredos e sem rede: le um clone publico ja feito e as chaves PUBLICAS do repo verificador. Nao assina nada.
Saida (stdout e --out): {"alvos": [{"task", "target", "mode", "motivo"}], "pulados": [{"task", "target", "motivo"}]}

Regras (as mesmas que o assinador e o kit aplicam; a descoberta so evita disparar o que seria recusado):
 - Cadeia: so a cadeia de primeiro pai de origin/main que ja contem o baseline_commit do trust (antes dele o kit recusa,
   UNTRUSTED_BASELINE). Processa do mais antigo para o mais novo.
 - Tarefa: merge commit Mi (exatamente 2 pais) cujo diff Mi^1..Mi cria ou altera governance/evidence/<onda>/<id>.json.
   Alvo = Mi; exige arvore(Mi) = arvore(Mi^2) (senao ARVORE_DIVERGENTE: o assinador recusa; ciclo manual ou revert).
 - Pula: tarefa ja aceita (tag_for assinada pelo verificador e valida), rejeicao ja emitida para (T, Mi), tarefa
   desconhecida/adiada/gate, evidencia removida, onda do caminho diferente da onda da tarefa, dependencia ainda nao aceita
   (volta a ser candidata depois), P0 aberto ligado a tarefa, outro Mi da mesma tarefa pendente antes.
 - Gate (policy.gate_tasks): quando todas as tarefas da onda tem aceite valido e o gate nao, alvo = ponta da cadeia
   (origin/main), se nao houver rejeicao em (gate, ponta).
 - --limit (padrao 1): o workflow processa um alvo por execucao (custo do revisor; concurrency do workflow).
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

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'kit'))
from gov import Gov, Denied, git  # noqa: E402

SHA = re.compile(r'^[0-9a-f]{40}$')
EVID = re.compile(r'^governance/evidence/([^/]+)/([^/]+)\.json$')


def out_lines(repo, *args):
    return [x for x in git(repo, *args).stdout.decode().split('\n') if x]


def has_tag(repo, name):
    return git(repo, 'rev-parse', '-q', '--verify', 'refs/tags/' + name, check=False).returncode == 0


def is_ancestor(repo, a, b):
    return git(repo, 'merge-base', '--is-ancestor', a, b, check=False).returncode == 0


def discover(repo, trust, limit):
    git(repo, 'checkout', '-q', '--detach', 'origin/main')
    if git(repo, 'status', '--porcelain').stdout:
        raise SystemExit('clone do produto sujo')
    tip = git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()
    base = trust['baseline_commit']
    if not SHA.match(base) or not is_ancestor(repo, base, tip):
        raise SystemExit('baseline do trust ausente da main do produto')
    g = Gov(repo, trust=trust, role='verifier')
    chain = out_lines(repo, 'rev-list', '--first-parent', '--reverse', 'origin/main')
    start = next(i for i, c in enumerate(chain) if is_ancestor(repo, base, c))   # monotono na cadeia de primeiro pai
    alvos, pulados, pendente = [], [], set()

    def pula(task, target, motivo):
        pulados.append({'task': task, 'target': target, 'motivo': motivo})

    for m in chain[start:]:
        parents = git(repo, 'rev-list', '--parents', '-n', '1', m).stdout.decode().split()
        changed = out_lines(repo, 'diff', '--name-only', parents[1] if len(parents) > 1 else m, m, '--', 'governance/evidence/') if len(parents) > 1 else []
        tasks = []
        for path in changed:
            mm = EVID.match(path)
            if mm:
                tasks.append((mm.group(1), mm.group(2), path))
        if len(parents) == 2 and tasks:
            for _, t, _ in tasks:
                pula(t, m, 'COMMIT_SEM_MERGE: evidencia entrou na main sem merge commit (o aceite de tarefa exige Mi)')
            continue
        if len(parents) != 3:
            continue
        for onda, t, path in tasks:
            if t not in g.tasks:
                pula(t, m, 'TAREFA_DESCONHECIDA'); continue
            task = g.tasks[t]
            if task['kind'] == 'gate' or task.get('deferred'):
                pula(t, m, 'GATE_OU_ADIADA'); continue
            if task['gate'] != onda:
                pula(t, m, 'ONDA_DIVERGENTE'); continue
            if git(repo, 'cat-file', '-e', f'{m}:{path}', check=False).returncode:
                pula(t, m, 'EVIDENCIA_REMOVIDA'); continue
            if g.accepted(t):
                pula(t, m, 'JA_ACEITA'); continue
            if has_tag(repo, f'task/{t}/rejected/{m}'):
                pula(t, m, 'REJEICAO_JA_EMITIDA'); continue
            if t in pendente:
                pula(t, m, 'OUTRO_ALVO_DA_TAREFA_PENDENTE_ANTES'); continue
            if git(repo, 'rev-parse', m + '^{tree}').stdout != git(repo, 'rev-parse', parents[2] + '^{tree}').stdout:
                pula(t, m, 'ARVORE_DIVERGENTE'); continue
            deps = [d['id'] for d in g.deps(t) if not d['accepted']]
            if deps:
                pula(t, m, 'DEP_NAO_ACEITA:' + ','.join(deps)); continue
            p0 = g.p0(t)
            if p0:
                pula(t, m, 'P0_ABERTO:' + ','.join(p0)); continue
            pendente.add(t)
            alvos.append({'task': t, 'target': m, 'mode': 'accept', 'motivo': 'evidencia em merge commit, sem aceite'})

    for onda, gid in sorted(g.policy.get('gate_tasks', {}).items()):
        if gid not in g.tasks or g.accepted(gid):
            continue
        itens = [x['id'] for x in g.tasks.values() if x['gate'] == onda and x['kind'] != 'gate']
        falta = [x for x in itens if not g.accepted(x)]
        if falta:
            pula(gid, tip, f'GATE_AGUARDA:{len(falta)}/{len(itens)}'); continue
        rej = g.tag_for(gid).removesuffix('/accepted') + '/rejected/' + tip
        if has_tag(repo, rej):
            pula(gid, tip, 'REJEICAO_JA_EMITIDA'); continue
        alvos.append({'task': gid, 'target': tip, 'mode': 'accept', 'motivo': f'todas as {len(itens)} tarefas da onda {onda} aceitas'})
    return {'alvos': alvos[:max(0, limit)], 'pulados': pulados, 'total_candidatos': len(alvos)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--product', required=True)
    ap.add_argument('--trust', required=True)
    ap.add_argument('--keys', required=True)
    ap.add_argument('--limit', type=int, default=1)
    ap.add_argument('--out')
    a = ap.parse_args()
    repo = pathlib.Path(a.product).resolve()
    trust_path = pathlib.Path(a.trust).resolve()
    if trust_path.is_relative_to(repo):
        raise SystemExit('TRUST_MUST_BE_EXTERNAL')
    trust = json.load(open(trust_path, encoding='utf-8'))
    home = tempfile.mkdtemp(prefix='ln-discover-gnupg-')
    old = os.environ.get('GNUPGHOME')
    try:
        os.chmod(home, 0o700)
        os.environ['GNUPGHOME'] = home   # chaveiro descartavel, so com as chaves PUBLICAS do repo verificador
        for f in sorted(pathlib.Path(a.keys).glob('*.asc')):
            subprocess.run(['gpg', '--batch', '--quiet', '--import', str(f)], check=True, capture_output=True)
        res = discover(repo, trust, a.limit)
    except Denied as e:
        raise SystemExit('descoberta recusada: ' + str(e))
    finally:
        subprocess.run(['gpgconf', '--homedir', home, '--kill', 'all'], capture_output=True)
        if old is None:
            os.environ.pop('GNUPGHOME', None)
        else:
            os.environ['GNUPGHOME'] = old
        shutil.rmtree(home, ignore_errors=True)
    txt = json.dumps(res, ensure_ascii=False, indent=2)
    if a.out:
        pathlib.Path(a.out).write_text(txt + '\n', encoding='utf-8')
    print(txt)


if __name__ == '__main__':
    main()
