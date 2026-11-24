#!/usr/bin/env python3
"""Job revisor (R0-06): parecer de OUTRO provedor (OpenAI via OpenRouter) sobre a tarefa no commit alvo.

Uso: review.py --product <clone limpo no alvo> --target <sha> --task <R0-NN> --trust <trust.json>
               --config reviewer/config.json --runner-report <runner-report.json> --out <dir>
Ambiente: OPENROUTER_API_KEY (segredo do ambiente 'reviewer'), REVIEWER_GPG_PRIVATE_KEY e REVIEWER_GPG_PASSPHRASE.
          OPENROUTER_BASE_URL so para teste local (servidor falso).

Faz, em ordem, falhando fechado:
 1. confere alvo, checkout limpo, trust (executor e revisor de provedores distintos) e configuracao;
 2. NAO chama o modelo se a evidencia nao existe ou se o relatorio do runner tem teste ausente/falho (economiza saldo);
 3. monta o pacote (tarefa, evidencia, artefatos com sha256 conferido, relatorio, resumo do diff), com teto de tamanho;
 4. estima o custo ANTES da chamada e recusa acima de max_cost_usd_per_call;
 5. chama /api/v1/chat/completions com provider.only=[openai] + allow_fallbacks=false + data_collection=deny,
    saida em JSON com esquema estrito;
 6. confere em /api/v1/generation: provider_name aceito, model igual ao da resposta e na lista aceita;
 7. assina a tag review/<T>/<alvo> com a chave do revisor e exporta o objeto (review-tag.txt) para o assinador.
Log publico: so provider, modelo, id da geracao, versao do prompt, custo e decisao. Nunca o prompt nem a resposta.
A TAG review/ (24/11, DP-45) grava tambem criterios[] (atendido + justificativa), problemas e resumo, com teto por campo e
padroes de credencial redigidos: e o registro auditavel que o accept-override exige.
"""
import argparse
import hashlib
import json
import os
import re
import pathlib
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'scripts'))
from lnsign import SHA, TASK, Keyring, SignError, canon, export_tag, git, sign_tag  # noqa: E402

SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'required': ['decision', 'criterios', 'problemas', 'resumo'],
    'properties': {
        'decision': {'type': 'string', 'enum': ['favorable', 'unfavorable']},
        'criterios': {'type': 'array', 'items': {'type': 'object', 'additionalProperties': False,
                                                 'required': ['criterio', 'atendido', 'justificativa'],
                                                 'properties': {'criterio': {'type': 'string'}, 'atendido': {'type': 'boolean'},
                                                                'justificativa': {'type': 'string'}}}},
        'problemas': {'type': 'array', 'items': {'type': 'string'}},
        'resumo': {'type': 'string'},
    },
}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def log(msg):
    print('[revisor] ' + msg, flush=True)


def same_model(model_id):
    """Id do modelo sem o sufixo de data -AAAAMMDD (unica normalizacao aceita na proveniencia)."""
    return re.sub(r'-\d{8}$', '', model_id or '')


def http_json(url, key, body=None, timeout=120):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method='POST' if body is not None else 'GET',
                                 headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json',
                                          'X-Title': 'LN Verifier reviewer'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise SignError(f'HTTP {e.code} em {url.split("/api/")[-1]}')
    except (urllib.error.URLError, TimeoutError) as e:
        raise SignError(f'rede: {type(e).__name__}')


def show(repo, target, path):
    p = git(repo, 'show', f'{target}:{path}', check=False)
    return None if p.returncode else p.stdout


DEC_ID = re.compile(r'\b(DP-\d{2,3}|D\d{2})\b')
MAX_ITEMS = 24
SECRET = re.compile(r'(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}'
                    r'|xox[abprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY( BLOCK)?-----)')


def clip(s, n):
    """Texto do parecer para a tag: string, padroes de credencial redigidos, teto de n caracteres (com aviso)."""
    s = SECRET.sub('[REDIGIDO]', s if isinstance(s, str) else '')
    return s if len(s) <= n else s[:n - 12] + ' [CORTADO]'


def _water_fill(lens, avail):
    """Divide `avail` caracteres entre artefatos: os menores entram inteiros, o que sobra e dividido igualmente entre os maiores."""
    alloc, pend, rest = {}, sorted(lens, key=lambda k: lens[k]), max(0, avail)
    while pend:
        share = rest // len(pend)
        if lens[pend[0]] <= share:
            k = pend.pop(0)
            alloc[k] = lens[k]
            rest -= lens[k]
        else:
            for k in pend:
                alloc[k] = share
            break
    return alloc


def build_package(repo, target, task, report, cfg):
    backlog = json.loads(show(repo, target, 'governance/backlog.yaml').decode('utf-8'))
    tasks = {t['id']: t for t in backlog}
    if task not in tasks:
        raise SignError('tarefa desconhecida no backlog do alvo')
    t = tasks[task]
    items = [x['id'] for x in backlog if x['gate'] == t['gate'] and x['kind'] != 'gate'] if t['kind'] == 'gate' else [task]
    keep = ('id', 'tarefa', 'teste', 'evidencia', 'criterio_de_aceite', 'dependencies', 'required_tests', 'kind', 'gate')
    parts = ['## Tarefa\n' + json.dumps({k: t.get(k) for k in keep}, ensure_ascii=False, indent=1)]
    budget = cfg['max_prompt_chars']
    evidences = {}
    for j in items:
        raw = show(repo, target, f"governance/evidence/{tasks[j]['gate']}/{j}.json")
        if raw is None:
            raise SignError(f'EVIDENCE_MISSING:{j} (modelo nao chamado)')
        evidences[j] = json.loads(raw.decode('utf-8'))
    for j, ev in evidences.items():
        parts.append(f'## Evidencia {j}\n' + json.dumps(ev, ensure_ascii=False, indent=1))
    # 24/11 (rev. 8 da R0-01, problema[2]; P3 do QA 6: logo depois da evidencia, antes dos artefatos, para o corte global no teto nunca a alcancar): a relacao entre o commit do registro de evidencia e o alvo e FATO do git, calculado
    # aqui (ancestralidade + sha256 de cada artefato nos dois commits), para o revisor nao ter de presumi-la.
    rel = []
    for j, ev in evidences.items():
        c = ev.get('commit_sha')
        if not isinstance(c, str) or not re.fullmatch(r'[0-9a-f]{40}', c):
            rel.append(f'- {j}: commit_sha do registro ausente ou invalido')
            continue
        anc = git(repo, 'merge-base', '--is-ancestor', c, target, check=False).returncode == 0
        same = []
        for a in ev.get('artefatos', []):
            b0, b1 = show(repo, c, a['caminho']), show(repo, target, a['caminho'])
            same.append(b0 is not None and b1 is not None and sha256(b0) == sha256(b1) == a.get('sha256'))
        # DP-48: o alvo vale se descende do commit do registro e SO acrescenta/altera arquivos em governance/evidence
        chg = git(repo, 'diff', '--name-only', c, target, check=False).stdout.decode(errors='replace').split() if anc else []
        fora = [x for x in chg if not x.startswith('governance/evidence/')]
        lista = (', '.join(fora[:10]) + (f' (+{len(fora) - 10})' if len(fora) > 10 else '')) if fora else ''
        rel.append(f"- {j}: registro aponta para {c[:12]}; {'E' if anc else 'NAO E'} ancestral do alvo {target[:12]} (git merge-base --is-ancestor); "
                   f"{sum(same)}/{len(same)} artefatos com o mesmo sha256 no commit do registro, no alvo e no registro; "
                   + (f"do commit do registro ao alvo mudaram {len(chg)} arquivo(s), "
                      + ("todos em governance/evidence/" if not fora else f"{len(fora)} FORA de governance/evidence/: {lista}") + ". "
                      if anc else '')
                   + "Por construcao, o gov_submit_evidence grava o commit dos artefatos e o registro entra no commit seguinte (DP-48).")
    parts.append('## Relacao do commit da evidencia com o alvo (calculada pelo verificador)\n' + '\n'.join(rel))
    # artefatos: lidos uma vez; texto decodificado (ou marcador de binario/ausente)
    arts = []
    for j, ev in evidences.items():
        for a in ev.get('artefatos', []):
            blob = show(repo, target, a['caminho'])
            okh = blob is not None and sha256(blob) == a.get('sha256')
            txt = None
            if blob is not None:
                try:
                    txt = blob.decode('utf-8')
                except UnicodeDecodeError:
                    txt = None
            arts.append((j, a['caminho'], blob, okh, txt))
    # 23/11: decisoes citadas pela evidencia ou pelos artefatos entram no pacote (governance/decisions.yaml do commit alvo)
    cited = ' '.join([json.dumps(evidences, ensure_ascii=False)] + [x[4] for x in arts if x[4]])
    ids = sorted(set(DEC_ID.findall(cited)))
    dec_raw = show(repo, target, 'governance/decisions.yaml') if ids else None
    dec_head = '## Decisoes citadas (governance/decisions.yaml no commit alvo)\n'
    if ids:
        decs = None
        if dec_raw is not None:
            try:
                decs = json.loads(dec_raw.decode('utf-8'))
            except ValueError:
                decs = None
        if not isinstance(decs, list):
            # 24/11 (nota QA 6): sem decisions.yaml legivel o pacote DIZ isso, em vez de omitir em silencio
            log('aviso: decisoes citadas, mas governance/decisions.yaml ausente ou invalido no alvo')
            parts.append(dec_head + f"[governance/decisions.yaml AUSENTE OU INVALIDO no commit alvo; ids citados: {', '.join(ids)}]")
        else:
            sel = [d for d in decs if isinstance(d, dict) and d.get('id') in ids]
            miss = [x for x in ids if x not in {d.get('id') for d in sel}]
            dtxt = json.dumps(sel, ensure_ascii=False, indent=1)
            if miss:
                dtxt += f"\n[ids citados sem entrada no decisions.yaml: {', '.join(miss)}]"
            cap = int(cfg['max_decisions_chars'])
            if len(dtxt) > cap:
                # 24/11 (nota QA 6): teto estrito, o aviso cabe dentro do teto
                mark = f'\n[TRUNCADO: {len(dtxt)} caracteres no total]'
                dtxt = dtxt[:max(0, cap - len(mark))] + mark
            parts.append(dec_head + dtxt)
    tail = ['## Relatorio do runner limpo\n' + json.dumps(report, ensure_ascii=False, indent=1)]
    parents = git(repo, 'rev-list', '--parents', '-n', '1', target).stdout.decode().split()
    if len(parents) >= 2:
        stat = git(repo, 'diff', '--stat', parents[1], target).stdout.decode()
        tail.append('## Mudancas do commit alvo (diff --stat contra o primeiro pai)\n' + stat[:4000])
    # 23/11: orcamento dos artefatos = teto - partes fixas; menores inteiros, so o excedente dos maiores e cortado (com aviso)
    head_of = lambda x: f"## Artefato {x[1]} ({x[0]}) sha256 {'confere' if x[3] else 'NAO CONFERE'}\n"
    fixed = len('\n\n'.join(parts + tail)) + sum(len(head_of(x)) + 2 for x in arts) + 400
    lens = {i: len(x[4]) for i, x in enumerate(arts) if x[4] is not None}
    alloc = _water_fill(lens, budget - fixed)
    for i, x in enumerate(arts):
        j, path, blob, okh, txt = x
        if blob is None:
            parts.append(f"## Artefato {path} ({j})\n[AUSENTE NO COMMIT ALVO]")
            continue
        if txt is None:
            body = f'[binario, {len(blob)} bytes]'
        else:
            lim = alloc.get(i, 0)
            body = txt if len(txt) <= lim else txt[:lim] + f'\n[TRUNCADO: {len(txt)} caracteres no total; mostrados {lim}]'
        parts.append(head_of(x) + body)
    pkg = '\n\n'.join(parts + tail)
    if len(pkg) > budget:
        pkg = pkg[:budget] + f'\n[PACOTE TRUNCADO NO TETO DE {budget} CARACTERES]'
    return pkg


def main():
    ap = argparse.ArgumentParser()
    for a in ('--product', '--target', '--task', '--trust', '--config', '--runner-report', '--out'):
        ap.add_argument(a, required=True)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    kr = None
    try:
        if not SHA.match(a.target) or not TASK.match(a.task):
            raise SignError('alvo ou tarefa invalidos')
        repo = pathlib.Path(a.product).resolve()
        if git(repo, 'rev-parse', 'HEAD').stdout.decode().strip() != a.target or git(repo, 'status', '--porcelain').stdout:
            raise SignError('checkout errado ou sujo')
        trust = json.load(open(a.trust, encoding='utf-8'))
        cfg = json.load(open(a.config, encoding='utf-8'))
        verifier_root = pathlib.Path(a.config).resolve().parents[1]
        if trust['executor']['provider'] == trust['reviewer']['provider']:
            raise SignError('REVIEW_NOT_INDEPENDENT: executor e revisor do mesmo provedor no trust')
        if cfg['reviewer_provider'] != trust['reviewer']['provider']:
            raise SignError('provedor do revisor na config difere do trust')
        report = json.load(open(a.runner_report, encoding='utf-8'))
        tests = report.get('tests', [])
        name = f'review/{a.task}/{a.target}'
        if report.get('commit_sha') != a.target or report.get('id') != a.task or report.get('clean_environment') is not True:
            raise SignError('relatorio do runner e de outro alvo/tarefa')
        if not tests or any(x.get('result') != 'pass' for x in tests):
            # Sem gasto: o assinador segue sem parecer e o verifier.py assina a REJEICAO com o motivo (06_MCP_SPEC caso 11).
            (out / 'review-meta.json').write_text(json.dumps({'name': name, 'skipped': 'runner_failed'}) + '\n')
            (out / 'review-tag.txt').write_bytes(b'')
            log('pulado: runner reprovou o alvo (modelo nao chamado; o assinador registra a rejeicao)')
            return 0
        key = os.environ.get('OPENROUTER_API_KEY', '')
        if not key:
            raise SignError('OPENROUTER_API_KEY ausente (falha fechada)')
        base = os.environ.get('OPENROUTER_BASE_URL') or cfg['openrouter_base_url']
        prompt = (verifier_root / cfg['prompt_file']).read_text(encoding='utf-8')
        try:
            pkg = build_package(repo, a.target, a.task, report, cfg)
        except SignError as e:
            if str(e).startswith('EVIDENCE_MISSING'):
                (out / 'review-meta.json').write_text(json.dumps({'name': name, 'skipped': 'evidence_missing'}) + '\n')
                (out / 'review-tag.txt').write_bytes(b'')
                log('pulado: ' + str(e))
                return 0
            raise
        est_in = (len(prompt) + len(pkg)) / 3.0
        est = est_in * cfg['price_usd_per_mtok']['input'] / 1e6 + cfg['max_tokens'] * cfg['price_usd_per_mtok']['output'] / 1e6
        if est > cfg['max_cost_usd_per_call']:
            raise SignError(f'custo estimado US$ {est:.4f} acima do teto {cfg["max_cost_usd_per_call"]} (modelo nao chamado)')
        body = {
            'model': cfg['model'],
            'messages': [{'role': 'system', 'content': prompt}, {'role': 'user', 'content': pkg}],
            'max_tokens': cfg['max_tokens'],   # sem 'temperature': o gpt-6.1-terra nao aceita e, com require_parameters, a OpenRouter devolvia 404 (23/11)
            'response_format': {'type': 'json_schema', 'json_schema': {'name': 'ln_review', 'strict': True, 'schema': SCHEMA}},
            'provider': {'order': cfg['provider_order'], 'only': cfg['provider_order'], 'allow_fallbacks': False,
                         'data_collection': 'deny', 'require_parameters': True},
            'usage': {'include': True},
        }
        # 23/11: so parametros declarados em supported_parameters (com require_parameters, um parametro nao aceito zera os endpoints e da 404)
        extra = sorted(set(body) - {'model', 'messages', 'provider', 'usage'} - set(cfg.get('supported_parameters') or []))
        if extra:
            raise SignError(f'parametro(s) fora de supported_parameters do config: {extra} (modelo nao chamado)')
        resp = http_json(base.rstrip('/') + '/api/v1/chat/completions', key, body)
        gid, rmodel = resp.get('id'), resp.get('model')
        content = ((resp.get('choices') or [{}])[0].get('message') or {}).get('content') or ''
        try:
            verdict = json.loads(content)
        except ValueError:
            raise SignError('resposta do modelo nao e JSON')
        if verdict.get('decision') not in ('favorable', 'unfavorable') or not isinstance(verdict.get('criterios'), list):
            raise SignError('resposta fora do esquema')
        if not gid or rmodel not in cfg['accepted_models']:
            raise SignError(f'modelo da resposta fora da lista aceita: {rmodel}')
        gen = None
        for _ in range(int(cfg['generation_lookup_retries'])):
            try:
                gen = http_json(base.rstrip('/') + '/api/v1/generation?id=' + gid, key).get('data')
                if gen:
                    break
            except SignError:
                pass
            time.sleep(float(cfg['generation_lookup_wait_sec']))
        if not gen:
            raise SignError('generation indisponivel: sem prova de upstream (falha fechada)')
        if gen.get('provider_name') not in cfg['accepted_provider_names']:
            raise SignError(f"upstream nao aceito: {gen.get('provider_name')}")
        # 23/11: a OpenRouter pode devolver o id com e sem o sufixo de data (ex.: openai/gpt-6.1-terra x openai/gpt-6.1-terra-20261026).
        # Os DOIS tem de estar em accepted_models e ser o MESMO modelo depois de tirar so o sufixo -AAAAMMDD; nada mais e normalizado.
        gmodel = gen.get('model')
        if gmodel not in cfg['accepted_models'] or same_model(gmodel) != same_model(rmodel) or same_model(rmodel) != same_model(cfg['model']):
            raise SignError(f'generation.model difere de response.model ou fora da lista aceita: {gmodel} x {rmodel}')
        fpr = trust['reviewer']['fingerprint']
        kr = Keyring(verifier_root / 'keys', 'REVIEWER_GPG_PRIVATE_KEY', 'REVIEWER_GPG_PASSPHRASE', expect_secret_fpr=fpr)
        payload = {
            'id': a.task, 'decision': verdict['decision'],
            'executor_provider': trust['executor']['provider'], 'reviewer_provider': trust['reviewer']['provider'],
            'executor_fingerprint': trust['executor']['fingerprint'], 'reviewer_fingerprint': fpr,
            'model': rmodel, 'generation_model': gmodel, 'provider_name': gen.get('provider_name'), 'generation_id': gid,
            'prompt_version': cfg['prompt_version'], 'prompt_sha256': sha256(prompt.encode()),
            'package_sha256': sha256(pkg.encode()), 'response_sha256': sha256(content.encode()),
            'runner_report_sha256': sha256(canon(report)), 'total_cost': gen.get('total_cost'),
            'criterios_atendidos': sum(1 for c in verdict['criterios'] if c.get('atendido') is True),
            'criterios_total': len(verdict['criterios']),
            # 24/11 (achado MEDIO do QA 6): total real de problemas; o override recusa se a lista gravada (teto MAX_ITEMS) for menor
            'problemas_total': len(verdict.get('problemas') or []),
            # 24/11 (DP-45): justificativas gravadas na tag, para conferir se a recusa e SO por ponto coberto por DP registrada.
            # Texto do modelo sobre artefatos publicos; com teto por campo e redacao de padroes de credencial.
            'criterios': [{'criterio': clip(c.get('criterio'), 600), 'atendido': c.get('atendido') is True,
                           'justificativa': clip(c.get('justificativa'), 1500)} for c in verdict['criterios'][:MAX_ITEMS]],
            'problemas': [clip(x, 800) for x in (verdict.get('problemas') or [])[:MAX_ITEMS]],
            'resumo': clip(verdict.get('resumo'), 2000),
            'em': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }
        sign_tag(repo, kr, fpr, name, a.target, payload, ('Loyalty Reviewer', 'reviewer@loyalty.invalid'))
        oid, raw = export_tag(repo, name)
        (out / 'review-tag.txt').write_bytes(raw)
        (out / 'review-meta.json').write_text(json.dumps({'name': name, 'oid': oid, 'decision': verdict['decision']}) + '\n')
        log(f"provider={gen.get('provider_name')} model={rmodel} generation={gid} prompt={cfg['prompt_version']} "
            f"custo={gen.get('total_cost')} decisao={verdict['decision']} tag={name}")
        return 0
    except (SignError, KeyError, ValueError, OSError) as e:
        log('FALHOU: ' + (str(e) if isinstance(e, SignError) else type(e).__name__))
        return 1
    finally:
        if kr:
            kr.close()


if __name__ == '__main__':
    sys.exit(main())
