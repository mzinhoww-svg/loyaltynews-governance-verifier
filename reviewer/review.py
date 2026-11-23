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
"""
import argparse
import hashlib
import json
import os
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
    per_art = max(2000, budget // max(1, 2 * sum(len(ev.get('artefatos', [])) for ev in evidences.values())))
    for j, ev in evidences.items():
        for a in ev.get('artefatos', []):
            blob = show(repo, target, a['caminho'])
            if blob is None:
                parts.append(f"## Artefato {a['caminho']} ({j})\n[AUSENTE NO COMMIT ALVO]")
                continue
            okh = sha256(blob) == a.get('sha256')
            try:
                txt = blob.decode('utf-8')
                body = txt if len(txt) <= per_art else txt[:per_art] + f'\n[TRUNCADO: {len(txt)} caracteres no total]'
            except UnicodeDecodeError:
                body = f'[binario, {len(blob)} bytes]'
            parts.append(f"## Artefato {a['caminho']} ({j}) sha256 {'confere' if okh else 'NAO CONFERE'}\n{body}")
    parts.append('## Relatorio do runner limpo\n' + json.dumps(report, ensure_ascii=False, indent=1))
    parents = git(repo, 'rev-list', '--parents', '-n', '1', target).stdout.decode().split()
    if len(parents) >= 2:
        stat = git(repo, 'diff', '--stat', parents[1], target).stdout.decode()
        parts.append('## Mudancas do commit alvo (diff --stat contra o primeiro pai)\n' + stat[:4000])
    pkg = '\n\n'.join(parts)
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
            'temperature': 0, 'max_tokens': cfg['max_tokens'],
            'response_format': {'type': 'json_schema', 'json_schema': {'name': 'ln_review', 'strict': True, 'schema': SCHEMA}},
            'provider': {'order': cfg['provider_order'], 'only': cfg['provider_order'], 'allow_fallbacks': False,
                         'data_collection': 'deny', 'require_parameters': True},
            'usage': {'include': True},
        }
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
        if gen.get('model') != rmodel:
            raise SignError('generation.model difere de response.model')
        fpr = trust['reviewer']['fingerprint']
        kr = Keyring(verifier_root / 'keys', 'REVIEWER_GPG_PRIVATE_KEY', 'REVIEWER_GPG_PASSPHRASE', expect_secret_fpr=fpr)
        payload = {
            'id': a.task, 'decision': verdict['decision'],
            'executor_provider': trust['executor']['provider'], 'reviewer_provider': trust['reviewer']['provider'],
            'executor_fingerprint': trust['executor']['fingerprint'], 'reviewer_fingerprint': fpr,
            'model': rmodel, 'provider_name': gen.get('provider_name'), 'generation_id': gid,
            'prompt_version': cfg['prompt_version'], 'prompt_sha256': sha256(prompt.encode()),
            'package_sha256': sha256(pkg.encode()), 'response_sha256': sha256(content.encode()),
            'runner_report_sha256': sha256(canon(report)), 'total_cost': gen.get('total_cost'),
            'criterios_atendidos': sum(1 for c in verdict['criterios'] if c.get('atendido') is True),
            'criterios_total': len(verdict['criterios']),
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
