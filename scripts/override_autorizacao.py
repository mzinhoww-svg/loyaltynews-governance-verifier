#!/usr/bin/env python3
"""DP-45: prepara o documento de autorizacao do accept-override (ln-override/1) para a RAIZ assinar fora do CI.

Uso (maquina do PM, sem segredo; so le o clone publico do produto com as tags):
  override_autorizacao.py mostrar   --product <clone> --task R0-NN --target <sha>
      -> lista os criterios NAO atendidos e os problemas do parecer review/<T>/<alvo>, com indice e justificativa
  override_autorizacao.py preparar  --product <clone> --task R0-NN --target <sha> --mapa mapa.json --out autorizacao.json
      mapa.json: {"criterios": [{"indice": 0, "dps": ["DP-44"]}], "problemas": [{"indice": 0, "dps": ["DP-33"]}], "nota": "..."}
      -> grava os bytes CANONICOS que a raiz assina (gpg --detach-sign) e imprime o dp= da entrada do workflow
  override_autorizacao.py empacotar --doc autorizacao.json --sig autorizacao.json.sig --out entrada-override.txt
      -> "<doc_b64>.<sig_b64>" (entrada 'override' do workflow) e confere a assinatura da raiz com keys/raiz.asc

O parecer e conferido pela chave PUBLICA do revisor (keys/ deste repo) e o hash do payload e o mesmo que o kit recalcula.
As DPs tem de existir no governance/decisions.yaml do alvo, junto com a DP-45. Nada aqui assina nem chama o GitHub.
"""
import argparse
import base64
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'kit'))
from lnsign import SHA, TASK, Keyring, SignError, canon, git, verify_tag  # noqa: E402
from verifier import DPID, root_signed_bytes  # noqa: E402
from gov import digest  # noqa: E402


KEYS = HERE.parent / 'keys'


def load_trust(path=None):
    return json.loads(pathlib.Path(path or HERE.parent / 'trust.json').read_text(encoding='utf-8'))


def read_review(product, task, target, trust):
    kr = Keyring(KEYS)
    try:
        name = f'review/{task}/{target}'
        pl = verify_tag(product, kr, name, trust['reviewer']['fingerprint'], target)
        if not pl:
            raise SignError(f'{name} ausente ou sem assinatura valida do revisor')
        oid = git(product, 'rev-parse', 'refs/tags/' + name).stdout.decode().strip()
        return name, oid, pl
    finally:
        kr.close()


def lists(pl):
    crit, probs = pl.get('criterios'), pl.get('problemas')
    if pl.get('decision') != 'unfavorable':
        raise SignError('parecer nao e desfavoravel: override nao se aplica')
    if not isinstance(crit, list) or not isinstance(probs, list):
        raise SignError('parecer sem criterios gravados (tag anterior ao ato DP-45): override nao se aplica')
    return [c for c in crit if c.get('atendido') is not True], probs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('acao', choices=['mostrar', 'preparar', 'empacotar'])
    for x in ('--product', '--task', '--target', '--mapa', '--out', '--doc', '--sig', '--trust', '--keys'):
        ap.add_argument(x)
    a = ap.parse_args()
    global KEYS
    KEYS = pathlib.Path(a.keys) if a.keys else KEYS
    trust = load_trust(a.trust)
    try:
        if a.acao == 'empacotar':
            doc, sig = pathlib.Path(a.doc).read_bytes(), pathlib.Path(a.sig).read_bytes()
            kr = Keyring(KEYS)
            try:
                import os
                old = os.environ.get('GNUPGHOME')
                os.environ['GNUPGHOME'] = kr.dir
                ok = root_signed_bytes(doc, sig, trust['root_fingerprint'])
            finally:
                if old is None:
                    os.environ.pop('GNUPGHOME', None)
                else:
                    os.environ['GNUPGHOME'] = old
                kr.close()
            if not ok:
                raise SignError('assinatura destacada NAO e da raiz (ou nao confere com o documento)')
            out = base64.b64encode(doc).decode() + '.' + base64.b64encode(sig).decode()
            pathlib.Path(a.out).write_text(out, encoding='ascii', newline='')
            print(f'ok: assinatura da raiz confere; entrada gravada em {a.out} ({len(out)} caracteres); autorizacao_sha256 {digest(doc)}')
            return 0
        if not (a.product and a.task and a.target and SHA.match(a.target) and TASK.match(a.task)):
            raise SignError('informe --product, --task R0-NN e --target <sha de 40>')
        product = pathlib.Path(a.product).resolve()
        name, oid, pl = read_review(product, a.task, a.target, trust)
        failed, probs = lists(pl)
        if a.acao == 'mostrar':
            print(f'parecer {name} (objeto {oid[:12]}): {pl.get("criterios_atendidos")}/{pl.get("criterios_total")} atendidos')
            for i, c in enumerate(failed):
                print(f'criterio[{i}] NAO atendido: {c.get("criterio")}\n    justificativa: {c.get("justificativa")}')
            for i, p in enumerate(probs):
                print(f'problema[{i}]: {p}')
            print(f'resumo: {pl.get("resumo")}')
            return 0
        mapa = json.loads(pathlib.Path(a.mapa).read_text(encoding='utf-8'))
        decs = json.loads(git(product, 'show', f'{a.target}:governance/decisions.yaml').stdout)
        ids = {d.get('id') for d in decs if isinstance(d, dict)}
        if 'DP-45' not in ids:
            raise SignError('DP-45 ausente no decisions.yaml do alvo')
        m = {'criterios': [], 'problemas': []}
        for key, src, field in (('criterios', failed, 'criterio'), ('problemas', probs, None)):
            seen = set()
            for e in mapa.get(key, []):
                i, dps = e['indice'], sorted(set(e['dps']))
                if not (0 <= i < len(src)) or i in seen or not dps or not all(DPID.match(x) and x in ids for x in dps):
                    raise SignError(f'mapa.{key}: indice {i} invalido/repetido ou DP inexistente no alvo: {dps}')
                seen.add(i)
                m[key].append({'texto': src[i][field] if field else src[i], 'dps': dps})
            if seen != set(range(len(src))):
                raise SignError(f'mapa.{key}: faltam indices {sorted(set(range(len(src))) - seen)} (todo ponto do parecer precisa de DP)')
        dps = sorted({x for k in m for e in m[k] for x in e['dps']})
        doc = {'formato': 'ln-override/1', 'base': 'DP-45', 'tarefa': a.task, 'alvo': a.target, 'dps': dps,
               'parecer': {'tag': name, 'oid': oid, 'payload_sha256': digest(canon(pl))}, 'mapeamento': m}
        if mapa.get('nota'):
            doc['nota'] = str(mapa['nota'])[:1000]
        raw = canon(doc)
        pathlib.Path(a.out).write_bytes(raw)
        print(f'ok: {a.out} ({len(raw)} bytes, sha256 {digest(raw)}); dp={",".join(dps)}')
        return 0
    except (SignError, KeyError, ValueError, OSError, TypeError) as e:
        print('FALHOU: ' + (str(e) if isinstance(e, (SignError, KeyError)) else type(e).__name__ + ': ' + str(e)))
        return 1


if __name__ == '__main__':
    sys.exit(main())
