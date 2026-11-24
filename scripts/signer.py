#!/usr/bin/env python3
"""Job assinador (R0-06): sela os checks, confere o parecer do revisor, roda kit/verifier.py e empurra SO as refs validadas.

Uso: signer.py --product <clone limpo do produto, com tags> --target <sha> --task <R0-NN> --mode accept|premerge
               --trust trust.json --policy checks/r0-policy.json --runner-report runner-report.json
               --review-tag review-tag.txt --review-meta review-meta.json --push-url <url do produto> [--no-push]
Ambiente: VERIFIER_GPG_PRIVATE_KEY, VERIFIER_GPG_PASSPHRASE, APP_TOKEN (token da App LN Verifier, so tags).

Pre-condicao: o relatorio do runner ja passou por scripts/provenance.py no mesmo job (workflow).
Regras (02 v3 par.2 e 03 v2/v3):
 - accept, tarefa: alvo Mi na cadeia de primeiro pai de origin/main, Mi^2 = Hi e arvore(Mi) = arvore(Hi);
 - accept, gate: alvo na cadeia de primeiro pai de origin/main;
 - premerge: alvo qualquer commit do produto; so checks/ e review/, nunca aceite.
 - checks/<T>/<alvo>: assinada pelo verificador com o relatorio do runner (clean_environment, politica, testes).
 - review/<T>/<alvo>: objeto vindo do revisor, reconstruido byte a byte (git mktag) e verificado pela chave do revisor.
 - aceite/rejeicao: kit/verifier.py (gov_accept_gate), que assina task/<T>/accepted ou task/<T>/rejected/<alvo>.
 - push: cada ref criada nesta execucao e reverificada (tipo, assinante, alvo, payload) antes; sem --force; so refs/tags/.
 - accept-override (DP-45, 24/11): mesmo alvo do accept; runner desta execucao 100% aprovado; parecer CONTRARIO existente
   (review/<T>/<alvo>, com criterios gravados); autorizacao ln-override/1 assinada pela RAIZ (--override-file) e --dp iguais
   ao documento. Quem confere a raiz, as DPs no decisions.yaml do alvo e o mapeamento criterio/problema -> DP e o kit
   (gov_accept_override). Recusa = nenhuma tag assinada, nada empurrado (sem tag de rejeicao nova).
"""
import argparse
import base64
import json
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from lnsign import SHA, TASK, Keyring, SignError, git, git_err, import_tag, sign_tag, verify_tag  # noqa: E402


def log(msg):
    print('[assinador] ' + msg, flush=True)


def first_parent_chain(repo):
    return set(git(repo, 'rev-list', '--first-parent', 'origin/main').stdout.decode().split())


def main():
    ap = argparse.ArgumentParser()
    for a in ('--product', '--target', '--task', '--mode', '--trust', '--policy', '--runner-report', '--push-url'):
        ap.add_argument(a, required=True)
    ap.add_argument('--review-tag')
    ap.add_argument('--review-meta')
    ap.add_argument('--override-file')   # accept-override (DP-45): "<doc_b64>.<sig_b64>" assinado pela raiz
    ap.add_argument('--dp')              # accept-override: DPs citadas, ordenadas, separadas por virgula
    ap.add_argument('--no-push', action='store_true')
    a = ap.parse_args()
    kr = None
    created = []
    try:
        if not SHA.match(a.target) or not TASK.match(a.task) or a.mode not in ('accept', 'premerge', 'accept-override'):
            raise SignError('entrada invalida')
        override = a.mode == 'accept-override'
        if override:
            if not a.dp or not re.fullmatch(r'(DP-\d{2,3}|D\d{2})(,(DP-\d{2,3}|D\d{2}))*', a.dp):
                raise SignError('accept-override sem DP valida (recusado)')
            if not a.override_file or not pathlib.Path(a.override_file).is_file():
                raise SignError('accept-override sem autorizacao da raiz (recusado)')
        elif not a.review_tag or not a.review_meta:
            raise SignError('entrada invalida: parecer do revisor ausente')
        repo = pathlib.Path(a.product).resolve()
        trust_path = pathlib.Path(a.trust).resolve()
        if trust_path.is_relative_to(repo):
            raise SignError('TRUST_MUST_BE_EXTERNAL')
        trust = json.load(open(trust_path, encoding='utf-8'))
        git(repo, 'checkout', '-q', '--detach', a.target)
        if git(repo, 'rev-parse', 'HEAD').stdout.decode().strip() != a.target or git(repo, 'status', '--porcelain').stdout:
            raise SignError('checkout errado ou sujo')
        backlog = {t['id']: t for t in json.loads(git(repo, 'show', f'{a.target}:governance/backlog.yaml').stdout)}
        if a.task not in backlog:
            raise SignError('tarefa desconhecida')
        is_gate = backlog[a.task]['kind'] == 'gate'

        # 02 v3 par.2: alvo do aceite (o override segue a mesma regra)
        if a.mode in ('accept', 'accept-override'):
            if a.target not in first_parent_chain(repo):
                raise SignError('alvo fora da cadeia de primeiro pai de origin/main')
            if not is_gate:
                parents = git(repo, 'rev-list', '--parents', '-n', '1', a.target).stdout.decode().split()
                if len(parents) != 3:
                    raise SignError('alvo do aceite de tarefa precisa ser o merge commit Mi')
                h = parents[2]
                if git(repo, 'rev-parse', a.target + '^{tree}').stdout != git(repo, 'rev-parse', h + '^{tree}').stdout:
                    raise SignError('ARVORE_DIVERGENTE: arvore(Mi) != arvore(Hi); exige ciclo completo sobre Mi (02 v3 par.2.5)')

        # Relatorio do runner (ja validado por provenance.py)
        report = json.load(open(a.runner_report, encoding='utf-8'))
        if report.get('id') != a.task or report.get('commit_sha') != a.target or report.get('clean_environment') is not True \
                or report.get('runner_policy_sha256') != trust['runner_policy_sha256']:
            raise SignError('relatorio do runner nao corresponde a tarefa/alvo/politica')
        if override and (not report.get('tests') or any(t.get('result') != 'pass' for t in report['tests'])):
            # DP-45 nao vale para falha de teste: runner falho = override recusado, nada assinado nem empurrado
            raise SignError('accept-override recusado: runner com teste ausente ou falho (DP-45 nao cobre falha de teste)')

        vfpr, rfpr = trust['verifier']['fingerprint'], trust['reviewer']['fingerprint']
        kr = Keyring(HERE.parent / 'keys', 'VERIFIER_GPG_PRIVATE_KEY', 'VERIFIER_GPG_PASSPHRASE', expect_secret_fpr=vfpr)
        who = ('Loyalty Verifier', 'verifier@loyalty.invalid')

        # checks/<T>/<alvo> (idempotente: se ja existe e e valida, reaproveita)
        cname = f'checks/{a.task}/{a.target}'
        if not verify_tag(repo, kr, cname, vfpr, a.target):
            sign_tag(repo, kr, vfpr, cname, a.target, {
                'id': a.task, 'clean_environment': True, 'runner_policy_sha256': report['runner_policy_sha256'],
                'tests': [{'id': t['id'], 'result': t['result'], 'log_sha256': t.get('log_sha256')} for t in report.get('tests', [])],
                'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
            }, who)
        # Toda ref valida desta tarefa/alvo vai para o push (idempotente: mesmo objeto = nada muda; objeto diferente no
        # remoto = push recusado, sem --force).
        created.append(cname)

        rname = f'review/{a.task}/{a.target}'
        if override:
            # parecer CONTRARIO ja existente (tag do produto, trazida com as tags); o modelo nao e chamado de novo
            review = verify_tag(repo, kr, rname, rfpr, a.target)
            if not review or review.get('decision') != 'unfavorable' or review.get('id') != a.task:
                raise SignError('accept-override recusado: sem parecer desfavoravel valido do revisor neste alvo')
            created.append(rname)
            ofile = pathlib.Path(a.override_file).resolve()
            kit = HERE.parent / 'kit' / 'verifier.py'
            if kr.gpg_program:
                git(repo, 'config', 'gpg.program', kr.gpg_program)
            p = subprocess.run([sys.executable, '-I', '-B', str(kit), '--repo', str(repo), '--trust', str(trust_path),
                                'gov_accept_override', a.task, '--override-file', str(ofile), '--dp', a.dp],
                               capture_output=True, env={**os.environ, **kr.env})
            if p.returncode:
                raise SignError('accept-override recusado: ' + git_err(p.stderr))
            gate_ref = ('gate/' + backlog[a.task]['gate'] if is_gate else 'task/' + a.task)
            created.append(gate_ref + '/accepted')
            verdict = 'accepted'
            meta = None
        else:
            meta = json.load(open(a.review_meta, encoding='utf-8'))
        if meta is not None:
            if meta.get('name') != rname:
                raise SignError('meta do revisor nao corresponde a tarefa/alvo')
            if meta.get('skipped'):
                review = None
                log(f"sem parecer: revisor pulou ({meta['skipped']}); o verifier.py vai rejeitar")
            else:
                if git(repo, 'rev-parse', '-q', '--verify', 'refs/tags/' + rname, check=False).returncode:
                    import_tag(repo, rname, pathlib.Path(a.review_tag).read_bytes(), meta['oid'])
                elif git(repo, 'rev-parse', 'refs/tags/' + rname).stdout.decode().strip() != meta.get('oid'):
                    raise SignError('parecer local difere do objeto entregue pelo revisor')
                review = verify_tag(repo, kr, rname, rfpr, a.target)
                if not review:
                    raise SignError('parecer do revisor invalido (assinatura, alvo ou payload)')
                created.append(rname)
                log(f"parecer {review.get('decision')} de {review.get('provider_name')} / {review.get('model')} (geracao {review.get('generation_id')})")
            verdict = 'premerge' if review and review.get('decision') == 'favorable' and all(
                t.get('result') == 'pass' for t in report.get('tests', [])) else 'premerge-unfavorable'
        if a.mode == 'accept':
            kit = HERE.parent / 'kit' / 'verifier.py'
            env = {**os.environ, **kr.env}
            # verifier.py assina via git do clone: aplica o gpg.program (loopback) so na config local do clone descartavel
            if kr.gpg_program:
                git(repo, 'config', 'gpg.program', kr.gpg_program)
            p = subprocess.run([sys.executable, '-I', '-B', str(kit), '--repo', str(repo), '--trust', str(trust_path),
                                'gov_accept_gate', a.task], capture_output=True, env=env)
            gate_ref = ('gate/' + backlog[a.task]['gate'] if is_gate else 'task/' + a.task)
            if p.returncode == 0:
                verdict = 'accepted'
                created.append(gate_ref + '/accepted')
            else:
                verdict = 'rejected'
                rej = gate_ref + '/rejected/' + a.target
                if git(repo, 'rev-parse', '-q', '--verify', 'refs/tags/' + rej, check=False).returncode == 0:
                    created.append(rej)
                log('verifier.py: ' + git_err(p.stderr))

        # Reverificacao de cada ref antes do push
        expect = {}
        for name in created:
            fpr = rfpr if name.startswith('review/') else vfpr
            pl = verify_tag(repo, kr, name, fpr, a.target)
            if not pl:
                raise SignError(f'ref {name} nao passou na reverificacao; nada empurrado')
            if name.startswith(('review/', 'checks/')) and pl.get('id') != a.task:
                raise SignError(f'ref {name}: id do payload difere')
            if name.endswith('/accepted') and (pl.get('decision') != 'accepted' or pl.get('id') != a.task):
                raise SignError(f'ref {name}: payload de aceite invalido')
            if name.endswith('/accepted') and override and (not isinstance(pl.get('override'), dict) or pl['override'].get('dps') != a.dp.split(',')
                                                          or pl['override'].get('raiz') != trust['root_fingerprint']):
                raise SignError(f'ref {name}: aceite por override sem o registro da raiz/DP')
            expect[name] = git(repo, 'rev-parse', 'refs/tags/' + name).stdout.decode().strip()

        if a.no_push:
            log(f'sem push (teste): {sorted(expect)}')
        else:
            token = os.environ.get('APP_TOKEN', '')
            env = {}
            if a.push_url.startswith('https://'):
                if not token:
                    raise SignError('APP_TOKEN ausente (falha fechada)')
                hdr = base64.b64encode(f'x-access-token:{token}'.encode()).decode()
                env = {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraheader',
                       'GIT_CONFIG_VALUE_0': f'AUTHORIZATION: basic {hdr}', 'GIT_TERMINAL_PROMPT': '0'}
            for name in sorted(expect, key=lambda n: (n.startswith(('task/', 'gate/')), n)):  # checks/review antes do aceite
                git(repo, 'push', '--no-verify', a.push_url, f'refs/tags/{name}:refs/tags/{name}', env=env)
                log(f'empurrada: {name} -> {expect[name][:12]}')
        log(f'resultado: {verdict} ({a.task} @ {a.target[:12]})')
        return 0 if verdict in ('accepted', 'premerge') else 2
    except (SignError, KeyError, ValueError, OSError) as e:
        log('FALHOU: ' + (str(e) if isinstance(e, SignError) else type(e).__name__) + ' - nenhuma ref empurrada')
        return 1
    finally:
        if kr:
            kr.close()


if __name__ == '__main__':
    sys.exit(main())
