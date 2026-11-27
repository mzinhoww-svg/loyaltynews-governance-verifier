#!/usr/bin/env python3
"""Laco do agendado (27/11): runner reprova o alvo, provenance.py encerrava antes do assinador, nenhuma tag nascia e o mesmo alvo voltava.

Reaproveita a fixture do test_gates_e2e (chaves FALSAS descartaveis, produto de fixture, OpenRouter FALSO em 127.0.0.1) e executa o
PROPRIO bloco 'run:' do workflow (proveniencia) com o scripts/provenance.py real; so a API do GitHub e o curl sao falsos.
Nada sai da maquina. Rodar da raiz do repo verificador:  python -B tests/test_laco_rejeicao.py   (GnuPG, git e bash)
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap
import unittest
import zipfile

V = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V / 'tests'))
import test_gates_e2e as gates  # noqa: E402
from test_r0_06 import PY, FakeOpenRouter, git, run  # noqa: E402

FALHA = [PY, '-c', 'import sys; sys.exit(1)']
PASSA = [PY, '-c', 'print("ok")']
PASSO = 'Baixar ZIP do relatorio pela API e validar proveniencia'


def achar_bash():
    if sys.platform != 'win32':
        return shutil.which('bash')
    for c in (os.environ.get('LN_TEST_BASH'), r'C:\Program Files\Git\bin\bash.exe'):
        if c and pathlib.Path(c).is_file():
            return c
    return None


# API falsa do Actions: responde o que o provenance.py pergunta, coerente com o ZIP desta "execucao".
EMBRULHO = '''import hashlib, json, os, sys
sys.dont_write_bytecode = True
sys.path.insert(0, os.environ['LN_SCRIPTS'])
import provenance
def api(path):
    wsha = os.environ['GITHUB_WORKFLOW_SHA']
    if '/attempts/' in path:
        return {'jobs': [{'name': 'runner', 'conclusion': 'success', 'head_sha': wsha}]}
    if '/artifacts/' in path:
        return {'workflow_run': {'id': 1, 'head_sha': wsha}, 'name': os.environ['LN_ARTIFACT_NAME'],
                'digest': 'sha256:' + hashlib.sha256(open(os.environ['LN_FAKE_ZIP'], 'rb').read()).hexdigest()}
    return {'path': '.github/workflows/verifier.yml', 'head_sha': wsha, 'head_branch': 'main', 'event': 'schedule', 'run_attempt': 1}
provenance.api = api
provenance.main()
'''


@unittest.skipUnless(achar_bash(), 'sem bash para executar o passo do workflow')
class Laco(gates.Gates):
    """Herda a fixture; os testes herdados sao desligados abaixo."""

    def politica(self, argv):
        p = json.loads(self.policy.read_text())
        p['checks']['R0-01'] = [{'id': 'R0-01-TEST', 'argv': argv, 'timeout_sec': 60}]
        self.policy.write_text(json.dumps(p))
        self.trust['runner_policy_sha256'] = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        self.trust_path.write_text(json.dumps(self.trust))

    def passo_do_job(self, job):
        y = (V / '.github' / 'workflows' / 'verifier.yml').read_text(encoding='utf-8')
        bloco = y[y.index(f'\n  {job}:\n') + 1:]
        fim = re.search(r'\n  [a-z-]+:\n', bloco[3:])
        bloco = bloco[:fim.start() + 3] if fim else bloco
        passo = bloco[bloco.index(PASSO):]
        linhas = passo[passo.index('run: |\n') + len('run: |\n'):].split('\n')
        corpo = []
        for ln in linhas:
            if ln.strip() and not ln.startswith(' ' * 10):
                break
            corpo.append(ln)
        return textwrap.dedent('\n'.join(corpo))

    def proveniencia(self, report, task, target, job='signer', mode='accept', adulterar=False):
        """Executa o bloco do workflow com bash -e (como o Actions). Devolve (codigo, saida)."""
        self.n += 1
        d = self.tmp / f'prov-{self.n}'
        (d / 'trusted' / 'checks').mkdir(parents=True)
        z = d / 'origem.zip'
        with zipfile.ZipFile(z, 'w') as zf:
            zf.writestr('runner-report.json', report.read_bytes())
        (d / 'trusted' / 'trust.json').write_bytes(self.trust_path.read_bytes())
        (d / 'trusted' / 'checks' / 'r0-policy.json').write_bytes(self.policy.read_bytes())
        (d / 'embrulho.py').write_text(EMBRULHO, encoding='utf-8')
        s = self.passo_do_job(job)
        s, n1 = re.subn(r'curl -sSfL[^\n]*\\\n[^\n]*\n', 'cp "$LN_FAKE_ZIP" report.zip\n', s)
        s, n2 = re.subn(r'python3 trusted/scripts/provenance\.py', f'"{pathlib.Path(PY).as_posix()}" embrulho.py', s)
        self.assertEqual((n1, n2), (1, 1), s)
        (d / 'passo.sh').write_bytes(s.encode())
        wsha = 'b' * 40
        zsha = hashlib.sha256(z.read_bytes()).hexdigest()
        env = {**os.environ, 'TARGET': target, 'TASK': task, 'MODE': mode, 'RUNNER_ARTIFACT_ID': '7', 'GITHUB_TOKEN': 'falso',
               'GITHUB_REPOSITORY': 'dono/verificador', 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_WORKFLOW_SHA': wsha,
               'GITHUB_WORKFLOW_REF': 'dono/verificador/.github/workflows/verifier.yml@refs/heads/main',
               'RUNNER_ARTIFACT_DIGEST': ('0' * 64) if adulterar else zsha,
               'RUNNER_REPORT_SHA256': hashlib.sha256(report.read_bytes()).hexdigest(),
               'LN_FAKE_ZIP': z.as_posix(), 'LN_SCRIPTS': (V / 'scripts').as_posix(), 'LN_ARTIFACT_NAME': f'runner-report-{task}-{target}'}
        p = subprocess.run([achar_bash(), '--noprofile', '--norc', '-eo', 'pipefail', 'passo.sh'], cwd=d, env=env, capture_output=True)
        return p.returncode, p.stdout.decode(errors='replace') + p.stderr.decode(errors='replace')

    def revisar(self, task, target, report):
        self.n += 1
        out = self.tmp / f'rev-{self.n}'
        git(self.clone, 'fetch', '-q', 'origin', '+refs/heads/*:refs/remotes/origin/*', 'refs/tags/*:refs/tags/*')
        git(self.clone, 'checkout', '-q', '--detach', target)
        r = run(PY, '-I', '-B', str(V / 'reviewer' / 'review.py'), '--product', str(self.clone), '--target', target, '--task', task,
                '--trust', str(self.trust_path), '--config', str(V / 'reviewer' / 'config.json'), '--runner-report', str(report),
                '--out', str(out), env=self.env(), check=False)
        self.assertEqual(r.returncode, 0, r.stdout.decode(errors='replace'))
        return out

    def assinar(self, task, target, report, out, mode='accept'):
        s = run(PY, '-I', '-B', str(V / 'scripts' / 'signer.py'), '--product', str(self.clone), '--target', target, '--task', task,
                '--mode', mode, '--trust', str(self.trust_path), '--policy', str(self.policy), '--runner-report', str(report),
                '--review-tag', str(out / 'review-tag.txt'), '--review-meta', str(out / 'review-meta.json'), '--push-url', str(self.bare),
                env=self.env(), check=False)
        return s.returncode, s.stdout.decode(errors='replace') + s.stderr.decode(errors='replace')

    def rodada_agendada(self):
        """Como o workflow: descoberta -> runner -> revisor -> (proveniencia; so se o passo passar) assinador."""
        d = self.discover(limit=1)
        if not d['alvos']:
            return d, None
        task, target = d['alvos'][0]['task'], d['alvos'][0]['target']
        report = self.runner(task, target)
        out = self.revisar(task, target, report)
        rc, log = self.proveniencia(report, task, target)
        if rc == 0:
            rc, log = self.assinar(task, target, report, out)
        return d, (rc, log)

    # ---------- o laco ----------
    def test_l01_runner_reprovado_nao_e_reescolhido_e_nao_chama_modelo(self):
        self.politica(FALHA)
        d1, r1 = self.rodada_agendada()
        self.assertEqual(self.pairs(d1), [('R0-01', self.M)])
        d2 = self.discover(limit=1)
        self.assertNotIn(('R0-01', self.M), self.pairs(d2), 'LACO: o mesmo alvo reprovado voltou a ser escolhido\n' + r1[1])
        self.assertIn('REJEICAO_JA_EMITIDA', self.reason(d2, 'R0-01', self.M))
        rej = f'task/R0-01/rejected/{self.M}'
        self.assertIn(rej, self.tags())
        self.assertNotIn('task/R0-01/accepted', self.tags())
        motivo = self.payload(self.fresh_clone('motivo'), rej)['reason']
        self.assertIn('REQUIRED_TESTS_FAILED', motivo)
        self.assertIn('R0-01-TEST', motivo)
        self.assertEqual(r1[0], 2, r1[1])
        self.assertEqual(FakeOpenRouter.state['calls'], [])
        self.assertNotIn(f'review/R0-01/{self.M}', self.tags())
        checks = self.payload(self.fresh_clone('checks'), f'checks/R0-01/{self.M}')
        self.assertEqual([t['result'] for t in checks['tests']], ['fail'])

    # ---------- nada afrouxado ----------
    def test_l02_alvo_reprovado_nao_vira_aceito_depois(self):
        self.politica(FALHA)
        self.rodada_agendada()
        self.politica(PASSA)                      # mesmo alvo, rodada manual com runner agora verde e parecer favoravel
        report = self.runner('R0-01', self.M)
        out = self.revisar('R0-01', self.M, report)
        rc, log = self.proveniencia(report, 'R0-01', self.M)
        self.assertEqual(rc, 0, log)
        rc, log = self.assinar('R0-01', self.M, report, out)
        self.assertNotEqual(rc, 0, log)
        self.assertNotIn('task/R0-01/accepted', self.tags(), log)

    def test_l03_checks_e_parecer_antigos_aprovados_nao_aceitam_runner_que_falhou_agora(self):
        report = self.runner('R0-01', self.M)     # 1) ensaio premerge verde: publica checks (pass) e parecer favoravel
        verde = self.revisar('R0-01', self.M, report)
        rc, log = self.assinar('R0-01', self.M, report, verde, mode='premerge')
        self.assertEqual(rc, 0, log)
        self.assertIn(f'review/R0-01/{self.M}', self.tags())
        self.politica_sem_trocar_hash_falha(report)
        pulado = self.tmp / 'revisao-pulada'                      # o revisor pula runner reprovado (sem modelo)
        pulado.mkdir()
        (pulado / 'review-meta.json').write_text(json.dumps({'name': f'review/R0-01/{self.M}', 'skipped': 'runner_failed'}))
        (pulado / 'review-tag.txt').write_bytes(b'')
        rc, log = self.assinar('R0-01', self.M, self.ruim, pulado)   # 2) aceite com o relatorio desta rodada reprovado
        self.assertNotIn('task/R0-01/accepted', self.tags(), log)
        self.assertEqual(rc, 2, log)
        self.assertIn(f'task/R0-01/rejected/{self.M}', self.tags())
        rc, log = self.assinar('R0-01', self.M, report, verde)    # 3) nem com o relatorio verde e o parecer favoravel antigos
        self.assertNotEqual(rc, 0, log)
        self.assertNotIn('task/R0-01/accepted', self.tags(), log)

    def politica_sem_trocar_hash_falha(self, report):
        r = json.loads(report.read_text())
        r['tests'][0].update(result='fail', exit_code=1)
        self.ruim = self.tmp / 'relatorio-reprovado.json'
        self.ruim.write_text(json.dumps(r))

    def test_l04_premerge_e_override_continuam_estritos(self):
        self.politica(FALHA)
        report = self.runner('R0-01', self.M)
        for job, mode in (('signer', 'premerge'), ('override', 'accept-override')):
            rc, log = self.proveniencia(report, 'R0-01', self.M, job=job, mode=mode)
            self.assertNotEqual(rc, 0, f'{job}/{mode} passou com teste reprovado\n{log}')
        rc, log = self.proveniencia(report, 'R0-01', self.M)
        self.assertEqual(rc, 0, log)
        self.assertEqual(self.tags(), set())

    def test_l05_so_reprovacao_integra_segue_para_rejeicao(self):
        self.politica(FALHA)
        bom = json.loads(self.runner('R0-01', self.M).read_text())
        t = bom['tests'][0]
        casos = {
            'zip adulterado': (bom, True),
            'sem teste': ({**bom, 'tests': []}, False),
            'id trocado': ({**bom, 'tests': [{**t, 'id': 'OUTRO'}]}, False),
            'teste a mais': ({**bom, 'tests': [t, {**t, 'id': 'OUTRO'}]}, False),
            'resultado desconhecido': ({**bom, 'tests': [{**t, 'result': 'skip'}]}, False),
            'id repetido falha e passa': ({**bom, 'tests': [{**t, 'result': 'pass'}, t]}, False),
            'id repetido passa por ultimo': ({**bom, 'tests': [t, {**t, 'result': 'pass'}]}, False),
            'outro commit': ({**bom, 'commit_sha': 'c' * 40}, False),
            'ambiente sujo': ({**bom, 'clean_environment': False}, False),
        }
        for nome, (rel, adulterar) in casos.items():
            p = self.tmp / 'caso.json'
            p.write_text(json.dumps(rel))
            rc, log = self.proveniencia(p, 'R0-01', self.M, adulterar=adulterar)
            self.assertNotEqual(rc, 0, f'{nome}: o passo deixou o assinador seguir\n{log}')

    def test_l06_tarefa_ja_aceita_nao_recebe_rejeicao(self):
        report = self.runner('R0-01', self.M)
        rc, log = self.assinar('R0-01', self.M, report, self.revisar('R0-01', self.M, report))
        self.assertEqual(rc, 0, log)
        antes = self.tags()
        self.politica_sem_trocar_hash_falha(report)
        rc, log = self.assinar('R0-01', self.M, self.ruim, self.revisar('R0-01', self.M, self.ruim))
        self.assertNotEqual(rc, 0, log)
        self.assertEqual(self.tags(), antes, log)

    def test_l07_repetir_a_rodada_reprovada_nao_cria_nada_novo(self):
        self.politica(FALHA)
        self.rodada_agendada()
        antes = sorted(git(self.bare, 'for-each-ref', '--format=%(objectname) %(refname)', 'refs/tags').stdout.decode().split('\n'))
        report = self.runner('R0-01', self.M)
        rc, log = self.assinar('R0-01', self.M, report, self.revisar('R0-01', self.M, report))
        self.assertNotEqual(rc, 0, log)
        depois = sorted(git(self.bare, 'for-each-ref', '--format=%(objectname) %(refname)', 'refs/tags').stdout.decode().split('\n'))
        self.assertEqual(antes, depois, log)
        self.assertEqual(FakeOpenRouter.state['calls'], [])


    def test_l08_gate_reprovado_pelo_runner_tambem_sai_da_fila(self):
        self.assertEqual(self.cycle('R0-01', self.M), 0, getattr(self, '_last', ''))
        m2 = self.merge_evidence('R0-02')
        self.assertEqual(self.cycle('R0-02', m2), 0, getattr(self, '_last', ''))
        p = json.loads(self.policy.read_text())
        p['checks']['R0-12'][0]['argv'] = FALHA
        self.policy.write_text(json.dumps(p))
        self.trust['runner_policy_sha256'] = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        self.trust_path.write_text(json.dumps(self.trust))
        chamadas = len(FakeOpenRouter.state['calls'])
        d1, r1 = self.rodada_agendada()
        self.assertEqual(self.pairs(d1), [('R0-12', m2)], d1)
        self.assertEqual(r1[0], 2, r1[1])
        self.assertIn(f'gate/R0/rejected/{m2}', self.tags())
        self.assertNotIn('gate/R0/accepted', self.tags())
        self.assertNotIn(('R0-12', m2), self.pairs(self.discover(limit=1)))
        self.assertEqual(len(FakeOpenRouter.state['calls']), chamadas)


for _classe in (gates.Gates, gates.base.R006):
    for _n in [n for n in dir(_classe) if n.startswith('test_') and not n.startswith('test_l')]:
        setattr(Laco, _n, None)
del _classe

if __name__ == '__main__':
    unittest.main(defaultTest='Laco', verbosity=2)
