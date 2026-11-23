#!/usr/bin/env python3
"""Testes do verificador-gates (frente 12): descoberta automatica + cadeia ponta a ponta em ENSAIO, sem aceite real.

Reaproveita a fixture do test_r0_06 (chaves falsas num GNUPGHOME descartavel, produto de fixture com 'origin' bare local,
OpenRouter falso em 127.0.0.1). Cadeia exercitada: scripts/discover.py -> kit/clean_checks.py (runner real, com politica de
TESTE sem docker) -> reviewer/review.py -> scripts/signer.py -> tags no 'origin' local -> kit/gov.py accepted().
Nao exercitado aqui: scripts/provenance.py (depende da API de Actions do GitHub) e o container do runner (docker).
Rodar da raiz do repo verificador:  python -B tests/test_gates_e2e.py   (GnuPG e git no PATH)
"""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import unittest

V = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V / 'tests'))
import test_r0_06 as base  # noqa: E402
from test_r0_06 import PY, FakeOpenRouter, Gov, canon, digest, git, run  # noqa: E402

SECRET_ENV = ('GNUPGHOME', 'GITHUB_TOKEN', 'GH_TOKEN', 'VERIFIER_PRIVATE_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'DEEPSEEK_API_KEY',
              'OPENROUTER_API_KEY', 'VERIFIER_GPG_PRIVATE_KEY', 'VERIFIER_GPG_PASSPHRASE', 'REVIEWER_GPG_PRIVATE_KEY', 'REVIEWER_GPG_PASSPHRASE')
OK = [PY, '-c', 'print("ok")']
POLICY = {'note': 'politica de TESTE (sem docker)', 'checks': {
    'R0-01': [{'id': 'R0-01-TEST', 'argv': OK, 'timeout_sec': 60}],
    'R0-02': [{'id': 'R0-02-TEST', 'argv': OK, 'timeout_sec': 60}],
    'R0-12': [{'id': i, 'argv': OK, 'timeout_sec': 60} for i in ('R0-01-TEST', 'R0-02-TEST', 'R0-12-TEST')]}}


class Gates(base.R006):
    """Herda so a fixture do R006; os testes herdados sao desligados abaixo (ja rodam em test_r0_06.py)."""

    def setUp(self):
        super().setUp()
        self.policy = self.tmp / 'policy-teste.json'
        self.policy.write_text(json.dumps(POLICY))
        self.trust['runner_policy_sha256'] = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        self.trust_path.write_text(json.dumps(self.trust))
        self.keysdir = self.tmp / 'keys'
        self.keysdir.mkdir()
        for role, fp in self.fp.items():
            (self.keysdir / f'{role}.asc').write_bytes(run('gpg', '--batch', '--armor', '--export', fp).stdout)
        self.n = 0

    # ---------- passos da cadeia ----------
    def discover(self, limit=5):
        c = self.fresh_clone(f'disc-{self.n}')
        self.n += 1
        p = run(PY, '-I', '-B', str(V / 'scripts' / 'discover.py'), '--product', str(c), '--trust', str(self.trust_path),
                '--keys', str(self.keysdir), '--limit', str(limit), check=False)
        self.assertEqual(p.returncode, 0, p.stdout.decode(errors='replace') + p.stderr.decode(errors='replace'))
        return json.loads(p.stdout)

    def runner(self, task, target):
        c = self.fresh_clone(f'run-{self.n}')
        self.n += 1
        git(c, 'checkout', '-q', '--detach', target)
        out = self.tmp / f'runner-{task}-{target[:7]}-{self.n}.json'
        env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
        p = subprocess.run([PY, '-I', '-B', str(V / 'kit' / 'clean_checks.py'), '--checkout', str(c), '--target', target, '--policy',
                            str(self.policy), '--task', task, '--output', str(out)], capture_output=True, env=env)
        self.assertTrue(out.exists(), p.stdout.decode(errors='replace') + p.stderr.decode(errors='replace'))
        return out

    def cycle(self, task, target):
        """runner -> revisor -> assinador (modo accept, push no 'origin' local). Devolve o codigo do assinador."""
        report = self.runner(task, target)
        rep = json.loads(report.read_text())
        self.assertEqual((rep['id'], rep['commit_sha'], rep['clean_environment']), (task, target, True))
        self.assertEqual(rep['runner_policy_sha256'], self.trust['runner_policy_sha256'])
        out = self.tmp / f'review-{task}-{target[:7]}-{self.n}'
        git(self.clone, 'fetch', '-q', 'origin', '+refs/heads/*:refs/remotes/origin/*', 'refs/tags/*:refs/tags/*')
        git(self.clone, 'checkout', '-q', '--detach', target)
        r = run(PY, '-I', '-B', str(V / 'reviewer' / 'review.py'), '--product', str(self.clone), '--target', target, '--task', task,
                '--trust', str(self.trust_path), '--config', str(V / 'reviewer' / 'config.json'), '--runner-report', str(report),
                '--out', str(out), env=self.env(), check=False)
        self.assertEqual(r.returncode, 0, r.stdout.decode(errors='replace') + r.stderr.decode(errors='replace'))
        s = run(PY, '-I', '-B', str(V / 'scripts' / 'signer.py'), '--product', str(self.clone), '--target', target, '--task', task,
                '--mode', 'accept', '--trust', str(self.trust_path), '--policy', str(self.policy), '--runner-report', str(report),
                '--review-tag', str(out / 'review-tag.txt'), '--review-meta', str(out / 'review-meta.json'), '--push-url', str(self.bare),
                env=self.env(), check=False)
        self._last = s.stdout.decode(errors='replace') + s.stderr.decode(errors='replace')
        return s.returncode

    def merge_evidence(self, task, extra_main_commit=False):
        """Evidencia de <task> num branch e merge commit em main (como o executor faz). Devolve o merge commit."""
        w = self.work
        git(w, 'checkout', '-q', 'main')
        git(w, 'pull', '-q', '--ff-only', 'origin', 'main')
        git(w, 'checkout', '-q', '-b', f'ft/{task.lower()}')
        gv = Gov(w, trust=self.trust)
        gv.call('gov_start_task', {'id': task, 'sessao': 's', 'chave_idempotencia': 'claim-' + task}) if gv.ready(task) else self._claim(task)
        art = f'{task}.log'
        (w / art).write_text('ok ' + task)
        self.commit('artefato ' + task)
        b = (w / art).read_bytes()
        h = digest(b)
        Gov(w, trust=self.trust).call('gov_submit_evidence', {
            'tarefa': task, 'artefatos': [art],
            'testes': [{'id': task + '-TEST', 'nome': 'check', 'resultado': 'passou', 'registro_sha256': h}],
            'chave_idempotencia': digest(canon([task, [{'caminho': art, 'sha256': h, 'bytes': len(b)}]]))})
        self.commit('evidencia ' + task)
        git(w, 'checkout', '-q', 'main')
        if extra_main_commit:
            (w / 'outro.txt').write_text('mudanca em main depois do branch')
            self.commit('mudanca paralela em main')
        git(w, 'merge', '-q', '--no-ff', '-m', 'merge ' + task, f'ft/{task.lower()}')
        git(w, 'push', '-q', 'origin', 'main')
        return self.head(w)

    def _claim(self, task):
        # gov_start_task exige dependencias aceitas; em fixture de "dependencia pendente" o claim e gravado direto (dado de teste)
        save = base.save
        save(self.work / 'governance' / 'claims' / f'{task}.json', {'id': task, 'sessao': 's', 'chave_idempotencia': 'claim-' + task})

    def tags(self):
        return set(self.remote_tags())

    @staticmethod
    def pairs(d, key='alvos'):
        return [(x['task'], x['target']) for x in d[key]]

    def reason(self, d, task, target=None):
        return [x['motivo'] for x in d['pulados'] if x['task'] == task and (target is None or x['target'] == target)]

    # ---------- testes ----------
    def test_g01_end_to_end_task_task_gate(self):
        d = self.discover()
        self.assertEqual(self.pairs(d), [('R0-01', self.M)])
        self.assertTrue(any(m.startswith('GATE_AGUARDA') for m in self.reason(d, 'R0-12')))
        self.assertEqual(self.cycle('R0-01', self.M), 0, self._last)
        self.assertIn('task/R0-01/accepted', self.tags())
        d = self.discover()
        self.assertEqual(self.pairs(d), [])
        self.assertIn('JA_ACEITA', self.reason(d, 'R0-01', self.M))
        m2 = self.merge_evidence('R0-02')
        d = self.discover()
        self.assertEqual(self.pairs(d), [('R0-02', m2)])
        self.assertEqual(self.cycle('R0-02', m2), 0, self._last)
        d = self.discover()
        self.assertEqual(self.pairs(d), [('R0-12', m2)])          # gate: alvo = ponta da cadeia
        self.assertEqual(self.cycle('R0-12', m2), 0, self._last)
        self.assertTrue({'task/R0-02/accepted', 'gate/R0/accepted', f'checks/R0-12/{m2}', f'review/R0-12/{m2}'} <= self.tags())
        c = self.fresh_clone('final')
        g = Gov(c, trust=self.trust)
        self.assertTrue(g.accepted('R0-01') and g.accepted('R0-02') and g.accepted('R0-12'))
        self.assertEqual(self.pairs(self.discover()), [])

    def test_g02_rejection_is_not_rediscovered(self):
        FakeOpenRouter.state['decision'] = 'unfavorable'
        self.assertEqual(self.cycle('R0-01', self.M), 2, self._last)
        self.assertIn(f'task/R0-01/rejected/{self.M}', self.tags())
        d = self.discover()
        self.assertEqual(self.pairs(d), [])
        self.assertIn('REJEICAO_JA_EMITIDA', self.reason(d, 'R0-01', self.M))

    def test_g03_divergent_tree_skipped(self):
        m2 = self.merge_evidence('R0-02', extra_main_commit=True)
        d = self.discover()
        self.assertIn('ARVORE_DIVERGENTE', self.reason(d, 'R0-02', m2))
        self.assertNotIn(('R0-02', m2), self.pairs(d))

    def test_g04_dependency_not_accepted_waits(self):
        m2 = self.merge_evidence('R0-02')
        d = self.discover()
        self.assertEqual(self.pairs(d), [('R0-01', self.M)])
        self.assertIn('DEP_NAO_ACEITA:R0-01', self.reason(d, 'R0-02', m2))

    def test_g05_direct_commit_on_main_is_not_target(self):
        w = self.work
        git(w, 'checkout', '-q', 'main')
        self._claim('R0-02')
        (w / 'R0-02.log').write_text('direto')
        self.commit('artefato direto')
        b = (w / 'R0-02.log').read_bytes()
        h = digest(b)
        Gov(w, trust=self.trust).call('gov_submit_evidence', {
            'tarefa': 'R0-02', 'artefatos': ['R0-02.log'],
            'testes': [{'id': 'R0-02-TEST', 'nome': 'check', 'resultado': 'passou', 'registro_sha256': h}],
            'chave_idempotencia': digest(canon(['R0-02', [{'caminho': 'R0-02.log', 'sha256': h, 'bytes': len(b)}]]))})
        self.commit('evidencia direta em main')
        direct = self.head(w)
        git(w, 'push', '-q', 'origin', 'main')
        d = self.discover()
        self.assertTrue(any(m.startswith('COMMIT_SEM_MERGE') for m in self.reason(d, 'R0-02', direct)))
        self.assertNotIn('R0-02', [t for t, _ in self.pairs(d)])

    def test_g06_commits_before_baseline_are_ignored(self):
        w = self.work
        git(w, 'checkout', '-q', 'main')
        (w / 'depois.txt').write_text('novo baseline')
        self.commit('novo baseline', 'root')
        git(w, 'push', '-q', 'origin', 'main')
        self.trust['baseline_commit'] = self.head(w)
        self.trust_path.write_text(json.dumps(self.trust))
        d = self.discover()
        self.assertEqual(self.pairs(d), [])
        self.assertEqual(self.reason(d, 'R0-01', self.M), [])      # M ficou antes do baseline: nem candidato, nem pulado

    def test_g07_limit_one_and_oldest_first(self):
        FakeOpenRouter.state['decision'] = 'favorable'
        self.assertEqual(self.cycle('R0-01', self.M), 0, self._last)
        m2 = self.merge_evidence('R0-02')
        d = self.discover(limit=1)
        self.assertEqual(self.pairs(d), [('R0-02', m2)])
        self.assertEqual(d['total_candidatos'], 1)

    def test_g08_workflow_contract(self):
        y = (V / '.github' / 'workflows' / 'verifier.yml').read_text(encoding='utf-8')
        disc = y[y.index('  discover:\n'):y.index('  fetch:\n')]
        self.assertIn('mode: ${{ steps.d.outputs.mode }}', disc)
        self.assertIn('trusted/scripts/discover.py', disc)
        self.assertIn('--limit 1', disc)
        self.assertIn('[[ "$IN_MODE" =~ ^(accept|premerge)$ ]]', disc)
        self.assertIn("MODE: ${{ needs.discover.outputs.mode }}", y)
        self.assertNotIn('${{ inputs.mode }}', y.split('  discover:\n')[1].split('IN_MODE: ${{ inputs.mode }}', 1)[1])
        # nenhuma expressao ${{ }} dentro de blocos run: (regra v3 do QA)
        for blk in re.findall(r'\n(\s+)run: \|\n((?:\1  .*\n|\s*\n)+)', y):
            self.assertNotIn('${{', blk[1])

    def test_g09_check_r0_r0_04_zip_layout(self):
        """r0_04 confere os blobs no layout dos ZIPs: v1.0 em baseline-v1.0/baseline/<arquivo>, v2.0 na raiz de spec-v2.0/."""
        w = self.work
        git(w, 'checkout', '-q', 'main')
        v1 = {f'doc{i}.md': f'v1 arquivo {i}\n'.encode() for i in range(7)}
        b1 = w / 'baseline-v1.0'
        (b1 / 'baseline').mkdir(parents=True)
        for k, v in v1.items():
            (b1 / 'baseline' / k).write_bytes(v)
        (b1 / 'README.md').write_text('v1\n')
        (b1 / 'manifest_sha256.json').write_text(json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in v1.items()}))
        self.commit('importa v1.0')
        a = self.head(w)
        regs = {'agents.registry.json': 64, 'workflows.registry.json': 17, 'meetings.registry.json': 28}
        v2 = {f'spec{i}.md': f'v2 arquivo {i}\n'.encode() for i in range(8)}
        for name, n in regs.items():
            v2['contracts/' + name] = json.dumps({'itens': [{'id': j} for j in range(n)]}).encode()
        b2 = w / 'spec-v2.0'
        for k, v in v2.items():
            (b2 / k).parent.mkdir(parents=True, exist_ok=True)
            (b2 / k).write_bytes(v)
        (b2 / 'README.md').write_text('v2\n')
        (b2 / 'manifest_sha256.json').write_text(json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in v2.items()}))
        self.commit('importa v2.0')
        b = self.head(w)
        for tag, c in (('v1.0', a), ('v2.0', b)):
            git(w, 'tag', '-s', '-u', self.fp['root'], '-m', 'R0-04 ' + tag, tag, c)
        keys = self.tmp / 'keys-raiz'
        keys.mkdir()
        (keys / 'raiz.asc').write_bytes(run('gpg', '--batch', '--armor', '--export', self.fp['root']).stdout)
        chk = [PY, '-I', '-B', str(V / 'checks' / 'scripts' / 'check_r0.py'), 'R0-04', str(w), '--keys', str(keys)]
        p = run(*chk, check=False)
        out = p.stdout.decode(errors='replace')
        self.assertEqual(p.returncode, 0, out)
        self.assertIn('v1.0: 7/7 blobs conferem', out)
        self.assertIn('v2.0: 11/11 blobs conferem', out)
        # adulterar um blob da v1.0 (novo commit + tag movida localmente) reprova
        (b1 / 'baseline' / 'doc0.md').write_bytes(b'adulterado\n')
        self.commit('adultera v1.0')
        git(w, 'tag', '-f', '-s', '-u', self.fp['root'], '-m', 'R0-04 v1.0 ruim', 'v1.0', self.head(w))
        p = run(*chk, check=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('v1.0: 6/7 blobs conferem', p.stdout.decode(errors='replace'))

for _name in [n for n in dir(base.R006) if n.startswith('test_')]:
    setattr(Gates, _name, None)   # nao repetir os 15 testes do R006 aqui

if __name__ == '__main__':
    unittest.main(verbosity=2)
