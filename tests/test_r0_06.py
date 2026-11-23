#!/usr/bin/env python3
"""Testes locais do R0-06 (revisor + assinador + politica) com CHAVES FALSAS e OpenRouter FALSO (127.0.0.1).

Nada sai da maquina: chaves geradas num GNUPGHOME descartavel, produto de fixture com remoto 'origin' local (bare),
servidor HTTP local imitando /api/v1/chat/completions e /api/v1/generation. Rodar da raiz do repo verificador:
  python -B tests/test_r0_06.py      (GnuPG e git no PATH)
"""
import hashlib
import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

V = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V / 'kit'))
sys.path.insert(0, str(V / 'scripts'))
from gov import Gov, canon, digest, save  # noqa: E402

PY = sys.executable
CFG = json.loads((V / 'reviewer' / 'config.json').read_text(encoding='utf-8'))
MODEL = CFG['model']


def run(*args, cwd=None, env=None, check=True, inp=None):
    p = subprocess.run(list(args), cwd=cwd, capture_output=True, env={**os.environ, **(env or {})}, input=inp)
    if check and p.returncode:
        raise AssertionError(f'{args[:3]} -> {p.returncode}: {p.stdout.decode(errors="replace")} {p.stderr.decode(errors="replace")}')
    return p


def git(repo, *args, **kw):
    return run('git', '-C', str(repo), *args, **kw)


class FakeOpenRouter(http.server.BaseHTTPRequestHandler):
    state = {}

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        s = FakeOpenRouter.state
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        s['calls'].append({'auth': self.headers.get('Authorization'), 'body': body})
        verdict = {'decision': s['decision'], 'criterios': [{'criterio': 'fixture', 'atendido': s['decision'] == 'favorable',
                                                               'justificativa': 'artefato R0-01.log'}], 'problemas': [], 'resumo': 'ok'}
        self._send(200, {'id': 'gen-test-1', 'model': s['model'], 'choices': [{'message': {'content': json.dumps(verdict)}}],
                         'usage': {'cost': 0.001}})

    def do_GET(self):
        s = FakeOpenRouter.state
        self._send(200, {'data': {'id': 'gen-test-1', 'provider_name': s['provider'], 'model': s['gen_model'], 'total_cost': 0.001}})


class R006(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.mkdtemp(prefix='ln-test-gnupg-')
        os.chmod(cls.keys, 0o700)
        cls.old = os.environ.get('GNUPGHOME')
        os.environ['GNUPGHOME'] = cls.keys
        cls.fp = {}
        for role in ('root', 'executor', 'reviewer', 'verifier'):
            uid = f'{role} <{role}@test.invalid>'
            run('gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key', uid, 'ed25519', 'sign', '0')
            out = run('gpg', '--batch', '--with-colons', '--list-keys', uid).stdout.decode()
            cls.fp[role] = next(l.split(':')[9] for l in out.splitlines() if l.startswith('fpr:'))
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeOpenRouter)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f'http://127.0.0.1:{cls.srv.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        run('gpgconf', '--kill', 'all', check=False)
        if cls.old is None:
            os.environ.pop('GNUPGHOME', None)
        else:
            os.environ['GNUPGHOME'] = cls.old
        shutil.rmtree(cls.keys, ignore_errors=True)

    # ---------- fixture ----------
    def setUp(self):
        FakeOpenRouter.state = {'calls': [], 'decision': 'favorable', 'provider': 'OpenAI', 'model': MODEL, 'gen_model': MODEL}
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='ln-test-r006-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        w = self.work = self.tmp / 'work'
        g = w / 'governance'
        g.mkdir(parents=True)
        rows = [{'id': i, 'gate': 'R0', 'kind': k, 'dependencies': d, 'required_tests': [i + '-TEST'], 'deferred': False,
                 'responsavel': 'Executor', 'achados_relacionados': '', 'criterio_de_aceite': 'fixture', 'teste': 'fixture',
                 'evidencia': 'fixture', 'tarefa': 'fixture ' + i}
                for i, k, d in (('R0-01', 'task', []), ('R0-02', 'task', ['R0-01']), ('R0-12', 'gate', ['R0-01', 'R0-02']))]
        save(g / 'backlog.yaml', rows)
        save(g / 'requirements.yaml', [])
        save(g / 'decisions.yaml', [])
        (g / 'findings.csv').write_text('id,severidade,status\n')
        ident = {'status': 'configured', 'root_fingerprint': self.fp['root'],
                 'executor': {'fingerprint': self.fp['executor'], 'provider': 'anthropic'},
                 'reviewer': {'fingerprint': self.fp['reviewer'], 'provider': 'openai'},
                 'verifier': {'fingerprint': self.fp['verifier']}}
        save(g / 'identities.yaml', ident)
        save(g / 'policy.json', {'p0_remediation': {}, 'p0_bootstrap_allowed': [], 'gate_tasks': {'R0': 'R0-12'}})
        (w / '.gitattributes').write_text('* -text\n')
        git(self.tmp, 'init', '-q', '-b', 'main', str(w))
        for k, v in (('user.name', 'Test'), ('user.email', 'test@test.invalid'), ('gpg.format', 'openpgp'), ('core.autocrlf', 'false')):
            git(w, 'config', k, v)
        self.commit('baseline', 'root')
        self.bare = self.tmp / 'origin.git'
        git(self.tmp, 'init', '-q', '--bare', '-b', 'main', str(self.bare))
        git(w, 'remote', 'add', 'origin', str(self.bare))
        git(w, 'push', '-q', 'origin', 'main')
        self.trust = {**ident, 'baseline_commit': self.head(w), 'runner_policy_sha256': 'a' * 64,
                      'protected': ['governance/backlog.yaml', 'governance/identities.yaml', 'governance/policy.json', '.github/']}
        self.trust_path = self.tmp / 'trust.json'
        self.trust_path.write_text(json.dumps(self.trust))
        self.out = self.tmp / 'out'
        # Evidencia da R0-01 num branch e merge commit M em main (02 v3: M^2 = H, arvores iguais)
        git(w, 'checkout', '-q', '-b', 'ft/r0-01')
        gv = Gov(w, trust=self.trust)
        gv.call('gov_start_task', {'id': 'R0-01', 'sessao': 's', 'chave_idempotencia': 'claim-s'})
        (w / 'R0-01.log').write_text('ok')
        self.commit('artefato')
        b = (w / 'R0-01.log').read_bytes()
        h = digest(b)
        gv.call('gov_submit_evidence', {'tarefa': 'R0-01', 'artefatos': ['R0-01.log'],
                                        'testes': [{'id': 'R0-01-TEST', 'nome': 'check', 'resultado': 'passou', 'registro_sha256': h}],
                                        'chave_idempotencia': digest(canon(['R0-01', [{'caminho': 'R0-01.log', 'sha256': h, 'bytes': len(b)}]]))})
        self.commit('evidencia')
        self.H = self.head(w)
        git(w, 'checkout', '-q', 'main')
        git(w, 'merge', '-q', '--no-ff', '-m', 'merge R0-01', 'ft/r0-01')
        self.M = self.head(w)
        git(w, 'push', '-q', 'origin', 'main')
        self.clone = self.fresh_clone('product')

    def commit(self, msg, role='executor'):
        git(self.work, 'add', '-A')
        git(self.work, 'commit', '-q', '-S' + self.fp[role], '-m', msg)

    @staticmethod
    def head(repo):
        return git(repo, 'rev-parse', 'HEAD').stdout.decode().strip()

    def fresh_clone(self, name):
        c = self.tmp / name
        git(self.tmp, 'clone', '-q', str(self.bare), str(c))
        for k, v in (('core.autocrlf', 'false'), ('user.name', 'Test'), ('user.email', 'test@test.invalid')):
            git(c, 'config', k, v)
        git(c, 'fetch', '-q', 'origin', 'refs/tags/*:refs/tags/*')
        return c

    def report(self, target, failed=False, task='R0-01'):
        p = self.tmp / f'report-{task}-{target[:7]}.json'
        p.write_text(json.dumps({'id': task, 'commit_sha': target, 'clean_environment': True, 'runner_policy_sha256': 'a' * 64,
                                 'tests': [{'id': task + '-TEST', 'result': 'fail' if failed else 'pass', 'exit_code': 1 if failed else 0,
                                            'log_sha256': '0' * 64}]}))
        return p

    def env(self, key=True):
        e = {'OPENROUTER_BASE_URL': self.base, 'LN_SIGN_TEST_GNUPGHOME': self.keys, 'GNUPGHOME': self.keys}
        e['OPENROUTER_API_KEY'] = 'sk-or-v1-' + '0' * 32 if key else ''
        return e

    def review(self, target, failed=False, key=True, config=None):
        git(self.clone, 'checkout', '-q', '--detach', target)
        return run(PY, '-I', '-B', str(V / 'reviewer' / 'review.py'), '--product', str(self.clone), '--target', target, '--task', 'R0-01',
                   '--trust', str(self.trust_path), '--config', str(config or V / 'reviewer' / 'config.json'),
                   '--runner-report', str(self.report(target, failed)), '--out', str(self.out), env=self.env(key), check=False)

    def sign(self, target, mode='accept', failed=False):
        return run(PY, '-I', '-B', str(V / 'scripts' / 'signer.py'), '--product', str(self.clone), '--target', target, '--task', 'R0-01',
                   '--mode', mode, '--trust', str(self.trust_path), '--policy', str(V / 'checks' / 'r0-policy.json'),
                   '--runner-report', str(self.report(target, failed)), '--review-tag', str(self.out / 'review-tag.txt'),
                   '--review-meta', str(self.out / 'review-meta.json'), '--push-url', str(self.bare), env=self.env(), check=False)

    def remote_tags(self):
        return sorted(l.split('\t')[1][len('refs/tags/'):] for l in git(self.bare, 'for-each-ref', '--format=%(objectname)\t%(refname)', 'refs/tags').stdout.decode().split('\n') if l)

    def payload(self, repo, tag):
        raw = git(repo, 'cat-file', 'tag', tag).stdout.decode()
        return json.loads(raw.split('\n\n', 1)[1].split('-----BEGIN PGP SIGNATURE-----', 1)[0])

    # ---------- revisor ----------
    def test_01_review_favorable_signed_with_routing_locked(self):
        r = self.review(self.M)
        self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        body = FakeOpenRouter.state['calls'][0]['body']
        self.assertEqual(body['provider']['only'], ['openai'])
        self.assertIs(body['provider']['allow_fallbacks'], False)
        self.assertEqual(body['provider']['data_collection'], 'deny')
        self.assertEqual(body['model'], MODEL)
        self.assertEqual(body['response_format']['type'], 'json_schema')
        tag = f'review/R0-01/{self.M}'
        v = git(self.clone, 'verify-tag', '--raw', tag, check=False)
        self.assertIn(self.fp['reviewer'], v.stderr.decode())
        p = self.payload(self.clone, tag)
        self.assertEqual((p['decision'], p['reviewer_provider'], p['executor_provider'], p['commit_sha'], p['provider_name']),
                         ('favorable', 'openai', 'anthropic', self.M, 'OpenAI'))
        log = r.stdout.decode()
        self.assertNotIn('sk-or-v1', log)
        self.assertNotIn('artefato R0-01.log', log)  # resposta do modelo nunca no log publico

    def test_02_upstream_not_openai_fails_closed(self):
        FakeOpenRouter.state['provider'] = 'Azure'
        r = self.review(self.M)
        self.assertEqual(r.returncode, 1)
        self.assertIn('upstream nao aceito', r.stdout.decode())
        self.assertFalse((self.out / 'review-tag.txt').exists())

    def test_03_generation_model_mismatch_fails(self):
        FakeOpenRouter.state['gen_model'] = 'openai/outro-modelo'
        self.assertEqual(self.review(self.M).returncode, 1)

    def test_04_runner_failed_skips_model_call(self):
        r = self.review(self.M, failed=True)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(FakeOpenRouter.state['calls'], [])
        self.assertEqual(json.loads((self.out / 'review-meta.json').read_text())['skipped'], 'runner_failed')

    def test_05_cost_cap_blocks_before_call(self):
        cfg = dict(CFG, max_cost_usd_per_call=0.000001)
        p = self.tmp / 'cfg' / 'reviewer'
        p.mkdir(parents=True)
        (p / 'config.json').write_text(json.dumps(cfg))
        shutil.copy(V / 'reviewer' / 'prompt-v1.md', p / 'prompt-v1.md')
        r = self.review(self.M, config=p / 'config.json')
        self.assertEqual(r.returncode, 1)
        self.assertIn('acima do teto', r.stdout.decode())
        self.assertEqual(FakeOpenRouter.state['calls'], [])

    def test_06_missing_key_fails_closed(self):
        r = self.review(self.M, key=False)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(FakeOpenRouter.state['calls'], [])

    # ---------- assinador ----------
    def test_07_accept_pushes_only_validated_refs(self):
        self.assertEqual(self.review(self.M).returncode, 0)
        s = self.sign(self.M)
        self.assertEqual(s.returncode, 0, s.stdout.decode() + s.stderr.decode())
        self.assertEqual(self.remote_tags(), sorted([f'checks/R0-01/{self.M}', f'review/R0-01/{self.M}', 'task/R0-01/accepted']))
        c = self.fresh_clone('check')
        self.assertTrue(Gov(c, trust=self.trust).accepted('R0-01'))
        self.assertIn('R0-02', [x['id'] for x in Gov(c, trust=self.trust).call('gov_next_tasks', {})])

    def test_08_unfavorable_review_signs_rejection(self):
        FakeOpenRouter.state['decision'] = 'unfavorable'
        self.assertEqual(self.review(self.M).returncode, 0)
        s = self.sign(self.M)
        self.assertEqual(s.returncode, 2, s.stdout.decode())
        tags = self.remote_tags()
        self.assertIn(f'task/R0-01/rejected/{self.M}', tags)
        self.assertNotIn('task/R0-01/accepted', tags)
        self.assertIn('REVIEW_NOT_INDEPENDENT_OR_MISSING', self.payload(self.fresh_clone('c2'), f'task/R0-01/rejected/{self.M}')['reason'])

    def test_09_runner_failed_signs_rejection_with_reason(self):
        self.assertEqual(self.review(self.M, failed=True).returncode, 0)
        s = self.sign(self.M, failed=True)
        self.assertEqual(s.returncode, 2, s.stdout.decode())
        reason = self.payload(self.fresh_clone('c3'), f'task/R0-01/rejected/{self.M}')['reason']
        self.assertIn('REQUIRED_TESTS_FAILED', reason)
        self.assertNotIn('task/R0-01/accepted', self.remote_tags())

    def test_10_task_accept_requires_merge_commit(self):
        self.assertEqual(self.review(self.H).returncode, 0)
        s = self.sign(self.H)
        self.assertEqual(s.returncode, 1)
        out = s.stdout.decode()
        # H nao e Mi: recusado por estar fora da cadeia de primeiro pai (ou, se estivesse nela, por nao ser merge commit)
        self.assertTrue('cadeia de primeiro pai' in out or 'merge commit' in out, out)
        self.assertEqual(self.remote_tags(), [])

    def test_11_forged_review_rejected_nothing_pushed(self):
        self.assertEqual(self.review(self.M).returncode, 0)
        # troca a tag do revisor por uma assinada pelo EXECUTOR com o mesmo payload
        tag = f'review/R0-01/{self.M}'
        body = git(self.clone, 'cat-file', 'tag', tag).stdout.decode().split('\n\n', 1)[1].split('-----BEGIN PGP SIGNATURE-----', 1)[0]
        git(self.clone, 'tag', '-d', tag)
        git(self.clone, '-c', 'gpg.format=openpgp', 'tag', '-s', '-u', self.fp['executor'], '-m', body, tag, self.M)
        oid = git(self.clone, 'rev-parse', 'refs/tags/' + tag).stdout.decode().strip()
        (self.out / 'review-tag.txt').write_bytes(git(self.clone, 'cat-file', 'tag', oid).stdout)
        (self.out / 'review-meta.json').write_text(json.dumps({'name': tag, 'oid': oid, 'decision': 'favorable'}))
        git(self.clone, 'tag', '-d', tag)
        s = self.sign(self.M)
        self.assertEqual(s.returncode, 1)
        self.assertIn('parecer do revisor invalido', s.stdout.decode())
        self.assertEqual(self.remote_tags(), [])

    def test_12_executor_signed_acceptance_is_not_acceptance(self):
        git(self.clone, '-c', 'gpg.format=openpgp', 'tag', '-s', '-u', self.fp['executor'], '-m',
            canon({'id': 'R0-01', 'decision': 'accepted', 'commit_sha': self.M}).decode(), 'task/R0-01/accepted', self.M)
        self.assertFalse(Gov(self.clone, trust=self.trust).accepted('R0-01'))

    def test_13_premerge_never_accepts(self):
        self.assertEqual(self.review(self.M).returncode, 0)
        s = self.sign(self.M, mode='premerge')
        self.assertEqual(s.returncode, 0, s.stdout.decode())
        self.assertEqual(self.remote_tags(), sorted([f'checks/R0-01/{self.M}', f'review/R0-01/{self.M}']))

    # ---------- politica e checks ----------
    def test_14_policy_has_entry_for_every_r0_task_and_matches_trust(self):
        raw = (V / 'checks' / 'r0-policy.json').read_bytes()
        pol = json.loads(raw)['checks']
        trust = json.loads((V / 'trust.json').read_text(encoding='utf-8'))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), trust['runner_policy_sha256'])
        ids = [f'R0-{n:02d}' for n in range(1, 13)]
        for t in ids:
            self.assertIn(t, pol)
            self.assertIn(f'{t}-TEST', [c['id'] for c in pol[t]])
            self.assertIn('GLOBAL-TESTFLAGS', [c['id'] for c in pol[t]])
            for c in pol[t]:
                self.assertIn('--network', c['argv'])
                self.assertEqual(c['argv'][c['argv'].index('--network') + 1], 'none')
        self.assertTrue({f'{t}-TEST' for t in ids} <= {c['id'] for c in pol['R0-12']})

    def test_15_check_r0_fails_closed(self):
        ck = V / 'checks' / 'scripts' / 'check_r0.py'
        self.assertEqual(run(PY, '-I', '-B', str(ck), 'R0-99', str(self.work), check=False).returncode, 1)
        self.assertEqual(run(PY, '-I', '-B', str(ck), 'R0-02', str(self.work), check=False).returncode, 1)  # 0 decisoes
        r = run(PY, '-I', '-B', str(ck), 'R0-11', str(self.work), check=False)
        self.assertEqual(r.returncode, 1)  # fixture sem os 7 gates de onda
        self.assertIn('sem ciclos', r.stdout.decode())


if __name__ == '__main__':
    unittest.main(verbosity=2)
