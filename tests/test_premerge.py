#!/usr/bin/env python3
"""Testes do status pre-merge (opcao B do PM): scripts/premerge.py, descoberta de PRs em scripts/discover.py e o job pr-status.

Fixture do test_r0_06 (chaves falsas, produto com 'origin' bare local) + API do GitHub FALSA em 127.0.0.1 (pulls, statuses).
Nada sai da maquina. Rodar da raiz do repo verificador:  python -B tests/test_premerge.py
"""
import hashlib
import http.server
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import unittest

V = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V / 'tests'))
import test_r0_06 as base  # noqa: E402
from test_r0_06 import PY, git, run  # noqa: E402

SECRET_ENV = ('GNUPGHOME', 'GITHUB_TOKEN', 'GH_TOKEN', 'VERIFIER_PRIVATE_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'DEEPSEEK_API_KEY')


class FakeGitHub(http.server.BaseHTTPRequestHandler):
    state = {'pulls': [], 'statuses': {}, 'posts': [], 'auth': []}

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self.state['auth'].append(self.headers.get('Authorization'))
        m = re.match(r'^/repos/[^/]+/[^/]+/(pulls|commits/([0-9a-f]{40})/statuses)', self.path)
        if not m:
            return self._send(404, {'message': 'Not Found'})
        if m.group(1) == 'pulls':
            return self._send(200, self.state['pulls'])
        return self._send(200, list(reversed(self.state['statuses'].get(m.group(2), []))))

    def do_POST(self):
        self.state['auth'].append(self.headers.get('Authorization'))
        m = re.match(r'^/repos/[^/]+/[^/]+/statuses/([0-9a-f]{40})$', self.path)
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
        if not m:
            return self._send(404, {'message': 'Not Found'})
        st = {**body, 'creator': {'login': 'ln-verifier[bot]', 'type': 'Bot'}}
        self.state['statuses'].setdefault(m.group(1), []).append(st)
        self.state['posts'].append((m.group(1), body))
        return self._send(201, st)


class PreMerge(base.R006):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.gh = http.server.ThreadingHTTPServer(('127.0.0.1', 0), FakeGitHub)
        threading.Thread(target=cls.gh.serve_forever, daemon=True).start()
        cls.api = f'http://127.0.0.1:{cls.gh.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.gh.shutdown()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        FakeGitHub.state = {'pulls': [], 'statuses': {}, 'posts': [], 'auth': []}
        self.keysdir = self.tmp / 'keys'
        self.keysdir.mkdir()
        for role, fp in self.fp.items():
            (self.keysdir / f'{role}.asc').write_bytes(run('gpg', '--batch', '--armor', '--export', fp).stdout)
        self.policy = self.tmp / 'policy-pr.json'
        self.write_policy(ok=True)
        self.n = 0

    def write_policy(self, ok=True):
        argv = [PY, '-c', 'print("ok")'] if ok else [PY, '-c', 'import sys; sys.exit(1)']
        self.policy.write_text(json.dumps({'checks': {'PR': [{'id': 'GLOBAL-TESTFLAGS', 'argv': argv, 'timeout_sec': 60}]}}))
        self.trust['runner_policy_sha256'] = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        self.trust_path.write_text(json.dumps(self.trust))

    # ---------- helpers ----------
    def pr_branch(self, name, files, role='executor'):
        """Branch de PR a partir da main atual, com um commit (assinado por <role>) que escreve <files>. Devolve H."""
        w = self.work
        git(w, 'checkout', '-q', 'main')
        git(w, 'checkout', '-q', '-b', name)
        for rel, txt in files.items():
            (w / rel).parent.mkdir(parents=True, exist_ok=True)
            (w / rel).write_text(txt)
        self.commit('pr ' + name, role)
        h = self.head(w)
        git(w, 'push', '-q', 'origin', name)
        git(w, 'checkout', '-q', 'main')
        return h

    def runner(self, target):
        self.n += 1
        c = self.fresh_clone(f'run-{target[:7]}-{self.n}')
        git(c, 'fetch', '-q', 'origin', '+refs/heads/*:refs/remotes/origin/*')
        git(c, 'checkout', '-q', '--detach', target)
        out = self.tmp / f'report-pr-{target[:7]}-{self.n}.json'
        env = {k: v for k, v in os.environ.items() if k not in SECRET_ENV}
        subprocess.run([PY, '-I', '-B', str(V / 'kit' / 'clean_checks.py'), '--checkout', str(c), '--target', target, '--policy',
                        str(self.policy), '--task', 'PR', '--output', str(out)], capture_output=True, env=env)
        self.assertTrue(out.exists())
        return out

    def avaliar(self, target, report=None):
        self.n += 1
        c = self.fresh_clone(f'aval-{target[:7]}-{self.n}')
        git(c, 'fetch', '-q', 'origin', '+refs/heads/*:refs/remotes/origin/*')
        git(c, 'checkout', '-q', '--detach', target)
        out = self.tmp / f'status-{target[:7]}-{self.n}.json'
        args = [PY, '-I', '-B', str(V / 'scripts' / 'premerge.py'), 'avaliar', '--product', str(c), '--target', target,
                '--trust', str(self.trust_path), '--keys', str(self.keysdir), '--out', str(out)]
        if report:
            args += ['--runner-report', str(report)]
        p = run(*args, check=False)
        self.assertEqual(p.returncode, 0, p.stdout.decode(errors='replace') + p.stderr.decode(errors='replace'))
        return out, {s['context']: s for s in json.loads(out.read_text())['statuses']}

    def postar(self, sha, status_file, token='tok-app-falso'):
        env = {'LN_GITHUB_API': self.api, 'APP_TOKEN': token}
        return run(PY, '-I', '-B', str(V / 'scripts' / 'premerge.py'), 'postar', '--repo', 'dono/produto', '--sha', sha,
                   '--statuses', str(status_file), '--target-url', 'https://exemplo.invalid/run/1', env=env, check=False)

    # ---------- protected-paths ----------
    def test_p01_pr_comum_sem_caminho_protegido(self):
        h = self.pr_branch('ft/a', {'apps/x.txt': 'x'})
        _, s = self.avaliar(h, self.runner(h))
        self.assertEqual(s['ln-verifier/protected-paths']['state'], 'success')
        self.assertEqual(s['ln-verifier/clean-checks']['state'], 'success')

    def test_p02_caminho_protegido_pelo_executor_reprova(self):
        h = self.pr_branch('ft/b', {'governance/backlog.yaml': '[]'})
        _, s = self.avaliar(h, self.runner(h))
        self.assertEqual(s['ln-verifier/protected-paths']['state'], 'failure')
        self.assertIn('governance/backlog.yaml', s['ln-verifier/protected-paths']['description'])

    def test_p03_ato_raiz_assinado_pela_raiz_passa(self):
        h = self.pr_branch('raiz/x', {'governance/backlog.yaml': '[]'}, role='root')
        _, s = self.avaliar(h, self.runner(h))
        self.assertEqual(s['ln-verifier/protected-paths']['state'], 'success')
        self.assertIn('raiz', s['ln-verifier/protected-paths']['description'])

    def test_p04_gitattributes_em_subpasta_reprova(self):
        h = self.pr_branch('ft/c', {'apps/sub/.gitattributes': '* text\n'})
        _, s = self.avaliar(h, self.runner(h))
        self.assertEqual(s['ln-verifier/protected-paths']['state'], 'failure')

    # ---------- clean-checks ----------
    def test_p05_clean_checks_falho_ausente_ou_de_outro_alvo(self):
        h = self.pr_branch('ft/d', {'apps/y.txt': 'y'})
        self.write_policy(ok=False)
        _, s = self.avaliar(h, self.runner(h))
        self.assertEqual(s['ln-verifier/clean-checks']['state'], 'failure')
        self.assertIn('GLOBAL-TESTFLAGS', s['ln-verifier/clean-checks']['description'])
        _, s = self.avaliar(h, None)
        self.assertEqual(s['ln-verifier/clean-checks']['state'], 'failure')
        self.write_policy(ok=True)
        rep = self.runner(h)
        d = json.loads(rep.read_text()); d['commit_sha'] = self.M; rep.write_text(json.dumps(d))
        _, s = self.avaliar(h, rep)
        self.assertEqual(s['ln-verifier/clean-checks']['state'], 'failure')

    # ---------- postar ----------
    def test_p06_postar_dois_status_idempotente_e_contrato(self):
        h = self.pr_branch('ft/e', {'apps/z.txt': 'z'})
        f, _ = self.avaliar(h, self.runner(h))
        p = self.postar(h, f)
        self.assertEqual(p.returncode, 0, p.stdout.decode() + p.stderr.decode())
        self.assertEqual(sorted(b['context'] for _, b in FakeGitHub.state['posts']), ['ln-verifier/clean-checks', 'ln-verifier/protected-paths'])
        self.assertTrue(all(a == 'Bearer tok-app-falso' for a in FakeGitHub.state['auth']))
        p = self.postar(h, f)
        self.assertEqual(len(FakeGitHub.state['posts']), 2, 'segunda execucao nao deve postar de novo')
        self.assertNotEqual(self.postar(h, f, token='').returncode, 0)                     # sem token: falha fechada
        bad = json.loads(f.read_text()); bad['statuses'][0]['state'] = 'pending'
        f2 = self.tmp / 'ruim.json'; f2.write_text(json.dumps(bad))
        self.assertNotEqual(self.postar(h, f2).returncode, 0)                                # fora do contrato
        self.assertNotEqual(self.postar(self.M, f).returncode, 0)                            # status.json de outro alvo

    # ---------- descoberta de PRs ----------
    def test_p07_descobre_pr_sem_status_e_pula_o_ja_postado(self):
        h1 = self.pr_branch('ft/f', {'apps/1.txt': '1'})
        h2 = self.pr_branch('ft/g', {'apps/2.txt': '2'})
        FakeGitHub.state['pulls'] = [{'number': 1, 'head': {'sha': h1}}, {'number': 2, 'head': {'sha': h2}}]
        for ctx in ('ln-verifier/protected-paths', 'ln-verifier/clean-checks'):
            FakeGitHub.state['statuses'].setdefault(h1, []).append({'context': ctx, 'state': 'success', 'creator': {'login': 'ln-verifier[bot]'}})
        FakeGitHub.state['statuses'].setdefault(h2, []).append({'context': 'ln-verifier/clean-checks', 'state': 'success', 'creator': {'login': 'outra-pessoa'}})
        c = self.fresh_clone('disc')
        p = run(PY, '-I', '-B', str(V / 'scripts' / 'discover.py'), '--product', str(c), '--trust', str(self.trust_path), '--keys', str(self.keysdir),
                '--limit', '5', '--prs', '--repo', 'dono/produto', env={'LN_GITHUB_API': self.api}, check=False)
        self.assertEqual(p.returncode, 0, p.stdout.decode(errors='replace') + p.stderr.decode(errors='replace'))
        d = json.loads(p.stdout)
        prs = [(x['task'], x['target'], x['mode']) for x in d['alvos'] if x['task'] == 'PR']
        self.assertEqual(prs, [('PR', h2, 'pr')])                                            # status de quem nao e a App nao conta
        self.assertTrue(any(x['motivo'].startswith('STATUS_JA_POSTADO') and x['target'] == h1 for x in d['pulados']))
        self.assertEqual(d['alvos'][0]['task'], 'R0-01')                                     # aceite vem antes dos PRs
        p1 = run(PY, '-I', '-B', str(V / 'scripts' / 'discover.py'), '--product', str(c), '--trust', str(self.trust_path), '--keys', str(self.keysdir),
                 '--limit', '1', '--prs', '--repo', 'dono/produto', env={'LN_GITHUB_API': self.api}, check=False)
        self.assertEqual([x['task'] for x in json.loads(p1.stdout)['alvos']], ['R0-01'])

    # ---------- contrato do workflow e da politica ----------
    def test_p08_workflow_e_politica(self):
        y = (V / '.github' / 'workflows' / 'verifier.yml').read_text(encoding='utf-8')
        pr = y[y.index('  pr-status:\n'):]
        self.assertIn("if: needs.discover.outputs.mode == 'pr'", pr)
        self.assertIn('environment: verifier-signing', pr)
        self.assertIn('needs: [trust-gate, discover, runner]', pr)
        self.assertIn('scripts/provenance.py', pr)
        self.assertIn('premerge.py avaliar', pr)
        self.assertIn('premerge.py postar', pr)
        for job in ('reviewer', 'signer'):
            blk = y[y.index(f'  {job}:\n'):]
            self.assertIn("if: needs.discover.outputs.mode != 'pr'", blk[:200])
        self.assertIn('^(R[0-6]-[0-9]{2}|PR)$', y)
        self.assertIn("+refs/pull/*/head:refs/remotes/origin/pr/*", y)
        self.assertIn('--prs --repo "$PRODUCT_REPO"', y)
        for blk in re.findall(r'\n(\s+)run: \|\n((?:\1  .*\n|\s*\n)+)', y):
            self.assertNotIn('${{', blk[1])
        pol = json.loads((V / 'checks' / 'r0-policy.json').read_text(encoding='utf-8'))
        self.assertEqual([c['id'] for c in pol['checks']['PR']], ['GLOBAL-TESTFLAGS'])
        trust = json.loads((V / 'trust.json').read_text(encoding='utf-8'))
        self.assertEqual(trust['runner_policy_sha256'], hashlib.sha256((V / 'checks' / 'r0-policy.json').read_bytes()).hexdigest())


for _n in [n for n in dir(base.R006) if n.startswith('test_')]:
    setattr(PreMerge, _n, None)

if __name__ == '__main__':
    unittest.main(verbosity=2)
