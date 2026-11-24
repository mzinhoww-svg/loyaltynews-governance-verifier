#!/usr/bin/env python3
"""Testes do accept-override (DP-45) com CHAVES FALSAS e OpenRouter FALSO, reaproveitando a fixture do test_r0_06.

Rodar da raiz do repo verificador:  python -B tests/test_override.py   (GnuPG e git no PATH)
Casos exigidos pelo PM: override sem DP, com DP inexistente e com runner falho sao recusados. Mais: assinatura que nao e da
raiz, mapeamento incompleto, parecer favoravel/sem criterios, DP-45 ausente no alvo, documento de outro parecer.
"""
import base64
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import test_r0_06 as B  # noqa: E402
from test_r0_06 import PY, V, git, run  # noqa: E402
from gov import Gov, canon, digest, save  # noqa: E402

DECS = [{'id': 'DP-33', 'decisao': 'teto pelos controles internos'}, {'id': 'DP-44', 'decisao': 'risco aceito de escopo'},
        {'id': 'DP-45', 'decisao': 'aceite com override assinado pela raiz'}]


def _post(self):
    s = B.FakeOpenRouter.state
    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
    s['calls'].append({'auth': self.headers.get('Authorization'), 'body': body})
    verdict = s.get('verdict') or {'decision': s['decision'], 'criterios': [{'criterio': 'fixture', 'atendido': s['decision'] == 'favorable',
                                                                           'justificativa': 'artefato R0-01.log'}], 'problemas': [], 'resumo': 'ok'}
    self._send(200, {'id': 'gen-test-1', 'model': s['model'], 'choices': [{'message': {'content': json.dumps(verdict)}}],
                     'usage': {'cost': 0.001}})


B.FakeOpenRouter.do_POST = _post   # mesmo servidor falso, com parecer configuravel por teste

UNFAV = {'decision': 'unfavorable',
         'criterios': [{'criterio': 'Nenhuma chave de escrita onde leitura basta', 'atendido': False,
                        'justificativa': 'C15 sem chave restrita; token sk-or-v1-' + '1' * 40 + ' citado'},
                       {'criterio': 'teto de US$ 50 registrado em cada provedor', 'atendido': False, 'justificativa': 'so 2 provedores'},
                       {'criterio': 'inventario completo', 'atendido': True, 'justificativa': 'secao 3'}],
         'problemas': ['teto ausente no painel de 6 provedores'], 'resumo': 'recusa literal'}
MAPA = {'criterios': [{'indice': 0, 'dps': ['DP-44']}, {'indice': 1, 'dps': ['DP-33']}], 'problemas': [{'indice': 0, 'dps': ['DP-33']}]}


class Override(unittest.TestCase):
    setUpClass = classmethod(B.R006.setUpClass.__func__)
    tearDownClass = classmethod(B.R006.tearDownClass.__func__)
    commit = B.R006.commit
    head = staticmethod(B.R006.head)
    fresh_clone = B.R006.fresh_clone
    report = B.R006.report
    env = B.R006.env
    review = B.R006.review
    sign = B.R006.sign
    remote_tags = B.R006.remote_tags
    payload = B.R006.payload

    def setUp(self, decs=DECS):
        B.R006.setUp(self)
        B.FakeOpenRouter.state['verdict'] = UNFAV
        # alvo M2: merge commit (M2^2 = H2, arvores iguais) cujo decisions.yaml tem as DPs
        w = self.work
        git(w, 'checkout', '-q', '-b', 'ft/decs')
        save(w / 'governance' / 'decisions.yaml', decs)
        self.commit('decisoes')
        git(w, 'checkout', '-q', 'main')
        git(w, 'merge', '-q', '--no-ff', '-m', 'merge decisoes', 'ft/decs')
        self.M2 = self.head(w)
        git(w, 'push', '-q', 'origin', 'main')
        git(self.clone, 'fetch', '-q', 'origin')
        git(self.clone, 'update-ref', 'refs/remotes/origin/main', self.M2)
        self.keysdir = self.tmp / 'pubkeys'
        self.keysdir.mkdir()
        for role, fp in self.fp.items():
            (self.keysdir / f'{role}.asc').write_bytes(run('gpg', '--batch', '--armor', '--export', fp).stdout)
        self.ovr = self.tmp / 'ovr'
        self.ovr.mkdir()

    # ---------- passos ----------
    def reject_first(self):
        """accept normal: parecer contrario gravado (com criterios) e rejeicao assinada."""
        self.assertEqual(self.review(self.M2).returncode, 0)
        s = self.sign(self.M2)
        self.assertEqual(s.returncode, 2, s.stdout.decode())
        git(self.clone, 'fetch', '-q', 'origin', 'refs/tags/*:refs/tags/*')

    def helper(self, *args):
        return run(PY, '-I', '-B', str(V / 'scripts' / 'override_autorizacao.py'), *args, '--trust', str(self.trust_path),
                   '--keys', str(self.keysdir), env=self.env(), check=False)

    def authorize(self, mapa=MAPA, doc=None, signer='root', tamper=None):
        """Documento (pelo helper ou cru) assinado pela chave pedida; devolve o arquivo de entrada <doc_b64>.<sig_b64>."""
        d = self.ovr / 'autorizacao.json'
        if doc is None:
            (self.ovr / 'mapa.json').write_text(json.dumps(mapa))
            r = self.helper('preparar', '--product', str(self.clone), '--task', 'R0-01', '--target', self.M2,
                            '--mapa', str(self.ovr / 'mapa.json'), '--out', str(d))
            self.assertEqual(r.returncode, 0, r.stdout.decode())
        else:
            d.write_bytes(canon(doc))
        if tamper:
            d.write_bytes(tamper(d.read_bytes()))
        sig = self.ovr / 'autorizacao.json.sig'
        if sig.exists():
            sig.unlink()
        run('gpg', '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', self.fp[signer],
            '--detach-sign', '--output', str(sig), str(d))
        entrada = self.ovr / 'entrada.txt'
        entrada.write_text(base64.b64encode(d.read_bytes()).decode() + '.' + base64.b64encode(sig.read_bytes()).decode())
        # o empacotador do PM confere a raiz antes: igual a entrada acima quando e a raiz; recusa senao
        r = self.helper('empacotar', '--doc', str(d), '--sig', str(sig), '--out', str(self.ovr / 'entrada-helper.txt'))
        if signer == 'root':
            self.assertEqual(r.returncode, 0, r.stdout.decode())
            self.assertEqual((self.ovr / 'entrada-helper.txt').read_text(), entrada.read_text())
        else:
            self.assertEqual(r.returncode, 1, r.stdout.decode())
            self.assertIn('NAO e da raiz', r.stdout.decode())
        return entrada

    def override(self, entrada, dp='DP-33,DP-44', failed=False):
        args = [PY, '-I', '-B', str(V / 'scripts' / 'signer.py'), '--product', str(self.clone), '--target', self.M2, '--task', 'R0-01',
                '--mode', 'accept-override', '--trust', str(self.trust_path), '--policy', str(V / 'checks' / 'r0-policy.json'),
                '--runner-report', str(self.report(self.M2, failed)), '--push-url', str(self.bare)]
        if entrada is not None:
            args += ['--override-file', str(entrada)]
        if dp is not None:
            args += ['--dp', dp]
        return run(*args, env=self.env(), check=False)

    def raw_doc(self, **kw):
        name = f'review/R0-01/{self.M2}'
        pl = self.payload(self.clone, name)
        d = {'formato': 'ln-override/1', 'base': 'DP-45', 'tarefa': 'R0-01', 'alvo': self.M2, 'dps': ['DP-33', 'DP-44'],
             'parecer': {'tag': name, 'oid': git(self.clone, 'rev-parse', 'refs/tags/' + name).stdout.decode().strip(),
                         'payload_sha256': digest(canon(pl))},
             'mapeamento': {'criterios': [{'texto': UNFAV['criterios'][0]['criterio'], 'dps': ['DP-44']},
                                          {'texto': UNFAV['criterios'][1]['criterio'], 'dps': ['DP-33']}],
                            'problemas': [{'texto': UNFAV['problemas'][0], 'dps': ['DP-33']}]}}
        d.update(kw)
        return d

    def assert_refused(self, r, needle):
        out = r.stdout.decode() + r.stderr.decode()
        self.assertEqual(r.returncode, 1, out)
        self.assertIn(needle, out)
        self.assertNotIn('task/R0-01/accepted', self.remote_tags())

    # ---------- casos ----------
    def test_o01_review_tag_grava_criterios_redigidos(self):
        self.reject_first()
        p = self.payload(self.clone, f'review/R0-01/{self.M2}')
        self.assertEqual([c['atendido'] for c in p['criterios']], [False, False, True])
        self.assertIn('[REDIGIDO]', p['criterios'][0]['justificativa'])
        self.assertNotIn('sk-or-v1-1111', json.dumps(p))
        self.assertEqual((p['problemas'], p['resumo'], p['criterios_atendidos'], p['criterios_total']),
                         (UNFAV['problemas'], 'recusa literal', 1, 3))

    def test_o02_override_valido_aceita_com_registro_da_raiz(self):
        self.reject_first()
        r = self.override(self.authorize())
        self.assertEqual(r.returncode, 0, r.stdout.decode() + r.stderr.decode())
        self.assertIn('task/R0-01/accepted', self.remote_tags())
        c = self.fresh_clone('chk')
        p = self.payload(c, 'task/R0-01/accepted')
        self.assertEqual((p['decision'], p['via']), ('accepted', 'override DP-33,DP-44 (DP-45)'))
        ov = p['override']
        self.assertEqual((ov['raiz'], ov['dps'], ov['base']), (self.fp['root'], ['DP-33', 'DP-44'], 'DP-45'))
        self.assertEqual(ov['parecer']['tag'], f'review/R0-01/{self.M2}')
        # reverificavel fora do GitHub: a assinatura embutida e da raiz sobre o documento embutido
        doc, sig = base64.b64decode(ov['autorizacao_b64']), base64.b64decode(ov['assinatura_raiz_b64'])
        (self.tmp / 'd').write_bytes(doc)
        (self.tmp / 's').write_bytes(sig)
        v = run('gpg', '--batch', '--status-fd', '1', '--verify', str(self.tmp / 's'), str(self.tmp / 'd'), check=False)
        self.assertIn(self.fp['root'], [ln.split()[-1] for ln in v.stdout.decode().splitlines() if ln.startswith('[GNUPG:] VALIDSIG')])
        self.assertEqual(digest(doc), ov['autorizacao_sha256'])
        self.assertTrue(Gov(c, trust=self.trust).accepted('R0-01'))
        self.assertIn('R0-02', [x['id'] for x in Gov(c, trust=self.trust).call('gov_next_tasks', {})])

    def test_o03_sem_dp_recusado(self):
        self.reject_first()
        e = self.authorize()
        self.assert_refused(self.override(e, dp=None), 'sem DP')
        self.assert_refused(self.override(e, dp='DP-33'), 'OVERRIDE_DP_MISMATCH')            # entrada != documento assinado
        self.assert_refused(self.override(self.authorize(doc=self.raw_doc(dps=[]))), 'OVERRIDE_WITHOUT_DP')
        self.assert_refused(self.override(None), 'sem autorizacao da raiz')

    def test_o04_dp_inexistente_recusada(self):
        self.reject_first()
        d = self.raw_doc(dps=['DP-33', 'DP-44', 'DP-99'])
        d['mapeamento']['problemas'][0]['dps'] = ['DP-99']
        self.assert_refused(self.override(self.authorize(doc=d), dp='DP-33,DP-44,DP-99'), 'OVERRIDE_DP_UNKNOWN:DP-99')
        (self.ovr / 'mapa.json').write_text(json.dumps({**MAPA, 'problemas': [{'indice': 0, 'dps': ['DP-99']}]}))
        r = self.helper('preparar', '--product', str(self.clone), '--task', 'R0-01', '--target', self.M2,
                        '--mapa', str(self.ovr / 'mapa.json'), '--out', str(self.ovr / 'x.json'))
        self.assertEqual(r.returncode, 1)                                                     # o helper tambem recusa
        self.assertIn('DP inexistente', r.stdout.decode())

    def test_o05_runner_falho_recusado(self):
        self.reject_first()
        self.assert_refused(self.override(self.authorize(), failed=True), 'runner com teste ausente ou falho')

    def test_o06_assinatura_que_nao_e_da_raiz_recusada(self):
        self.reject_first()
        for who in ('verifier', 'executor', 'reviewer'):
            self.assert_refused(self.override(self.authorize(doc=self.raw_doc(), signer=who)), 'OVERRIDE_ROOT_SIGNATURE_INVALID')
        # documento alterado depois da assinatura da raiz
        e = self.authorize(doc=self.raw_doc())
        doc_b64, sig_b64 = e.read_text().split('.')
        bad = canon(self.raw_doc(dps=['DP-33']))
        e.write_text(base64.b64encode(bad).decode() + '.' + sig_b64)
        self.assert_refused(self.override(e, dp='DP-33'), 'OVERRIDE_ROOT_SIGNATURE_INVALID')

    def test_o07_mapeamento_incompleto_recusado(self):
        self.reject_first()
        d = self.raw_doc()
        d['mapeamento']['criterios'] = d['mapeamento']['criterios'][:1]                      # criterio 2 sem DP
        self.assert_refused(self.override(self.authorize(doc=d)), 'OVERRIDE_MAPPING_INCOMPLETE:criterios')
        d = self.raw_doc()
        d['mapeamento']['problemas'] = []                                                      # problema sem DP
        self.assert_refused(self.override(self.authorize(doc=d)), 'OVERRIDE_MAPPING_INCOMPLETE:problemas')
        (self.ovr / 'mapa.json').write_text(json.dumps({**MAPA, 'criterios': MAPA['criterios'][:1]}))
        r = self.helper('preparar', '--product', str(self.clone), '--task', 'R0-01', '--target', self.M2,
                        '--mapa', str(self.ovr / 'mapa.json'), '--out', str(self.ovr / 'x.json'))
        self.assertIn('faltam indices [1]', r.stdout.decode())

    def test_o08_parecer_favoravel_ou_adulterado_recusado(self):
        B.FakeOpenRouter.state['verdict'] = None                                               # parecer favoravel
        self.assertEqual(self.review(self.M2).returncode, 0)
        git(self.clone, 'push', '-q', str(self.bare), f'refs/tags/review/R0-01/{self.M2}')
        d = self.raw_doc()
        self.assert_refused(self.override(self.authorize(doc=d)), 'sem parecer desfavoravel')

    def test_o09_documento_de_outro_parecer_recusado(self):
        self.reject_first()
        d = self.raw_doc()
        d['parecer'] = {**d['parecer'], 'payload_sha256': '0' * 64}
        self.assert_refused(self.override(self.authorize(doc=d)), 'OVERRIDE_REVIEW_MISMATCH')
        self.assert_refused(self.override(self.authorize(doc=self.raw_doc(alvo='0' * 40))), 'OVERRIDE_INVALID')

    def test_o10_dp45_ausente_no_alvo_recusada(self):
        # novo alvo M3 sem a DP-45 no decisions.yaml
        w = self.work
        git(w, 'checkout', '-q', '-b', 'ft/sem45')
        save(w / 'governance' / 'decisions.yaml', DECS[:2])
        self.commit('sem DP-45')
        git(w, 'checkout', '-q', 'main')
        git(w, 'merge', '-q', '--no-ff', '-m', 'merge sem45', 'ft/sem45')
        self.M2 = self.head(w)
        git(w, 'push', '-q', 'origin', 'main')
        git(self.clone, 'fetch', '-q', 'origin')
        self.reject_first()
        self.assert_refused(self.override(self.authorize(doc=self.raw_doc())), 'OVERRIDE_DP45_NOT_IN_TARGET')

    def test_o11_parecer_antigo_sem_criterios_recusado(self):
        self.reject_first()
        name = f'review/R0-01/{self.M2}'
        pl = self.payload(self.clone, name)
        for k in ('criterios', 'problemas', 'resumo'):
            pl.pop(k)
        git(self.clone, 'tag', '-d', name)
        git(self.clone, '-c', 'gpg.format=openpgp', 'tag', '-s', '-u', self.fp['reviewer'], '-m', canon(pl).decode(), name, self.M2)
        self.assert_refused(self.override(self.authorize(doc=self.raw_doc())), 'OVERRIDE_REVIEW_WITHOUT_CRITERIA')

    def test_o13_parecer_com_mais_pontos_que_a_tag_recusado(self):
        # 24/11 (achado MEDIO do QA 6): 30 problemas no parecer, a tag guarda 24 -> um ponto pode estar invisivel -> recusa
        B.FakeOpenRouter.state['verdict'] = {**UNFAV, 'problemas': [f'problema {i}' for i in range(30)]}
        self.reject_first()
        p = self.payload(self.clone, f'review/R0-01/{self.M2}')
        self.assertEqual((len(p['problemas']), p['problemas_total']), (24, 30))
        d = self.raw_doc()
        d['mapeamento']['problemas'] = [{'texto': t, 'dps': ['DP-33']} for t in p['problemas']]
        self.assert_refused(self.override(self.authorize(doc=d)), 'OVERRIDE_REVIEW_TRUNCATED')
        # total adulterado numa tag re-assinada pelo revisor tambem e recusado (criterios_total != lista)
        name = f'review/R0-01/{self.M2}'
        pl = {**p, 'problemas': p['problemas'][:1], 'problemas_total': 1, 'criterios_total': 9}
        git(self.clone, 'tag', '-d', name)
        git(self.clone, '-c', 'gpg.format=openpgp', 'tag', '-s', '-u', self.fp['reviewer'], '-m', canon(pl).decode(), name, self.M2)
        d = self.raw_doc()
        d['mapeamento']['problemas'] = [{'texto': 'problema 0', 'dps': ['DP-33']}]
        self.assert_refused(self.override(self.authorize(doc=d)), 'OVERRIDE_REVIEW_TRUNCATED')

    def test_o12_ja_aceita_nao_repete(self):
        self.reject_first()
        e = self.authorize()
        self.assertEqual(self.override(e).returncode, 0)
        git(self.clone, 'fetch', '-q', 'origin', 'refs/tags/*:refs/tags/*')
        self.assert_refused_keep = self.override(e)
        self.assertEqual(self.assert_refused_keep.returncode, 1)
        self.assertIn('ALREADY_ACCEPTED', self.assert_refused_keep.stdout.decode())


if __name__ == '__main__':
    unittest.main(verbosity=2)
