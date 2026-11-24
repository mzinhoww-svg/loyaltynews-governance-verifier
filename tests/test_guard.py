"""Guard: desvio de configuracao (23/11). Sem rede: troca guard.api por respostas fixas.
Rodar da raiz do repo verificador: python -B tests/test_guard.py -v"""
import copy, io, json, os, pathlib, sys, unittest
from contextlib import redirect_stdout
V = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V / 'scripts'))
import guard  # noqa: E402

TRUST = json.loads((V / 'trust.json').read_text(encoding='utf-8'))
PROD = 'mzinhoww-svg/loyaltynews'
VER = 'mzinhoww-svg/loyaltynews-governance-verifier'


def world():
    """Estado 'bom': o esperado pelo trust, com main-required-checks completo."""
    rs = {}
    rid = 100
    for repo, want in TRUST['expected_config']['repos'].items():
        for name in want['rulesets_active']:
            rid += 1
            rules = []
            if name in (want.get('required_status_checks') or {}):
                rules = [{'type': 'required_status_checks', 'parameters': {'required_status_checks': copy.deepcopy(want['required_status_checks'][name])}}]
            rs[(repo, name)] = {'id': rid, 'name': name, 'enforcement': 'active', 'rules': rules}
        for name in want.get('rulesets_disabled', []):
            rid += 1
            rs[(repo, name)] = {'id': rid, 'name': name, 'enforcement': 'disabled', 'rules': []}
    return rs


class Guard(unittest.TestCase):
    def run_guard(self, rs):
        def api(path):
            for repo, want in TRUST['expected_config']['repos'].items():
                if path == f'/repos/{repo}':
                    return {'visibility': want['visibility'], 'default_branch': want['default_branch']}
                if path == f'/repos/{repo}/rulesets':
                    return [{'id': v['id'], 'name': n} for (r, n), v in rs.items() if r == repo]
                for (r, n), v in rs.items():
                    if r == repo and path == f'/repos/{repo}/rulesets/{v["id"]}':
                        return v
            raise AssertionError('chamada inesperada: ' + path)
        guard.api = api
        tp = V / 'trust.json'
        out = io.StringIO()
        os.environ['LN_EMERGENCY_STOP'] = '0'
        sys.argv = ['guard.py', str(tp)]
        code = 0
        with redirect_stdout(out):
            try:
                guard.main()
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def test_01_trust_espera_main_required_checks(self):
        want = TRUST['expected_config']['repos'][PROD]
        self.assertIn('main-required-checks', want['rulesets_active'])
        self.assertEqual(sorted(c['context'] for c in want['required_status_checks']['main-required-checks']),
                         ['ln-verifier/clean-checks', 'ln-verifier/protected-paths'])

    def test_02_estado_bom_passa(self):
        code, out = self.run_guard(world())
        self.assertEqual(code, 0, out)
        self.assertIn('guard ok', out)

    def test_03_ruleset_sumiu_reprova(self):
        rs = world(); del rs[(PROD, 'main-required-checks')]
        code, out = self.run_guard(rs)
        self.assertEqual(code, 1); self.assertIn('ruleset ausente main-required-checks', out)

    def test_04_ruleset_desativado_reprova(self):
        rs = world(); rs[(PROD, 'main-required-checks')]['enforcement'] = 'disabled'
        code, out = self.run_guard(rs)
        self.assertEqual(code, 1); self.assertIn('main-required-checks nao ativo', out)

    def test_05_contexto_a_menos_reprova(self):
        rs = world(); rs[(PROD, 'main-required-checks')]['rules'][0]['parameters']['required_status_checks'].pop()
        code, out = self.run_guard(rs)
        self.assertEqual(code, 1); self.assertIn('sem o check', out)

    def test_06_check_de_outro_app_reprova(self):
        rs = world()
        for c in rs[(PROD, 'main-required-checks')]['rules'][0]['parameters']['required_status_checks']:
            c['integration_id'] = 15368   # GitHub Actions, nao a App LN Verifier
        code, out = self.run_guard(rs)
        self.assertEqual(code, 1); self.assertIn('sem o check', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
