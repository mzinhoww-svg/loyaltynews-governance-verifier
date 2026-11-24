"""Pacote do revisor (23/11): artefatos nao truncados quando cabem no teto; corte so do excedente, com aviso; decisoes citadas no pacote.
Sem rede e sem chave: monta um repo git descartavel e chama reviewer/review.py:build_package. Rodar: python -B tests/test_review_package.py -v"""
import json, pathlib, shutil, subprocess, sys, tempfile, unittest
V = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V / 'scripts'))
sys.path.insert(0, str(V / 'reviewer'))
import review  # noqa: E402

CFG = json.loads((V / 'reviewer' / 'config.json').read_text(encoding='utf-8'))


def git(repo, *a):
    return subprocess.run(['git', '-C', str(repo), '-c', 'core.autocrlf=false', '-c', 'commit.gpgsign=false', *a], check=True, capture_output=True).stdout.decode().strip()


class Pacote(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.repo = self.tmp / 'p'
        self.repo.mkdir()
        git(self.repo, 'init', '-q')
        git(self.repo, 'config', 'user.email', 't@t.invalid'); git(self.repo, 'config', 'user.name', 't')

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def commit(self, arts, decisions, cite=''):
        r = self.repo
        (r / 'governance' / 'evidence' / 'R0').mkdir(parents=True, exist_ok=True)
        (r / 'governance' / 'backlog.yaml').write_text(json.dumps([{'id': 'R0-01', 'gate': 'R0', 'kind': 'task', 'tarefa': 't', 'criterio_de_aceite': 'c', 'required_tests': ['R0-01-TEST']}]), encoding='utf-8')
        (r / 'governance' / 'decisions.yaml').write_text(json.dumps(decisions, ensure_ascii=False), encoding='utf-8')
        ev = []
        for name, text in arts.items():
            (r / name).write_text(text, encoding='utf-8')
            ev.append({'caminho': name, 'sha256': review.sha256(text.encode('utf-8')), 'bytes': len(text.encode('utf-8'))})
        (r / 'governance' / 'evidence' / 'R0' / 'R0-01.json').write_text(json.dumps({'tarefa': 'R0-01', 'artefatos': ev, 'nota': cite}), encoding='utf-8')
        git(r, 'add', '-A'); git(r, 'commit', '-q', '-m', 'ev')
        return git(r, 'rev-parse', 'HEAD')

    def test_01_quatro_artefatos_que_cabem_entram_inteiros(self):
        # caso real da R0-01: 10.000 + 2.824 + 7.697 + 4.755 caracteres; antes cada um era cortado em 7.500
        arts = {'inv.md': 'A' * 9000 + '\nSECAO 3: PENDENTE C15 ... fim do inventario', 'teto.md': 'B' * 2824, 'escopo.log': 'C' * 7697, 'escopo.json': 'D' * 4755}
        h = self.commit(arts, [])
        pkg = review.build_package(self.repo, h, 'R0-01', {'tests': []}, CFG)
        self.assertIn('SECAO 3: PENDENTE C15 ... fim do inventario', pkg)
        self.assertNotIn('[TRUNCADO', pkg)
        self.assertLessEqual(len(pkg), CFG['max_prompt_chars'])

    def test_02_decisoes_citadas_entram_no_pacote(self):
        decs = [{'id': 'D01', 'escolha': 'x'}, {'id': 'DP-33', 'escolha': 'teto dispensado'}, {'id': 'DP-44', 'escolha': 'risco aceito C15 C19 C20 C21 C22'}, {'id': 'DP-40', 'escolha': 'nao citada'}]
        h = self.commit({'inv.md': 'risco aceito pela DP-44; teto pela DP-33'}, decs, cite='ver DP-33')
        pkg = review.build_package(self.repo, h, 'R0-01', {'tests': []}, CFG)
        self.assertIn('## Decisoes citadas (governance/decisions.yaml no commit alvo)', pkg)
        self.assertIn('risco aceito C15 C19 C20 C21 C22', pkg)
        self.assertIn('teto dispensado', pkg)
        self.assertNotIn('nao citada', pkg)       # so as citadas
        self.assertNotIn('"D01"', pkg)

    def test_03_excedente_cortado_com_aviso_e_total_no_teto(self):
        cfg = dict(CFG, max_prompt_chars=20000)
        arts = {'grande1.md': 'X' * 30000, 'pequeno.md': 'Y' * 1000, 'grande2.md': 'Z' * 30000}
        h = self.commit(arts, [])
        pkg = review.build_package(self.repo, h, 'R0-01', {'tests': []}, cfg)
        self.assertIn('Y' * 1000, pkg)                   # o pequeno entra inteiro
        self.assertEqual(pkg.count('[TRUNCADO: 30000 caracteres no total'), 2)
        self.assertLessEqual(len(pkg), 20000 + 80)        # teto (mais a linha de aviso final, se houver)
        self.assertNotIn('[PACOTE TRUNCADO', pkg)          # o orcamento dos artefatos ja cabe

    def test_04_sha_divergente_e_ausente_sinalizados(self):
        h = self.commit({'a.md': 'ok'}, [])
        ev = json.loads(git(self.repo, 'show', f'{h}:governance/evidence/R0/R0-01.json'))
        ev['artefatos'][0]['sha256'] = '0' * 64
        ev['artefatos'].append({'caminho': 'sumiu.md', 'sha256': '1' * 64})
        (self.repo / 'governance' / 'evidence' / 'R0' / 'R0-01.json').write_text(json.dumps(ev), encoding='utf-8')
        git(self.repo, 'add', '-A'); git(self.repo, 'commit', '-q', '-m', 'adulterado')
        pkg = review.build_package(self.repo, git(self.repo, 'rev-parse', 'HEAD'), 'R0-01', {'tests': []}, CFG)
        self.assertIn('sha256 NAO CONFERE', pkg)
        self.assertIn('[AUSENTE NO COMMIT ALVO]', pkg)

    def test_05_water_fill(self):
        self.assertEqual(review._water_fill({1: 10, 2: 100, 3: 1000}, 2000), {1: 10, 2: 100, 3: 1000})
        self.assertEqual(review._water_fill({1: 10, 2: 1000, 3: 1000}, 610), {1: 10, 2: 300, 3: 300})
        self.assertEqual(review._water_fill({1: 50}, -5), {1: 0})


if __name__ == '__main__':
    unittest.main(verbosity=2)
