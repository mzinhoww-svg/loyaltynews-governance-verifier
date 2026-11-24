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

    def test_06_secao_de_decisoes_respeita_o_teto_estrito(self):
        # 24/11 (nota QA 6): o aviso de corte cabe DENTRO de max_decisions_chars
        cfg = dict(CFG, max_decisions_chars=500)
        decs = [{'id': 'DP-44', 'escolha': 'Q' * 3000}]
        h = self.commit({'inv.md': 'risco aceito pela DP-44'}, decs)
        pkg = review.build_package(self.repo, h, 'R0-01', {'tests': []}, cfg)
        head = '## Decisoes citadas (governance/decisions.yaml no commit alvo)\n'
        sec = pkg.split(head, 1)[1].split('\n\n## ', 1)[0]
        self.assertLessEqual(len(sec), 500)
        self.assertIn('[TRUNCADO:', sec)
        self.assertEqual(CFG['max_decisions_chars'], 20000)   # o teto vem do config (nao mais de um padrao no codigo)

    def test_07_decisions_ausente_ou_id_sem_entrada_e_dito_no_pacote(self):
        # 24/11 (nota QA 6): sem decisions.yaml legivel, o pacote avisa em vez de omitir em silencio
        h = self.commit({'inv.md': 'risco aceito pela DP-44'}, [])
        (self.repo / 'governance' / 'decisions.yaml').write_text('{nao e json', encoding='utf-8')
        git(self.repo, 'add', '-A'); git(self.repo, 'commit', '-q', '-m', 'decisions invalido')
        pkg = review.build_package(self.repo, git(self.repo, 'rev-parse', 'HEAD'), 'R0-01', {'tests': []}, CFG)
        self.assertIn('[governance/decisions.yaml AUSENTE OU INVALIDO no commit alvo; ids citados: DP-44]', pkg)
        h = self.commit({'inv.md': 'DP-44 e DP-46'}, [{'id': 'DP-44', 'escolha': 'x'}])
        pkg = review.build_package(self.repo, h, 'R0-01', {'tests': []}, CFG)
        self.assertIn('[ids citados sem entrada no decisions.yaml: DP-46]', pkg)

    def test_08_relacao_commit_da_evidencia_com_o_alvo(self):
        # 24/11 (problema[2] da rev. 8): fato do git no pacote: ancestral + artefatos iguais
        r = self.repo
        a = self.commit({'inv.md': 'conteudo'}, [])                      # commit dos artefatos (A)
        ev = json.loads(git(r, 'show', f'{a}:governance/evidence/R0/R0-01.json'))
        ev['commit_sha'] = a
        (r / 'governance' / 'evidence' / 'R0' / 'R0-01.json').write_text(json.dumps(ev), encoding='utf-8')
        git(r, 'add', '-A'); git(r, 'commit', '-q', '-m', 'registro')
        h = git(r, 'rev-parse', 'HEAD')
        pkg = review.build_package(r, h, 'R0-01', {'tests': []}, CFG)
        self.assertIn('## Relacao do commit da evidencia com o alvo (calculada pelo verificador)', pkg)
        self.assertIn(f'- R0-01: registro aponta para {a[:12]}; E ancestral do alvo {h[:12]}', pkg)
        self.assertIn('1/1 artefatos com o mesmo sha256', pkg)
        self.assertIn('do commit do registro ao alvo mudaram 1 arquivo(s), todos em governance/evidence/', pkg)   # condicao da DP-48
        # alvo que tambem muda arquivo fora de governance/evidence: o pacote nomeia o arquivo
        (r / 'outro.md').write_text('mudou fora'); git(r, 'add', '-A'); git(r, 'commit', '-q', '-m', 'fora da evidencia')
        pkg = review.build_package(r, git(r, 'rev-parse', 'HEAD'), 'R0-01', {'tests': []}, CFG)
        self.assertIn('1 FORA de governance/evidence/: outro.md', pkg)
        git(r, 'reset', '-q', '--hard', h)
        # commit fora da historia do alvo e artefato alterado depois: o pacote diz
        git(r, 'checkout', '-q', '--orphan', 'outra'); git(r, 'rm', '-rq', '--cached', '.')
        (r / 'x.txt').write_text('x'); git(r, 'add', 'x.txt'); git(r, 'commit', '-q', '-m', 'fora')
        fora = git(r, 'rev-parse', 'HEAD'); git(r, 'checkout', '-q', '-f', h)
        ev['commit_sha'] = fora
        (r / 'governance' / 'evidence' / 'R0' / 'R0-01.json').write_text(json.dumps(ev), encoding='utf-8')
        git(r, 'add', '-A'); git(r, 'commit', '-q', '-m', 'registro ruim')
        h2 = git(r, 'rev-parse', 'HEAD')
        pkg = review.build_package(r, h2, 'R0-01', {'tests': []}, CFG)
        self.assertIn(f'NAO E ancestral do alvo {h2[:12]}', pkg)
        self.assertIn('0/1 artefatos', pkg)
        ev['commit_sha'] = 'xyz'
        (r / 'governance' / 'evidence' / 'R0' / 'R0-01.json').write_text(json.dumps(ev), encoding='utf-8')
        git(r, 'add', '-A'); git(r, 'commit', '-q', '-m', 'sem sha')
        pkg = review.build_package(r, git(r, 'rev-parse', 'HEAD'), 'R0-01', {'tests': []}, CFG)
        self.assertIn('- R0-01: commit_sha do registro ausente ou invalido', pkg)

    def test_09_relacao_sobrevive_ao_corte_global_e_vem_antes_dos_artefatos(self):
        # 24/11 (P3 do QA 6): a secao fica logo depois da evidencia; o corte global no teto corta o fim, nunca ela
        r = self.repo
        a = self.commit({'inv.md': 'conteudo'}, [])
        ev = json.loads(git(r, 'show', f'{a}:governance/evidence/R0/R0-01.json'))
        ev['commit_sha'] = a
        (r / 'governance' / 'evidence' / 'R0' / 'R0-01.json').write_text(json.dumps(ev), encoding='utf-8')
        git(r, 'add', '-A'); git(r, 'commit', '-q', '-m', 'registro')
        h = git(r, 'rev-parse', 'HEAD')
        big = {'tests': [{'id': f'T{i}', 'result': 'pass', 'log_sha256': '0' * 64} for i in range(400)]}   # relatorio enorme no fim
        cfg = dict(CFG, max_prompt_chars=3000)
        pkg = review.build_package(r, h, 'R0-01', big, cfg)
        self.assertIn('[PACOTE TRUNCADO NO TETO DE 3000 CARACTERES]', pkg)        # houve corte global
        sec = '## Relacao do commit da evidencia com o alvo (calculada pelo verificador)'
        self.assertIn(sec, pkg)
        self.assertIn('E ancestral do alvo', pkg)
        self.assertLess(pkg.index(sec), pkg.index('## Artefato '))

    def test_05_water_fill(self):
        self.assertEqual(review._water_fill({1: 10, 2: 100, 3: 1000}, 2000), {1: 10, 2: 100, 3: 1000})
        self.assertEqual(review._water_fill({1: 10, 2: 1000, 3: 1000}, 610), {1: 10, 2: 300, 3: 300})
        self.assertEqual(review._water_fill({1: 50}, -5), {1: 0})


if __name__ == '__main__':
    unittest.main(verbosity=2)
