"""Testes do git_err (scripts/lnsign.py). Destino no repo: tests/test_lnsign_git_err.py."""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
for cand in (ROOT.parent / 'scripts', ROOT):
    if (cand / 'lnsign.py').exists():
        sys.path.insert(0, str(cand))
        break
from lnsign import SignError, git, git_err  # noqa: E402

# Saida real do push de task/R0-01/rejected (run 45301645684), com o motivo final que o corte em 300 escondia.
PUSH = ('remote: Bypassed rule violations for refs/tags/task/R0-01/rejected/c496dff1f8295f592517f3bbaa0620e7e7a37509:        \n'
        'remote: \nremote: - Cannot create ref due to creations being restricted.        \nremote: \n'
        'To https://github.com/mzinhoww-svg/loyaltynews.git\n'
        ' ! [remote rejected] task/R0-01/rejected/c496dff1f8295f592517f3bbaa0620e7e7a37509 -> '
        'task/R0-01/rejected/c496dff1f8295f592517f3bbaa0620e7e7a37509 (MOTIVO-FINAL-DO-SERVIDOR)\n'
        "error: failed to push some refs to 'https://github.com/mzinhoww-svg/loyaltynews.git'\n")


class GitErr(unittest.TestCase):
    def test_g1_push_real_mostra_motivo(self):
        out = git_err(PUSH.encode())
        self.assertIn('(MOTIVO-FINAL-DO-SERVIDOR)', out)
        self.assertIn('[remote rejected]', out)
        self.assertIn('failed to push some refs', out)

    def test_g2_longo_guarda_diagnostico_inteiro_e_fim(self):
        ruido = ''.join(f'remote: linha de ruido {i:04d} ' + 'x' * 60 + '\n' for i in range(200))
        out = git_err((ruido + PUSH).encode())
        self.assertLessEqual(len(out), 1500)
        self.assertIn('(MOTIVO-FINAL-DO-SERVIDOR)', out)
        self.assertTrue(out.startswith('remote: linha de ruido 0000'))

    def test_g3_curto_inalterado(self):
        self.assertEqual(git_err(b'  fatal: not a git repository  \n'), 'fatal: not a git repository')

    def test_g4_teto(self):
        out = git_err(('error: ' + 'y' * 5000 + '\n').encode() * 5)
        self.assertLessEqual(len(out), 1500)

    def test_g6_linhas_de_diagnostico_nunca_cortadas_no_meio(self):
        # 24/11 (nota baixa do QA 6): diagnosticos longos entram inteiros ou sao contados, nunca pela metade
        linhas = [f'error: diagnostico {i:02d} ' + 'z' * 150 + f' FIM{i:02d}' for i in range(12)]
        out = git_err(('remote: ' + 'r' * 300 + '\n' + '\n'.join(linhas) + '\n' + 'remote: ' + 'q' * 500 + '\n').encode())
        self.assertLessEqual(len(out), 1500)
        mid = out.split(' [...] ')[1]
        for i in range(12):
            frag = f'diagnostico {i:02d} '
            if frag in mid:
                self.assertIn(f'FIM{i:02d}', mid)      # se entrou, entrou inteira
        self.assertRegex(mid, r'\[\+\d+ linha\(s\) de diagnostico\]')

    def test_g5_git_levanta_signerror_com_mensagem_completa(self):
        with self.assertRaises(SignError) as cm:
            git(ROOT, 'rev-parse', '--verify', 'refs/tags/nao-existe-' + 'z' * 40)
        self.assertTrue(str(cm.exception).startswith('git rev-parse --verify: '))


if __name__ == '__main__':
    unittest.main()
