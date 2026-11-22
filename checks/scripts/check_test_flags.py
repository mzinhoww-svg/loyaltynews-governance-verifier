#!/usr/bin/env python3
"""Reprova flags de teste fora de caminhos de teste (alerta de seguranca do PM, 22/11/2026).

- LN_STUDIO_TEST_SESSION: sessao simulada do LN Studio (so e2e). Reprova se for DEFINIDA (atribuida/configurada) fora de teste.
- PORTAL_SOURCE=mock / PORTAL_MODE=mock: fixtures MOCK do portal. Reprova se definidas como 'mock' fora de teste.
Ler a variavel no codigo (ex.: process.env.X === '1') e permitido: e o proprio portao. Mencoes em .md e linhas so de comentario sao permitidas.
Uso: check_test_flags.py <raiz do produto>   (somente leitura; sem rede; saida 0 = ok, 1 = violacao)
"""
import os, re, sys

ROOT = sys.argv[1] if len(sys.argv) > 1 else '.'
SKIP_DIRS = {'.git', 'node_modules', '.next', 'dist', 'build', 'coverage', '.turbo'}
TEST_PATH = re.compile(r'(^|/)(tests?|e2e|__tests__|__mocks__|fixtures)(/|$)|\.(test|spec)\.[cm]?[jt]sx?$|(^|/)(playwright|vitest|jest)\.config\.[cm]?[jt]s$', re.I)
DOC_PATH = re.compile(r'\.(md|mdx|txt)$', re.I)
TYPES_PATH = re.compile(r'\.d\.ts$', re.I)
# definicao da sessao simulada: atribuicao (= ou :) que NAO seja comparacao (==, ===) e nao seja tipo opcional (?:)
SESSION_SET = re.compile(r'LN_STUDIO_TEST_SESSION["\']?\s*(?:=(?!=)|:(?!:))\s*\S|ENV\s+LN_STUDIO_TEST_SESSION\b|export\s+LN_STUDIO_TEST_SESSION\b|set\s+LN_STUDIO_TEST_SESSION\b')
COMMENT_LINE = re.compile(r'^\s*(//|/\*|\*|#|<!--)')
PORTAL_MOCK = re.compile(r'PORTAL_(?:SOURCE|MODE)["\']?\s*(?:=(?!=)|:(?!:))\s*["\']?mock\b')

def main():
    bad = []
    for d, dirs, files in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for name in files:
            p = os.path.join(d, name)
            rel = os.path.relpath(p, ROOT).replace(os.sep, '/')
            if TEST_PATH.search(rel) or DOC_PATH.search(rel):
                continue
            try:
                if os.path.getsize(p) > 2_000_000:
                    continue
                with open(p, 'rb') as fh:
                    raw = fh.read()
            except OSError:
                continue
            if b'\0' in raw[:4096]:
                continue
            text = raw.decode('utf-8-sig', 'replace')
            for n, line in enumerate(text.splitlines(), 1):
                if COMMENT_LINE.match(line):
                    continue
                if not TYPES_PATH.search(rel) and SESSION_SET.search(line):
                    bad.append(f'{rel}:{n}: LN_STUDIO_TEST_SESSION definida fora de teste')
                if PORTAL_MOCK.search(line):
                    bad.append(f'{rel}:{n}: PORTAL_SOURCE/PORTAL_MODE=mock fora de teste')
    for b in bad:
        print('VIOLACAO', b)
    print(f'check_test_flags: {len(bad)} violacao(oes)')
    sys.exit(1 if bad else 0)

if __name__ == '__main__':
    main()
