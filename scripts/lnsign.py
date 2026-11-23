#!/usr/bin/env python3
"""Utilitarios comuns do revisor e do assinador (R0-06): chaveiro descartavel, tags assinadas, verificacao e transporte.

- Nenhum segredo e impresso. Chave privada so entra por variavel de ambiente do job (ambiente GitHub restrito a main)
  e vai para um GNUPGHOME temporario, apagado no fim.
- O formato da tag e o mesmo que kit/gov.py le em signed(): mensagem = JSON canonico com commit_sha = alvo.
"""
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import tempfile

SHA = re.compile(r'^[0-9a-f]{40}$')
TASK = re.compile(r'^R[0-6]-[0-9]{2}$')
FPR = re.compile(r'^[0-9A-F]{40}$')


class SignError(Exception):
    pass


def canon(x):
    return json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def git(repo, *args, env=None, check=True, inp=None):
    e = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', **(env or {})}
    p = subprocess.run(['git', '-C', str(repo), '-c', 'core.hooksPath=' + os.devnull, *args],
                       capture_output=True, env=e, input=inp)
    if check and p.returncode:
        raise SignError('git ' + ' '.join(args[:2]) + ': ' + p.stderr.decode(errors='replace').strip()[:300])
    return p


class Keyring:
    """GNUPGHOME descartavel com as chaves publicas confiaveis e, opcionalmente, UMA chave privada (a do papel do job)."""

    def __init__(self, pubkeys_dir, private_env=None, passphrase_env=None, expect_secret_fpr=None):
        self.dir = tempfile.mkdtemp(prefix='ln-gnupg-')
        os.chmod(self.dir, 0o700)
        self.env = {'GNUPGHOME': self.dir}
        self.gpg_program = None
        for f in sorted(pathlib.Path(pubkeys_dir).glob('*.asc')):
            self._gpg('--batch', '--quiet', '--import', str(f))
        armored = os.environ.get(private_env) if private_env else None
        if armored:
            self._gpg('--batch', '--quiet', '--pinentry-mode', 'loopback', '--passphrase',
                      os.environ.get(passphrase_env or '', ''), '--import', inp=armored.encode())
            pw = os.environ.get(passphrase_env or '')
            if pw:
                # gpg.program com loopback + arquivo de senha (0600) dentro do GNUPGHOME descartavel.
                pf = pathlib.Path(self.dir) / '.pw'
                pf.write_text(pw)
                os.chmod(pf, stat.S_IRUSR | stat.S_IWUSR)
                w = pathlib.Path(self.dir) / 'gpg-loopback.sh'
                w.write_text('#!/bin/sh\nexec gpg --batch --pinentry-mode loopback --passphrase-file "%s" "$@"\n' % pf)
                os.chmod(w, stat.S_IRWXU)
                self.gpg_program = str(w)
        elif private_env:
            # Sem chave por ambiente: so permitido em teste local, com o GNUPGHOME de fixture (LN_SIGN_TEST_GNUPGHOME).
            fixture = os.environ.get('LN_SIGN_TEST_GNUPGHOME')
            if not fixture:
                self.close()
                raise SignError(f'{private_env} ausente (falha fechada)')
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = fixture
            self.env = {'GNUPGHOME': fixture}
            self._fixture = True
        if expect_secret_fpr:
            out = self._gpg('--batch', '--with-colons', '--list-secret-keys').stdout.decode()
            fprs = {l.split(':')[9] for l in out.splitlines() if l.startswith('fpr:')}
            if expect_secret_fpr.upper() not in fprs:
                self.close()
                raise SignError('chave privada do papel nao corresponde a fingerprint do trust.json')

    def _gpg(self, *args, inp=None):
        p = subprocess.run(['gpg', *args], capture_output=True, env={**os.environ, **self.env}, input=inp)
        if p.returncode:
            raise SignError('gpg falhou: ' + ' '.join(a for a in args if not a.startswith('-----'))[:80])
        return p

    def git_cfg(self):
        return ['-c', 'gpg.format=openpgp'] + (['-c', 'gpg.program=' + self.gpg_program] if self.gpg_program else [])

    def close(self):
        if getattr(self, '_fixture', False):
            return
        subprocess.run(['gpgconf', '--kill', 'all'], capture_output=True, env={**os.environ, **self.env})
        shutil.rmtree(self.dir, ignore_errors=True)


def sign_tag(repo, keyring, fpr, name, target, payload, who):
    body = canon({**payload, 'commit_sha': target}).decode()
    git(repo, *keyring.git_cfg(), '-c', f'user.name={who[0]}', '-c', f'user.email={who[1]}',
        'tag', '-s', '-u', fpr, '-m', body, name, target, env=keyring.env)
    return json.loads(body)


def verify_tag(repo, keyring, name, fpr, target):
    """Payload da tag se: objeto tag anotado, assinatura VALIDSIG da fingerprint pedida, aponta para target e
    commit_sha do payload == target. Senao None (mesma regra do kit/gov.py signed())."""
    t = git(repo, 'cat-file', '-t', name, check=False)
    if t.returncode or t.stdout.decode().strip() != 'tag':
        return None
    v = git(repo, 'verify-tag', '--raw', name, env=keyring.env, check=False)
    lines = [l for l in v.stderr.decode(errors='replace').upper().splitlines() if l.startswith('[GNUPG:] VALIDSIG ')]
    if v.returncode or not any(fpr.upper() in l.split()[2:] for l in lines):
        return None
    if git(repo, 'rev-parse', name + '^{commit}').stdout.decode().strip() != target:
        return None
    raw = git(repo, 'cat-file', 'tag', name).stdout.decode()
    try:
        payload = json.loads(raw.split('\n\n', 1)[1].split('-----BEGIN PGP SIGNATURE-----', 1)[0])
    except (IndexError, ValueError):
        return None
    return payload if payload.get('commit_sha') == target else None


def export_tag(repo, name):
    oid = git(repo, 'rev-parse', 'refs/tags/' + name).stdout.decode().strip()
    return oid, git(repo, 'cat-file', 'tag', oid).stdout


def import_tag(repo, name, raw, expect_oid):
    oid = git(repo, 'mktag', inp=raw).stdout.decode().strip()
    if oid != expect_oid:
        raise SignError('objeto da tag importada difere do exportado')
    git(repo, 'update-ref', 'refs/tags/' + name, oid, '')  # '' = so cria se nao existir
    return oid
