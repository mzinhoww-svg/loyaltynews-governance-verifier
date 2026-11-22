#!/usr/bin/env bash
# Verifica que TODO commit de TRUST_ANCHOR_SHA ate o SHA alvo (inclusive a ancora) foi assinado pela chave raiz fixada.
# Entradas por ambiente: ROOT_FPR (40 hex), ROOT_PUBKEY (armored), TRUST_ANCHOR_SHA (40 hex), TARGET_SHA (40 hex).
# Sai 0 so se tudo confere. Usa chaveiro vazio e descartavel; nao le config Git do sistema nem hooks.
set -euo pipefail
: "${ROOT_FPR:?}" "${ROOT_PUBKEY:?}" "${TRUST_ANCHOR_SHA:?}" "${TARGET_SHA:?}"
[[ "$ROOT_FPR" =~ ^[0-9A-Fa-f]{40}$ ]] || { echo "ROOT_FPR invalido"; exit 1; }
[[ "$TRUST_ANCHOR_SHA" =~ ^[0-9a-f]{40}$ && "$TARGET_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "SHA invalido"; exit 1; }
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; chmod 700 "$GNUPGHOME"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$GNUPGHOME"' EXIT
printf '%s\n' "$ROOT_PUBKEY" | gpg --batch --quiet --import
got="$(gpg --batch --with-colons --list-keys | awk -F: '/^fpr:/{print $10; exit}')"
[[ "${got^^}" == "${ROOT_FPR^^}" ]] || { echo "ROOT_PUBKEY nao corresponde a ROOT_FPR"; exit 1; }
git -c core.hooksPath=/dev/null merge-base --is-ancestor "$TRUST_ANCHOR_SHA" "$TARGET_SHA" || { echo "ancora nao e ancestral do alvo"; exit 1; }
fail=0
for c in "$TRUST_ANCHOR_SHA" $(git rev-list "${TRUST_ANCHOR_SHA}..${TARGET_SHA}"); do
  out="$(git -c core.hooksPath=/dev/null -c gpg.program=gpg verify-commit --raw "$c" 2>&1 || true)"
  if ! printf '%s\n' "$out" | awk -v fp="${ROOT_FPR^^}" 'toupper($0) ~ /^\[GNUPG:\] VALIDSIG / { for (i=3;i<=NF;i++) if (toupper($i)==fp) ok=1 } END { exit ok?0:1 }'; then
    echo "commit sem assinatura valida da raiz: $c"; fail=1
  fi
done
[[ $fail -eq 0 ]] && echo "cadeia raiz ok: ${TRUST_ANCHOR_SHA}..${TARGET_SHA}"
exit $fail
