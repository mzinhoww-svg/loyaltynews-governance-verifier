# loyaltynews-governance-verifier — plano de controle do Loyalty News
Repositório **público** (DP-06). Aqui não há nenhum segredo: chaves privadas e tokens ficam só nos ambientes `verifier-signing` e `reviewer`, restritos ao branch `main`.

| Caminho | Conteúdo |
|---|---|
| `.github/workflows/verifier.yml` | Jobs `trust-gate` → `guard` → `discover` → `fetch` → `runner` → `reviewer` → `signer` |
| `trust.json` | Fingerprints, baseline do produto, hash da política, caminhos protegidos, configuração esperada. Muda só por commit assinado pela raiz |
| `checks/r0-policy.json` | Política de checks (argv fixo, container sem rede) |
| `scripts/verify_root_chain.sh` | Todo commit desde `TRUST_ANCHOR_SHA` precisa ter assinatura da raiz (`ROOT_FPR`) |
| `scripts/guard.py` | Detecção de desvio (rulesets, visibilidade, parada de emergência) |
| `scripts/provenance.py` | Validação conjunta: workflow, run, tentativa, job, ZIP, JSON, política, commit |
| `kit/` | `verifier.py`, `gov.py`, `clean_checks.py` do pacote v2.1 com o patch V21-16 v2 |
| `runner/Dockerfile` | Imagem dos testes (git + gnupg), sem rede na execução |

Variáveis de repositório (públicas): `ROOT_FPR`, `ROOT_PUBKEY`, `TRUST_ANCHOR_SHA`, `LN_EMERGENCY_STOP`, `LN_VERIFIER_APP_ID`.

Estado: os jobs `reviewer` e `signer` **falham fechados** de propósito, até a R0-06 entregar o prompt e o modelo do revisor e a integração final do signer. Até lá, nenhuma tag é assinada. A descoberta automática de alvos também está pendente; por ora o disparo é manual (`workflow_dispatch`).

Parada de emergência: `LN_EMERGENCY_STOP=1` faz o `guard` falhar e nada roda depois dele.
