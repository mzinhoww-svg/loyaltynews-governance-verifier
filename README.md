# loyaltynews-governance-verifier — plano de controle do Loyalty News
Repositório **público** (DP-06). Aqui não há nenhum segredo: chaves privadas e tokens ficam só nos ambientes `verifier-signing` e `reviewer`, restritos ao branch `main`.

| Caminho | Conteúdo |
|---|---|
| `.github/workflows/verifier.yml` | Jobs `trust-gate` → `guard` → `discover` → `fetch` → `runner` → `reviewer` → `signer` |
| `trust.json` | Fingerprints, baseline do produto, hash da política, caminhos protegidos, configuração esperada. Muda só por commit assinado pela raiz |
| `checks/r0-policy.json` | Política de checks (argv fixo, container sem rede), com uma entrada por tarefa R0 e o gate R0-12 reunindo os testes exigidos da onda |
| `checks/scripts/check_r0.py` | Regras confiáveis da forma verificável da evidência de cada tarefa R0 (o mérito é do revisor); falha fechada |
| `keys/*.asc` | Chaves **públicas** de raiz, executor, revisor e verificador (as mesmas fingerprints do `trust.json`) |
| `reviewer/` | `review.py`, `config.json` (modelo, preço, teto de custo) e `prompt-v1.md` do revisor de outro provedor |
| `scripts/signer.py` | Assinador: `checks/<T>/<SHA>`, parecer do revisor, `kit/verifier.py gov_accept_gate`, push só das refs validadas |
| `scripts/discover.py` | Descoberta automatica (02 v3 par.2): um alvo pendente por execucao agendada (Mi da tarefa ou ponta para o gate), pulando com motivo o que seria recusado; sem segredo |
| `scripts/premerge.py` | Status pre-merge (opcao B do PM): `ln-verifier/protected-paths` (caminho protegido sem ato raiz assinado = failure) e `ln-verifier/clean-checks` (runner limpo, politica `PR`), postados pela App no head do PR; sem LLM por PR |
| `scripts/lnsign.py` | Chaveiro descartável, assinatura, verificação e transporte de tags (comum ao revisor e ao assinador) |
| `scripts/verify_root_chain.sh` | Todo commit desde `TRUST_ANCHOR_SHA` precisa ter assinatura da raiz (`ROOT_FPR`) |
| `scripts/guard.py` | Detecção de desvio (rulesets, visibilidade, parada de emergência) |
| `scripts/provenance.py` | Validação conjunta: workflow, run, tentativa, job, ZIP, JSON, política, commit |
| `kit/` | `verifier.py`, `gov.py`, `clean_checks.py` do pacote v2.1 com o patch V21-16 v2 |
| `runner/Dockerfile` | Imagem dos testes (git + gnupg), sem rede na execução |
| `tests/test_r0_06.py` | Testes locais com **chaves falsas** e **OpenRouter falso** (127.0.0.1): `python -B tests/test_r0_06.py` |

Variáveis de repositório (públicas): `ROOT_FPR`, `ROOT_PUBKEY`, `TRUST_ANCHOR_SHA`, `LN_EMERGENCY_STOP`, `LN_VERIFIER_APP_CLIENT_ID`.
Segredos:
- ambiente `reviewer`: `OPENROUTER_API_KEY` (a chave OpenRouter existente, DP-19), `REVIEWER_GPG_PRIVATE_KEY`, `REVIEWER_GPG_PASSPHRASE`;
- ambiente `verifier-signing`: `VERIFIER_GPG_PRIVATE_KEY`, `VERIFIER_GPG_PASSPHRASE`, `LN_VERIFIER_APP_PRIVATE_KEY`.

## Revisor (R0-06)
- OpenRouter → modelo `openai/gpt-6.1-terra`, a rota `openai-text-review` da política DP-02 v5. Requisição com `provider.only=[openai]`, `allow_fallbacks=false`, `data_collection=deny` e saída JSON com esquema estrito.
- Prova de upstream: `/api/v1/generation` precisa trazer `provider_name` = OpenAI e `model` igual ao da resposta. Sem isso, falha fechada.
- Economia de saldo:
  - não chama o modelo se a evidência não existe ou se o runner reprovou (nesses casos registra "pulado", e o assinador assina a rejeição);
  - estima o custo antes e recusa acima de `max_cost_usd_per_call`.
- Log público: só provider, modelo, id da geração, versão do prompt, custo e decisão.

## Assinador (R0-06)
- Aceite de tarefa só no merge commit Mᵢ da cadeia de primeiro pai de `main`, com Mᵢ^2 = Hᵢ e árvores iguais (02 v3). Gate: alvo na cadeia de primeiro pai. `premerge` nunca aceita.
- Assina `checks/<T>/<SHA>`, reconstrói a tag do revisor byte a byte (`git mktag`), roda `kit/verifier.py gov_accept_gate` (aceite ou rejeição assinada com motivo), reverifica cada ref e empurra só `refs/tags/` com o token da App, sem `--force`.

Estado: implementado na branch `r0-06/revisor-assinador`, com testes locais 15/15. Entra em `main` só por **commit assinado pela raiz** (o ruleset `verifier-main` restringe updates, e `verify_root_chain.sh` exige assinatura da raiz em todo commit). Descoberta automática (frente 12, `r0-gates/descoberta`): `scripts/discover.py` escolhe, a cada execução agendada, um alvo pendente (merge commit Mᵢ da tarefa, do mais antigo ao mais novo; gate quando a onda inteira tem aceite) e pula, com motivo, o que o assinador ou o kit recusariam. Testes `tests/test_gates_e2e.py` (8), com a cadeia descoberta → runner → revisor → assinador → `accepted()` em ensaio local. Status pre-merge (branch `r0-03/premerge-status`): job `pr-status` (ambiente `verifier-signing`, token da App só no produto) depois do runner limpo e da proveniência; a descoberta inclui PRs abertos sem os 2 status (`--prs`); política ganha a entrada `PR` (GLOBAL-TESTFLAGS) e o `trust.json` o novo `runner_policy_sha256`. Testes `tests/test_premerge.py` (8). Depois do ato raiz: `main-required-checks` com 2 contextos (`05 -Fase Main`). Pendente: gravação no `ledger` (03 v3).

Testes no Windows: GnuPG nativo na frente do PATH e `gpg.program` do git apontando para ele (por exemplo `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=gpg.program`, `GIT_CONFIG_VALUE_0=C:/Program Files/GnuPG/bin/gpg.exe`).

Parada de emergência: `LN_EMERGENCY_STOP=1` faz o `guard` falhar, e nada roda depois dele.
