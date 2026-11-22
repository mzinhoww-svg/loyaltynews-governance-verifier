# Imagem do runner de checks. Construida no job 'runner' (com rede); os testes rodam nela SEM rede.
# Imagem base fixada por digest do indice multi-arquitetura (Docker Hub, consultado em 22/11/2026; reconfirmar antes do primeiro push).
# linux/amd64 = sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt-get update \
 && apt-get install -y --no-install-recommends git gnupg \
 && rm -rf /var/lib/apt/lists/* \
 && git config --system core.autocrlf false \
 && git config --system core.hooksPath /dev/null
ENV PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8
