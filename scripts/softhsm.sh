#!/usr/bin/env bash
# Os testes do driver GD Burti com o SoftHSM2 no lugar do módulo do SafeSign.
# Com o SoftHSM2 no host (o CI instala o pacote), rodam aqui mesmo; sem ele,
# num container Debian com o pacote, sem instalar nada no host:
#
#   scripts/softhsm.sh
#
# SOFTHSM2_MODULE aponta o módulo do host quando ele está fora dos caminhos de
# sempre.
set -euo pipefail
cd "$(dirname "$0")/.."

TESTE=(cargo test --locked -p driver-gd-burti --test softhsm)

modulo_no_host() {
    [[ -n ${SOFTHSM2_MODULE:-} ]] && return 0
    local caminho
    for caminho in /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so; do
        [[ -e $caminho ]] && return 0
    done
    return 1
}

if modulo_no_host; then
    exec "${TESTE[@]}"
fi

echo "softhsm.sh: sem o SoftHSM2 no host; os testes rodam num container" >&2
imagem=remote-certificate-softhsm:teste
docker build --quiet -t "$imagem" - >/dev/null <<'DOCKERFILE'
FROM rust:1.92-slim-trixie
RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
DOCKERFILE

# O código entra só para leitura; a compilação e o cache do cargo ficam em
# target/softhsm, fora do git, e os arquivos saem com o dono de quem rodou.
mkdir -p target/softhsm
docker run --rm --cpus 8 --memory 6g \
    --user "$(id -u):$(id -g)" \
    -v "$PWD:/src:ro" -v "$(realpath target/softhsm):/alvo" \
    -e CARGO_HOME=/alvo/cargo -e CARGO_TARGET_DIR=/alvo/target \
    -w /src "$imagem" "${TESTE[@]}"
