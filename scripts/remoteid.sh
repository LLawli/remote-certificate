#!/usr/bin/env bash
# Compila o `remoteid` e o servidor falso (`remoteid-mock`) do RemoteID-linux,
# que os testes de integração do driver RemoteID usam, e imprime as variáveis
# que apontam para eles:
#
#   eval "$(scripts/remoteid.sh)"
#
# Usa REMOTEID_LINUX_DIR quando apontado para uma cópia local; senão clona o
# RemoteID-linux na revisão fixada abaixo, dentro de target/ (fora do git).
set -euo pipefail
cd "$(dirname "$0")/.."

# A revisão do RemoteID-linux que este projeto testa (a release v0.5.1).
REPOSITORIO=https://github.com/LLawli/RemoteID-linux.git
REVISAO=8e441b84e27b02090b188157d6fc5e8b2556f095

dir=${REMOTEID_LINUX_DIR:-}
if [[ -z $dir ]]; then
    dir=$PWD/target/deps/RemoteID-linux
    if [[ ! -d $dir/.git ]]; then
        git clone --quiet "$REPOSITORIO" "$dir" >&2
    fi
    if [[ $(git -C "$dir" rev-parse HEAD) != "$REVISAO" ]]; then
        git -C "$dir" fetch --quiet origin "$REVISAO" >&2
        git -C "$dir" -c advice.detachedHead=false checkout --quiet "$REVISAO" >&2
    fi
fi

# Release: em debug, gerar a chave RSA do registro leva segundos.
cargo build --quiet --release --locked --no-default-features \
    --manifest-path "$dir/Cargo.toml" --bin remoteid --bin remoteid-mock >&2

alvo=$(cargo metadata --format-version 1 --no-deps --manifest-path "$dir/Cargo.toml" \
    | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')
for bin in remoteid remoteid-mock; do
    test -x "$alvo/release/$bin" || { echo "não achei $alvo/release/$bin" >&2; exit 1; }
done
echo "export REMOTEID_BIN='$alvo/release/remoteid'"
echo "export REMOTEID_MOCK_BIN='$alvo/release/remoteid-mock'"
