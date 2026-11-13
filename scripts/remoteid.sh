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
    # Sempre com --git-dir: o cache do CI pode devolver o clone sem parte do
    # .git, e um `git -C` subiria até o repositório deste projeto e buscaria a
    # revisão no remote errado. Clone que não chega à revisão é refeito.
    clone() { git --git-dir="$dir/.git" --work-tree="$dir" "$@"; }
    na_revisao() {
        clone fetch --quiet origin "$REVISAO" >&2 \
            && clone -c advice.detachedHead=false checkout --quiet --force "$REVISAO" >&2
    }
    if [[ $(clone rev-parse HEAD 2>/dev/null) != "$REVISAO" ]] && ! na_revisao 2>/dev/null; then
        rm -rf "$dir"
        git clone --quiet "$REPOSITORIO" "$dir" >&2
        na_revisao
    fi
    test "$(clone rev-parse HEAD)" = "$REVISAO"
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
