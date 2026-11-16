#!/usr/bin/env bash
# Todos os gates do projeto. O CI roda este mesmo script: verde aqui, verde lá.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
# Os testes de integração do driver RemoteID rodam o `remoteid` e o servidor
# falso do RemoteID-linux (REMOTEID_LINUX_DIR aponta para uma cópia local).
# Numa variável, para que uma falha do script pare o CI (`eval "$(...)"` a engole).
remoteid=$(scripts/remoteid.sh)
eval "$remoteid"
cargo test --workspace --locked
# De novo os do lançador, com a saída à mostra: o nível do Landlock que o
# kernel aplicou fica no log, e um teste pulado por falta de ABI aparece.
cargo test --locked -p servidor --test isolar -- --nocapture --test-threads 1
cargo audit --deny warnings
shellcheck -x scripts/*.sh bin/* drivers/*/*.sh
actionlint
