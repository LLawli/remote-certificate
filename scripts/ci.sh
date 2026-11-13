#!/usr/bin/env bash
# Todos os gates do projeto. O CI roda este mesmo script: verde aqui, verde lá.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit --deny warnings
shellcheck -x scripts/*.sh bin/*
actionlint
