# Desenvolvimento

## Gates

```sh
scripts/ci.sh
```

Formatação, clippy com warnings como erro, testes, `cargo audit`, shellcheck e
actionlint. O CI roda o mesmo script. As versões do shellcheck e do actionlint
vêm do `mise.toml`.

## Testes

- **Unitários** nas regras de negócio invariantes (`crates/servidor/src/fatores.rs`,
  `crates/servidor/src/token.rs`, a tradução de cada driver).
- **Integração** em `drivers/<driver>/tests/`: o servidor, o driver e o token
  de ponta a ponta, cobrindo cada tipo de assinatura que o driver oferece, com a
  assinatura conferida contra a chave pública do certificado.

Os testes do driver RemoteID rodam o `remoteid` e o servidor falso do
RemoteID-linux. O `scripts/remoteid.sh` os compila (em release, porque em debug
gerar a chave RSA do registro leva segundos) e imprime as variáveis que os
testes leem:

```sh
eval "$(scripts/remoteid.sh)"
cargo test --workspace
```

Sem `REMOTEID_LINUX_DIR`, o script clona o RemoteID-linux na revisão fixada
dentro de `target/deps/`. Com ele, usa a cópia apontada, para testar uma
mudança no RemoteID-linux antes de ela ser publicada.
