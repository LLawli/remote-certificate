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

## A imagem de um driver

Cada driver tem um script que confere a imagem dele como ela roda em produção.
O do RemoteID sobe o `compose.yaml` do projeto (só leitura, sem
capabilities), com o servidor falso fazendo a Certisign na 443 e uma estação
nesta máquina assinando pelo `pkcs11-tool`:

```sh
docker build -t remote-certificate .
docker build -f drivers/remoteid/Dockerfile -t remote-certificate-remoteid .
drivers/remoteid/conferir-imagem.sh
```

O lançador (`remote-certificate isolar`) tem os testes dele em
`crates/servidor/tests/isolar.rs`, com um script no lugar do driver tentando o
que um driver comprometido tentaria. O `scripts/laboratorio.sh` também sobe o
driver isolado, com o manifesto apontando para a porta do servidor falso.
