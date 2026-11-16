# Driver GD Burti

Para quem guarda tokens A3 GD Burti no servidor: o driver fala o contrato de
[docs/drivers.md](../../docs/drivers.md) e chega ao token pelo módulo PKCS#11
oficial, o `libaetpkss.so` do SafeSign IC (A.E.T. Europe). Binário
`remote-certificate-driver-gd-burti`.

## Imagem

```sh
docker build -t remote-certificate .
docker build -f drivers/gd-burti/Dockerfile -t remote-certificate-gd-burti .
```

O Dockerfile baixa o pacote do SafeSign do link oficial, confere o SHA-256 e
só desempacota os arquivos (nenhum script do pacote roda). O driver e o
manifesto vão para `/drivers`, o módulo para `/usr/lib/libaetpkss.so.3`.

O SafeSign chega ao token pelo `pcscd` do host, por um socket UNIX. O
manifesto pede só esse socket (`/run/pcscd/pcscd.comm`), sem rede. No host:

1. `bin/deploy pcscd`, uma vez: instala a regra do polkit
   (`deploy/50-remote-certificate-pcscd.rules`) que libera o pcscd para o uid
   10001 do container. Sem ela, um `pcscd` com polkit recusa o driver
   (`Process ... (user: 10001) is NOT authorized for action: access_pcsc` no
   log dele), e o SafeSign responde como se não houvesse leitor.
2. `COMPOSE_FILE=compose.yaml:compose.pcscd.yaml` no `.env` do host: monta o
   `/run/pcscd` do host no container.

O cliente do PC/SC na imagem é o do Debian 12 (protocolo 4:4), não o do
Debian 13 (4:5): um `pcscd` mais velho que o cliente recusa a conversa
(`Communication protocol mismatch` no log dele), e o do Ubuntu 24.04 fala o
4:4. Um `pcscd` mais novo atende o cliente mais velho.

## Token

```sh
remote-certificate token criar <nome> remote-certificate-driver-gd-burti
```

- **Configuração**: a série do token (vazia, vale o único conectado; com
  vários, a série escolhe) e o PIN do token. O driver confere o PIN no token
  antes de aceitar e grava só a série, em `configuracao.json` no diretório de
  estado.
- **Fator**: o PIN do token, `guardado`.
- **Argumentos**: `--modulo <caminho>` troca o módulo PKCS#11 (os testes usam
  o SoftHSM2).

## Testes

Os de integração sobem o driver e conversam com ele pelo contrato, assinando
com cada mecanismo que ele declara e conferindo a assinatura com o
certificado.

- **SoftHSM2** (`tests/softhsm.rs`, roda no CI): com o pacote `softhsm2` no
  host, roda nele; sem, num container Debian com o pacote. `SOFTHSM2_MODULE`
  aponta o `.so` do host se ele não estiver num dos caminhos de sempre.

  ```sh
  scripts/softhsm.sh
  ```

- **Cartão virtual do gdburti-rs** (`tests/gdburti_virtual.rs`, fora do CI):
  a reimplementação do SafeSign com um cartão virtual que fala os APDUs do
  applet da GD Burti. Cobre também o PIN bloqueado depois de três erros.

  O gdburti-rs não é publicado: com uma cópia local em `$GDBURTI_RS`,

  ```sh
  (cd "$GDBURTI_RS" && cargo build --release)
  GDBURTI_PKCS11="$GDBURTI_RS/target/release/libgdburti_pkcs11.so" \
      cargo test -p driver-gd-burti --test gdburti_virtual -- --ignored
  ```
