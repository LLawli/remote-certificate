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
manifesto pede só esse socket (`/run/pcscd/pcscd.comm`), sem rede, e o
container precisa do `/run/pcscd` do host montado:

```yaml
volumes:
  - /run/pcscd:/run/pcscd
```

Um `pcscd` com polkit (o padrão no Arch, no Fedora e no Debian) recusa um
processo cujo usuário não tem permissão, e o do container é o uid 10001: o
log do `pcscd` diz `Process ... (user: 10001) is NOT authorized for action:
access_pcsc`, e o SafeSign responde como se não houvesse leitor. O host
precisa de uma regra do polkit que libere `org.debian.pcsc-lite.access_pcsc`
e `org.debian.pcsc-lite.access_card` para esse uid. A regra ainda não foi
validada.

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
