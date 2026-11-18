# A estação

Como pôr o token do servidor nos programas de um computador Linux: o
navegador, o leitor de PDF e os assinadores. O desenho está em
[arquitetura.md](arquitetura.md).

## Instalar e parear

O administrador gera um código no servidor:

```sh
remote-certificate dispositivo parear <usuario> <nome-do-computador>
```

Na estação, como o próprio usuário (sem root):

```sh
tar xzf remote-certificate-estacao-x86_64.tar.gz
remote-certificate-estacao/instalar.sh
~/.local/bin/remote-certificate-agente parear <servidor>:8443   # cole o código
systemctl --user start remote-certificate-agente
```

O `instalar.sh` põe o agente, a janela do OTP e o módulo PKCS#11 em `~/.local`,
registra o módulo no p11-kit do usuário e liga o agente como serviço do
usuário. `./instalar.sh remover` desfaz; o pareamento fica até
`remote-certificate-agente esquecer`.

O PIN que os programas pedem para o token é o PIN pessoal. O OTP é pedido numa
janela à parte, quando o token precisa.

## O que já funciona e o que precisa de um passo a mais

O registro no p11-kit basta onde o NSS lê os módulos do p11-kit. Onde não lê,
o módulo precisa ser carregado no banco de certificados de cada programa.

| Sistema | Programa | O que fazer |
|---|---|---|
| Fedora 44 | Firefox, Chromium, Papers | nada |
| Fedora 44 | PJeOffice, Assinador Serpro (Java) | apontar para o módulo (abaixo) |
| Ubuntu 24.04, Debian | Evince, Chromium e Firefox instalados por pacote | registrar em `~/.pki/nssdb` e no perfil do Firefox |
| Ubuntu 24.04 | Firefox e Chromium em snap | preferir o pacote `.deb`; ou o passo dos snaps (abaixo) |
| Arch | Firefox, Chromium, Okular | registrar em `~/.pki/nssdb` e no perfil do Firefox |

Medido nas VMs de teste em 2026-11-14 (Fedora 44 GNOME, Ubuntu 24.04 GNOME,
Arch com KDE Plasma 6.8). No Firefox snap do Ubuntu e no Firefox da Arch, o TLS
com certificado de cliente fechou com a janela do OTP.

Num desktop sem GTK (KDE, por exemplo), a janela do OTP precisa do GTK 4 e da
libadwaita: o `instalar.sh` avisa e diz o pacote de cada distribuição.

### Bancos NSS do usuário (Chromium, Evince, Papers, Okular)

```sh
modutil -dbdir sql:$HOME/.pki/nssdb -add remote-certificate \
    -libfile $HOME/.local/lib/remote-certificate/libremote_certificate_pkcs11.so
```

O `modutil` vem no `libnss3-tools` (Debian, Ubuntu) ou no `nss` (Arch). Se
`~/.pki/nssdb` não existir, crie antes com
`certutil -N -d sql:$HOME/.pki/nssdb --empty-password`.

### Firefox instalado por pacote

Configurações > Privacidade e Segurança > Certificados > Dispositivos de
segurança > Carregar, com o caminho
`~/.local/lib/remote-certificate/libremote_certificate_pkcs11.so` (escrito por
inteiro, com `/home/<usuario>`).

### Firefox em snap (Ubuntu)

O snap não enxerga `~/.local` nem o socket do agente. Funciona com três passos:

1. Copiar o módulo para dentro do snap:
   `mkdir -p ~/snap/firefox/common/remote-certificate && cp ~/.local/lib/remote-certificate/libremote_certificate_pkcs11.so ~/snap/firefox/common/remote-certificate/`
2. Carregá-lo pelos Dispositivos de segurança, com o caminho
   `/home/<usuario>/snap/firefox/common/remote-certificate/libremote_certificate_pkcs11.so`.
3. Um segundo agente escutando onde o snap procura. Copie a unit e acrescente o
   caminho do socket:

   ```sh
   cd ~/.config/systemd/user
   sed '/^\[Service\]/a Environment=REMOTE_CERTIFICATE_AGENTE=%t/snap.firefox/remote-certificate/agente.sock' \
       remote-certificate-agente.service > remote-certificate-agente-firefox.service
   systemctl --user daemon-reload
   systemctl --user enable --now remote-certificate-agente-firefox.service
   ```

Atualizar a estação não atualiza a cópia de dentro do snap: refaça o passo 1.

### Pelo Tessera (apps em Flatpak)

O [Tessera](https://github.com/pedrohqb/tessera) publica drivers de token para
os apps em Flatpak. O módulo roda dentro do sandbox dele e procura o agente em
`/run/user/<uid>/app/io.github.pedrohqb.Tessera/`, o único diretório de
execução que o sandbox enxerga. Um segundo agente escuta ali:

```sh
cd ~/.config/systemd/user
sed '/^\[Service\]/a Environment=REMOTE_CERTIFICATE_AGENTE=%t/app/io.github.pedrohqb.Tessera/remote-certificate/agente.sock' \
    remote-certificate-agente.service > remote-certificate-agente-tessera.service
systemctl --user daemon-reload
systemctl --user enable --now remote-certificate-agente-tessera.service
```

Enquanto a extensão do Tessera não está no FlatPark, o driver entra por uma
pasta (`TESSERA_DRIVERS_PATH`), com uma subpasta por driver:

```sh
mkdir -p ~/tessera-drivers/remote-certificate/lib
cp ~/.local/lib/remote-certificate/libremote_certificate_pkcs11.so ~/tessera-drivers/remote-certificate/lib/
cat > ~/tessera-drivers/remote-certificate/driver.toml <<'FIM'
name = "remote-certificate"
vendor = "remote-certificate"
description = "Tokens do servidor remote-certificate"
module = "lib/libremote_certificate_pkcs11.so"
FIM
flatpak override --user --filesystem=$HOME/tessera-drivers:ro io.github.pedrohqb.Tessera
flatpak run --env=TESSERA_DRIVERS_PATH=$HOME/tessera-drivers io.github.pedrohqb.Tessera
```

Medido no Tessera 0.4.3 (Fedora 44): o `tessera probe-sign` assinou pelo
módulo de dentro do sandbox, com a janela do OTP aberta pelo agente do host, e
um programa do host assinou pelo servidor do driver que o Tessera publica em
`/run/user/<uid>/tessera/remote-certificate` (conferido com o `openssl`).

### PJeOffice e Assinador Serpro

Instalados pelo FlatPark (`br.jus.cnj.PJeOfficePro`,
`br.gov.serpro.desktop.assinador`), os dois chegam aos tokens pelo servidor do
p11-kit do usuário, que exporta o módulo já registrado pelo `instalar.sh`. Basta
ligar o servidor uma vez:

```sh
systemctl --user enable --now p11-kit-server.socket
```

Medido no Fedora 44: o Assinador Serpro achou o token e entrou com o PIN
pessoal. A assinatura em si não foi conferida nos dois, porque o Serpro só
assina com um certificado de cadeia ICP-Brasil, que o servidor falso de testes
não tem.

Instalados de outro jeito, os dois carregam o módulo pelo Java (SunPKCS11), com
o caminho configurado neles. Use `/home/<usuario>/.local/lib/remote-certificate/libremote_certificate_pkcs11.so`,
ou o `p11-kit-proxy.so` do sistema onde o NSS lê o p11-kit. O SunPKCS11 assinou
e cifrou com a chave privada (o caminho do PJeOffice) no Fedora 44, direto e
pelo proxy.

### TLS 1.3 (RSA-PSS e ECDSA)

Um token cujo driver declara `CKM_RSA_PKCS_PSS` (numa chave RSA) ou
`CKM_ECDSA` (numa EC) serve para o TLS 1.3 com certificado de cliente. Um que
não declara, como o RemoteID, fica no TLS 1.2.

Medido em 2026-11-18 com o driver GD Burti sobre o SoftHSM, contra um
`openssl s_server` só em TLS 1.3 que exige o certificado: o NSS (`tstclnt`) e
o GnuTLS (`gnutls-cli`) fecharam o handshake com a chave RSA e com a EC, no
Debian 13 e no Debian forky.

No Firefox 160 do Fedora 44 (2026-11-24, VM GNOME pareada com esse servidor),
o mesmo servidor abriu a página com as duas chaves: o Firefox pediu o PIN
pessoal do token, listou os dois certificados e assinou por `CKM_RSA_PKCS_PSS`
com a chave RSA e por `CKM_ECDSA` com a EC. Nenhum passo a mais do que no
TLS 1.2.

Pelo OpenSSL, com o `pkcs11-provider`:

- Carregue o provedor `default` antes do `pkcs11` e prefira o `default`
  (`?provider=default`) para o que não é a chave do token. Na ordem inversa, o
  `pkcs11-provider` tenta conferir a assinatura do servidor e gerar a chave
  efêmera da troca dentro do token, que é só de leitura, e o handshake cai.
- Com uma chave RSA, use o `pkcs11-provider` 1.3.0 (Debian forky), que fechou
  com as duas chaves. O 1.0 (Debian 13) perde os parâmetros do PSS quando o
  token não tem o `CKM_SHA256_RSA_PKCS_PSS` e falha antes de pedir a
  assinatura; com a chave EC, ele funciona.

## Se o Firefox disser que a conexão expirou

O Firefox dá 30 segundos para estabelecer uma conexão segura, contando o PIN, a
escolha do certificado e o OTP. Passou disso, ele desiste, e a página seguinte
abre sem certificado até o Firefox ser reaberto. Feche o Firefox e tente de
novo, com o OTP à mão.
