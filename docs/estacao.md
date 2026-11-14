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

### PJeOffice e Assinador Serpro

Os dois carregam o módulo pelo Java (SunPKCS11), com o caminho configurado
neles. Use `/home/<usuario>/.local/lib/remote-certificate/libremote_certificate_pkcs11.so`,
ou o `p11-kit-proxy.so` do sistema onde o NSS lê o p11-kit. O SunPKCS11 assinou
e cifrou com a chave privada (o caminho do PJeOffice) no Fedora 44, direto e
pelo proxy.

## Se o Firefox disser que a conexão expirou

O Firefox dá 30 segundos para estabelecer uma conexão segura, contando o PIN, a
escolha do certificado e o OTP. Passou disso, ele desiste, e a página seguinte
abre sem certificado até o Firefox ser reaberto. Feche o Firefox e tente de
novo, com o OTP à mão.
