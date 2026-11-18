# Changelog

Todas as mudanças visíveis deste projeto. O formato segue o
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/), e as versões, o
[Semantic Versioning](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Added

- Contrato de driver v0, em `docs/drivers.md` e `crates/protocolo`, com a
  configuração do token declarada pelo próprio driver. Cada versão do contrato
  declara as anteriores com que é compatível, e o servidor aceita um driver
  quando chega à versão dele por essa cadeia; uma breaking change corta a
  cadeia, e um driver mais novo que o servidor é recusado. A recusa é na
  partida do driver, com as duas versões na mensagem.
- Driver do RemoteID (`remote-certificate-driver-remoteid`), sobre o
  `remoteid servir`: assina com `CKM_RSA_PKCS` e `CKM_SHA256_RSA_PKCS`,
  `CKM_SHA384_RSA_PKCS` e `CKM_SHA512_RSA_PKCS`, pedindo o OTP a quem assina.
  Exige o `remoteid` 0.5.1 ou mais novo e avisa quando o instalado é anterior.
  Testado com o 0.5.2, que fecha a memória do `remoteid` para outros
  processos; é o recomendado.
- Driver da GD Burti (`remote-certificate-driver-gd-burti`), sobre o módulo
  PKCS#11 oficial do SafeSign IC, com a imagem derivada que baixa o SafeSign
  do link oficial conferido pelo SHA-256. Declara os mecanismos que o token
  assina (`CKM_RSA_PKCS`, `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`,
  `CKM_SHA512_RSA_PKCS` e `CKM_RSA_PKCS_PSS` numa chave RSA, `CKM_ECDSA` numa
  EC), escolhe o token pela série quando há mais de um e confere o PIN ao
  configurar. PIN recusado volta como `fator_recusado`, sem nova tentativa, e
  PIN travado como `bloqueado`, sem gastar tentativa. O manifesto pede só o
  socket do `pcscd` do host. Validado com o SoftHSM2 e com o cartão virtual
  do gdburti-rs; falta o token físico.
- `bin/deploy pcscd` e `compose.pcscd.yaml`: num host com token físico, a
  regra do polkit que deixa o driver no container (uid 10001) usar o `pcscd`
  do host, e o socket dele montado no container.
- O servidor responde os fatores guardados (PIN e senha) sem que ninguém os
  conheça, e para o token, sem nova tentativa, quando o token recusa um deles,
  mesmo que o token peça junto um fator da pessoa. O token parado continua
  parado depois de o servidor reiniciar. O token também para quando o driver
  desiste com `fator_recusado` logo depois de receber um fator guardado.
- Banco SQLite cifrado inteiro com SQLCipher, com a chave num secret do
  Docker, travada na RAM. Guarda os tokens e os fatores guardados; recusa
  abrir um banco em claro.
- `remote-certificate backup`: cópia com o serviço rodando, conferida contra
  o banco antes de dar certo.
- `remote-certificate recuperacao`: o código de recuperação da chave do banco.
- `bin/deploy chave`: gera a chave do banco no host, selada no TPM, e a abre
  em `/run` a cada boot.
- Usuários com PIN pessoal em Argon2id e dispositivos de cada usuário. Errar
  o PIN pessoal 3 vezes seguidas bloqueia o dispositivo, até o administrador
  desbloquear; o acerto zera o contador. O fator guardado do token só é usado
  depois de o PIN pessoal conferir, e o PIN pessoal nunca chega ao token.
- `remote-certificate usuario criar|pin` e
  `remote-certificate dispositivo listar|desbloquear`.
- `remote-certificate servir`: o serviço na porta 8443, em mTLS 1.3 com
  chaves fixadas dos dois lados. Uma chave que não é de dispositivo pareado cai
  no handshake.
- `remote-certificate dispositivo parear <usuario> <nome>`: um código de
  pareamento de uso único, que vale por 10 minutos e traz a impressão da chave
  do servidor.
- `/v1/agente`: o WebSocket do agente da estação. Entra com o PIN pessoal,
  lista as chaves de todos os tokens e assina, com o pedido do OTP no meio da
  assinatura. Avisa quando o dispositivo é bloqueado e quando um token para.
- `remote-certificate token criar|configurar|listar`. Configurar com o serviço
  rodando relança o driver daquele token.
- `remote-certificate dispositivo revogar`: a chave do dispositivo deixa de
  ser aceita, inclusive numa conexão já aberta.
- Auditoria só de acréscimo: cada assinatura, cada tentativa de PIN pessoal e
  cada mudança em quem pode assinar, com o SHA-256 do que foi assinado e nada
  secreto. O banco recusa alterar ou apagar uma linha, e cada linha é selada
  com a anterior. Nenhuma assinatura sai sem a linha dela.
- `remote-certificate auditoria listar|verificar`.
- O container sobe com `servir`; `PUBLICAR` escolhe onde a porta aparece no
  host (o IP da tailnet, por exemplo).
- O servidor e o driver RemoteID não se deixam inspecionar por outro processo
  nem deixam core dump; o container roda só leitura e sem capabilities.
- Uma linha do contrato de driver tem no máximo 1 MiB.
- Imagem de container do servidor.
- `remote-certificate-agente`, o agente da estação: `parear`, `estado`,
  `esquecer` e `servir`. Guarda a chave do dispositivo num arquivo só do
  usuário, atende as faces por um socket Unix e pergunta o OTP numa janela à
  parte. Cada aplicação tem o seu login do PIN pessoal.
- O módulo PKCS#11 da estação (`libremote_certificate_pkcs11.so`): cada token
  do servidor aparece como um token local que pede o PIN pessoal no login e
  assina com `CKM_RSA_PKCS` e `CKM_SHA256/384/512_RSA_PKCS`. Testado com o
  `pkcs11-tool`, o `p11tool` e pelo `p11-kit-proxy`.
- A face também mostra chaves EC e assina com `CKM_RSA_PKCS_PSS` e
  `CKM_ECDSA` quando o driver os declara: um token assim serve para o TLS
  1.3. Parâmetros de PSS fora do contrato são recusados no `C_SignInit`, sem
  chegar ao token. Testado num handshake TLS 1.3 com certificado de cliente
  pelo Firefox (Fedora 44), pelo NSS, pelo GnuTLS e pelo OpenSSL
  (`pkcs11-provider` 1.3.0); o
  `docs/estacao.md` diz o que o OpenSSL pede.
- `remote-certificate-dialogo`, a janela do OTP no Linux.
- `scripts/laboratorio.sh`: um servidor e uma estação inteiros nesta máquina,
  para testar o módulo com programas de verdade. Com `SO_SERVIDOR=1`, só o
  servidor, para parear a estação de uma VM.
- O pacote da estação (`estacao/`): compilado no Ubuntu 24.04, com um
  `instalar.sh` por usuário, sem root, que registra o módulo no p11-kit do
  usuário e sobe o agente como serviço do systemd do usuário. No Fedora 44,
  Firefox, Chromium e Papers usam o token só com isso.
- `docs/estacao.md`: como pôr o token em cada programa, medido no Fedora 44,
  no Ubuntu 24.04 (incluindo os navegadores em snap) e no Arch com KDE.
- O `instalar.sh` avisa quando falta o GTK 4 ou a libadwaita da janela do
  OTP, e o agente registra no journal quando não consegue abrir a janela.
- A janela do OTP usa os ícones do Adwaita também no KDE, onde ficavam
  quebrados.
- O módulo, dentro de um Flatpak (o Tessera), procura o agente no diretório
  de execução do app, `$XDG_RUNTIME_DIR/app/$FLATPAK_ID`. Testado no Tessera
  0.4.3.
- `remote-certificate servir --sessao <segundos>`: quanto o login do PIN
  pessoal dura sem uso (15 minutos, se não mudar).
- O módulo da estação sabe o prazo do login e o dá por vencido antes do
  servidor: o Firefox pede o PIN de novo, em vez de travar na página.
- Um mecanismo que o token não tem (o RSA-PSS do TLS 1.3) volta
  `CKR_MECHANISM_INVALID` mesmo com parâmetros, e não
  `CKR_MECHANISM_PARAM_INVALID`.
- O cliente (agente, pareamento e API) desiste de conectar depois de 10 s, em
  vez de esperar para sempre um servidor atrás de um firewall que descarta os
  pacotes.
- API HTTP `/v1` para sistemas integrados: `GET /v1/chaves` e a assinatura
  como recurso em `/v1/assinaturas`, com um lote de até 1000 documentos por
  PIN pessoal, o pedido do OTP no meio, a desistência e a consulta que espera
  a assinatura mudar.
- O PIN pessoal confere no máximo 4 vezes ao mesmo tempo, no agente e na API,
  para limitar a memória do Argon2id.
- Imagem do driver RemoteID (`drivers/remoteid/Dockerfile`), derivada da
  imagem do servidor, com o `remoteid` 0.5.2 da release do RemoteID-linux
  conferido pelo SHA-256. O `bin/deploy` encadeia os drivers de `DRIVERS`.
- `remote-certificate isolar`: o servidor sobe cada driver isolado pelo
  Landlock, sem privilégio nenhum. O driver lê o sistema e a própria pasta,
  escreve só no estado do token (onde não executa nada), conecta só nas portas
  TCP do manifesto e não manda sinal para fora; roda sem core dump, com teto de
  memória e de arquivos abertos. O log diz o nível que o kernel aplicou. Num
  kernel sem Landlock o driver sobe do mesmo jeito, e um teto que o ambiente
  já impôs, menor, fica como está.
- Cada token tem o seu diretório de estado (`/dados/drivers/<id>`, opção
  `--estados`), que é o diretório de trabalho do driver. O driver RemoteID não
  precisa mais de `--estado`.
- O manifesto do driver (`<driver>.manifesto.json`): as portas TCP, os
  sockets UNIX (o do `pcscd`, para um token físico) e o teto de memória. Sem
  um socket no manifesto, o driver não conecta em nenhum.
- O container tem nome de máquina fixo (o RemoteID registra a instalação com
  ele) e um teto de 1024 processos.
- `drivers/remoteid/conferir-imagem.sh`: a imagem no compose de produção, com
  o servidor falso do RemoteID e uma estação assinando de verdade.
