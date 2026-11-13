# Arquitetura

Para quem vai contribuir. O que o projeto resolve está no [README](../README.md);
o contrato dos drivers, em [drivers.md](drivers.md).

## As peças

```
 estação Linux                               servidor (container)
 ┌──────────────────────────┐               ┌───────────────────────────────┐
 │ Firefox, Chromium, Papers│               │ remote-certificate            │
 │ PJeOffice, Serpro        │               │  usuários, PIN pessoal,       │
 │        │ PKCS#11         │   rede,       │  dispositivos, auditoria,     │
 │  face (.so) ── IPC ──▶ agente ◀────────▶ │  segredos cifrados            │
 │                 chave do dispositivo     │   │ JSON por linha (stdio)    │
 └──────────────────────────┘   pareada     │   ├─▶ driver remoteid ─▶ Certisign
                                            │   └─▶ driver gdburti ─▶ token USB
 sistema interno ──── API HTTP ───────────▶ │                               │
                                            └───────────────────────────────┘
```

- **Servidor** (`crates/servidor`, binário `remote-certificate`): roda num
  container, fala com os tokens pelos drivers e guarda o que precisa ficar no
  servidor: usuários, PINs pessoais, dispositivos pareados, os segredos dos
  tokens cifrados e a auditoria.
- **Drivers**: executáveis à parte, um por tipo de token, instalados só por quem
  tem aquele token. O servidor de quem tem um GD Burti físico não carrega o
  RemoteID. O servidor lança um processo por token configurado e conversa pelo
  contrato de [drivers.md](drivers.md) (`crates/protocolo`). Processo separado
  também isola o servidor de um módulo de fornecedor que trava ou vaza memória,
  e um token que trava não para os outros. Cada token tem uma thread dona do
  driver (`servidor::tokens`), que o sobe no primeiro uso, o relança quando o
  processo morre e quando o token é configurado de novo com o serviço rodando
  (a `geracao` do token no banco sobe a cada configuração).
- **Administração**: uma CLI no próprio servidor (`docker compose exec`):
  `token criar|configurar|listar`, `usuario criar|pin`,
  `dispositivo parear|listar|desbloquear|revogar`, `backup`, `recuperacao`.
  Se um dia precisar de mais, no máximo uma API de administração, sem
  interface web.
- **Cliente da estação**: um agente e as faces (abaixo).
- **Sistemas integrados**: falam com a API HTTP do servidor.

## Os dois usos

### API HTTP, para sistemas

O sistema é um cliente pareado como uma estação, com chave própria, e tem um PIN
único. Como ele gerencia os próprios usuários é decisão dele: aceitar uso sem
PIN, repassar o PIN pessoal de cada um ou criar um PIN interno. As operações são
as mesmas do driver (listar chaves e mecanismos, assinar). Quando o token pede
um fator da pessoa (o OTP), a assinatura volta pedindo esse fator, com o rótulo
para mostrar, e o sistema completa a mesma operação com o código.

O escopo inicial é só esse. A API nasce versionada (`/v1`) e com a operação
de assinatura como recurso próprio (criar, responder fatores, consultar), para
que operações novas (assinar em lote, outros formatos) entrem sem quebrar quem
já integra.

### Token virtual, para estações

A estação vê um token como o físico, mas a chave e o PIN do token ficam no
servidor. Para que Windows e macOS entrem depois sem reescrita, o cliente tem
duas camadas:

- **Agente** (por usuário, portátil, sem nada específico de sistema operacional
  além do IPC e do cofre da chave): guarda a chave do dispositivo, mantém a
  conexão com o servidor, recebe o PIN pessoal da face e pergunta o OTP numa
  janela quando o servidor pede. Toda a lógica fica aqui.
- **Faces** (finas, uma por forma de expor um token): só traduzem para o agente.
  - Linux (v1): módulo PKCS#11 (`.so`) registrado no p11-kit. Cobre Firefox,
    Chromium (NSS), Papers, PJeOffice e Assinador Serpro. O PIN pessoal entra
    pelo `C_Login`, então os assinadores pedem o PIN do jeito que já pedem.
  - Windows (depois): o mesmo módulo como `.dll`, para quem lê PKCS#11; para
    Chrome, Edge e o repositório de certificados do Windows, um KSP ou um
    leitor de smartcard virtual.
  - macOS (depois): CryptoTokenKit.
  - O IPC entre face e agente fica atrás de um trait: socket Unix no Linux e no
    macOS, named pipe no Windows.

O agente fala com o servidor por um WebSocket em `/v1/agente`, sobre o mTLS
do dispositivo, com uma mensagem JSON por quadro (`rede::agente`):

- `entrar` com o PIN pessoal abre a sessão para assinar; ela vence depois de
  15 minutos sem uso (provisório, a medir na VM) ou com `sair`. `listar` não
  pede o PIN, como um token físico mostra os certificados antes do login.
- `assinar` pode receber, no meio, um `pedido_de_fatores` (o OTP, com a recusa
  quando pede de novo), que o agente responde com `fatores` ou `desistir`, no
  mesmo `id`. Uma operação por conexão de cada vez.
- O servidor avisa sem ser perguntado: `dispositivo_bloqueado` e
  `token_parado`.
- Antes de cada mensagem, o servidor confere o dispositivo no banco: revogado,
  a conexão cai; bloqueado, toda operação volta `bloqueado`.

A face expõe só o que o driver declara. Um token sem RSA-PSS nem ECDSA não se
anuncia para TLS 1.3 (`protocolo::suporta_tls13`).

O cliente é testado numa VM com o ambiente da estação (os navegadores e os
assinadores instalados de verdade), não só na máquina de desenvolvimento.

## Segurança

O modelo de ameaça, as defesas de cada peça e os riscos aceitos estão em
[seguranca.md](seguranca.md).

### Pareamento

Cada estação e cada sistema gera um par de chaves P-256 ao ser configurado. O
administrador gera no servidor um código de uso único; com ele, cliente e
servidor trocam as chaves públicas: o servidor guarda a do dispositivo, o
cliente fixa a do servidor. Uma conexão de chave desconhecida é recusada antes
de qualquer operação, então uma URL vazada, sozinha, não serve para nada, mesmo
com o servidor na internet.

- O código (`remote-certificate dispositivo parear <usuario> <nome>`) traz os
  primeiros 128 bits do SHA-256 da chave do servidor e um segredo de 80 bits,
  no formato `RP1-XXXX-...` (`crates/rede`). Vale uma vez, por 10 minutos, e o
  banco guarda só o SHA-256 do segredo.
- O cliente conecta aceitando só um servidor cuja chave confere com o código e
  manda o segredo por essa conexão (`POST /v1/pareamento`). Quem está no meio
  não se passa pelo servidor, e ninguém precisa de outra criptografia além do
  TLS com certificado de cliente, que qualquer linguagem tem. Depois, o cliente
  fixa a impressão inteira.
- Enquanto há um código pendente, o handshake aceita uma chave nova, que só
  alcança `POST /v1/pareamento`. Sem código pendente, chave desconhecida cai no
  handshake.
- O dispositivo nasce do usuário e com o nome que o administrador deu ao gerar
  o código.
- Ficou de fora um PAKE (SPAKE2, CPace) com código curto: cada sistema
  integrado precisaria de uma biblioteca de PAKE, pelo mesmo motivo que tirou o
  Noise. O preço é um código de uns 60 caracteres, para copiar e colar.

### Transporte

mTLS (TLS 1.3) dos dois lados, sem autoridade certificadora: o certificado de
cada lado é autoassinado e o que vale é a chave dentro dele. O servidor confere
a chave do cliente contra os dispositivos pareados e derruba o handshake de uma
chave desconhecida, antes de ler qualquer HTTP; o cliente confere a do servidor
contra a que fixou no pareamento.

- O agente da estação mantém um WebSocket aberto sobre esse mTLS. Por ele o
  servidor pede o OTP no meio de uma assinatura e avisa o que mudou sem ser
  perguntado (token desatualizado, dispositivo bloqueado, certificado novo).
- Os sistemas usam a API HTTP comum sobre o mesmo mTLS, que qualquer linguagem
  fala com um certificado de cliente.
- A chave do dispositivo só precisa assinar, então pode ficar em hardware (TPM,
  Secure Enclave) quando o cliente desses sistemas chegar.

Como o TLS precisa chegar inteiro ao servidor, um proxy no meio só repassa a
conexão, sem abri-la. A forma recomendada de expor o servidor é o Tailscale:
as estações falam com o IP dele na tailnet, sem proxy. O servidor não depende
do Tailscale; a tailnet controla quem alcança a rede, o pareamento controla quem
é atendido.

Ficaram de fora o Noise IK sobre WebSocket (a conexão nos dois sentidos vem do
WebSocket, não do Noise; ele exigiria uma biblioteca Noise de quem integra e
não aceita chave em TPM) e a assinatura de cada requisição HTTP pela RFC 9421
(recusa só depois do HTTP, proteção contra repetição por nossa conta). O Noise
volta a fazer sentido se for preciso atender por um proxy que abre o TLS, como
o Cloudflare Tunnel.

### PIN pessoal e bloqueio

- Cada usuário tem um PIN pessoal, guardado com Argon2id. Ele identifica quem
  fez o quê na auditoria e faz com que só ter acesso ao computador não baste.
- Errar o PIN pessoal 3 vezes seguidas bloqueia o dispositivo, até o
  administrador desbloquear. O acerto zera o contador. Assim quem pega o
  computador de alguém não consegue força bruta no PIN dessa pessoa.
- O PIN pessoal nunca chega ao token. O PIN do token é um segredo guardado no
  servidor, e o servidor só o envia depois de validar o PIN pessoal: o token não
  recebe tentativa errada vinda de um usuário.
- O OTP não tem contador: é de uso único, e quem o valida é o token.
- Cada dispositivo é de um usuário só. Um sistema integrado é um usuário com o
  dispositivo dele.
- O administrador cria o usuário e troca o PIN pela CLI
  (`remote-certificate usuario criar|pin <nome>`, com o PIN no stdin, nunca em
  argumento), e vê e desbloqueia os dispositivos por ela
  (`dispositivo listar`, `dispositivo desbloquear <id>`).
- No código, `Token::assinar` exige um `pin::Autenticado`, que só
  `pin::conferir` cria e que não carrega o PIN: sem conferir o PIN pessoal,
  o fator guardado não sai do cofre.

### Segredos guardados

Todo o estado do servidor fica num único SQLite cifrado com SQLCipher: usuários,
PINs pessoais, dispositivos, tokens, os fatores `guardado` (PIN do token,
senhas de conta) e a auditoria. A chave do banco vem de um secret do Docker; o
servidor não prevê rodar fora de container. Quem tem o volume sem o secret não
lê nada; quem tem os dois lê tudo, e o serviço volta sozinho depois de
reiniciar. Se o token recusar um fator guardado
(`fator_recusado`), o servidor não tenta de novo sozinho, porque um token físico
trava depois de poucas tentativas: ele marca o segredo como desatualizado e para
de usar aquele token até o administrador corrigir.

### Auditoria

Registro só de acréscimo: quando, usuário, dispositivo, token, chave, mecanismo,
o SHA-256 do que foi assinado e o resultado. PIN, OTP, senha e documento nunca
entram, nem em log. `protocolo::Segredo` não aparece em `Debug` por isso.

## Container

- Imagem final com glibc (Debian slim), porque os módulos PKCS#11 dos
  fornecedores de token físico são compilados para glibc. Roda como usuário não
  root.
- Estado em `/dados` (volume): o banco SQLCipher. A chave dele, num secret do
  Docker.
- A imagem base não traz driver nenhum. Cada driver aceito tem um Dockerfile em
  `drivers/<nome>/` que gera uma imagem derivada da base com o driver e o que
  ele precisa (`FROM ... COPY ... /drivers/`). Quem tem dois tipos de token
  junta os dois numa imagem sua.
- Token físico plugado no servidor: pelo `pcscd` do host com o socket
  `/run/pcscd` montado no container, ou pelo dispositivo USB passado ao
  container. A escolha depende de medir com um token real.

## Primeiro driver: RemoteID

`drivers/remoteid`, binário `remote-certificate-driver-remoteid`. O
[RemoteID-linux](https://github.com/LLawli/RemoteID-linux) tem um servidor
falso (`remoteid-mock`), o que permite desenvolver e testar sem token nem conta
real. O driver é um adaptador sobre o `remoteid servir` (JSON por linha no
stdio), que ele roda como processo filho; o `remoteid` estático do pacote de
servidor daquele projeto é instalado junto do driver. Não é uma dependência de
crate: o servidor não carrega o RemoteID.

- **Configuração**: o administrador dá e-mail e senha. O driver entra na conta
  com um PIN local que ele mesmo gera (sem chaveiro no container, esse PIN
  cifra a senha no estado do `remoteid`) e o devolve para o servidor guardar.
- **Fatores**: o PIN local e a senha são `guardado`; o OTP é `da_pessoa`.
- **Mecanismos**: `CKM_SHA256_RSA_PKCS` vai ao `servir` como o hash SHA-256,
  o caminho do aplicativo oficial. `CKM_SHA384_RSA_PKCS`,
  `CKM_SHA512_RSA_PKCS` e `CKM_RSA_PKCS` vão como um DigestInfo pronto
  (`digest_info`), que o `servir` aceita desde a v0.5.1 do RemoteID-linux, a
  mesma que traz o DER do certificado na visão. O driver exige essa versão e
  reconhece uma anterior pelo que falta no protocolo (o `remoteid` não diz a
  versão), respondendo `versao_incompativel`.
- A Certisign não assina RSA-PSS: o driver não declara `CKM_RSA_PKCS_PSS`, e o
  token virtual não se anuncia para TLS 1.3.

## Novos drivers

Não há driver PKCS#11 genérico, e o projeto não declara suporte genérico a
tokens. Muitos módulos de fornecedor seguem mal o padrão PKCS#11, e quem
conhece o token é quem lida com isso: cada driver traduz o próprio token para o
contrato de [drivers.md](drivers.md) e entra no repositório em `drivers/<nome>/`,
com o Dockerfile e os testes dele. Um token só é suportado quando tem um driver
aceito aqui.

## Decisões tomadas

- **Transporte**: mTLS 1.3 com chaves P-256 fixadas (rustls, sem OpenSSL),
  WebSocket para o agente; exposição recomendada pelo Tailscale, na porta 8443.
- **Pareamento**: código com a impressão da chave do servidor e um segredo de
  uso único, sem PAKE.
- **Dispositivo comprometido**: `dispositivo revogar`, que não apaga a linha
  (a auditoria aponta para ela) e deixa a chave cair no handshake para sempre.
- **Chave do banco**: secret do Docker. O servidor não prevê rodar fora de
  container. O desbloqueio pelo administrador a cada partida ficou de fora:
  deixaria o serviço parado depois de toda queda até alguém aparecer.
- **Banco**: um SQLite em `/dados`, cifrado inteiro com SQLCipher. Os segredos
  não têm uma camada de cifra própria por cima.
- **Processos de driver**: um por token configurado.
- **Administração**: CLI.
- **Drivers**: um por tipo de token, aceito no repositório; nenhum genérico.
