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
                                            │   └─▶ driver pkcs11 ─▶ token USB
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
  também isola o servidor de um módulo de fornecedor que trava ou vaza memória.
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

A face expõe só o que o driver declara. Um token sem RSA-PSS nem ECDSA não se
anuncia para TLS 1.3 (`protocolo::suporta_tls13`).

## Segurança

### Pareamento

Cada estação e cada sistema gera um par de chaves P-256 ao ser configurado. O
administrador gera no servidor um código de uso único; com ele, cliente e
servidor trocam as chaves públicas: o servidor guarda a do dispositivo, o
cliente fixa a do servidor. Uma conexão de chave desconhecida é recusada antes
de qualquer operação, então uma URL vazada, sozinha, não serve para nada, mesmo
com o servidor na internet. A forma do transporte é uma decisão aberta (abaixo).

### PIN pessoal e bloqueio

- Cada usuário tem um PIN pessoal, guardado com Argon2id. Ele identifica quem
  fez o quê na auditoria e faz com que só ter acesso ao computador não baste.
- Errar o PIN pessoal N vezes seguidas bloqueia o dispositivo, até o
  administrador desbloquear. O acerto zera o contador. Assim quem pega o
  computador de alguém não consegue força bruta no PIN dessa pessoa.
- O PIN pessoal nunca chega ao token. O PIN do token é um segredo guardado no
  servidor, e o servidor só o envia depois de validar o PIN pessoal: o token não
  recebe tentativa errada vinda de um usuário.
- O OTP não tem contador: é de uso único, e quem o valida é o token.

### Segredos guardados

O PIN do token e as senhas de conta (fatores `guardado`) ficam cifrados em
repouso com uma chave mestra (AEAD). Se o token recusar um fator guardado
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
- Estado em `/dados` (volume): banco, segredos cifrados, auditoria.
- Drivers em `/drivers`, por volume ou por uma imagem derivada
  (`FROM ... COPY driver /drivers/`). A imagem base não traz driver nenhum.
- Token físico plugado no servidor: pelo `pcscd` do host com o socket
  `/run/pcscd` montado no container, ou pelo dispositivo USB passado ao
  container. A escolha depende de medir com um token real.

## Primeiro driver: RemoteID

O [RemoteID-linux](https://github.com/LLawli/RemoteID-linux) tem um servidor
falso (`remoteid-mock`), o que permite desenvolver e testar sem token nem conta
real. O driver é um adaptador sobre o `remoteid servir` (JSON por linha no
stdio), instalado à parte junto do `remoteid` estático do pacote de servidor
daquele projeto. Não é uma dependência de crate: o servidor não carrega o
RemoteID.

Mapeamento dos fatores: o OTP é `da_pessoa`; a senha da conta e o PIN local que
a cifra (sem chaveiro no container) são `guardado`.

Lacunas conhecidas:

- O `servir` assina em modo `cru` só sobre um SHA-256. No TLS 1.2 o navegador
  pode pedir DigestInfo de SHA-384 ou SHA-512. Para a face expor `CKM_RSA_PKCS`
  inteiro, o `servir` precisa aceitar um DigestInfo pronto (o motor do RemoteID
  já tem esse modo). Medir antes quais hashes os navegadores e o PJeOffice pedem.
- A Certisign não assina RSA-PSS: o driver não declara `CKM_RSA_PKCS_PSS`, e o
  token virtual não se anuncia para TLS 1.3.

## Próximo driver: pkcs11 genérico

Carrega o módulo PKCS#11 do fornecedor (por exemplo o SafeSign de um GD Burti)
e traduz o contrato para chamadas Cryptoki. O PIN do token é `guardado`. Um
driver só cobre a maior parte dos tokens A3 físicos.

## Decisões abertas

Cada uma se decide medindo, não por preferência.

1. **Transporte entre cliente e servidor.**
   - (a) mTLS com uma AC própria do servidor, que assina o certificado do
     cliente no pareamento. Recusa no handshake; qualquer cliente HTTP fala
     (`curl --cert`). Atrás de proxy reverso exige passthrough de TLS.
   - (b) Noise IK sobre WebSocket: chaves estáticas fixadas dos dois lados e
     sigilo futuro. Quem integra precisa de uma biblioteca Noise.
   - (c) HTTPS comum e cada requisição assinada com a chave P-256 (RFC 9421).
     Passa por qualquer proxy, mas a recusa só acontece depois do TLS, e quem
     integra assina cada requisição.

   A medir: custo de integração num cliente HTTP comum, latência do handshake e
   comportamento atrás de Caddy e Traefik.
2. **Origem da chave mestra.** Arquivo ou secret do Docker (o serviço volta
   sozinho depois de reiniciar; quem lê o volume e o secret lê tudo) ou
   desbloqueio pelo administrador a cada partida (mais seguro, serviço parado
   até alguém desbloquear).
3. **Banco.** SQLite em `/dados` é o candidato.
4. **Processos de driver.** Um processo por token configurado (isolamento,
   simples) ou um por driver com vários tokens (menos processos).
