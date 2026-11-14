# Changelog

Todas as mudanças visíveis deste projeto. O formato segue o
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/), e as versões, o
[Semantic Versioning](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Added

- Contrato de driver v0 (rascunho), em `docs/drivers.md` e `crates/protocolo`,
  com a configuração do token declarada pelo próprio driver.
- Driver do RemoteID (`remote-certificate-driver-remoteid`), sobre o
  `remoteid servir`: assina com `CKM_RSA_PKCS` e `CKM_SHA256_RSA_PKCS`,
  `CKM_SHA384_RSA_PKCS` e `CKM_SHA512_RSA_PKCS`, pedindo o OTP a quem assina.
  Exige o `remoteid` 0.5.1 ou mais novo e avisa quando o instalado é anterior.
  Testado com o 0.5.2, que fecha a memória do `remoteid` para outros
  processos; é o recomendado.
- O servidor responde os fatores guardados (PIN e senha) sem que ninguém os
  conheça, e para o token, sem nova tentativa, quando o token recusa um deles,
  mesmo que o token peça junto um fator da pessoa. O token parado continua
  parado depois de o servidor reiniciar.
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
- API HTTP `/v1` para sistemas integrados: `GET /v1/chaves` e a assinatura
  como recurso em `/v1/assinaturas`, com um lote de até 1000 documentos por
  PIN pessoal, o pedido do OTP no meio, a desistência e a consulta que espera
  a assinatura mudar.
- O PIN pessoal confere no máximo 4 vezes ao mesmo tempo, no agente e na API,
  para limitar a memória do Argon2id.
