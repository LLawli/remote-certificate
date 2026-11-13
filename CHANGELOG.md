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
- O servidor responde os fatores guardados (PIN e senha) sem que ninguém os
  conheça, e para o token, sem nova tentativa, quando o token recusa um deles.
- Imagem de container do servidor, ainda sem a API.
