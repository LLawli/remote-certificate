# remote-certificate

Só invariantes do sistema: regras que valem para qualquer versão. O estado atual,
o desenho e as decisões abertas ficam em `docs/`.

## O que o sistema é

Um servidor que guarda tokens A3 e certificados em nuvem e os compartilha pela
rede com estações de trabalho (como um token virtual) e com sistemas (por API
HTTP).

## Drivers

- Um driver é um executável à parte, instalado só por quem tem aquele token. O
  servidor nunca depende de um driver como crate nem o traz na imagem base.
- O servidor fala com os drivers só pelo contrato de `docs/drivers.md`.
- Não existe driver genérico. Um tipo de token só é suportado quando tem um
  driver próprio aceito em `drivers/<nome>/`, com o Dockerfile da imagem
  derivada e os testes; a tradução das manias do fornecedor é do driver.
- As capacidades vêm do driver. O cliente nunca expõe um mecanismo que o driver
  não declarou (um token sem RSA-PSS nem ECDSA não se anuncia para TLS 1.3).

## Segurança

- PIN, senha, OTP e o conteúdo dos documentos nunca vão para log, auditoria,
  fixture, teste ou disco em claro.
- Os fatores guardados (PIN do token, senha de conta) ficam cifrados no servidor
  e nunca saem dele para um cliente.
- O OTP vem da pessoa a cada operação e nunca é guardado.
- Cada usuário tem um PIN pessoal. Ele nunca chega ao token: o servidor valida o
  PIN pessoal e só então usa o fator guardado.
- Errar o PIN pessoal N vezes seguidas bloqueia o dispositivo até o
  administrador desbloquear.
- Quando o token recusa um fator guardado, o servidor não tenta de novo sozinho.
- Só dispositivos e sistemas pareados são atendidos. Uma chave desconhecida é
  recusada antes de qualquer operação.
- A auditoria é só de acréscimo e registra quem, de qual dispositivo, com qual
  token e chave, o hash do que foi assinado e o resultado.

## Portabilidade do cliente

Tudo o que é específico de um sistema operacional fica nas faces (a forma de
expor o token), no IPC entre face e agente e no cofre da chave do dispositivo.
O resto do cliente não depende de sistema operacional.

## Testes

- **Unitários nas regras de negócio invariantes**, não em toda função: bloqueio
  por PIN, recusa de dispositivo não pareado, o que entra e o que não entra na
  auditoria, exposição de capacidades por driver, não repetir fator guardado
  recusado, segredos fora de log.
- **Integração da aplicação inteira com fluxos de uso reais**: servidor, driver
  e cliente juntos, cobrindo cada tipo de assinatura que o driver oferece (no
  RemoteID, contra o servidor falso dele). Um fluxo novo de uso entra com seu
  teste de integração.

## Licença

AGPL-3.0. Toda contribuição entra sob ela.
