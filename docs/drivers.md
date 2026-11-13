# Contrato de driver (v0, rascunho)

Um driver é o que sabe falar com um tipo de token. É um executável à parte,
instalado só por quem tem aquele token, e qualquer linguagem serve. Os tipos em
Rust estão em `crates/protocolo`, e os testes de lá mostram cada mensagem no
fio.

## Como o servidor roda um driver

- O servidor lança o executável com os argumentos da configuração daquele
  token, um processo por token.
- A conversa é JSON, uma mensagem por linha, pelo stdin e pelo stdout. O stdout
  é só do protocolo; log vai para o stderr.
- Um pedido por vez: o servidor só manda o próximo depois da resposta. Tokens
  físicos serializam as operações de qualquer forma.
- Fechar o stdin encerra o driver.

## Envelope

Cada pedido tem um `id` numérico, que volta igual, e um `op`:

```json
{"id": 1, "op": "apresentar", "versao": 0}
```

O driver responde com o resultado ou com uma falha:

```json
{"id": 1, "ok": { ... }}
{"id": 1, "erro": {"tipo": "token_ausente", "mensagem": "Token removido"}}
```

`tipo` é estável e serve para o servidor decidir; `mensagem` é para a pessoa
ler. Os tipos: `pedido_invalido`, `versao_incompativel`, `token_ausente`,
`chave_ausente`, `mecanismo_nao_suportado`, `fator_recusado`, `bloqueado`,
`cancelado`, `rede`. Um tipo que o servidor não conhece é lido como `outro`.

## Operações

### `apresentar`

A primeira mensagem de toda conversa. O servidor diz a versão do contrato; o
driver responde quem é e que fatores pode pedir, ou `versao_incompativel`.

```json
{"id": 1, "ok": {
  "driver": "remoteid", "versao": "0.1.0", "protocolo": 0,
  "fatores": [
    {"nome": "senha", "tipo": "guardado", "rotulo": "Senha da conta"},
    {"nome": "otp", "tipo": "da_pessoa", "rotulo": "Código do autenticador"}
  ]
}}
```

- `guardado`: o servidor guarda cifrado e responde sozinho (PIN do token, senha
  de uma conta). Quem usa o token nunca o vê.
- `da_pessoa`: o servidor pergunta a quem pediu a operação, a cada vez, e nunca
  guarda (OTP).

### `listar`

As chaves que o driver enxerga agora.

```json
{"id": 2, "op": "listar"}
{"id": 2, "ok": {"chaves": [{
  "id": "1234;AC Exemplo", "rotulo": "FULANO:00000000000",
  "certificado": "<DER em base64>",
  "mecanismos": ["CKM_RSA_PKCS", "CKM_SHA256_RSA_PKCS"]
}]}}
```

`id` é estável enquanto o token existir. Os mecanismos usam os nomes do
PKCS#11; a face do cliente expõe exatamente esses. Um nome que o servidor não
conhece é ignorado.

### `assinar`

```json
{"id": 3, "op": "assinar", "chave": "1234;AC Exemplo",
 "mecanismo": "CKM_RSA_PKCS", "dados": "<base64>"}
{"id": 3, "ok": {"assinatura": "<base64>"}}
```

Com `CKM_RSA_PKCS`, `dados` é o DigestInfo pronto; com `CKM_SHA256_RSA_PKCS` e
parecidos, os dados inteiros; com `CKM_RSA_PKCS_PSS` e `CKM_ECDSA`, o hash.

## Fatores no meio de uma operação

Quando precisa de fatores, o driver pergunta antes de responder, no mesmo `id`:

```json
{"id": 3, "pedir": {"fatores": ["senha", "otp"], "recusa": null}}
```

e o servidor responde com os fatores ou desiste:

```json
{"id": 3, "fatores": {"senha": "...", "otp": "123456"}}
{"id": 3, "cancelar": true}
```

`recusa` traz a mensagem da tentativa anterior quando o token recusou. O
driver pode pedir de novo; o servidor decide quantas vezes aceita.

## Segredos

PIN, senha e OTP só passam pela memória e pelo canal. Um driver nunca os grava
em disco nem em log, inclusive no stderr.

## Versão

`protocolo` muda quando uma mensagem muda de forma incompatível. Campo novo e
opcional não muda a versão.
