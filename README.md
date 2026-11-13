# remote-certificate

Um token A3 ou um certificado em nuvem (RemoteID, por exemplo) só funciona na
máquina em que está plugado ou configurado. Este serviço deixa os tokens num
servidor e os compartilha pela rede, para escritórios (de advocacia, de
contabilidade) que usam um único certificado em várias estações de trabalho e
nos próprios sistemas internos.

> **Em construção.** Nada disto funciona ainda. O desenho está em
> [docs/arquitetura.md](docs/arquitetura.md).

## O que ele vai fazer

- **Token virtual nas estações**: cada computador pareado vê um token como o
  físico, no navegador, no PJeOffice, no Assinador Serpro e no Papers. A
  assinatura acontece no servidor.
- **API HTTP** para sistemas internos assinarem com o mesmo token.
- **Um PIN por pessoa**, para saber quem assinou o quê. O PIN do token fica
  cifrado no servidor e ninguém precisa conhecê-lo. Errar o PIN pessoal 3 vezes
  seguidas bloqueia o computador; o OTP, quando o token pede, vem da pessoa.
- **Só computadores pareados** são atendidos, mesmo com o servidor na internet.
- **Drivers à parte**: cada servidor instala só os drivers dos tokens que tem.
  O primeiro é o do RemoteID, pelo
  [RemoteID-linux](https://github.com/LLawli/RemoteID-linux).

As estações começam pelo Linux; Windows e macOS estão previstos no desenho.

## Desenvolvimento

```sh
scripts/ci.sh
```

Como testar, em [docs/desenvolvimento.md](docs/desenvolvimento.md); o contrato
entre o servidor e os drivers, em [docs/drivers.md](docs/drivers.md).

## Licença

[AGPL-3.0](LICENSE).
