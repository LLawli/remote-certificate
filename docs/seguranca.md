# Segurança

O modelo de ameaça, as defesas de cada peça e os riscos aceitos. As regras que
não mudam estão no `CLAUDE.md`; aqui fica como elas se cumprem hoje. Parte das
primitivas veio de
[um relato do Akita](https://akitaonrails.com/2026/11/06/adicionando-seguranca-de-verdade-nos-seus-apps-gui-linux-vibecoded/),
adaptada ao que este sistema é: um serviço sem tela, em container, que precisa
voltar sozinho depois de reiniciar.

## Ameaças

1. Alguém copia o volume `/dados` ou um backup.
2. Um processo do mesmo usuário (no container, ou na estação) tenta ler a
   memória de outro: a chave do banco, um PIN guardado, a chave do dispositivo.
3. Um driver com defeito, ou um módulo de fornecedor ruim, trava, consome
   memória sem fim ou responde lixo.
4. Um driver comprometido tenta ler o banco, a chave dele ou falar com quem não
   deve na rede.
5. Uma máquina da tailnet, ou alguém com a URL, que não foi pareada.
6. Quem pega o computador de alguém tenta adivinhar o PIN pessoal.

## Servidor

### Banco

SQLCipher, configurado em toda conexão antes de qualquer consulta:

| PRAGMA | Valor | Por quê |
|---|---|---|
| `key` | `x'<64 hex>'` | A chave crua de 256 bits do secret. Sem KDF: ela já é aleatória, e o PBKDF2 só atrasaria a partida. |
| `cipher_compatibility` | `4` | Fixa os algoritmos (AES-256-CBC, HMAC-SHA512 por página). |
| `cipher_plaintext_header_size` | `0` | Nem o cabeçalho fica legível: o arquivo é ruído do primeiro byte. |
| `cipher_memory_security` | `ON` | O SQLCipher trava e apaga a própria memória. |
| `secure_delete` | `ON` | Página apagada é sobrescrita. |
| `temp_store` | `MEMORY` | Tabela temporária não vai para o disco. |
| `trusted_schema` | `OFF` | Gatilho ou função embutida no arquivo não roda. |
| `foreign_keys` | `ON` | |

- Um arquivo que começa com `SQLite format 3\0` é recusado: o servidor nunca
  abre um banco em claro. Chave errada e arquivo corrompido dão o mesmo erro
  (uma consulta a `sqlite_schema` confere a chave).
- Migração de esquema numa transação (o SQLite tem DDL transacional), com um
  backup verificado antes.
- O banco e cada backup nascem com permissão `0600`.

### Chave do banco

- Vem do secret do Docker (`/run/secrets/...`), lido uma vez na partida. Nunca
  passa por variável de ambiente nem argumento, que aparecem em `/proc`.
- Em memória: numa página só dela (`crates/memoria`), com `mlock` (não vai
  para o swap), `MADV_DONTDUMP` (fora de core dump) e zerada no fim. O arquivo
  é lido direto para essa página.
- **No host**: `bin/deploy chave` gera a chave no próprio host e a sela no TPM
  com `systemd-creds` (`/etc/credstore.encrypted`). A cada boot, antes do
  Docker, o `remote-certificate-chave.service` a abre em `/run` (tmpfs), de
  onde o `compose.yaml` a entrega como secret. Em claro, ela só existe em RAM.
  Copiar o disco do host não leva a chave junto. Sem TPM, a receita sela com a
  chave do próprio host, o que só protege contra copiar o arquivo sozinho.
- **Código de recuperação**: logo depois de gerar a chave, a receita roda
  `remote-certificate recuperacao mostrar`, que mostra a chave uma vez, em
  Base32 com conferência contra erro de digitação, pede para digitá-la de
  volta e limpa o terminal. `bin/deploy chave --restaurar` sela no TPM de um
  host novo a chave de um código. Perder a chave e o código perde usuários,
  pareamentos e auditoria; os tokens se configuram de novo.

### PIN pessoal

- Guardado em Argon2id com a segunda opção recomendada da RFC 9106: 64 MiB,
  3 passadas, 4 vias. Medido em 2026-11-13 (Ryzen 7 5700U, release): 141 ms e
  66 MiB por conferência, sem a feature `parallel` (com o rayon, 85 ms; não
  compensa a dependência num login). A primeira opção da RFC, 2 GiB, levou
  1,7 s e 2 GiB por conferência: alguns logins juntos derrubariam o container.
  Os parâmetros ficam no próprio hash, então subi-los depois não invalida os
  PINs guardados. De 4 a 64 caracteres.
- A tentativa conta como erro antes de o hash ser conferido, numa transação
  `IMMEDIATE`, e o acerto zera o contador. Uma rajada de tentativas em paralelo
  não ganha mais de 3 chutes, nem com a CLI aberta noutra conexão, e uma queda
  no meio da conferência conta como erro.
- Bloqueado, o dispositivo recusa até o PIN certo, sem conferir o hash: o
  bloqueio não revela se o chute estava certo.
- Com o banco aberto, um PIN de 4 dígitos cai por força bruta offline; quem
  guarda o PIN pessoal de verdade é o SQLCipher. O Argon2id só encarece isso.

### Processo e container

- Na partida: `PR_SET_DUMPABLE 0` (outro processo do mesmo usuário não faz
  `ptrace` nem lê `/proc/<pid>/mem`) e `RLIMIT_CORE 0`. Medido: o container sai
  com core dump ilimitado por padrão.
- `compose.yaml`: `read_only: true`, `cap_drop: [ALL]`,
  `security_opt: [no-new-privileges:true]`, `ulimits: {core: 0}`, `tmpfs` só
  onde precisa, usuário não root (já é).

### Conexões

- Só TLS 1.3 e só chaves P-256, dos dois lados (`crates/rede`). O servidor
  consulta o banco no handshake: chave que não é de dispositivo pareado cai
  ali, antes de qualquer HTTP (ameaça 5).
- Um handshake tem 10 segundos para terminar.
- Com um código de pareamento pendente, qualquer chave termina o handshake,
  mas só alcança `POST /v1/pareamento`, e sem o segredo não vira dispositivo.
  O segredo tem 80 bits e vale por 10 minutos, uma vez; o banco guarda o
  SHA-256 dele.
- Um código vazado deixa alguém parear no lugar da pessoa, dentro do prazo. O
  dispositivo dele ainda depende do PIN pessoal dela, o administrador vê o
  dispositivo a mais em `dispositivo listar` e o tira com
  `dispositivo revogar`. A conexão aberta de um dispositivo revogado cai na
  mensagem seguinte.
- No WebSocket do agente, uma mensagem tem no máximo 4 MiB, e o servidor
  espera a pessoa responder um fator por 3 minutos antes de cancelar. O maior
  bloco medido nos programas de verdade foi de 254 bytes (os atributos
  assinados de um PDF no Papers); TLS manda 51.
- Na API HTTP, o PIN pessoal vai em cada assinatura (um lote conta como uma)
  e não abre sessão: nenhum identificador de sessão circula para ser roubado,
  e quem chega ao computador do sistema depois não assina sem o PIN. O corpo
  de uma assinatura tem no máximo 4 MiB, e um dispositivo tem no máximo 4
  assinaturas em curso e 64 guardadas em memória.
- No máximo 4 conferências do PIN pessoal rodam ao mesmo tempo (64 MiB cada):
  uma enxurrada de pedidos espera a vez em vez de esgotar a memória.

### Mensagens de fora

Toda linha e mensagem que chega tem tamanho máximo, com constante nomeada: o
JSON por linha dos drivers, o corpo da API HTTP e as mensagens do WebSocket.
Passou do limite, a conexão cai. Toda entrada vira tipo estrito (serde) antes de
qualquer uso.

### Backup

`remote-certificate backup <arquivo>` copia pela API de backup do SQLite
(consistente com o serviço rodando, ao contrário de um `cp`) e só diz que deu
certo depois de abrir a cópia com a chave, rodar `cipher_integrity_check` e
`integrity_check` e comparar uma impressão digital lógica (SHA-256 de todas as
linhas, em ordem) com a do banco original. A cópia já é SQLCipher, autenticada
página a página; não precisa de um formato próprio por cima. Para onde ela vai
(restic, NAS) é escolha de quem opera.

## Drivers

Cada driver roda por um lançador (`remote-certificate isolar -- <driver>`), que
se restringe e então executa o driver; as restrições atravessam o `execve` e
valem para os filhos do driver (o `remoteid`):

- **Landlock** (sem privilégio nenhum, funciona com `cap_drop: ALL`; medido no
  Docker 29, ABI 9 no kernel 7.2): o driver lê e executa `/usr`, `/lib`,
  `/bin`, `/sbin`, `/etc` e a pasta do próprio executável, lê o nome da
  máquina e a versão do kernel em `/proc/sys/kernel`, e escreve só no
  diretório de estado do token, onde não executa nada. Não alcança o banco, o
  secret nem o estado de outro token.
- **Rede**: só conecta nas portas TCP do manifesto (o RemoteID, na 443) e não
  escuta em nenhuma (ABI 4). Não conecta em socket UNIX nenhum (ABI 9) nem em
  socket abstrato de fora, e não manda sinal para fora dele, nem para o
  servidor (ABI 6).
- **Limites**: `RLIMIT_CORE 0`, memória virtual (512 MiB no RemoteID, que
  sobe com 128), 256 arquivos abertos. O número de processos é o
  `pids_limit` do container: o `RLIMIT_NPROC` conta as threads do servidor
  junto, que roda com o mesmo usuário.
- O que o driver precisa vem do manifesto ao lado do executável
  ([drivers.md](drivers.md#manifesto)), que o Dockerfile do driver instala. O
  lançador aplica o mais restrito que o kernel aceita e registra o nível obtido
  no log. Ele recusa a raiz como pasta do driver ou como diretório de trabalho,
  que liberariam o disco inteiro.
- Segredos chegam ao driver só pelo stdin, nunca por argumento ou ambiente.
- O driver aplica `PR_SET_DUMPABLE 0` no próprio `main` (o `execve` volta o
  valor para 1). Vale para todo driver aceito em `drivers/`.

## Estação

- **Chave do dispositivo**: no Linux (v1), um arquivo `0600` num diretório
  `0700` (`$XDG_DATA_HOME/remote-certificate/dispositivo.json`), como uma
  chave SSH. O agente recusa um cofre que outro usuário consegue ler. Sozinha,
  a chave só lista os certificados e gasta as tentativas do PIN pessoal, que
  bloqueiam o dispositivo. O TPM (`systemd-creds --user`, CNG no Windows,
  Secure Enclave no macOS) entra atrás do mesmo trait (`agente::cofre`).
- O agente roda com `PR_SET_DUMPABLE 0` e `RLIMIT_CORE 0`. A chave do
  dispositivo fica num buffer que é zerado ao sair, mas o rustls guarda a
  cópia dele, que não é travada na RAM.
- O socket entre face e agente fica em
  `$XDG_RUNTIME_DIR/remote-certificate/agente.sock`, num diretório `0700`, e o
  agente confere o usuário do outro lado (`SO_PEERCRED`). Uma mensagem tem no
  máximo 6 MiB; passou disso, a conexão cai.
- A janela do OTP é um programa à parte (`remote-certificate-dialogo`): a
  pergunta vai pelo stdin e o código volta pelo stdout, nunca por argumento
  nem por ambiente. Sem resposta em 3 minutos, o agente fecha a janela e
  desiste.
- Cada aplicação tem a sua conexão com o servidor e o seu login, como o
  `C_Login` do PKCS#11: o PIN que o Firefox mandou não assina pelo PJeOffice.
- A face (o módulo PKCS#11) roda dentro do processo de cada aplicação: não
  guarda o PIN depois do `C_Login`, não escreve nada no stdout nem no stderr,
  e o registro dela leva só a função, o resultado, o tamanho e o começo do
  SHA-256 dos dados, nunca o PIN nem o documento.
- **Sessão que expira**: depois de 15 minutos sem uso (`servir --sessao`), o
  servidor esquece o login do PIN pessoal. O prazo vai junto da resposta do
  login, e a face se dá por deslogada um pouco antes (um décimo do prazo, até
  30 s), renovando a cada assinatura como o servidor. Assim o NSS vê a sessão
  pública e pede o PIN antes de assinar. Sem isso, medido no Firefox: a
  recusa só aparecia no `C_Sign`, no meio do handshake, e a página ficava
  carregando sem pedir o PIN.

## O que ficou de fora

- **Desbloqueio a cada partida (Polkit, TPM do servidor)**: o serviço precisa
  voltar sozinho; a decisão foi o secret do Docker.
- **Navegador isolado, compositor aninhado, ponte de área de transferência,
  firewall por usuário com nftables**: aqui não há navegador nem tela no
  servidor, e o nftables exigiria `NET_ADMIN` no container. O Landlock cobre a
  parte de rede que dá (portas, não destinos).
- **Leitor de documentos em sandbox**: o servidor não interpreta documento;
  recebe dados para resumir ou um resumo pronto.
- **Formato próprio de backup com HMAC**: o SQLCipher já autentica cada página.

## Riscos aceitos

- **Quem tem a chave do banco reescreve a auditoria inteira**, com selos novos
  que fecham. A corrente só prova que nada mudou antes do último selo anotado
  fora da máquina (`auditoria verificar`); a anotação é do administrador.

- **Root no host**, ou quem está no grupo `docker`, lê a memória do servidor e
  o secret enquanto ele roda.
- **Quem controla o host ligado** abre a chave do TPM como o serviço abre. O
  TPM protege o disco copiado ou roubado, não o host invadido.
- **O `remoteid servir` anterior ao 0.5.2** guarda a senha e o PIN da conta
  na memória dele e não se marca como não depurável (o `execve` desfaz o que o
  driver marcou). O 0.5.2 se marca sozinho; o driver aceita o 0.5.1 porque não
  tem como distinguir os dois pelo protocolo, e a imagem do driver leva o
  0.5.2.
- **SSD e Btrfs** guardam blocos antigos: o que um dia foi gravado em claro
  pode sobreviver no disco. Por isso nada é gravado em claro, nem uma vez.
- **Captura de tela**: na estação, um programa do mesmo usuário pode capturar a
  janela onde a pessoa digita o OTP. O OTP é de uso único e expira rápido.
- **Limites do Landlock** dependem do kernel do host; num kernel antigo, o
  driver fica só com os limites de processo. O log de cada partida do driver
  diz o nível (`isolar: ...: Landlock completo (ABI 9)`).
- **A rede do Landlock filtra portas, não destinos**: o driver do RemoteID
  alcança qualquer servidor na 443, não só a Certisign.
