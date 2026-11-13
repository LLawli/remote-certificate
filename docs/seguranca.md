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
- `umask 077`: nada em `/dados` é legível por outro usuário.

### Chave do banco

- Vem do secret do Docker (`/run/secrets/...`), lido uma vez na partida. Nunca
  passa por variável de ambiente nem argumento, que aparecem em `/proc`.
- Em memória: `Box<[u8; 32]>` (endereço estável), com `mlock` (não vai para o
  swap), `MADV_DONTDUMP` (fora de core dump) e `zeroize` no fim.
- **Código de recuperação**: `remote-certificate iniciar` gera a chave, grava o
  arquivo do secret com modo `0600` e mostra a chave uma vez, em Base32 com
  dígito de conferência, pedindo para digitá-la de volta. Perder a chave perde
  usuários, pareamentos e auditoria; os tokens se configuram de novo.

### Processo e container

- Na partida: `PR_SET_DUMPABLE 0` (outro processo do mesmo usuário não faz
  `ptrace` nem lê `/proc/<pid>/mem`) e `RLIMIT_CORE 0`. Medido: o container sai
  com core dump ilimitado por padrão.
- `compose.yaml`: `read_only: true`, `cap_drop: [ALL]`,
  `security_opt: [no-new-privileges:true]`, `ulimits: {core: 0}`, `tmpfs` só
  onde precisa, usuário não root (já é).

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
se restringe e então executa o driver; as restrições atravessam o `execve`:

- **Landlock** (sem privilégio nenhum, funciona com `cap_drop: ALL`; medido no
  Docker 29): o driver lê `/usr`, `/lib`, `/etc` e o próprio executável, e
  escreve só no diretório de estado dele. Não alcança o banco nem o secret.
  Onde o kernel permite (ABI 4 ou mais), só conecta nas portas TCP que declarou
  (o RemoteID, na 443).
- `RLIMIT_CORE 0`, limite de memória, de arquivos abertos e de processos.
- O que o driver precisa (portas, dispositivos, socket do `pcscd`) vem de um
  manifesto ao lado do executável, que o Dockerfile do driver instala. O
  lançador aplica o mais restrito que o kernel aceita e registra o nível obtido.
- Segredos chegam ao driver só pelo stdin, nunca por argumento ou ambiente.
- O driver aplica `PR_SET_DUMPABLE 0` no próprio `main` (o `execve` volta o
  valor para 1). Vale para todo driver aceito em `drivers/`.

## Estação

- **Chave do dispositivo**: no Linux, selada no TPM com `systemd-creds --user`
  quando o systemd tem isso (256 ou mais) e há TPM; copiar os arquivos do
  agente para outra máquina não leva o dispositivo junto. Sem TPM, arquivo
  `0600`. Windows e macOS usam o cofre deles (CNG/TPM, Secure Enclave). A medir
  na VM: em quais distribuições o `--user` existe.
- Em memória, como a chave do banco: `mlock`, `MADV_DONTDUMP`, `zeroize`; o
  agente com `PR_SET_DUMPABLE 0` e `RLIMIT_CORE 0`.
- O socket entre face e agente fica em `$XDG_RUNTIME_DIR`, modo `0600`, e o
  agente confere o usuário do outro lado (`SO_PEERCRED`).
- **Sessão que expira**: depois de um tempo sem uso, o servidor esquece o login
  do PIN pessoal e a próxima operação pede o PIN de novo. A medir na VM: como
  Firefox, PJeOffice e Serpro reagem a `CKR_USER_NOT_LOGGED_IN` no meio do uso.

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

- **Root no host**, ou quem está no grupo `docker`, lê a memória do servidor e
  o secret enquanto ele roda.
- **O secret fica em disco no host.** Quem copia o volume e o arquivo do secret
  lê tudo. Uma receita opcional de deploy pode guardar o secret selado no TPM do
  host e abri-lo em `/run` (tmpfs) na partida.
- **SSD e Btrfs** guardam blocos antigos: o que um dia foi gravado em claro
  pode sobreviver no disco. Por isso nada é gravado em claro, nem uma vez.
- **Captura de tela**: na estação, um programa do mesmo usuário pode capturar a
  janela onde a pessoa digita o OTP. O OTP é de uso único e expira rápido.
- **Limites do Landlock** dependem do kernel do host; num kernel antigo, o
  driver fica só com os limites de processo.
