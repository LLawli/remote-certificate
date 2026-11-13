//! O estado do servidor: um SQLite cifrado inteiro com SQLCipher. As escolhas
//! de cada PRAGMA estão em `docs/seguranca.md`.

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use memoria::Travado;
use protocolo::Segredo;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const TAMANHO_DA_CHAVE: usize = 32;

/// A chave crua de 256 bits do banco, travada na RAM.
pub type ChaveDoBanco = Travado<TAMANHO_DA_CHAVE>;

/// Onde o Docker monta o secret com a chave.
pub const CHAVE_PADRAO: &str = "/run/secrets/remote-certificate-chave";
pub const BANCO_PADRAO: &str = "/dados/remote-certificate.db";

/// O começo de todo banco SQLite em claro.
const CABECALHO_EM_CLARO: &[u8; 16] = b"SQLite format 3\0";

/// Depois da chave e antes de qualquer consulta, em toda conexão. A ordem
/// importa: `cipher_compatibility` volta os outros `cipher_*` ao padrão dela.
const PRAGMAS: &str = "
    PRAGMA cipher_compatibility = 4;
    PRAGMA cipher_plaintext_header_size = 0;
    PRAGMA cipher_memory_security = ON;
    PRAGMA secure_delete = ON;
    PRAGMA temp_store = MEMORY;
    PRAGMA trusted_schema = OFF;
    PRAGMA foreign_keys = ON;
";

/// O esquema, uma migração por versão (`PRAGMA user_version`). Uma migração
/// entra no fim e nunca muda depois de publicada.
const MIGRACOES: &[&str] = &["
    CREATE TABLE token (
        id INTEGER PRIMARY KEY,
        nome TEXT NOT NULL UNIQUE,
        driver TEXT NOT NULL,
        argumentos TEXT NOT NULL,
        desatualizado TEXT
    ) STRICT;
    CREATE TABLE fator_guardado (
        token INTEGER NOT NULL REFERENCES token (id) ON DELETE CASCADE,
        nome TEXT NOT NULL,
        valor TEXT NOT NULL,
        PRIMARY KEY (token, nome)
    ) STRICT;
"];

#[derive(Debug)]
pub enum FalhaDoBanco {
    /// Chave errada ou arquivo corrompido. De propósito, não dá para saber
    /// qual dos dois.
    ChaveOuArquivo,
    /// Um banco SQLite em claro: o servidor nunca abre um.
    EmClaro,
    /// O arquivo da chave não tem os 32 bytes de uma chave.
    ChaveMalFormada,
    /// O banco é de uma versão mais nova do servidor.
    EsquemaNovo(u32),
    /// O backup não confere com o banco.
    BackupDivergente(&'static str),
    JaExiste(PathBuf),
    Io(io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for FalhaDoBanco {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalhaDoBanco::ChaveOuArquivo => f.write_str("chave errada ou banco corrompido"),
            FalhaDoBanco::EmClaro => {
                f.write_str("o banco está em claro; o servidor só abre banco cifrado")
            }
            FalhaDoBanco::ChaveMalFormada => {
                write!(f, "a chave do banco tem que ter {TAMANHO_DA_CHAVE} bytes")
            }
            FalhaDoBanco::EsquemaNovo(v) => write!(
                f,
                "o banco é de uma versão mais nova do servidor (esquema {v})"
            ),
            FalhaDoBanco::BackupDivergente(o_que) => write!(f, "o backup não confere: {o_que}"),
            FalhaDoBanco::JaExiste(caminho) => write!(f, "{} já existe", caminho.display()),
            FalhaDoBanco::Io(e) => e.fmt(f),
            FalhaDoBanco::Sqlite(e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for FalhaDoBanco {
    fn from(e: io::Error) -> FalhaDoBanco {
        FalhaDoBanco::Io(e)
    }
}

impl From<rusqlite::Error> for FalhaDoBanco {
    fn from(e: rusqlite::Error) -> FalhaDoBanco {
        FalhaDoBanco::Sqlite(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdDoToken(i64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroDoToken {
    pub id: IdDoToken,
    pub nome: String,
    /// O executável do driver, em `/drivers`.
    pub driver: String,
    pub argumentos: Vec<String>,
}

pub struct Banco {
    conexao: Connection,
    chave: ChaveDoBanco,
}

/// Lê a chave do arquivo direto para a memória travada.
pub fn ler_chave(caminho: &Path) -> Result<ChaveDoBanco, FalhaDoBanco> {
    let mut arquivo = File::open(caminho)?;
    if arquivo.metadata()?.len() != TAMANHO_DA_CHAVE as u64 {
        return Err(FalhaDoBanco::ChaveMalFormada);
    }
    let mut chave = ChaveDoBanco::zerado()?;
    arquivo.read_exact(chave.expor_mut())?;
    Ok(chave)
}

impl Banco {
    /// Abre o banco, ou o cria com permissão `0600` se não existir, e o leva à
    /// versão de esquema desta versão do servidor.
    pub fn abrir(caminho: &Path, chave: ChaveDoBanco) -> Result<Banco, FalhaDoBanco> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(caminho)
        {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let conexao = conectar(caminho, &chave)?;
        let banco = Banco { conexao, chave };
        banco.migrar(caminho)?;
        Ok(banco)
    }

    fn migrar(&self, caminho: &Path) -> Result<(), FalhaDoBanco> {
        let versao: u32 = self
            .conexao
            .pragma_query_value(None, "user_version", |l| l.get(0))?;
        let alvo = MIGRACOES.len() as u32;
        if versao > alvo {
            return Err(FalhaDoBanco::EsquemaNovo(versao));
        }
        if versao == alvo {
            return Ok(());
        }
        if versao > 0 {
            let mut copia = caminho.as_os_str().to_owned();
            copia.push(format!(".esquema-{versao}"));
            self.backup(Path::new(&copia))?;
        }
        let transacao = self.conexao.unchecked_transaction()?;
        for (i, migracao) in MIGRACOES.iter().enumerate().skip(versao as usize) {
            transacao.execute_batch(migracao)?;
            transacao.pragma_update(None, "user_version", i as u32 + 1)?;
        }
        transacao.commit()?;
        Ok(())
    }

    pub fn criar_token(
        &self,
        nome: &str,
        driver: &str,
        argumentos: &[String],
    ) -> Result<IdDoToken, FalhaDoBanco> {
        let argumentos = serde_json::to_string(argumentos).expect("strings viram JSON");
        self.conexao.execute(
            "INSERT INTO token (nome, driver, argumentos) VALUES (?1, ?2, ?3)",
            params![nome, driver, argumentos],
        )?;
        Ok(IdDoToken(self.conexao.last_insert_rowid()))
    }

    pub fn tokens(&self) -> Result<Vec<RegistroDoToken>, FalhaDoBanco> {
        let mut consulta = self
            .conexao
            .prepare("SELECT id, nome, driver, argumentos FROM token ORDER BY nome")?;
        let linhas = consulta.query_map([], |l| {
            let argumentos: String = l.get(3)?;
            Ok(RegistroDoToken {
                id: IdDoToken(l.get(0)?),
                nome: l.get(1)?,
                driver: l.get(2)?,
                argumentos: serde_json::from_str(&argumentos).unwrap_or_default(),
            })
        })?;
        Ok(linhas.collect::<Result<_, _>>()?)
    }

    /// Os fatores guardados do token.
    pub fn cofre(&self, token: IdDoToken) -> Result<BTreeMap<String, Segredo>, FalhaDoBanco> {
        let mut consulta = self
            .conexao
            .prepare("SELECT nome, valor FROM fator_guardado WHERE token = ?1")?;
        let linhas = consulta.query_map([token.0], |l| {
            Ok((l.get::<_, String>(0)?, Segredo::novo(l.get(1)?)))
        })?;
        Ok(linhas.collect::<Result<_, _>>()?)
    }

    /// Os fatores guardados que o token recusou, se ele está parado.
    pub fn desatualizado(&self, token: IdDoToken) -> Result<Option<Vec<String>>, FalhaDoBanco> {
        let nomes: Option<String> = self
            .conexao
            .query_row(
                "SELECT desatualizado FROM token WHERE id = ?1",
                [token.0],
                |l| l.get(0),
            )
            .optional()?
            .flatten();
        Ok(nomes.map(|n| serde_json::from_str(&n).unwrap_or_default()))
    }

    /// Troca o cofre do token pelo da configuração nova e o libera, numa
    /// transação só.
    pub fn configurado(
        &self,
        token: IdDoToken,
        cofre: &BTreeMap<String, Segredo>,
    ) -> Result<(), FalhaDoBanco> {
        let transacao = self.conexao.unchecked_transaction()?;
        transacao.execute("DELETE FROM fator_guardado WHERE token = ?1", [token.0])?;
        for (nome, valor) in cofre {
            transacao.execute(
                "INSERT INTO fator_guardado (token, nome, valor) VALUES (?1, ?2, ?3)",
                params![token.0, nome, valor.expor()],
            )?;
        }
        transacao.execute(
            "UPDATE token SET desatualizado = NULL WHERE id = ?1",
            [token.0],
        )?;
        transacao.commit()?;
        Ok(())
    }

    /// Para o token: ele recusou estes fatores guardados.
    pub fn marcar_desatualizado(
        &self,
        token: IdDoToken,
        nomes: &[String],
    ) -> Result<(), FalhaDoBanco> {
        let nomes = serde_json::to_string(nomes).expect("strings viram JSON");
        self.conexao.execute(
            "UPDATE token SET desatualizado = ?2 WHERE id = ?1",
            params![token.0, nomes],
        )?;
        Ok(())
    }

    /// Copia o banco para `destino`, que não pode existir, com o serviço
    /// rodando, e só termina bem depois de abrir a cópia com a chave e conferir
    /// a integridade e cada linha.
    pub fn backup(&self, destino: &Path) -> Result<(), FalhaDoBanco> {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(destino)
        {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(FalhaDoBanco::JaExiste(destino.to_owned()));
            }
            Err(e) => return Err(e.into()),
        }
        let copiado = self.copiar(destino);
        if copiado.is_err() {
            let _ = std::fs::remove_file(destino);
        }
        copiado
    }

    fn copiar(&self, destino: &Path) -> Result<(), FalhaDoBanco> {
        let caminho = destino.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "caminho do backup não é UTF-8")
        })?;
        // O SQLite não anexa dentro de uma transação: anexa antes, e a cópia e
        // a impressão digital acontecem numa transação só, vendo o mesmo banco.
        self.conexao.execute(
            "ATTACH DATABASE ?1 AS copia KEY ?2",
            params![caminho, chave_em_texto(&self.chave).as_str()],
        )?;
        let exportado = (|| {
            let transacao = self.conexao.unchecked_transaction()?;
            let original = impressao_digital(&transacao)?;
            transacao.query_row("SELECT sqlcipher_export('copia')", [], |_| Ok(()))?;
            // O export copia esquema e linhas, mas não a versão do esquema.
            let versao: u32 = transacao.pragma_query_value(None, "user_version", |l| l.get(0))?;
            transacao.pragma_update(Some("copia"), "user_version", versao)?;
            transacao.commit()?;
            Ok::<_, FalhaDoBanco>(original)
        })();
        self.conexao.execute("DETACH DATABASE copia", [])?;
        let original = exportado?;

        let copia = conectar(destino, &self.chave)?;
        let falhas: Vec<String> = copia
            .prepare("PRAGMA cipher_integrity_check")?
            .query_map([], |l| l.get(0))?
            .collect::<Result<_, _>>()?;
        if !falhas.is_empty() {
            return Err(FalhaDoBanco::BackupDivergente("HMAC de página"));
        }
        let integridade: String = copia.query_row("PRAGMA integrity_check", [], |l| l.get(0))?;
        if integridade != "ok" {
            return Err(FalhaDoBanco::BackupDivergente("integridade do SQLite"));
        }
        if impressao_digital(&copia)? != original {
            return Err(FalhaDoBanco::BackupDivergente("o conteúdo"));
        }
        Ok(())
    }
}

/// `x'<hex>'`: a chave crua, sem KDF (ela já é aleatória).
fn chave_em_texto(chave: &ChaveDoBanco) -> Zeroizing<String> {
    let mut texto = Zeroizing::new(String::with_capacity(TAMANHO_DA_CHAVE * 2 + 3));
    texto.push_str("x'");
    for byte in chave.expor() {
        let _ = write!(texto, "{byte:02x}");
    }
    texto.push('\'');
    texto
}

/// Uma conexão com a chave e as PRAGMAs, conferida antes de qualquer uso.
fn conectar(caminho: &Path, chave: &ChaveDoBanco) -> Result<Connection, FalhaDoBanco> {
    let mut inicio = [0u8; CABECALHO_EM_CLARO.len()];
    let lidos = File::open(caminho)?.read(&mut inicio)?;
    if lidos == inicio.len() && &inicio == CABECALHO_EM_CLARO {
        return Err(FalhaDoBanco::EmClaro);
    }
    let conexao = Connection::open(caminho)?;
    let pragma = Zeroizing::new(format!(
        "PRAGMA key = \"{}\";",
        chave_em_texto(chave).as_str()
    ));
    // O erro de uma PRAGMA com a chave podia citar o texto dela: some aqui.
    conexao
        .execute_batch(&pragma)
        .map_err(|_| FalhaDoBanco::ChaveOuArquivo)?;
    conexao.execute_batch(PRAGMAS)?;
    conexao
        .query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
        .map_err(|_| FalhaDoBanco::ChaveOuArquivo)?;
    Ok(conexao)
}

/// SHA-256 da versão do esquema, do esquema e de todas as linhas de todas as
/// tabelas, em ordem.
fn impressao_digital(conexao: &Connection) -> Result<[u8; 32], FalhaDoBanco> {
    let mut hash = Sha256::new();
    let versao: u32 = conexao.pragma_query_value(Some("main"), "user_version", |l| l.get(0))?;
    hash.update(versao.to_le_bytes());
    let tabelas: Vec<(String, String)> = conexao
        .prepare(
            "SELECT name, sql FROM main.sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?
        .query_map([], |l| Ok((l.get(0)?, l.get(1)?)))?
        .collect::<Result<_, _>>()?;
    for (nome, sql) in &tabelas {
        hash.update(sql.as_bytes());
        let colunas: i64 =
            conexao.query_row("SELECT count(*) FROM pragma_table_info(?1)", [nome], |l| {
                l.get(0)
            })?;
        let colunas = colunas as usize;
        let ordem: Vec<String> = (1..=colunas).map(|c| c.to_string()).collect();
        let mut consulta = conexao.prepare(&format!(
            "SELECT * FROM main.\"{nome}\" ORDER BY {}",
            ordem.join(", ")
        ))?;
        let mut linhas = consulta.query([])?;
        while let Some(linha) = linhas.next()? {
            for c in 0..colunas {
                match linha.get_ref(c)? {
                    ValueRef::Null => hash.update([0]),
                    ValueRef::Integer(i) => {
                        hash.update([1]);
                        hash.update(i.to_le_bytes());
                    }
                    ValueRef::Real(r) => {
                        hash.update([2]);
                        hash.update(r.to_le_bytes());
                    }
                    ValueRef::Text(t) => {
                        hash.update([3]);
                        hash.update((t.len() as u64).to_le_bytes());
                        hash.update(t);
                    }
                    ValueRef::Blob(b) => {
                        hash.update([4]);
                        hash.update((b.len() as u64).to_le_bytes());
                        hash.update(b);
                    }
                }
            }
        }
    }
    Ok(hash.finalize().into())
}
