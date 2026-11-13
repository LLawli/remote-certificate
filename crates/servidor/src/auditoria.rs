//! A auditoria: um registro só de acréscimo de cada assinatura, de cada
//! tentativa de PIN pessoal e de cada mudança em quem pode assinar.
//!
//! O banco recusa alterar ou apagar uma linha (gatilhos da migração). Cada
//! linha leva um selo, o SHA-256 do selo anterior e dos campos dela: mexer numa
//! linha por fora quebra a corrente dali em diante, e o selo da última linha,
//! anotado fora da máquina, prova que nada antes dele mudou. PIN, OTP, senha e
//! o que foi assinado nunca entram: dos dados, só o SHA-256.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

use crate::banco::FalhaDoBanco;

/// O selo antes da primeira linha.
const SELO_INICIAL: [u8; 32] = [0; 32];

/// Uma linha nova da auditoria.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lancamento {
    pub evento: &'static str,
    pub usuario: Option<i64>,
    pub dispositivo: Option<i64>,
    pub token: Option<String>,
    pub chave: Option<String>,
    pub mecanismo: Option<String>,
    /// O SHA-256 do que foi assinado.
    pub resumo: Option<[u8; 32]>,
    pub resultado: String,
}

/// Uma linha gravada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linha {
    pub id: i64,
    /// Milissegundos desde 1970, em UTC.
    pub quando_ms: i64,
    pub evento: String,
    pub usuario: Option<String>,
    pub dispositivo: Option<i64>,
    pub token: Option<String>,
    pub chave: Option<String>,
    pub mecanismo: Option<String>,
    pub resumo: Option<Vec<u8>>,
    pub resultado: String,
    pub selo: Vec<u8>,
}

/// O que `verificar` encontrou.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verificacao {
    /// A corrente fecha: quantas linhas e o selo da última.
    Integra { linhas: u64, ultimo_selo: [u8; 32] },
    /// A primeira linha cujo selo não confere.
    Quebrada { id: i64 },
}

/// Acrescenta a linha. Chamado dentro da transação da mudança que ela
/// registra, que tem de ser `IMMEDIATE`: o selo anterior não muda entre a
/// leitura e a escrita.
pub(crate) fn acrescentar(
    conexao: &Connection,
    lancamento: &Lancamento,
) -> Result<(), FalhaDoBanco> {
    let anterior: Option<(i64, Vec<u8>)> = conexao
        .query_row(
            "SELECT id, selo FROM auditoria ORDER BY id DESC LIMIT 1",
            [],
            |l| Ok((l.get(0)?, l.get(1)?)),
        )
        .optional()?;
    let (id, anterior) = match anterior {
        Some((id, selo)) => (id + 1, selo),
        None => (1, SELO_INICIAL.to_vec()),
    };
    let quando_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64);
    let resumo = lancamento.resumo.map(|r| r.to_vec());
    let selo = selar(
        &anterior,
        id,
        quando_ms,
        lancamento.evento,
        lancamento.usuario,
        lancamento.dispositivo,
        lancamento.token.as_deref(),
        lancamento.chave.as_deref(),
        lancamento.mecanismo.as_deref(),
        resumo.as_deref(),
        &lancamento.resultado,
    );
    conexao.execute(
        "INSERT INTO auditoria (id, quando_ms, evento, usuario, dispositivo, token, chave,
             mecanismo, resumo, resultado, selo)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            id,
            quando_ms,
            lancamento.evento,
            lancamento.usuario,
            lancamento.dispositivo,
            lancamento.token,
            lancamento.chave,
            lancamento.mecanismo,
            resumo,
            lancamento.resultado,
            selo.as_slice(),
        ],
    )?;
    Ok(())
}

/// As últimas `quantas` linhas, da mais antiga para a mais nova.
pub(crate) fn ultimas(conexao: &Connection, quantas: u32) -> Result<Vec<Linha>, FalhaDoBanco> {
    let mut consulta = conexao.prepare(
        "SELECT * FROM (
             SELECT a.id, a.quando_ms, a.evento, u.nome, a.dispositivo, a.token, a.chave,
                 a.mecanismo, a.resumo, a.resultado, a.selo
             FROM auditoria a LEFT JOIN usuario u ON u.id = a.usuario
             ORDER BY a.id DESC LIMIT ?1
         ) ORDER BY id",
    )?;
    let linhas = consulta.query_map([quantas], |l| {
        Ok(Linha {
            id: l.get(0)?,
            quando_ms: l.get(1)?,
            evento: l.get(2)?,
            usuario: l.get(3)?,
            dispositivo: l.get(4)?,
            token: l.get(5)?,
            chave: l.get(6)?,
            mecanismo: l.get(7)?,
            resumo: l.get(8)?,
            resultado: l.get(9)?,
            selo: l.get(10)?,
        })
    })?;
    Ok(linhas.collect::<Result<_, _>>()?)
}

/// Refaz a corrente de selos desde a primeira linha.
pub(crate) fn verificar(conexao: &Connection) -> Result<Verificacao, FalhaDoBanco> {
    let mut consulta = conexao.prepare(
        "SELECT id, quando_ms, evento, usuario, dispositivo, token, chave, mecanismo, resumo,
             resultado, selo
         FROM auditoria ORDER BY id",
    )?;
    let mut linhas = consulta.query([])?;
    let mut anterior = SELO_INICIAL;
    let mut esperado = 1;
    let mut contadas = 0;
    while let Some(l) = linhas.next()? {
        let id: i64 = l.get(0)?;
        let resumo: Option<Vec<u8>> = l.get(8)?;
        let selo: Vec<u8> = l.get(10)?;
        let refeito = selar(
            &anterior,
            id,
            l.get(1)?,
            &l.get::<_, String>(2)?,
            l.get(3)?,
            l.get(4)?,
            l.get::<_, Option<String>>(5)?.as_deref(),
            l.get::<_, Option<String>>(6)?.as_deref(),
            l.get::<_, Option<String>>(7)?.as_deref(),
            resumo.as_deref(),
            &l.get::<_, String>(9)?,
        );
        // Uma linha a menos no meio também quebra: o id é o seguinte.
        if id != esperado || selo != refeito {
            return Ok(Verificacao::Quebrada { id });
        }
        anterior = refeito;
        esperado += 1;
        contadas += 1;
    }
    Ok(Verificacao::Integra {
        linhas: contadas,
        ultimo_selo: anterior,
    })
}

/// SHA-256 do selo anterior e de cada campo, com tipo e tamanho, para que
/// dois conjuntos de campos diferentes nunca deem a mesma sequência de bytes.
#[allow(clippy::too_many_arguments)]
fn selar(
    anterior: &[u8],
    id: i64,
    quando_ms: i64,
    evento: &str,
    usuario: Option<i64>,
    dispositivo: Option<i64>,
    token: Option<&str>,
    chave: Option<&str>,
    mecanismo: Option<&str>,
    resumo: Option<&[u8]>,
    resultado: &str,
) -> [u8; 32] {
    fn numero(hash: &mut Sha256, valor: Option<i64>) {
        match valor {
            None => hash.update([0]),
            Some(v) => {
                hash.update([1]);
                hash.update(v.to_le_bytes());
            }
        }
    }
    fn bytes(hash: &mut Sha256, valor: Option<&[u8]>) {
        match valor {
            None => hash.update([0]),
            Some(b) => {
                hash.update([1]);
                hash.update((b.len() as u64).to_le_bytes());
                hash.update(b);
            }
        }
    }
    let mut hash = Sha256::new();
    hash.update(anterior);
    numero(&mut hash, Some(id));
    numero(&mut hash, Some(quando_ms));
    bytes(&mut hash, Some(evento.as_bytes()));
    numero(&mut hash, usuario);
    numero(&mut hash, dispositivo);
    bytes(&mut hash, token.map(str::as_bytes));
    bytes(&mut hash, chave.map(str::as_bytes));
    bytes(&mut hash, mecanismo.map(str::as_bytes));
    bytes(&mut hash, resumo);
    bytes(&mut hash, Some(resultado.as_bytes()));
    hash.finalize().into()
}
