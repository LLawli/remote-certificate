//! O que o `configurar` deixa para as próximas partidas: só a série do token.
//!
//! Fica no diretório de estado do token (o diretório de trabalho do driver),
//! em claro, porque não é segredo. O PIN nunca vem para cá: ele é um fator
//! guardado, e o servidor o responde a cada assinatura.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const ARQUIVO: &str = "configuracao.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuracao {
    /// A série do token (`serialNumber` do `CK_TOKEN_INFO`), sem os espaços
    /// de preenchimento.
    pub serie: String,
}

pub struct Estado {
    diretorio: PathBuf,
}

impl Estado {
    pub fn em(diretorio: impl Into<PathBuf>) -> Self {
        Self {
            diretorio: diretorio.into(),
        }
    }

    fn caminho(&self) -> PathBuf {
        self.diretorio.join(ARQUIVO)
    }

    /// A configuração gravada, ou `None` se o token ainda não foi configurado.
    pub fn ler(&self) -> io::Result<Option<Configuracao>> {
        match fs::read(self.caminho()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Grava num arquivo novo e renomeia por cima: uma queda no meio deixa a
    /// configuração anterior inteira.
    pub fn gravar(&self, configuracao: &Configuracao) -> io::Result<()> {
        let novo = self.diretorio.join(format!("{ARQUIVO}.novo"));
        let json = serde_json::to_vec(configuracao).map_err(io::Error::other)?;
        fs::write(&novo, json)?;
        fs::rename(&novo, self.caminho())
    }

    pub fn diretorio(&self) -> &Path {
        &self.diretorio
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn diretorio_de_teste(nome: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gd-burti-estado-{nome}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sem_arquivo_nao_esta_configurado() {
        let dir = diretorio_de_teste("vazio");
        assert_eq!(Estado::em(&dir).ler().unwrap(), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn grava_e_le_so_a_serie() {
        let dir = diretorio_de_teste("serie");
        let estado = Estado::em(&dir);
        let configuracao = Configuracao {
            serie: "0011223344556677".into(),
        };
        estado.gravar(&configuracao).unwrap();
        assert_eq!(estado.ler().unwrap(), Some(configuracao));
        let gravado = fs::read_to_string(dir.join(ARQUIVO)).unwrap();
        assert_eq!(gravado, r#"{"serie":"0011223344556677"}"#);
        fs::remove_dir_all(dir).unwrap();
    }
}
