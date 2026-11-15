//! Como o servidor sobe o driver de um token: o executável na pasta dos
//! drivers, no diretório de estado do token e, no serviço, pelo lançador que o
//! isola (`remote-certificate isolar`, em [`crate::isolar`]).

use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::Command;

use crate::banco::RegistroDoToken;

/// Onde a imagem derivada de cada driver o instala.
pub const DRIVERS_PADRAO: &str = "/drivers";

/// Onde fica o diretório de estado de cada token, no volume dos dados.
pub const ESTADOS_PADRAO: &str = "/dados/drivers";

#[derive(Debug, Clone)]
pub struct Lancador {
    drivers: PathBuf,
    estados: PathBuf,
    /// O executável com o `isolar`; sem ele, o driver sobe sem restrição.
    isolador: Option<PathBuf>,
}

impl Lancador {
    /// Sem isolamento: o driver roda com o que o servidor pode.
    pub fn novo(drivers: impl Into<PathBuf>, estados: impl Into<PathBuf>) -> Lancador {
        Lancador {
            drivers: drivers.into(),
            estados: estados.into(),
            isolador: None,
        }
    }

    /// Cada driver passa pelo `isolar` de `executavel` (o próprio
    /// `remote-certificate`).
    pub fn isolado(self, executavel: impl Into<PathBuf>) -> Lancador {
        Lancador {
            isolador: Some(executavel.into()),
            ..self
        }
    }

    /// O diretório de estado do token: só dele, e o único em que o driver
    /// isolado escreve. Fica entre as partidas.
    pub fn estado(&self, registro: &RegistroDoToken) -> PathBuf {
        self.estados.join(registro.id.to_string())
    }

    /// O comando que sobe o driver do token, com o diretório de estado já
    /// criado (`0700`) e como diretório de trabalho.
    pub fn comando(&self, registro: &RegistroDoToken) -> io::Result<Command> {
        let estado = self.estado(registro);
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&estado)?;
        let driver = self.drivers.join(&registro.driver);
        let mut comando = match &self.isolador {
            Some(isolador) => {
                let mut comando = Command::new(isolador);
                comando.arg("isolar").arg("--").arg(&driver);
                comando
            }
            None => Command::new(&driver),
        };
        comando.args(&registro.argumentos).current_dir(&estado);
        Ok(comando)
    }
}
