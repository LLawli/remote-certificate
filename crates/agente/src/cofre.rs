//! O cofre da chave do dispositivo: a única parte do agente, além do IPC, que
//! depende do sistema operacional.
//!
//! No Linux (v1), um arquivo `0600` num diretório `0700`, como uma chave SSH.
//! A chave sozinha só lista os certificados e gasta as tentativas do PIN
//! pessoal, que bloqueiam o dispositivo. Um cofre em hardware (TPM) entra
//! atrás do mesmo trait.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rede::tls::{Identidade, Impressao};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Troca o diretório do cofre.
pub const ENV_DADOS: &str = "REMOTE_CERTIFICATE_DADOS";
const ARQUIVO: &str = "dispositivo.json";

/// O que o agente sabe depois de parear.
pub struct Pareamento {
    /// `host:porta` do servidor.
    pub endereco: String,
    /// A chave do servidor, fixada.
    pub servidor: Impressao,
    pub dispositivo: i64,
    pub identidade: Identidade,
}

pub trait Cofre {
    fn ler(&self) -> io::Result<Option<Pareamento>>;
    fn gravar(&self, pareamento: &Pareamento) -> io::Result<()>;
    /// Apaga o pareamento. Não existir não é erro.
    fn esquecer(&self) -> io::Result<()>;
}

/// O formato no disco.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoDisco {
    endereco: String,
    #[serde(with = "protocolo::b64")]
    servidor: Vec<u8>,
    dispositivo: i64,
    #[serde(with = "protocolo::b64")]
    certificado: Vec<u8>,
    /// A chave PKCS#8.
    #[serde(with = "protocolo::b64")]
    chave: Vec<u8>,
}

impl Drop for NoDisco {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.chave);
    }
}

pub struct CofreEmArquivo {
    diretorio: PathBuf,
}

impl CofreEmArquivo {
    pub fn em(diretorio: impl Into<PathBuf>) -> CofreEmArquivo {
        CofreEmArquivo {
            diretorio: diretorio.into(),
        }
    }

    /// [`ENV_DADOS`], ou `$XDG_DATA_HOME/remote-certificate`, ou
    /// `~/.local/share/remote-certificate`.
    pub fn padrao() -> io::Result<CofreEmArquivo> {
        if let Some(dir) = std::env::var_os(ENV_DADOS) {
            return Ok(CofreEmArquivo::em(dir));
        }
        let base = match std::env::var_os("XDG_DATA_HOME") {
            Some(dados) if !dados.is_empty() => PathBuf::from(dados),
            _ => std::env::var_os("HOME")
                .map(|casa| PathBuf::from(casa).join(".local/share"))
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "sem HOME"))?,
        };
        Ok(CofreEmArquivo::em(base.join("remote-certificate")))
    }

    pub fn arquivo(&self) -> PathBuf {
        self.diretorio.join(ARQUIVO)
    }
}

/// Recusa o que outro usuário pode ler ou trocar, como o ssh faz com uma
/// chave aberta demais.
fn so_do_dono(caminho: &Path, metadados: &fs::Metadata) -> io::Result<()> {
    let dono = rustix::process::getuid().as_raw();
    if metadados.uid() != dono || metadados.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} não pode ser legível por outros usuários (modo {:o})",
                caminho.display(),
                metadados.mode() & 0o777
            ),
        ));
    }
    Ok(())
}

fn invalido(o_que: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("cofre estragado: {o_que}"),
    )
}

impl Cofre for CofreEmArquivo {
    fn ler(&self) -> io::Result<Option<Pareamento>> {
        let arquivo = self.arquivo();
        let metadados = match fs::metadata(&arquivo) {
            Ok(metadados) => metadados,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        so_do_dono(&self.diretorio, &fs::metadata(&self.diretorio)?)?;
        so_do_dono(&arquivo, &metadados)?;
        let texto = Zeroizing::new(fs::read(&arquivo)?);
        let mut disco: NoDisco = serde_json::from_slice(&texto).map_err(|_| invalido("JSON"))?;
        let servidor = disco
            .servidor
            .as_slice()
            .try_into()
            .map_err(|_| invalido("impressão do servidor"))?;
        let chave = Zeroizing::new(std::mem::take(&mut disco.chave));
        let identidade = Identidade::de(std::mem::take(&mut disco.certificado), chave)
            .ok_or_else(|| invalido("certificado"))?;
        Ok(Some(Pareamento {
            endereco: std::mem::take(&mut disco.endereco),
            servidor,
            dispositivo: disco.dispositivo,
            identidade,
        }))
    }

    fn gravar(&self, pareamento: &Pareamento) -> io::Result<()> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.diretorio)?;
        // Um diretório que já existia pode ter nascido aberto.
        fs::set_permissions(&self.diretorio, fs::Permissions::from_mode(0o700))?;
        let disco = NoDisco {
            endereco: pareamento.endereco.clone(),
            servidor: pareamento.servidor.to_vec(),
            dispositivo: pareamento.dispositivo,
            certificado: pareamento.identidade.certificado().to_vec(),
            chave: pareamento.identidade.chave_pkcs8().to_vec(),
        };
        let texto = Zeroizing::new(serde_json::to_vec(&disco).map_err(io::Error::other)?);
        // Escrito ao lado e renomeado: uma queda no meio não deixa meio cofre.
        let provisorio = self.diretorio.join(format!(".{ARQUIVO}.novo"));
        let _ = fs::remove_file(&provisorio);
        let mut arquivo = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&provisorio)?;
        arquivo.write_all(&texto)?;
        arquivo.sync_all()?;
        fs::rename(&provisorio, self.arquivo())
    }

    fn esquecer(&self) -> io::Result<()> {
        match fs::remove_file(self.arquivo()) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            outro => outro,
        }
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    fn diretorio(nome: &str) -> PathBuf {
        let dir = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/testes"))
            .join(format!("cofre-{nome}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn pareamento() -> Pareamento {
        Pareamento {
            endereco: "10.0.0.5:8443".into(),
            servidor: [7; 32],
            dispositivo: 3,
            identidade: Identidade::gerar().unwrap(),
        }
    }

    #[test]
    fn grava_so_para_o_dono_e_le_de_volta() {
        let dir = diretorio("ida-e-volta");
        let cofre = CofreEmArquivo::em(&dir);
        assert!(cofre.ler().unwrap().is_none());
        let original = pareamento();
        cofre.gravar(&original).unwrap();

        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(cofre.arquivo()).unwrap().mode() & 0o777, 0o600);
        let lido = cofre.ler().unwrap().unwrap();
        assert_eq!(lido.endereco, original.endereco);
        assert_eq!(lido.servidor, original.servidor);
        assert_eq!(lido.dispositivo, 3);
        assert_eq!(lido.identidade.impressao(), original.identidade.impressao());

        cofre.esquecer().unwrap();
        assert!(cofre.ler().unwrap().is_none());
        cofre.esquecer().unwrap();
    }

    #[test]
    fn recusa_um_cofre_que_outros_podem_ler() {
        let dir = diretorio("aberto");
        let cofre = CofreEmArquivo::em(&dir);
        cofre.gravar(&pareamento()).unwrap();
        fs::set_permissions(cofre.arquivo(), fs::Permissions::from_mode(0o644)).unwrap();
        let falha = cofre.ler().err().expect("recusa o arquivo 0644");
        assert_eq!(falha.kind(), io::ErrorKind::PermissionDenied);

        fs::set_permissions(cofre.arquivo(), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let falha = cofre.ler().err().expect("recusa o diretório 0755");
        assert_eq!(falha.kind(), io::ErrorKind::PermissionDenied);

        // Gravar de novo fecha o diretório.
        cofre.gravar(&pareamento()).unwrap();
        assert!(cofre.ler().unwrap().is_some());
    }
}
