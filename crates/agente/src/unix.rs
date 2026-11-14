//! O IPC no Linux (e no macOS): um socket Unix num diretório `0700` do
//! usuário, que só atende processos do mesmo usuário.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use tokio::net::{UnixListener, UnixStream};

use crate::{Agente, face};

/// Atende as faces em `caminho` até o processo acabar.
pub async fn ouvir(agente: Arc<Agente>, caminho: &Path) -> io::Result<()> {
    let ouvinte = abrir(caminho).await?;
    let dono = rustix::process::getuid().as_raw();
    loop {
        let (conexao, _) = ouvinte.accept().await?;
        // Outro usuário nem chega a falar.
        if !conexao.peer_cred().is_ok_and(|c| c.uid() == dono) {
            continue;
        }
        tokio::spawn(face::atender(agente.clone(), conexao));
    }
}

/// O socket, num diretório só do usuário. Um socket velho, de um agente que
/// caiu, é trocado; um agente vivo no mesmo lugar é erro.
async fn abrir(caminho: &Path) -> io::Result<UnixListener> {
    if let Some(diretorio) = caminho.parent() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(diretorio)?;
        fs::set_permissions(diretorio, fs::Permissions::from_mode(0o700))?;
    }
    if caminho.exists() {
        if UnixStream::connect(caminho).await.is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("já há um agente atendendo em {}", caminho.display()),
            ));
        }
        fs::remove_file(caminho)?;
    }
    UnixListener::bind(caminho)
}
