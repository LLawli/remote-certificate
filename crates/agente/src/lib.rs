//! O agente da estação: guarda a chave do dispositivo, fala com o servidor
//! pelo WebSocket de `/v1/agente` e atende as faces (o módulo PKCS#11 no
//! Linux) pelo IPC (`ipc`). O desenho está em `docs/arquitetura.md`.
//!
//! O que depende do sistema operacional fica no [`cofre`], no IPC
//! ([`unix`]) e no programa da janela do OTP ([`dialogo`]). O resto
//! ([`face`]) é igual em qualquer sistema.

pub mod cofre;
pub mod dialogo;
pub mod face;
#[cfg(unix)]
pub mod unix;

use std::sync::Arc;

use cofre::Pareamento;
use dialogo::Dialogo;
use rede::pareamento::{FalhaDoPareamento, parear};
use rede::tls::Identidade;

pub struct Agente {
    pub pareamento: Pareamento,
    pub dialogo: Arc<dyn Dialogo>,
}

impl Agente {
    pub fn novo(pareamento: Pareamento, dialogo: Arc<dyn Dialogo>) -> Arc<Agente> {
        Arc::new(Agente {
            pareamento,
            dialogo,
        })
    }
}

/// Gera a chave deste dispositivo e a pareia com o servidor em `endereco`,
/// com o código que o administrador gerou.
pub async fn novo_pareamento(
    endereco: &str,
    codigo: &str,
) -> Result<Pareamento, FalhaDoPareamento> {
    let identidade = Identidade::gerar()
        .map_err(|e| FalhaDoPareamento::Conexao(std::io::Error::other(e.to_string())))?;
    let pareado = parear(endereco, codigo, &identidade).await?;
    Ok(Pareamento {
        endereco: endereco.to_string(),
        servidor: pareado.servidor,
        dispositivo: pareado.dispositivo,
        identidade,
    })
}
