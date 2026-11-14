//! A conexão com o agente. Uma por processo: é ela que carrega o login do
//! PIN pessoal desta aplicação.
//!
//! O agente atende um pedido de cada vez por conexão, e uma assinatura pode
//! esperar a pessoa digitar o OTP. Por isso a conexão tem a trava dela, à
//! parte da do módulo, e a listagem não espera por ela: com a conexão ocupada,
//! o módulo responde com o que já tinha.

use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use ipc::{Cliente, DaFace, DoAgente};

use crate::trava;

static CANAL: Mutex<Option<Cliente>> = Mutex::new(None);
/// Sobe a cada conexão nova com o agente. O login vale para a conexão em que
/// foi feito: uma conexão nova começa sem ele.
static GERACAO: AtomicU64 = AtomicU64::new(0);

pub fn geracao() -> u64 {
    GERACAO.load(Ordering::SeqCst)
}

/// A resposta do agente, e a geração da conexão que a deu.
pub type Resposta = io::Result<(DoAgente, u64)>;

/// Pergunta ao agente, esperando a conexão ficar livre.
pub fn pedir(pedido: &DaFace) -> Resposta {
    conversar(&mut trava(&CANAL), pedido)
}

/// Pergunta ao agente se a conexão estiver livre; `None` se estiver ocupada.
pub fn pedir_se_livre(pedido: &DaFace) -> Option<Resposta> {
    let mut canal = match CANAL.try_lock() {
        Ok(canal) => canal,
        Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return None,
    };
    Some(conversar(&mut canal, pedido))
}

/// Fecha a conexão: o login desta aplicação acaba junto.
pub fn fechar() {
    *trava(&CANAL) = None;
}

fn conversar(canal: &mut Option<Cliente>, pedido: &DaFace) -> Resposta {
    let nova = canal.is_none();
    let resposta = abrir(canal).and_then(|cliente| cliente.pedir(pedido));
    match resposta {
        Ok(resposta) => Ok((resposta, geracao())),
        // Uma conexão velha que caiu (o agente reiniciou) ganha uma segunda
        // chance numa nova. Numa nova que falhou, o agente não está lá.
        Err(_) if !nova => {
            *canal = None;
            let resposta = abrir(canal).and_then(|cliente| cliente.pedir(pedido));
            if resposta.is_err() {
                *canal = None;
            }
            resposta.map(|r| (r, geracao()))
        }
        Err(e) => {
            *canal = None;
            Err(e)
        }
    }
}

fn abrir(canal: &mut Option<Cliente>) -> io::Result<&mut Cliente> {
    if canal.is_none() {
        *canal = Some(Cliente::conectar()?);
        GERACAO.fetch_add(1, Ordering::SeqCst);
    }
    Ok(canal.as_mut().expect("aberto logo acima"))
}
