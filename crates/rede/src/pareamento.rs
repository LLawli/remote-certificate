//! O pareamento: o administrador gera um código de uso único no servidor; com
//! ele, o cliente fixa a chave do servidor e o servidor guarda a do cliente.
//!
//! O código traz o começo da impressão da chave do servidor e um segredo. O
//! cliente só fala com um servidor cuja chave confere com o código, e o segredo
//! só vai por essa conexão: quem está no meio não se passa pelo servidor, e
//! ninguém precisa de outra criptografia além do TLS.

use std::fmt;
use std::io;
use std::sync::Arc;

use bytes::Bytes;
use data_encoding::BASE32_NOPAD;
use http_body_util::{BodyExt, Full, Limited};
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

use crate::codigo::{self, CodigoInvalido};
use crate::tls::{
    self, Fixacao, Identidade, Impressao, config_do_cliente, e_chave_recusada, nome_do_servidor,
};

pub const CAMINHO: &str = "/v1/pareamento";
/// O maior corpo de pedido ou resposta do pareamento.
pub const LIMITE_DO_CORPO: usize = 4096;

const PREFIXO: &str = "RP1";
const TAMANHO_DA_IMPRESSAO: usize = 16;
pub const TAMANHO_DO_SEGREDO: usize = 10;
const CONFERENCIA: usize = 2;

pub struct CodigoDePareamento {
    pub impressao: [u8; TAMANHO_DA_IMPRESSAO],
    pub segredo: Zeroizing<[u8; TAMANHO_DO_SEGREDO]>,
}

impl CodigoDePareamento {
    /// Um código novo para o servidor com esta impressão.
    pub fn novo(impressao: &Impressao) -> io::Result<CodigoDePareamento> {
        let mut segredo = Zeroizing::new([0u8; TAMANHO_DO_SEGREDO]);
        getrandom::fill(segredo.as_mut()).map_err(io::Error::from)?;
        Ok(CodigoDePareamento {
            impressao: impressao[..TAMANHO_DA_IMPRESSAO]
                .try_into()
                .expect("a impressão tem 32 bytes"),
            segredo,
        })
    }

    pub fn escrever(&self) -> Zeroizing<String> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            TAMANHO_DA_IMPRESSAO + TAMANHO_DO_SEGREDO,
        ));
        bytes.extend_from_slice(&self.impressao);
        bytes.extend_from_slice(self.segredo.as_ref());
        codigo::escrever(PREFIXO, &bytes, CONFERENCIA)
    }

    pub fn ler(digitado: &str) -> Result<CodigoDePareamento, CodigoInvalido> {
        let bytes = codigo::ler(
            PREFIXO,
            digitado,
            TAMANHO_DA_IMPRESSAO + TAMANHO_DO_SEGREDO,
            CONFERENCIA,
        )?;
        let (impressao, segredo) = bytes.split_at(TAMANHO_DA_IMPRESSAO);
        let mut guardado = Zeroizing::new([0u8; TAMANHO_DO_SEGREDO]);
        guardado.copy_from_slice(segredo);
        Ok(CodigoDePareamento {
            impressao: impressao.try_into().expect("tamanho conferido"),
            segredo: guardado,
        })
    }
}

/// O corpo de `POST /v1/pareamento`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PedidoDePareamento {
    /// O segredo do código, em Base32.
    pub segredo: String,
}

impl fmt::Debug for PedidoDePareamento {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PedidoDePareamento(***)")
    }
}

/// A resposta de um pareamento aceito (`201`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pareamento {
    pub dispositivo: i64,
}

/// O que o cliente guarda depois de parear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pareado {
    pub dispositivo: i64,
    /// A chave do servidor, fixada daqui em diante.
    pub servidor: Impressao,
}

#[derive(Debug)]
pub enum FalhaDoPareamento {
    Codigo(CodigoInvalido),
    /// A chave do servidor não é a do código: outro servidor, ou alguém no
    /// meio.
    ServidorDiferente,
    /// O servidor não está esperando pareamento, ou recusou o segredo (usado,
    /// vencido ou errado).
    Recusado,
    Conexao(io::Error),
    Tls(rustls::Error),
    Http(String),
}

impl fmt::Display for FalhaDoPareamento {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalhaDoPareamento::Codigo(CodigoInvalido::Formato) => {
                f.write_str("isso não é um código de pareamento")
            }
            FalhaDoPareamento::Codigo(CodigoInvalido::Conferencia) => {
                f.write_str("o código não confere: confira cada grupo")
            }
            FalhaDoPareamento::ServidorDiferente => {
                f.write_str("a chave do servidor não é a do código")
            }
            FalhaDoPareamento::Recusado => {
                f.write_str("o servidor recusou o código: peça outro ao administrador")
            }
            FalhaDoPareamento::Conexao(e) => write!(f, "sem conexão com o servidor: {e}"),
            FalhaDoPareamento::Tls(e) => e.fmt(f),
            FalhaDoPareamento::Http(o_que) => write!(f, "resposta inesperada do servidor: {o_que}"),
        }
    }
}

/// Uma conexão mTLS com o servidor em `endereco` (`host:porta`).
pub async fn conectar(
    endereco: &str,
    identidade: &Identidade,
    fixacao: Fixacao,
) -> Result<TlsStream<TcpStream>, FalhaDoPareamento> {
    let config = config_do_cliente(identidade, fixacao).map_err(FalhaDoPareamento::Tls)?;
    let tcp = TcpStream::connect(endereco)
        .await
        .map_err(FalhaDoPareamento::Conexao)?;
    TlsConnector::from(Arc::new(config))
        .connect(nome_do_servidor(), tcp)
        .await
        .map_err(|e| {
            if e_chave_recusada(&e) {
                FalhaDoPareamento::ServidorDiferente
            } else {
                FalhaDoPareamento::Conexao(e)
            }
        })
}

/// Pareia esta identidade com o servidor em `endereco`, com o código que o
/// administrador gerou.
pub async fn parear(
    endereco: &str,
    codigo: &str,
    identidade: &Identidade,
) -> Result<Pareado, FalhaDoPareamento> {
    let codigo = CodigoDePareamento::ler(codigo).map_err(FalhaDoPareamento::Codigo)?;
    let conexao = conectar(endereco, identidade, Fixacao::Pareamento(codigo.impressao)).await?;
    let servidor = conexao
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(|c| tls::chave_publica(c))
        .map(|c| tls::impressao(&c))
        .ok_or(FalhaDoPareamento::ServidorDiferente)?;

    let http = |e: hyper::Error| {
        if tls::recusaram_a_nossa_chave(&e) {
            FalhaDoPareamento::Recusado
        } else {
            FalhaDoPareamento::Http(e.to_string())
        }
    };
    let (mut envio, conversa) = hyper::client::conn::http1::handshake(TokioIo::new(conexao))
        .await
        .map_err(http)?;
    let conversa = tokio::spawn(conversa);
    let corpo = serde_json::to_vec(&PedidoDePareamento {
        segredo: BASE32_NOPAD.encode(codigo.segredo.as_ref()),
    })
    .expect("struct simples vira JSON");
    let pedido = Request::post(CAMINHO)
        .header(HOST, "remote-certificate")
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(corpo)))
        .expect("pedido bem formado");
    let resposta = match envio.send_request(pedido).await {
        Ok(resposta) => resposta,
        // A falha de verdade (o alerta do TLS) fica com a conversa.
        Err(e) => return Err(http(conversa.await.ok().and_then(Result::err).unwrap_or(e))),
    };
    match resposta.status() {
        StatusCode::CREATED => {}
        StatusCode::FORBIDDEN => return Err(FalhaDoPareamento::Recusado),
        outro => return Err(FalhaDoPareamento::Http(outro.to_string())),
    }
    let corpo = Limited::new(resposta.into_body(), LIMITE_DO_CORPO)
        .collect()
        .await
        .map_err(|e| FalhaDoPareamento::Http(e.to_string()))?
        .to_bytes();
    let Pareamento { dispositivo } =
        serde_json::from_slice(&corpo).map_err(|e| FalhaDoPareamento::Http(e.to_string()))?;
    Ok(Pareado {
        dispositivo,
        servidor,
    })
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_codigo_volta_com_a_impressao_e_o_segredo() {
        let impressao = [5u8; 32];
        let codigo = CodigoDePareamento::novo(&impressao).unwrap();
        let escrito = codigo.escrever();
        assert!(escrito.starts_with("RP1-"), "{}", escrito.as_str());
        let lido = CodigoDePareamento::ler(&escrito).unwrap();
        assert_eq!(lido.impressao, impressao[..16]);
        assert_eq!(*lido.segredo, *codigo.segredo);
        assert_ne!(
            *CodigoDePareamento::novo(&impressao).unwrap().segredo,
            *codigo.segredo
        );
    }
}
