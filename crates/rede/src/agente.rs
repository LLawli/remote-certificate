//! A conversa do agente da estação com o servidor: um WebSocket em
//! `/v1/agente`, sobre o mTLS de um dispositivo pareado, com uma mensagem JSON
//! por quadro de texto.
//!
//! O agente entra com o PIN pessoal, lista as chaves e assina. No meio de uma
//! assinatura o servidor pode pedir um fator da pessoa (o OTP), e o agente
//! responde com o mesmo `id`. Uma operação por conexão de cada vez. O servidor
//! também avisa, sem ser perguntado, o que mudou.

use std::collections::BTreeMap;
use std::fmt;

use futures_util::{SinkExt, StreamExt};
use protocolo::{Chave, Mecanismo, Segredo};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::pareamento::{FalhaDoPareamento, conectar};
use crate::tls::{self, Fixacao, Identidade, Impressao};

pub const CAMINHO: &str = "/v1/agente";
/// A maior mensagem, nos dois sentidos. Cabe o documento que um assinador
/// manda para o token resumir.
pub const LIMITE_DA_MENSAGEM: usize = 4 * 1024 * 1024;

/// O que o agente manda.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "snake_case", deny_unknown_fields)]
pub enum DoAgente {
    /// O PIN pessoal: abre a sessão para assinar.
    Entrar {
        id: u64,
        pin: Segredo,
    },
    Listar {
        id: u64,
    },
    Assinar {
        id: u64,
        token: String,
        chave: String,
        mecanismo: Mecanismo,
        #[serde(with = "protocolo::b64")]
        dados: Vec<u8>,
    },
    /// A resposta a um `pedido_de_fatores`.
    Fatores {
        id: u64,
        valores: BTreeMap<String, Segredo>,
    },
    /// A pessoa não quis responder o `pedido_de_fatores`.
    Desistir {
        id: u64,
    },
    /// Fecha a sessão aberta pelo PIN.
    Sair {
        id: u64,
    },
}

/// O que o servidor manda.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "snake_case", deny_unknown_fields)]
pub enum DoServidor {
    Entrou {
        id: u64,
    },
    Chaves {
        id: u64,
        chaves: Vec<ChaveDoToken>,
    },
    /// O token pede estes fatores à pessoa; `recusa` diz por que pede de novo.
    PedidoDeFatores {
        id: u64,
        fatores: Vec<FatorPedido>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recusa: Option<String>,
    },
    Assinatura {
        id: u64,
        #[serde(with = "protocolo::b64")]
        assinatura: Vec<u8>,
    },
    Saiu {
        id: u64,
    },
    /// `id` vazio quando a mensagem nem chegou a ser entendida.
    Falha {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<u64>,
        erro: Erro,
    },
    Aviso {
        aviso: Aviso,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaveDoToken {
    /// O token no servidor: vai no `assinar`.
    pub token: String,
    #[serde(flatten)]
    pub chave: Chave,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatorPedido {
    pub nome: String,
    /// Para a pessoa ler.
    pub rotulo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Erro {
    pub tipo: TipoDeFalha,
    /// Para a pessoa ler.
    pub mensagem: String,
    /// Com `pin_errado`: quantas tentativas faltam até bloquear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restantes: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipoDeFalha {
    PinErrado,
    /// O dispositivo está bloqueado até o administrador desbloquear.
    Bloqueado,
    /// Falta o `entrar`, ou a sessão venceu.
    NaoAutenticado,
    TokenDesconhecido,
    /// O token recusou um fator guardado e espera o administrador.
    TokenParado,
    ChaveAusente,
    MecanismoNaoSuportado,
    Cancelado,
    /// Já há uma operação em curso nesta conexão.
    Ocupado,
    PedidoInvalido,
    /// O token ou o driver falhou.
    Token,
    Interno,
    #[serde(other)]
    Outro,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "snake_case")]
pub enum Aviso {
    DispositivoBloqueado,
    TokenParado { token: String },
}

#[derive(Debug)]
pub enum FalhaDoAgente {
    Conexao(FalhaDoPareamento),
    /// O servidor recusou a chave deste dispositivo: revogado, ou nunca
    /// pareado.
    Recusado,
    WebSocket(String),
    /// O servidor mandou algo fora do protocolo.
    Protocolo(String),
    Fechada,
}

impl fmt::Display for FalhaDoAgente {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalhaDoAgente::Conexao(falha) => falha.fmt(f),
            FalhaDoAgente::Recusado => f.write_str("o servidor não atende mais este dispositivo"),
            FalhaDoAgente::WebSocket(e) => write!(f, "WebSocket: {e}"),
            FalhaDoAgente::Protocolo(e) => write!(f, "o servidor saiu do protocolo: {e}"),
            FalhaDoAgente::Fechada => f.write_str("o servidor fechou a conexão"),
        }
    }
}

fn do_websocket(e: tokio_tungstenite::tungstenite::Error) -> FalhaDoAgente {
    if tls::recusaram_a_nossa_chave(&e) {
        FalhaDoAgente::Recusado
    } else {
        FalhaDoAgente::WebSocket(e.to_string())
    }
}

pub fn configuracao_do_websocket() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(LIMITE_DA_MENSAGEM))
        .max_frame_size(Some(LIMITE_DA_MENSAGEM))
}

/// A conexão do agente com o servidor.
pub struct Conexao {
    ws: WebSocketStream<TlsStream<TcpStream>>,
}

impl Conexao {
    /// Conecta ao servidor pareado em `endereco`, cuja chave tem a impressão
    /// `servidor`.
    pub async fn abrir(
        endereco: &str,
        identidade: &Identidade,
        servidor: Impressao,
    ) -> Result<Conexao, FalhaDoAgente> {
        let conexao = conectar(endereco, identidade, Fixacao::Completa(servidor))
            .await
            .map_err(FalhaDoAgente::Conexao)?;
        let (ws, _) = tokio_tungstenite::client_async_with_config(
            format!("wss://remote-certificate{CAMINHO}"),
            conexao,
            Some(configuracao_do_websocket()),
        )
        .await
        .map_err(do_websocket)?;
        Ok(Conexao { ws })
    }

    pub async fn enviar(&mut self, mensagem: &DoAgente) -> Result<(), FalhaDoAgente> {
        let texto = serde_json::to_string(mensagem).expect("mensagem vira JSON");
        self.ws
            .send(Message::text(texto))
            .await
            .map_err(do_websocket)
    }

    /// A próxima mensagem do servidor.
    pub async fn receber(&mut self) -> Result<DoServidor, FalhaDoAgente> {
        loop {
            match self.ws.next().await {
                Some(Ok(Message::Text(texto))) => {
                    return serde_json::from_str(&texto)
                        .map_err(|e| FalhaDoAgente::Protocolo(e.to_string()));
                }
                Some(Ok(Message::Close(_))) | None => return Err(FalhaDoAgente::Fechada),
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(do_websocket(e)),
            }
        }
    }
}

#[cfg(test)]
mod testes {
    use super::*;

    #[test]
    fn o_pin_nao_aparece_em_debug() {
        let entrar = DoAgente::Entrar {
            id: 1,
            pin: Segredo::novo("2468".into()),
        };
        assert!(!format!("{entrar:?}").contains("2468"));
    }

    #[test]
    fn as_mensagens_tem_o_formato_do_protocolo() {
        let assinar: DoAgente = serde_json::from_str(
            r#"{"tipo":"assinar","id":7,"token":"RemoteID","chave":"k1",
                "mecanismo":"CKM_SHA256_RSA_PKCS","dados":"AAEC"}"#,
        )
        .unwrap();
        assert!(matches!(
            assinar,
            DoAgente::Assinar { id: 7, ref dados, .. } if dados == &[0, 1, 2]
        ));
        let falha = DoServidor::Falha {
            id: Some(3),
            erro: Erro {
                tipo: TipoDeFalha::PinErrado,
                mensagem: "PIN errado".into(),
                restantes: Some(2),
            },
        };
        assert_eq!(
            serde_json::to_string(&falha).unwrap(),
            r#"{"tipo":"falha","id":3,"erro":{"tipo":"pin_errado","mensagem":"PIN errado","restantes":2}}"#
        );
        assert!(
            serde_json::from_str::<DoAgente>(r#"{"tipo":"listar","id":1,"extra":true}"#).is_err(),
            "campo desconhecido é recusado"
        );
    }
}
