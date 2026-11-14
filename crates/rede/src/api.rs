//! A API HTTP para os sistemas integrados, sobre o mTLS de um dispositivo
//! pareado, como uma estação.
//!
//! Ler (as chaves, uma assinatura) não pede o PIN pessoal. Cada assinatura
//! pede, e uma assinatura pode levar um lote de documentos: o PIN confere uma
//! vez para o lote inteiro e não fica valendo para a próxima. A assinatura é um
//! recurso: o sistema cria, consulta, responde o fator que o token pedir (o
//! OTP) ou desiste.
//!
//! - `GET /v1/chaves`: as chaves de todos os tokens.
//! - `POST /v1/assinaturas`: [`PedidoDeAssinatura`]; `201` com a
//!   [`Assinatura`].
//! - `GET /v1/assinaturas/{id}?esperar=<segundos>`: a [`Assinatura`]. Com
//!   `esperar`, enquanto ela está `em_curso`, a resposta espera ela mudar, até
//!   [`ESPERA_MAXIMA`].
//! - `POST /v1/assinaturas/{id}/fatores`: [`Fatores`], a resposta ao
//!   `pedindo_fatores`.
//! - `POST /v1/assinaturas/{id}/desistir`: cancela o que falta do lote.
//!
//! Uma falha volta com o status HTTP e uma [`Falha`] no corpo.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use protocolo::{Mecanismo, Segredo};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::agente::{ChaveDoToken, Erro, FatorPedido, LIMITE_DA_MENSAGEM};
use crate::pareamento::{FalhaDoPareamento, conectar};
use crate::tls::{self, Fixacao, Identidade, Impressao};

pub const CHAVES: &str = "/v1/chaves";
pub const ASSINATURAS: &str = "/v1/assinaturas";
/// O maior corpo, de pedido ou de resposta: o lote inteiro cabe nele.
pub const LIMITE_DO_CORPO: usize = LIMITE_DA_MENSAGEM;
pub const DOCUMENTOS_POR_LOTE: usize = 1000;
/// O máximo que um `GET ?esperar=` segura a resposta.
pub const ESPERA_MAXIMA: Duration = Duration::from_secs(60);

pub fn caminho_da_assinatura(id: &str) -> String {
    format!("{ASSINATURAS}/{id}")
}

/// O corpo de `POST /v1/assinaturas`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PedidoDeAssinatura {
    /// O PIN pessoal: vale só para esta assinatura.
    pub pin: Segredo,
    pub token: String,
    pub chave: String,
    pub mecanismo: Mecanismo,
    /// O lote, de 1 a [`DOCUMENTOS_POR_LOTE`], na ordem em que as assinaturas
    /// voltam.
    #[serde(with = "protocolo::b64::lista")]
    pub documentos: Vec<Vec<u8>>,
}

/// Sem o PIN e sem os documentos.
impl fmt::Debug for PedidoDeAssinatura {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PedidoDeAssinatura")
            .field("token", &self.token)
            .field("chave", &self.chave)
            .field("mecanismo", &self.mecanismo)
            .field("documentos", &self.documentos.len())
            .finish_non_exhaustive()
    }
}

/// A resposta de `GET /v1/chaves`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chaves {
    pub chaves: Vec<ChaveDoToken>,
}

/// Uma assinatura (um lote) e onde ela está.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assinatura {
    pub id: String,
    #[serde(flatten)]
    pub estado: EstadoDaAssinatura,
    /// As assinaturas prontas, na ordem dos documentos. Com `falhou`, as que
    /// saíram antes da falha.
    #[serde(with = "protocolo::b64::lista")]
    pub assinaturas: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "estado", rename_all = "snake_case")]
pub enum EstadoDaAssinatura {
    EmCurso,
    /// O token pede estes fatores à pessoa; `recusa` diz por que pede de novo.
    PedindoFatores {
        fatores: Vec<FatorPedido>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recusa: Option<String>,
    },
    Concluida,
    Falhou {
        erro: Erro,
    },
}

/// O corpo de `POST /v1/assinaturas/{id}/fatores`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fatores {
    pub valores: BTreeMap<String, Segredo>,
}

/// O corpo de uma resposta de falha.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Falha {
    pub erro: Erro,
}

#[derive(Debug)]
pub enum FalhaDaApi {
    Conexao(FalhaDoPareamento),
    /// O servidor recusou a chave deste dispositivo: revogado, ou nunca
    /// pareado.
    Recusado,
    Http(String),
    /// O servidor respondeu com uma falha.
    Servidor {
        status: u16,
        erro: Erro,
    },
}

impl fmt::Display for FalhaDaApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalhaDaApi::Conexao(falha) => falha.fmt(f),
            FalhaDaApi::Recusado => f.write_str("o servidor não atende mais este dispositivo"),
            FalhaDaApi::Http(o_que) => write!(f, "resposta inesperada do servidor: {o_que}"),
            FalhaDaApi::Servidor { status, erro } => write!(f, "{status}: {}", erro.mensagem),
        }
    }
}

/// Um sistema integrado falando com o servidor, numa conexão só.
pub struct Cliente {
    envio: SendRequest<Full<Bytes>>,
    conversa: JoinHandle<Result<(), hyper::Error>>,
}

impl Cliente {
    /// Conecta ao servidor pareado em `endereco`, cuja chave tem a impressão
    /// `servidor`.
    pub async fn abrir(
        endereco: &str,
        identidade: &Identidade,
        servidor: Impressao,
    ) -> Result<Cliente, FalhaDaApi> {
        let conexao = conectar(endereco, identidade, Fixacao::Completa(servidor))
            .await
            .map_err(FalhaDaApi::Conexao)?;
        let (envio, conversa) = hyper::client::conn::http1::handshake(TokioIo::new(conexao))
            .await
            .map_err(do_hyper)?;
        Ok(Cliente {
            envio,
            conversa: tokio::spawn(conversa),
        })
    }

    pub async fn chaves(&mut self) -> Result<Vec<ChaveDoToken>, FalhaDaApi> {
        let Chaves { chaves } = self.pedir(Method::GET, CHAVES, None).await?;
        Ok(chaves)
    }

    pub async fn assinar(&mut self, pedido: &PedidoDeAssinatura) -> Result<Assinatura, FalhaDaApi> {
        let corpo = serde_json::to_vec(pedido).expect("pedido vira JSON");
        self.pedir(Method::POST, ASSINATURAS, Some(corpo)).await
    }

    /// Com `esperar`, segura enquanto a assinatura está `em_curso`.
    pub async fn consultar(
        &mut self,
        id: &str,
        esperar: Option<Duration>,
    ) -> Result<Assinatura, FalhaDaApi> {
        let mut caminho = caminho_da_assinatura(id);
        if let Some(espera) = esperar {
            caminho.push_str(&format!("?esperar={}", espera.as_secs()));
        }
        self.pedir(Method::GET, &caminho, None).await
    }

    pub async fn responder(
        &mut self,
        id: &str,
        valores: BTreeMap<String, Segredo>,
    ) -> Result<Assinatura, FalhaDaApi> {
        let corpo = serde_json::to_vec(&Fatores { valores }).expect("fatores viram JSON");
        let caminho = format!("{}/fatores", caminho_da_assinatura(id));
        self.pedir(Method::POST, &caminho, Some(corpo)).await
    }

    pub async fn desistir(&mut self, id: &str) -> Result<Assinatura, FalhaDaApi> {
        let caminho = format!("{}/desistir", caminho_da_assinatura(id));
        self.pedir(Method::POST, &caminho, None).await
    }

    async fn pedir<T: for<'de> Deserialize<'de>>(
        &mut self,
        metodo: Method,
        caminho: &str,
        corpo: Option<Vec<u8>>,
    ) -> Result<T, FalhaDaApi> {
        let mut pedido = Request::builder()
            .method(metodo)
            .uri(caminho)
            .header(HOST, "remote-certificate");
        if corpo.is_some() {
            pedido = pedido.header(CONTENT_TYPE, "application/json");
        }
        let pedido = pedido
            .body(Full::new(Bytes::from(corpo.unwrap_or_default())))
            .expect("pedido bem formado");
        let resposta = match self.envio.send_request(pedido).await {
            Ok(resposta) => resposta,
            Err(e) => {
                // A falha de verdade (o alerta do TLS) fica com a conversa.
                if self.conversa.is_finished()
                    && let Ok(Err(causa)) = (&mut self.conversa).await
                {
                    return Err(do_hyper(causa));
                }
                return Err(do_hyper(e));
            }
        };
        let status = resposta.status();
        let corpo = Limited::new(resposta.into_body(), LIMITE_DO_CORPO)
            .collect()
            .await
            .map_err(|e| FalhaDaApi::Http(e.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(match serde_json::from_slice::<Falha>(&corpo) {
                Ok(Falha { erro }) => FalhaDaApi::Servidor {
                    status: status.as_u16(),
                    erro,
                },
                Err(_) => FalhaDaApi::Http(status.to_string()),
            });
        }
        serde_json::from_slice(&corpo).map_err(|e| FalhaDaApi::Http(e.to_string()))
    }
}

fn do_hyper(e: hyper::Error) -> FalhaDaApi {
    if tls::recusaram_a_nossa_chave(&e) {
        FalhaDaApi::Recusado
    } else {
        FalhaDaApi::Http(e.to_string())
    }
}

/// O status HTTP de cada falha.
pub fn status_da_falha(tipo: crate::agente::TipoDeFalha) -> StatusCode {
    use crate::agente::TipoDeFalha as T;
    match tipo {
        T::PinErrado | T::NaoAutenticado => StatusCode::UNAUTHORIZED,
        T::Bloqueado => StatusCode::LOCKED,
        T::Ocupado => StatusCode::TOO_MANY_REQUESTS,
        T::PedidoInvalido => StatusCode::BAD_REQUEST,
        T::TokenDesconhecido | T::ChaveAusente | T::MecanismoNaoSuportado => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        T::TokenParado | T::Token => StatusCode::SERVICE_UNAVAILABLE,
        T::Cancelado => StatusCode::CONFLICT,
        T::Interno | T::Outro => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[cfg(test)]
mod testes {
    use super::*;
    use crate::agente::TipoDeFalha;

    #[test]
    fn o_pedido_nao_mostra_o_pin_nem_os_documentos() {
        let pedido = PedidoDeAssinatura {
            pin: Segredo::novo("2468".into()),
            token: "RemoteID".into(),
            chave: "k1".into(),
            mecanismo: Mecanismo::Sha256RsaPkcs,
            documentos: vec![b"procuracao".to_vec()],
        };
        let debug = format!("{pedido:?}");
        assert!(!debug.contains("2468"), "{debug}");
        assert!(!debug.contains("procuracao") && !debug.contains("112, 114"));
    }

    #[test]
    fn a_assinatura_tem_o_formato_da_api() {
        let pedido: PedidoDeAssinatura = serde_json::from_str(
            r#"{"pin":"2468","token":"RemoteID","chave":"k1",
                "mecanismo":"CKM_SHA256_RSA_PKCS","documentos":["AAEC","Aw=="]}"#,
        )
        .unwrap();
        assert_eq!(pedido.documentos, [vec![0, 1, 2], vec![3]]);

        let pedindo = Assinatura {
            id: "abc".into(),
            estado: EstadoDaAssinatura::PedindoFatores {
                fatores: vec![FatorPedido {
                    nome: "otp".into(),
                    rotulo: "Código".into(),
                }],
                recusa: None,
            },
            assinaturas: vec![vec![9]],
        };
        assert_eq!(
            serde_json::to_string(&pedindo).unwrap(),
            r#"{"id":"abc","estado":"pedindo_fatores","fatores":[{"nome":"otp","rotulo":"Código"}],"assinaturas":["CQ=="]}"#
        );
        let falhou = Assinatura {
            id: "abc".into(),
            estado: EstadoDaAssinatura::Falhou {
                erro: Erro {
                    tipo: TipoDeFalha::Cancelado,
                    mensagem: "desistiu".into(),
                    restantes: None,
                },
            },
            assinaturas: vec![],
        };
        let texto = serde_json::to_string(&falhou).unwrap();
        assert_eq!(
            texto,
            r#"{"id":"abc","estado":"falhou","erro":{"tipo":"cancelado","mensagem":"desistiu"},"assinaturas":[]}"#
        );
        assert_eq!(serde_json::from_str::<Assinatura>(&texto).unwrap(), falhou);
        assert!(
            serde_json::from_str::<PedidoDeAssinatura>(
                r#"{"pin":"1","token":"t","chave":"k","mecanismo":"CKM_RSA_PKCS","documentos":[],"extra":1}"#
            )
            .is_err(),
            "campo desconhecido é recusado"
        );
    }
}
