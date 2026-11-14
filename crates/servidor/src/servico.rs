//! O serviço na rede: mTLS 1.3 com as chaves pareadas e a API por cima.
//!
//! Uma chave desconhecida cai no handshake, antes de qualquer HTTP. A exceção
//! é enquanto há um pareamento pendente: aí uma chave nova entra, mas só
//! alcança `POST /v1/pareamento`.

use std::fmt;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{DefaultBodyLimit, Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use data_encoding::BASE32_NOPAD;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use protocolo::Segredo;
use rede::agente::{Erro, LIMITE_DA_MENSAGEM, TipoDeFalha};
use rede::pareamento::{
    self, CodigoDePareamento, LIMITE_DO_CORPO, Pareamento, PedidoDePareamento, TAMANHO_DO_SEGREDO,
};
use rede::tls::{self, Identidade, Porteiro, config_do_servidor};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

use crate::agente;
use crate::api::{self, Assinaturas};
use crate::banco::{
    Banco, FalhaDoBanco, IdDoDispositivo, IdDoUsuario, IdentidadeGuardada, Instante, travar,
};
use crate::pin::{self, Autenticado, FalhaDoPin};
use crate::tokens::{Evento, Tokens, erro};

/// Onde o container atende.
pub const ENDERECO_PADRAO: &str = "0.0.0.0:8443";
/// Quanto uma conexão tem para terminar o handshake.
const PRAZO_DO_HANDSHAKE: Duration = Duration::from_secs(10);
/// Quanto um código de pareamento vale depois de gerado.
pub const VALIDADE_DO_PAREAMENTO: Duration = Duration::from_secs(10 * 60);
/// A espera depois de um `accept` que falhou (sem descritores, por exemplo).
const PAUSA_DEPOIS_DE_FALHA: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub enum FalhaDoServico {
    Banco(FalhaDoBanco),
    /// A identidade guardada não é uma chave P-256 com certificado.
    IdentidadeInvalida,
    Tls(rustls::Error),
    Io(io::Error),
}

impl fmt::Display for FalhaDoServico {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalhaDoServico::Banco(falha) => falha.fmt(f),
            FalhaDoServico::IdentidadeInvalida => {
                f.write_str("a identidade do servidor no banco está estragada")
            }
            FalhaDoServico::Tls(e) => e.fmt(f),
            FalhaDoServico::Io(e) => e.fmt(f),
        }
    }
}

impl From<FalhaDoBanco> for FalhaDoServico {
    fn from(falha: FalhaDoBanco) -> FalhaDoServico {
        FalhaDoServico::Banco(falha)
    }
}

impl From<io::Error> for FalhaDoServico {
    fn from(e: io::Error) -> FalhaDoServico {
        FalhaDoServico::Io(e)
    }
}

pub fn agora() -> Instante {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as Instante)
}

/// A identidade do servidor: a guardada, ou uma nova na primeira vez.
pub fn identidade(banco: &Mutex<Banco>) -> Result<Identidade, FalhaDoServico> {
    let banco = travar(banco);
    if let Some(guardada) = banco.identidade()? {
        return Identidade::de(guardada.certificado, guardada.chave)
            .ok_or(FalhaDoServico::IdentidadeInvalida);
    }
    let nova = Identidade::gerar().map_err(|e| io::Error::other(e.to_string()))?;
    banco.gravar_identidade(&IdentidadeGuardada {
        certificado: nova.certificado().to_vec(),
        chave: Zeroizing::new(nova.chave_pkcs8().to_vec()),
    })?;
    Ok(nova)
}

/// Um código de pareamento de uso único para um dispositivo novo de
/// `usuario`, chamado `nome`, que vale por [`VALIDADE_DO_PAREAMENTO`].
pub fn novo_pareamento(
    banco: &Mutex<Banco>,
    usuario: IdDoUsuario,
    nome: &str,
) -> Result<Zeroizing<String>, FalhaDoServico> {
    let codigo = CodigoDePareamento::novo(&identidade(banco)?.impressao())?;
    let segredo: [u8; 32] = Sha256::digest(codigo.segredo.as_ref()).into();
    let expira = agora() + VALIDADE_DO_PAREAMENTO.as_secs() as Instante;
    travar(banco).criar_pareamento(&segredo, usuario, nome, expira)?;
    Ok(codigo.escrever())
}

struct PorteiroDoBanco(Arc<Mutex<Banco>>);

impl fmt::Debug for PorteiroDoBanco {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PorteiroDoBanco")
    }
}

impl Porteiro for PorteiroDoBanco {
    fn deixa_entrar(&self, chave_publica: &[u8]) -> bool {
        // Sem conseguir consultar, ninguém entra.
        travar(&self.0)
            .deixa_entrar(chave_publica, agora())
            .unwrap_or(false)
    }
}

/// Quantos eventos um agente lento pode deixar para trás.
const EVENTOS_NA_FILA: usize = 64;
/// Quantas conferências do PIN pessoal rodam ao mesmo tempo. Cada uma ocupa
/// 64 MiB e uns 106 ms de CPU (medido em 2026-11-14): 4 juntas ficam em
/// 256 MiB, e as outras esperam a vez.
const CONFERENCIAS_SIMULTANEAS: usize = 4;

pub const BLOQUEADO: &str = "dispositivo bloqueado; o administrador desbloqueia";

/// O que todas as conexões compartilham.
pub struct Estado {
    pub banco: Arc<Mutex<Banco>>,
    pub tokens: Tokens,
    pub eventos: broadcast::Sender<Evento>,
    assinaturas: Assinaturas,
    conferencias: Semaphore,
}

impl Estado {
    /// O estado com os tokens do banco, com os drivers em `drivers`.
    pub fn iniciar(
        banco: Arc<Mutex<Banco>>,
        drivers: &Path,
    ) -> Result<Arc<Estado>, FalhaDoServico> {
        let (eventos, _) = broadcast::channel(EVENTOS_NA_FILA);
        let tokens = Tokens::iniciar(&banco, drivers, &eventos)?;
        Ok(Arc::new(Estado {
            banco,
            tokens,
            eventos,
            assinaturas: Assinaturas::default(),
            conferencias: Semaphore::new(CONFERENCIAS_SIMULTANEAS),
        }))
    }

    pub(crate) fn assinaturas(&self) -> &Assinaturas {
        &self.assinaturas
    }

    /// Confere o PIN pessoal digitado em `dispositivo`, fora das threads do
    /// tokio. Quando o erro bloqueia o dispositivo, avisa os agentes dele.
    pub(crate) async fn conferir_pin(
        &self,
        dispositivo: IdDoDispositivo,
        pin: Segredo,
    ) -> Result<Autenticado, Erro> {
        let _vez = self
            .conferencias
            .acquire()
            .await
            .expect("o semáforo nunca fecha");
        let banco = self.banco.clone();
        let conferido =
            tokio::task::spawn_blocking(move || pin::conferir(&banco, dispositivo, &pin)).await;
        match conferido {
            Ok(Ok(autenticado)) => Ok(autenticado),
            Ok(Err(FalhaDoPin::Errado { restantes })) => Err(Erro {
                tipo: TipoDeFalha::PinErrado,
                mensagem: "PIN pessoal errado".into(),
                restantes: Some(restantes),
            }),
            Ok(Err(FalhaDoPin::Bloqueado)) => {
                let _ = self.eventos.send(Evento::DispositivoBloqueado(dispositivo));
                Err(erro(TipoDeFalha::Bloqueado, BLOQUEADO))
            }
            Ok(Err(_)) | Err(_) => Err(erro(TipoDeFalha::Interno, "falha no servidor")),
        }
    }
}

/// Quem está do outro lado de uma conexão que passou do handshake.
#[derive(Debug, Clone)]
pub(crate) enum Quem {
    Dispositivo(IdDoDispositivo),
    /// Uma chave nova, aceita porque há pareamento pendente.
    Pareando(Arc<Vec<u8>>),
}

/// Atende em `ouvinte` até o processo acabar.
pub async fn servir(ouvinte: TcpListener, estado: Arc<Estado>) -> Result<(), FalhaDoServico> {
    let banco = estado.banco.clone();
    let config = config_do_servidor(
        &identidade(&banco)?,
        Arc::new(PorteiroDoBanco(banco.clone())),
    )
    .map_err(FalhaDoServico::Tls)?;
    let aceitador = TlsAcceptor::from(Arc::new(config));
    let rotas = rotas(estado);
    loop {
        let Ok((tcp, _)) = ouvinte.accept().await else {
            tokio::time::sleep(PAUSA_DEPOIS_DE_FALHA).await;
            continue;
        };
        let aceitador = aceitador.clone();
        let rotas = rotas.clone();
        let banco = banco.clone();
        tokio::spawn(async move {
            let Ok(Ok(conexao)) =
                tokio::time::timeout(PRAZO_DO_HANDSHAKE, aceitador.accept(tcp)).await
            else {
                return;
            };
            let Some(chave) = conexao
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(|c| tls::chave_publica(c))
            else {
                return;
            };
            let quem = match travar(&banco).dispositivo_da_chave(&chave) {
                Ok(Some(dispositivo)) => Quem::Dispositivo(dispositivo),
                Ok(None) => Quem::Pareando(Arc::new(chave)),
                Err(_) => return,
            };
            let servico = TowerToHyperService::new(rotas.layer(Extension(quem)));
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(conexao), servico)
                .with_upgrades()
                .await;
        });
    }
}

fn rotas(estado: Arc<Estado>) -> Router {
    Router::new()
        .route(rede::agente::CAMINHO, get(conectar_agente))
        .route(pareamento::CAMINHO, post(parear))
        .route(rede::api::CHAVES, get(api::chaves))
        .route(
            rede::api::ASSINATURAS,
            post(api::criar).layer(DefaultBodyLimit::max(rede::api::LIMITE_DO_CORPO)),
        )
        .route("/v1/assinaturas/{id}", get(api::consultar))
        .route("/v1/assinaturas/{id}/fatores", post(api::responder))
        .route("/v1/assinaturas/{id}/desistir", post(api::desistir))
        .fallback(fora_das_rotas)
        .layer(DefaultBodyLimit::max(LIMITE_DO_CORPO))
        .with_state(estado)
}

async fn parear(
    State(estado): State<Arc<Estado>>,
    Extension(quem): Extension<Quem>,
    corpo: Bytes,
) -> Response {
    let Quem::Pareando(chave) = quem else {
        return StatusCode::CONFLICT.into_response();
    };
    let Ok(PedidoDePareamento { segredo }) = serde_json::from_slice(&corpo) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(segredo) = BASE32_NOPAD
        .decode(segredo.as_bytes())
        .ok()
        .map(Zeroizing::new)
        .filter(|s| s.len() == TAMANHO_DO_SEGREDO)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let segredo: [u8; 32] = Sha256::digest(segredo.as_slice()).into();
    match travar(&estado.banco).usar_pareamento(&segredo, &chave, agora()) {
        Ok(Some(dispositivo)) => (
            StatusCode::CREATED,
            Json(Pareamento {
                dispositivo: dispositivo.0,
            }),
        )
            .into_response(),
        Ok(None) => StatusCode::FORBIDDEN.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Uma chave em pareamento só alcança o pareamento.
async fn fora_das_rotas(Extension(quem): Extension<Quem>) -> StatusCode {
    match quem {
        Quem::Pareando(_) => StatusCode::FORBIDDEN,
        Quem::Dispositivo(_) => StatusCode::NOT_FOUND,
    }
}

async fn conectar_agente(
    State(estado): State<Arc<Estado>>,
    Extension(quem): Extension<Quem>,
    ws: WebSocketUpgrade,
) -> Response {
    let Quem::Dispositivo(dispositivo) = quem else {
        return StatusCode::FORBIDDEN.into_response();
    };
    ws.max_message_size(LIMITE_DA_MENSAGEM)
        .max_frame_size(LIMITE_DA_MENSAGEM)
        .on_upgrade(move |socket| agente::atender(socket, dispositivo, estado))
}
