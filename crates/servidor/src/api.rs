//! A API HTTP para os sistemas integrados (o protocolo está em `rede::api`).
//!
//! Cada assinatura é um recurso em memória, visível só para o dispositivo que
//! a criou. O PIN pessoal confere uma vez por assinatura, para o lote inteiro;
//! a thread do token assina um documento de cada vez e, quando o token pede um
//! fator da pessoa, a assinatura fica `pedindo_fatores` até o sistema
//! responder. Terminada, ela continua consultável por [`PRAZO_DO_RESULTADO`].
//! Depois de o servidor reiniciar, nenhuma volta: o resultado de cada
//! documento fica na auditoria.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::LOCATION;
use axum::response::{IntoResponse, Json, Response};
use data_encoding::HEXLOWER;
use protocolo::{Fator, Mecanismo, Segredo};
use rede::agente::{Erro, FatorPedido, TipoDeFalha};
use rede::api::{
    Assinatura, Chaves, DOCUMENTOS_POR_LOTE, ESPERA_MAXIMA, EstadoDaAssinatura, Falha, Fatores,
    PedidoDeAssinatura, caminho_da_assinatura, status_da_falha,
};
use serde::Deserialize;
use tokio::sync::watch;

use crate::agente::PRAZO_DA_PESSOA;
use crate::banco::{IdDoDispositivo, Situacao, travar};
use crate::fatores::Pessoa;
use crate::pin::{Autenticado, ERROS_PARA_BLOQUEAR};
use crate::servico::{BLOQUEADO, Estado, Quem};
use crate::tokens::erro;

/// Quanto uma assinatura terminada continua consultável.
pub const PRAZO_DO_RESULTADO: Duration = Duration::from_secs(10 * 60);
/// Quantas assinaturas em curso um dispositivo pode ter ao mesmo tempo.
pub const EM_CURSO_POR_DISPOSITIVO: usize = 4;
/// Quantas assinaturas, em curso ou terminadas, ficam guardadas de um
/// dispositivo. Passando disso, a terminada mais antiga sai.
pub const GUARDADAS_POR_DISPOSITIVO: usize = 64;
/// Bytes aleatórios no identificador de uma assinatura.
const TAMANHO_DO_ID: usize = 16;

/// A resposta da pessoa ao pedido de fatores; `None` é desistir.
type Resposta = Option<BTreeMap<String, Segredo>>;

/// Uma assinatura, compartilhada entre a API e a thread do token.
struct Operacao {
    dispositivo: IdDoDispositivo,
    visao: watch::Sender<Assinatura>,
    respostas: mpsc::Sender<Resposta>,
    recebidas: Mutex<mpsc::Receiver<Resposta>>,
    desistiu: AtomicBool,
    /// Quando terminou.
    fim: Mutex<Option<Instant>>,
}

impl Operacao {
    fn nova(dispositivo: IdDoDispositivo, id: String) -> Operacao {
        let (respostas, recebidas) = mpsc::channel();
        let (visao, _) = watch::channel(Assinatura {
            id,
            estado: EstadoDaAssinatura::EmCurso,
            assinaturas: Vec::new(),
        });
        Operacao {
            dispositivo,
            visao,
            respostas,
            recebidas: Mutex::new(recebidas),
            desistiu: AtomicBool::new(false),
            fim: Mutex::new(None),
        }
    }

    fn fim(&self) -> Option<Instant> {
        *self.fim.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn agora(&self) -> Assinatura {
        self.visao.borrow().clone()
    }

    /// Entrega a resposta ao pedido de fatores em aberto. Sem pedido em aberto,
    /// não entrega nada.
    fn responder(&self, resposta: Resposta) -> bool {
        let mut entregue = false;
        // Trocar o estado e entregar a resposta juntos: a thread do token não
        // abre um pedido novo no meio.
        self.visao.send_if_modified(|visao| {
            if !matches!(visao.estado, EstadoDaAssinatura::PedindoFatores { .. }) {
                return false;
            }
            entregue = self.respostas.send(resposta).is_ok();
            visao.estado = EstadoDaAssinatura::EmCurso;
            true
        });
        entregue
    }

    /// O documento que está no token termina; os seguintes não começam.
    fn desistir(&self) {
        self.desistiu.store(true, Ordering::SeqCst);
        self.responder(None);
    }

    fn desistiu(&self) -> bool {
        self.desistiu.load(Ordering::SeqCst)
    }
}

/// O sistema do outro lado da API, visto da thread do token.
struct PessoaDaApi(Arc<Operacao>);

impl Pessoa for PessoaDaApi {
    fn pedir(&mut self, fatores: &[&Fator], recusa: Option<&str>) -> Resposta {
        let operacao = &self.0;
        let recebidas = operacao.recebidas.lock().unwrap_or_else(|e| e.into_inner());
        // Uma resposta repetida a um pedido anterior não vale para este.
        while recebidas.try_recv().is_ok() {}
        let fatores = fatores
            .iter()
            .map(|f| FatorPedido {
                nome: f.nome.clone(),
                rotulo: f.rotulo.clone(),
            })
            .collect();
        operacao.visao.send_modify(|visao| {
            visao.estado = EstadoDaAssinatura::PedindoFatores {
                fatores,
                recusa: recusa.map(str::to_string),
            };
        });
        // Conferido depois de abrir o pedido: uma desistência que chegou antes
        // não o viu aberto.
        let resposta = if operacao.desistiu() {
            None
        } else {
            // Prazo vencido ou desistência: a operação cancela.
            recebidas.recv_timeout(PRAZO_DA_PESSOA).ok().flatten()
        };
        operacao.visao.send_if_modified(|visao| {
            let aberto = matches!(visao.estado, EstadoDaAssinatura::PedindoFatores { .. });
            if aberto {
                visao.estado = EstadoDaAssinatura::EmCurso;
            }
            aberto
        });
        resposta
    }
}

/// As assinaturas da API, de todos os dispositivos.
#[derive(Default)]
pub struct Assinaturas {
    todas: Mutex<HashMap<String, Arc<Operacao>>>,
}

impl Assinaturas {
    fn travar(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<Operacao>>> {
        let mut todas = self.todas.lock().unwrap_or_else(|e| e.into_inner());
        todas.retain(|_, o| o.fim().is_none_or(|fim| fim.elapsed() < PRAZO_DO_RESULTADO));
        todas
    }

    /// A assinatura `id`, se for de `dispositivo`.
    fn de(&self, dispositivo: IdDoDispositivo, id: &str) -> Option<Arc<Operacao>> {
        self.travar()
            .get(id)
            .filter(|o| o.dispositivo == dispositivo)
            .cloned()
    }

    fn em_curso(todas: &HashMap<String, Arc<Operacao>>, dispositivo: IdDoDispositivo) -> usize {
        todas
            .values()
            .filter(|o| o.dispositivo == dispositivo && o.fim().is_none())
            .count()
    }

    fn cabe(&self, dispositivo: IdDoDispositivo) -> bool {
        Self::em_curso(&self.travar(), dispositivo) < EM_CURSO_POR_DISPOSITIVO
    }

    fn guardar(&self, id: String, operacao: Arc<Operacao>) -> bool {
        let dispositivo = operacao.dispositivo;
        let mut todas = self.travar();
        if Self::em_curso(&todas, dispositivo) >= EM_CURSO_POR_DISPOSITIVO {
            return false;
        }
        let mut terminadas: Vec<(Instant, String)> = todas
            .iter()
            .filter(|(_, o)| o.dispositivo == dispositivo)
            .filter_map(|(id, o)| o.fim().map(|fim| (fim, id.clone())))
            .collect();
        let guardadas = todas
            .values()
            .filter(|o| o.dispositivo == dispositivo)
            .count();
        terminadas.sort();
        for (_, velha) in terminadas
            .into_iter()
            .take((guardadas + 1).saturating_sub(GUARDADAS_POR_DISPOSITIVO))
        {
            todas.remove(&velha);
        }
        todas.insert(id, operacao);
        true
    }

    /// Bloqueado ou revogado, o dispositivo não termina o que começou.
    fn desistir_de_todas(&self, dispositivo: IdDoDispositivo) {
        for operacao in self.travar().values() {
            if operacao.dispositivo == dispositivo {
                operacao.desistir();
            }
        }
    }
}

fn falha(status: StatusCode, erro: Erro) -> Response {
    (status, Json(Falha { erro })).into_response()
}

fn falha_do(erro: Erro) -> Response {
    falha(status_da_falha(erro.tipo), erro)
}

fn pedido_invalido(mensagem: &str) -> Response {
    falha_do(erro(TipoDeFalha::PedidoInvalido, mensagem))
}

/// O dispositivo do outro lado, se ele pode ser atendido agora.
fn atendido(estado: &Estado, quem: &Quem) -> Result<IdDoDispositivo, Box<Response>> {
    let Quem::Dispositivo(dispositivo) = quem else {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    };
    let dispositivo = *dispositivo;
    match travar(&estado.banco).situacao(dispositivo, ERROS_PARA_BLOQUEAR) {
        Ok(Situacao::Ativo) => Ok(dispositivo),
        Ok(Situacao::Bloqueado) => {
            estado.assinaturas().desistir_de_todas(dispositivo);
            Err(Box::new(falha_do(erro(TipoDeFalha::Bloqueado, BLOQUEADO))))
        }
        Ok(Situacao::Fora) => {
            estado.assinaturas().desistir_de_todas(dispositivo);
            Err(Box::new(StatusCode::FORBIDDEN.into_response()))
        }
        Err(_) => Err(Box::new(falha_do(erro(
            TipoDeFalha::Interno,
            "falha no servidor",
        )))),
    }
}

pub(crate) async fn chaves(
    State(estado): State<Arc<Estado>>,
    Extension(quem): Extension<Quem>,
) -> Response {
    if let Err(resposta) = atendido(&estado, &quem) {
        return *resposta;
    }
    Json(Chaves {
        chaves: estado.tokens.listar().await,
    })
    .into_response()
}

pub(crate) async fn criar(
    State(estado): State<Arc<Estado>>,
    Extension(quem): Extension<Quem>,
    corpo: Bytes,
) -> Response {
    let dispositivo = match atendido(&estado, &quem) {
        Ok(dispositivo) => dispositivo,
        Err(resposta) => return *resposta,
    };
    let Ok(PedidoDeAssinatura {
        pin,
        token,
        chave,
        mecanismo,
        documentos,
    }) = serde_json::from_slice(&corpo)
    else {
        return pedido_invalido("pedido fora da API");
    };
    if !(1..=DOCUMENTOS_POR_LOTE).contains(&documentos.len()) {
        return pedido_invalido("um lote tem de 1 a 1000 documentos");
    }
    // Antes do PIN, para um engano não gastar uma tentativa.
    if !estado.tokens.existe(&token) {
        return falha_do(erro(TipoDeFalha::TokenDesconhecido, "não há esse token"));
    }
    let ocupado = || falha_do(erro(TipoDeFalha::Ocupado, "assinaturas demais em curso"));
    if !estado.assinaturas().cabe(dispositivo) {
        return ocupado();
    }
    let quem = match estado.conferir_pin(dispositivo, pin).await {
        Ok(quem) => quem,
        Err(erro) => {
            if erro.tipo == TipoDeFalha::Bloqueado {
                estado.assinaturas().desistir_de_todas(dispositivo);
            }
            return falha_do(erro);
        }
    };
    let Some(id) = novo_id() else {
        return falha_do(erro(TipoDeFalha::Interno, "falha no servidor"));
    };
    let operacao = Arc::new(Operacao::nova(dispositivo, id.clone()));
    if !estado.assinaturas().guardar(id.clone(), operacao.clone()) {
        return ocupado();
    }
    let visao = operacao.agora();
    tokio::spawn(executar(
        estado,
        operacao,
        Lote {
            quem,
            token,
            chave,
            mecanismo,
            documentos,
        },
    ));
    (
        StatusCode::CREATED,
        [(LOCATION, caminho_da_assinatura(&id))],
        Json(visao),
    )
        .into_response()
}

fn novo_id() -> Option<String> {
    let mut bytes = [0u8; TAMANHO_DO_ID];
    getrandom::fill(&mut bytes).ok()?;
    Some(HEXLOWER.encode(&bytes))
}

struct Lote {
    quem: Autenticado,
    token: String,
    chave: String,
    mecanismo: Mecanismo,
    documentos: Vec<Vec<u8>>,
}

/// Assina o lote, um documento de cada vez, até o fim ou a primeira falha.
async fn executar(estado: Arc<Estado>, operacao: Arc<Operacao>, lote: Lote) {
    let mut falhou = None;
    for dados in lote.documentos {
        if operacao.desistiu() {
            falhou = Some(erro(TipoDeFalha::Cancelado, "o sistema desistiu"));
            break;
        }
        let assinada = estado
            .tokens
            .assinar(
                &lote.token,
                lote.quem.clone(),
                lote.chave.clone(),
                lote.mecanismo,
                dados,
                Box::new(PessoaDaApi(operacao.clone())),
            )
            .await;
        match assinada {
            Ok(assinatura) => operacao
                .visao
                .send_modify(|visao| visao.assinaturas.push(assinatura)),
            Err(falha_da_operacao) => {
                falhou = Some(falha_da_operacao.para_o_cliente());
                break;
            }
        }
    }
    *operacao.fim.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    operacao.visao.send_modify(|visao| {
        visao.estado = match falhou {
            None => EstadoDaAssinatura::Concluida,
            Some(erro) => EstadoDaAssinatura::Falhou { erro },
        };
    });
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Espera {
    /// Em segundos.
    esperar: Option<u64>,
}

pub(crate) async fn consultar(
    State(estado): State<Arc<Estado>>,
    Extension(quem): Extension<Quem>,
    Path(id): Path<String>,
    espera: Result<Query<Espera>, QueryRejection>,
) -> Response {
    let dispositivo = match atendido(&estado, &quem) {
        Ok(dispositivo) => dispositivo,
        Err(resposta) => return *resposta,
    };
    let Ok(Query(Espera { esperar })) = espera else {
        return pedido_invalido("esperar é um número de segundos");
    };
    let Some(operacao) = estado.assinaturas().de(dispositivo, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(segundos) = esperar {
        let prazo = Duration::from_secs(segundos).min(ESPERA_MAXIMA);
        let mut visao = operacao.visao.subscribe();
        let mudou = visao.wait_for(|v| !matches!(v.estado, EstadoDaAssinatura::EmCurso));
        let _ = tokio::time::timeout(prazo, mudou).await;
    }
    Json(operacao.agora()).into_response()
}

pub(crate) async fn responder(
    State(estado): State<Arc<Estado>>,
    Extension(quem): Extension<Quem>,
    Path(id): Path<String>,
    corpo: Bytes,
) -> Response {
    let dispositivo = match atendido(&estado, &quem) {
        Ok(dispositivo) => dispositivo,
        Err(resposta) => return *resposta,
    };
    let Some(operacao) = estado.assinaturas().de(dispositivo, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Ok(Fatores { valores }) = serde_json::from_slice(&corpo) else {
        return pedido_invalido("pedido fora da API");
    };
    if !operacao.responder(Some(valores)) {
        return falha(
            StatusCode::CONFLICT,
            erro(
                TipoDeFalha::PedidoInvalido,
                "a assinatura não está pedindo fatores",
            ),
        );
    }
    (StatusCode::ACCEPTED, Json(operacao.agora())).into_response()
}

pub(crate) async fn desistir(
    State(estado): State<Arc<Estado>>,
    Extension(quem): Extension<Quem>,
    Path(id): Path<String>,
) -> Response {
    let dispositivo = match atendido(&estado, &quem) {
        Ok(dispositivo) => dispositivo,
        Err(resposta) => return *resposta,
    };
    let Some(operacao) = estado.assinaturas().de(dispositivo, &id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    operacao.desistir();
    (StatusCode::ACCEPTED, Json(operacao.agora())).into_response()
}
