//! A sessão de um agente pareado em `/v1/agente` (o protocolo está em
//! `rede::agente`).
//!
//! Antes de cada mensagem o servidor confere o dispositivo no banco: revogado,
//! a conexão cai; bloqueado, nada passa. O PIN pessoal abre a sessão para
//! assinar, e ela vence depois de [`PRAZO_DA_SESSAO`] sem uso.

use std::collections::BTreeMap;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use protocolo::{Fator, Segredo};
use rede::agente::{Aviso, DoAgente, DoServidor, FatorPedido, TipoDeFalha};
use tokio::sync::{broadcast, mpsc as canal};

use crate::banco::{IdDoDispositivo, Situacao, travar};
use crate::driver::Falha;
use crate::fatores::Pessoa;
use crate::pin::{Autenticado, ERROS_PARA_BLOQUEAR};
use crate::servico::{BLOQUEADO, Estado};
use crate::token::FalhaDoToken;
use crate::tokens::{Evento, FalhaDaOperacao, erro};

/// Quanto o login do PIN pessoal dura sem uso. Provisório: a medir na VM como
/// os assinadores reagem a pedir o PIN de novo.
pub const PRAZO_DA_SESSAO: Duration = Duration::from_secs(15 * 60);
/// Quanto o token espera a pessoa responder um fator (o OTP).
pub const PRAZO_DA_PESSOA: Duration = Duration::from_secs(3 * 60);

/// O que a thread do token manda para a sessão durante uma assinatura.
enum DaOperacao {
    Pedido(Vec<FatorPedido>, Option<String>),
    Fim(Result<Vec<u8>, FalhaDaOperacao>),
}

/// A assinatura em curso nesta conexão.
struct EmCurso {
    id: u64,
    eventos: canal::UnboundedReceiver<DaOperacao>,
    /// A resposta da pessoa ao último pedido; `None` é desistir.
    respostas: mpsc::Sender<Option<BTreeMap<String, Segredo>>>,
}

/// A pessoa do outro lado do WebSocket, vista da thread do token.
struct PessoaRemota {
    pedidos: canal::UnboundedSender<DaOperacao>,
    respostas: mpsc::Receiver<Option<BTreeMap<String, Segredo>>>,
}

impl Pessoa for PessoaRemota {
    fn pedir(
        &mut self,
        fatores: &[&Fator],
        recusa: Option<&str>,
    ) -> Option<BTreeMap<String, Segredo>> {
        let pedidos = fatores
            .iter()
            .map(|f| FatorPedido {
                nome: f.nome.clone(),
                rotulo: f.rotulo.clone(),
            })
            .collect();
        self.pedidos
            .send(DaOperacao::Pedido(pedidos, recusa.map(str::to_string)))
            .ok()?;
        // Conexão caída, prazo vencido ou desistência: a operação cancela.
        self.respostas.recv_timeout(PRAZO_DA_PESSOA).ok().flatten()
    }
}

struct Sessao {
    dispositivo: IdDoDispositivo,
    estado: Arc<Estado>,
    /// O login do PIN pessoal e o último uso dele.
    entrada: Option<(Autenticado, Instant)>,
    em_curso: Option<EmCurso>,
}

fn falha(id: Option<u64>, tipo: TipoDeFalha, mensagem: impl Into<String>) -> DoServidor {
    DoServidor::Falha {
        id,
        erro: erro(tipo, mensagem),
    }
}

/// O que fazer com a conexão depois de uma mensagem.
enum Depois {
    Seguir,
    Fechar,
}

pub async fn atender(mut ws: WebSocket, dispositivo: IdDoDispositivo, estado: Arc<Estado>) {
    let mut avisos = estado.eventos.subscribe();
    let mut sessao = Sessao {
        dispositivo,
        estado,
        entrada: None,
        em_curso: None,
    };
    loop {
        let saida = tokio::select! {
            mensagem = ws.recv() => match mensagem {
                Some(Ok(Message::Text(texto))) => sessao.tratar(&texto).await,
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => continue,
            },
            evento = proximo_da_operacao(&mut sessao.em_curso) => {
                (sessao.da_operacao(evento), Depois::Seguir)
            }
            evento = avisos.recv() => match evento {
                Ok(evento) => (sessao.aviso(evento), Depois::Seguir),
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            },
        };
        let (respostas, depois) = saida;
        for resposta in respostas {
            let texto = serde_json::to_string(&resposta).expect("mensagem vira JSON");
            if ws.send(Message::Text(texto.into())).await.is_err() {
                return;
            }
        }
        if let Depois::Fechar = depois {
            break;
        }
    }
}

/// O próximo evento da assinatura em curso; sem assinatura, nunca. Um canal
/// fechado sem o fim (a tarefa caiu) termina a operação.
async fn proximo_da_operacao(em_curso: &mut Option<EmCurso>) -> DaOperacao {
    match em_curso {
        Some(operacao) => operacao.eventos.recv().await.unwrap_or_else(|| {
            DaOperacao::Fim(Err(FalhaDaOperacao::Token(FalhaDoToken::Driver(
                Falha::Contrato("a operação parou sem resposta".into()),
            ))))
        }),
        None => std::future::pending().await,
    }
}

impl Sessao {
    async fn tratar(&mut self, texto: &str) -> (Vec<DoServidor>, Depois) {
        let Ok(mensagem) = serde_json::from_str::<DoAgente>(texto) else {
            return (
                vec![falha(
                    None,
                    TipoDeFalha::PedidoInvalido,
                    "mensagem fora do protocolo",
                )],
                Depois::Seguir,
            );
        };
        let situacao = travar(&self.estado.banco).situacao(self.dispositivo, ERROS_PARA_BLOQUEAR);
        match situacao {
            Ok(Situacao::Ativo) => {}
            Ok(Situacao::Fora) | Err(_) => return (Vec::new(), Depois::Fechar),
            Ok(Situacao::Bloqueado) => {
                self.entrada = None;
                // Uma assinatura esperando a pessoa cancela agora.
                if let Some(operacao) = &self.em_curso {
                    let _ = operacao.respostas.send(None);
                }
                let id = id_da(&mensagem);
                return (
                    vec![falha(Some(id), TipoDeFalha::Bloqueado, BLOQUEADO)],
                    Depois::Seguir,
                );
            }
        }
        if self
            .entrada
            .as_ref()
            .is_some_and(|(_, uso)| uso.elapsed() > PRAZO_DA_SESSAO)
        {
            self.entrada = None;
        }
        let resposta = match mensagem {
            // A próxima mensagem vem da operação: outro pedido ou o fim.
            DoAgente::Fatores { id, valores } => match self.responder_fatores(id, Some(valores)) {
                Ok(()) => return (Vec::new(), Depois::Seguir),
                Err(falha) => falha,
            },
            DoAgente::Desistir { id } => match self.responder_fatores(id, None) {
                Ok(()) => return (Vec::new(), Depois::Seguir),
                Err(falha) => falha,
            },
            outra if self.em_curso.is_some() => falha(
                Some(id_da(&outra)),
                TipoDeFalha::Ocupado,
                "há uma assinatura em curso nesta conexão",
            ),
            DoAgente::Entrar { id, pin } => self.entrar(id, pin).await,
            DoAgente::Listar { id } => DoServidor::Chaves {
                id,
                chaves: self.estado.tokens.listar().await,
            },
            DoAgente::Assinar {
                id,
                token,
                chave,
                mecanismo,
                dados,
            } => match self.entrada.as_mut() {
                None => falha(
                    Some(id),
                    TipoDeFalha::NaoAutenticado,
                    "digite o PIN pessoal",
                ),
                Some((quem, uso)) => {
                    *uso = Instant::now();
                    let quem = quem.clone();
                    self.comecar_assinatura(id, token, quem, chave, mecanismo, dados);
                    return (Vec::new(), Depois::Seguir);
                }
            },
            DoAgente::Sair { id } => {
                self.entrada = None;
                DoServidor::Saiu { id }
            }
        };
        (vec![resposta], Depois::Seguir)
    }

    async fn entrar(&mut self, id: u64, pin: Segredo) -> DoServidor {
        match self.estado.conferir_pin(self.dispositivo, pin).await {
            Ok(autenticado) => {
                self.entrada = Some((autenticado, Instant::now()));
                DoServidor::Entrou { id }
            }
            Err(erro) => {
                self.entrada = None;
                DoServidor::Falha { id: Some(id), erro }
            }
        }
    }

    fn comecar_assinatura(
        &mut self,
        id: u64,
        token: String,
        quem: Autenticado,
        chave: String,
        mecanismo: protocolo::Mecanismo,
        dados: Vec<u8>,
    ) {
        let (pedidos, eventos) = canal::unbounded_channel();
        let (respostas, recebidas) = mpsc::channel();
        let pessoa = PessoaRemota {
            pedidos: pedidos.clone(),
            respostas: recebidas,
        };
        let estado = self.estado.clone();
        tokio::spawn(async move {
            let resultado = estado
                .tokens
                .assinar(&token, quem, chave, mecanismo, dados, Box::new(pessoa))
                .await;
            let _ = pedidos.send(DaOperacao::Fim(resultado));
        });
        self.em_curso = Some(EmCurso {
            id,
            eventos,
            respostas,
        });
    }

    /// Entrega a resposta da pessoa à assinatura em curso com este `id`.
    fn responder_fatores(
        &mut self,
        id: u64,
        valores: Option<BTreeMap<String, Segredo>>,
    ) -> Result<(), DoServidor> {
        match &self.em_curso {
            Some(operacao) if operacao.id == id => {
                let _ = operacao.respostas.send(valores);
                Ok(())
            }
            _ => Err(falha(
                Some(id),
                TipoDeFalha::PedidoInvalido,
                "nenhum pedido de fatores com este id",
            )),
        }
    }

    fn da_operacao(&mut self, evento: DaOperacao) -> Vec<DoServidor> {
        let id = self.em_curso.as_ref().map_or(0, |o| o.id);
        match evento {
            DaOperacao::Pedido(fatores, recusa) => vec![DoServidor::PedidoDeFatores {
                id,
                fatores,
                recusa,
            }],
            DaOperacao::Fim(resultado) => {
                self.em_curso = None;
                vec![match resultado {
                    Ok(assinatura) => DoServidor::Assinatura { id, assinatura },
                    Err(falha_da_operacao) => DoServidor::Falha {
                        id: Some(id),
                        erro: falha_da_operacao.para_o_cliente(),
                    },
                }]
            }
        }
    }

    fn aviso(&self, evento: Evento) -> Vec<DoServidor> {
        let aviso = match evento {
            Evento::TokenParado(token) => Aviso::TokenParado { token },
            Evento::DispositivoBloqueado(d) if d == self.dispositivo => Aviso::DispositivoBloqueado,
            Evento::DispositivoBloqueado(_) => return Vec::new(),
        };
        vec![DoServidor::Aviso { aviso }]
    }
}

fn id_da(mensagem: &DoAgente) -> u64 {
    match mensagem {
        DoAgente::Entrar { id, .. }
        | DoAgente::Listar { id }
        | DoAgente::Assinar { id, .. }
        | DoAgente::Fatores { id, .. }
        | DoAgente::Desistir { id }
        | DoAgente::Sair { id } => *id,
    }
}
