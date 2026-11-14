//! Uma face conectada: uma aplicação (Firefox, PJeOffice) falando com o
//! agente pelo IPC.
//!
//! Cada face tem a sua conexão com o servidor, aberta no primeiro pedido.
//! Assim o login do PIN pessoal é dela, como o `C_Login` do PKCS#11, e duas
//! aplicações assinam ao mesmo tempo. Quando o token pede o OTP, o agente
//! pergunta à pessoa na janela e a face só espera o fim.

use std::collections::BTreeMap;
use std::sync::Arc;

use ipc::{ChaveDoToken, DaFace, DoAgente, Falha, TipoDeFalha};
use rede::agente::{self as remoto, Conexao, FalhaDoAgente};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::Agente;
use crate::dialogo::{FatorPedido, Pergunta};

/// Atende a face até ela fechar a conexão.
pub async fn atender<S>(agente: Arc<Agente>, conexao: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (leitor, mut escritor) = tokio::io::split(conexao);
    let mut leitor = BufReader::new(leitor);
    let mut sessao = Sessao {
        agente,
        servidor: None,
        proximo_id: 1,
        rotulos: BTreeMap::new(),
    };
    loop {
        let resposta = match ler(&mut leitor).await {
            Ok(Some(pedido)) => sessao.tratar(pedido).await,
            Ok(None) => break,
            // Linha grande demais: a face saiu do protocolo e a conexão cai.
            Err(Lida::Grande) => break,
            Err(Lida::ForaDoProtocolo) => DoAgente::Falha {
                erro: Falha::nova(TipoDeFalha::PedidoInvalido, "pedido fora do protocolo"),
            },
        };
        let mut linha = serde_json::to_vec(&resposta).expect("resposta vira JSON");
        linha.push(b'\n');
        if escritor.write_all(&linha).await.is_err() || escritor.flush().await.is_err() {
            break;
        }
    }
}

enum Lida {
    Grande,
    ForaDoProtocolo,
}

async fn ler<L: AsyncBufReadExt + Unpin>(leitor: &mut L) -> Result<Option<DaFace>, Lida> {
    let mut linha = zeroize::Zeroizing::new(Vec::new());
    let lidos = (&mut *leitor)
        .take(ipc::LIMITE as u64 + 1)
        .read_until(b'\n', &mut linha)
        .await
        .map_err(|_| Lida::Grande)?;
    if lidos == 0 {
        return Ok(None);
    }
    if lidos > ipc::LIMITE {
        return Err(Lida::Grande);
    }
    serde_json::from_slice(&linha)
        .map(Some)
        .map_err(|_| Lida::ForaDoProtocolo)
}

struct Sessao {
    agente: Arc<Agente>,
    servidor: Option<Conexao>,
    proximo_id: u64,
    /// O rótulo de cada chave, da última listagem, para a janela do OTP dizer
    /// com qual certificado vai assinar.
    rotulos: BTreeMap<(String, String), String>,
}

fn falha(tipo: TipoDeFalha, mensagem: impl Into<String>) -> DoAgente {
    DoAgente::Falha {
        erro: Falha::nova(tipo, mensagem),
    }
}

fn sem_servidor(falha_do_agente: &FalhaDoAgente) -> DoAgente {
    match falha_do_agente {
        FalhaDoAgente::Recusado => falha(
            TipoDeFalha::SemServidor,
            "o servidor não atende mais este computador; peça ao administrador para parear de novo",
        ),
        outra => falha(
            TipoDeFalha::SemServidor,
            format!("sem conexão com o servidor: {outra}"),
        ),
    }
}

impl Sessao {
    async fn tratar(&mut self, pedido: DaFace) -> DoAgente {
        let (certificado, mensagem) = match pedido {
            DaFace::Listar {} => (None, remoto::DoAgente::Listar { id: 0 }),
            DaFace::Entrar { pin } => (None, remoto::DoAgente::Entrar { id: 0, pin }),
            DaFace::Sair {} => (None, remoto::DoAgente::Sair { id: 0 }),
            DaFace::Assinar {
                token,
                chave,
                mecanismo,
                dados,
            } => (
                self.rotulos.get(&(token.clone(), chave.clone())).cloned(),
                remoto::DoAgente::Assinar {
                    id: 0,
                    token,
                    chave,
                    mecanismo,
                    dados,
                },
            ),
        };
        let resposta = match self.conversar(mensagem, certificado).await {
            Ok(resposta) => resposta,
            Err(falha_do_agente) => {
                // A conexão caiu: a próxima abre outra, já sem o login.
                self.servidor = None;
                return sem_servidor(&falha_do_agente);
            }
        };
        self.traduzir(resposta)
    }

    async fn conexao(&mut self) -> Result<&mut Conexao, FalhaDoAgente> {
        if self.servidor.is_none() {
            let pareamento = &self.agente.pareamento;
            let conexao = Conexao::abrir(
                &pareamento.endereco,
                &pareamento.identidade,
                pareamento.servidor,
            )
            .await?;
            self.servidor = Some(conexao);
        }
        Ok(self.servidor.as_mut().expect("aberta logo acima"))
    }

    /// Manda a mensagem e espera a resposta dela, respondendo no caminho os
    /// pedidos de fatores com a janela.
    async fn conversar(
        &mut self,
        mut mensagem: remoto::DoAgente,
        certificado: Option<String>,
    ) -> Result<remoto::DoServidor, FalhaDoAgente> {
        let id = self.proximo_id;
        self.proximo_id += 1;
        definir_id(&mut mensagem, id);
        let dialogo = self.agente.dialogo.clone();
        let conexao = self.conexao().await?;
        conexao.enviar(&mensagem).await?;
        loop {
            match conexao.receber().await? {
                remoto::DoServidor::Aviso { .. } => continue,
                remoto::DoServidor::PedidoDeFatores {
                    id: pedido,
                    fatores,
                    recusa,
                } if pedido == id => {
                    let pergunta = Pergunta {
                        fatores: fatores
                            .into_iter()
                            .map(|f| FatorPedido {
                                nome: f.nome,
                                rotulo: f.rotulo,
                            })
                            .collect(),
                        recusa,
                        certificado: certificado.clone(),
                    };
                    let dialogo = dialogo.clone();
                    let valores = tokio::task::spawn_blocking(move || dialogo.perguntar(&pergunta))
                        .await
                        .ok()
                        .flatten();
                    let resposta = match valores {
                        Some(valores) => remoto::DoAgente::Fatores { id, valores },
                        None => remoto::DoAgente::Desistir { id },
                    };
                    conexao.enviar(&resposta).await?;
                }
                outra if id_da_resposta(&outra) == Some(id) => return Ok(outra),
                // Resposta de outro pedido, ou falha sem id: fora do esperado.
                outra => {
                    return Err(FalhaDoAgente::Protocolo(format!(
                        "resposta inesperada: {outra:?}"
                    )));
                }
            }
        }
    }

    fn traduzir(&mut self, resposta: remoto::DoServidor) -> DoAgente {
        match resposta {
            remoto::DoServidor::Chaves { chaves, .. } => {
                self.rotulos = chaves
                    .iter()
                    .map(|c| {
                        (
                            (c.token.clone(), c.chave.id.clone()),
                            c.chave.rotulo.clone(),
                        )
                    })
                    .collect();
                DoAgente::Chaves {
                    chaves: chaves
                        .into_iter()
                        .map(|c| ChaveDoToken {
                            token: c.token,
                            chave: c.chave,
                        })
                        .collect(),
                }
            }
            remoto::DoServidor::Entrou { sessao, .. } => DoAgente::Entrou { sessao },
            remoto::DoServidor::Saiu { .. } => DoAgente::Saiu {},
            remoto::DoServidor::Assinatura { assinatura, .. } => {
                DoAgente::Assinatura { assinatura }
            }
            remoto::DoServidor::Falha { erro, .. } => DoAgente::Falha {
                erro: Falha {
                    tipo: tipo_da_falha(erro.tipo),
                    mensagem: erro.mensagem,
                    restantes: erro.restantes,
                },
            },
            outra => falha(
                TipoDeFalha::Interno,
                format!("resposta inesperada do servidor: {outra:?}"),
            ),
        }
    }
}

fn definir_id(mensagem: &mut remoto::DoAgente, novo: u64) {
    match mensagem {
        remoto::DoAgente::Entrar { id, .. }
        | remoto::DoAgente::Listar { id }
        | remoto::DoAgente::Assinar { id, .. }
        | remoto::DoAgente::Fatores { id, .. }
        | remoto::DoAgente::Desistir { id }
        | remoto::DoAgente::Sair { id } => *id = novo,
    }
}

fn id_da_resposta(resposta: &remoto::DoServidor) -> Option<u64> {
    match resposta {
        remoto::DoServidor::Entrou { id, .. }
        | remoto::DoServidor::Chaves { id, .. }
        | remoto::DoServidor::PedidoDeFatores { id, .. }
        | remoto::DoServidor::Assinatura { id, .. }
        | remoto::DoServidor::Saiu { id } => Some(*id),
        remoto::DoServidor::Falha { id, .. } => *id,
        remoto::DoServidor::Aviso { .. } => None,
    }
}

fn tipo_da_falha(tipo: remoto::TipoDeFalha) -> TipoDeFalha {
    use remoto::TipoDeFalha as R;
    match tipo {
        R::PinErrado => TipoDeFalha::PinErrado,
        R::Bloqueado => TipoDeFalha::Bloqueado,
        R::NaoAutenticado => TipoDeFalha::NaoAutenticado,
        R::TokenDesconhecido => TipoDeFalha::TokenDesconhecido,
        R::TokenParado => TipoDeFalha::TokenParado,
        R::ChaveAusente => TipoDeFalha::ChaveAusente,
        R::MecanismoNaoSuportado => TipoDeFalha::MecanismoNaoSuportado,
        R::Cancelado => TipoDeFalha::Cancelado,
        R::PedidoInvalido => TipoDeFalha::PedidoInvalido,
        R::Token => TipoDeFalha::Token,
        R::Interno => TipoDeFalha::Interno,
        R::Ocupado | R::Outro => TipoDeFalha::Outro,
    }
}
