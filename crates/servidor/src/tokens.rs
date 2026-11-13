//! Os tokens configurados, cada um numa thread dona do driver dele: o driver
//! fala por stdin e stdout, uma operação de cada vez.
//!
//! A thread relança o driver quando o processo morre e quando o administrador
//! configura o token de novo com o serviço rodando (a `geracao` no banco
//! muda).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use protocolo::{Chave, Mecanismo};
use rede::agente::ChaveDoToken;
use tokio::sync::{broadcast, oneshot};

use crate::banco::{Banco, FalhaDoBanco, IdDoDispositivo, RegistroDoToken, travar};
use crate::driver::{Driver, Falha};
use crate::fatores::Pessoa;
use crate::pin::Autenticado;
use crate::token::{FalhaDoToken, GuardaNoBanco, Token};

/// Onde a imagem derivada de cada driver o instala.
pub const DRIVERS_PADRAO: &str = "/drivers";

/// O que muda sem ninguém perguntar, para os agentes conectados saberem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evento {
    TokenParado(String),
    DispositivoBloqueado(IdDoDispositivo),
}

#[derive(Debug)]
pub enum FalhaDaOperacao {
    TokenDesconhecido,
    Token(FalhaDoToken),
}

/// Quem pediu a assinatura, dono do canal até a pessoa.
pub type PessoaDaOperacao = Box<dyn Pessoa + Send>;

enum Trabalho {
    Listar(oneshot::Sender<Result<Vec<Chave>, FalhaDoToken>>),
    Assinar {
        quem: Autenticado,
        chave: String,
        mecanismo: Mecanismo,
        dados: Vec<u8>,
        pessoa: PessoaDaOperacao,
        resposta: oneshot::Sender<Result<Vec<u8>, FalhaDoToken>>,
    },
}

pub struct Tokens {
    filas: BTreeMap<String, mpsc::Sender<Trabalho>>,
}

impl Tokens {
    /// Uma thread para cada token do banco. O driver só sobe no primeiro uso.
    pub fn iniciar(
        banco: &Arc<Mutex<Banco>>,
        drivers: &Path,
        eventos: &broadcast::Sender<Evento>,
    ) -> Result<Tokens, FalhaDoBanco> {
        let mut filas = BTreeMap::new();
        for registro in travar(banco).tokens()? {
            let (fila, trabalhos) = mpsc::channel();
            let nome = registro.nome.clone();
            let trabalhador = Trabalhador {
                registro,
                banco: banco.clone(),
                drivers: drivers.to_owned(),
                eventos: eventos.clone(),
                token: None,
            };
            thread::Builder::new()
                .name(format!("token {nome}"))
                .spawn(move || trabalhador.trabalhar(trabalhos))?;
            filas.insert(nome, fila);
        }
        Ok(Tokens { filas })
    }

    /// As chaves de todos os tokens. Um token que falha fica de fora.
    pub async fn listar(&self) -> Vec<ChaveDoToken> {
        let mut todas = Vec::new();
        for (nome, fila) in &self.filas {
            let (resposta, recebida) = oneshot::channel();
            if fila.send(Trabalho::Listar(resposta)).is_err() {
                continue;
            }
            if let Ok(Ok(chaves)) = recebida.await {
                todas.extend(chaves.into_iter().map(|chave| ChaveDoToken {
                    token: nome.clone(),
                    chave,
                }));
            }
        }
        todas
    }

    pub async fn assinar(
        &self,
        token: &str,
        quem: Autenticado,
        chave: String,
        mecanismo: Mecanismo,
        dados: Vec<u8>,
        pessoa: PessoaDaOperacao,
    ) -> Result<Vec<u8>, FalhaDaOperacao> {
        let fila = self
            .filas
            .get(token)
            .ok_or(FalhaDaOperacao::TokenDesconhecido)?;
        let (resposta, recebida) = oneshot::channel();
        let trabalho = Trabalho::Assinar {
            quem,
            chave,
            mecanismo,
            dados,
            pessoa,
            resposta,
        };
        let parou = || {
            FalhaDaOperacao::Token(FalhaDoToken::Driver(Falha::Contrato(
                "a thread do token parou".into(),
            )))
        };
        fila.send(trabalho).map_err(|_| parou())?;
        recebida
            .await
            .map_err(|_| parou())?
            .map_err(FalhaDaOperacao::Token)
    }
}

struct Trabalhador {
    registro: RegistroDoToken,
    banco: Arc<Mutex<Banco>>,
    drivers: PathBuf,
    eventos: broadcast::Sender<Evento>,
    /// O driver rodando e a geração da configuração com que subiu.
    token: Option<(Token, i64)>,
}

impl Trabalhador {
    fn trabalhar(mut self, trabalhos: mpsc::Receiver<Trabalho>) {
        for trabalho in trabalhos {
            match trabalho {
                Trabalho::Listar(resposta) => {
                    let resultado = self.com_o_token(|token| token.listar());
                    let _ = resposta.send(resultado);
                }
                Trabalho::Assinar {
                    quem,
                    chave,
                    mecanismo,
                    dados,
                    mut pessoa,
                    resposta,
                } => {
                    let resultado = self.com_o_token(|token| {
                        token.assinar(&quem, &chave, mecanismo, &dados, pessoa.as_mut())
                    });
                    if let Err(FalhaDoToken::Desatualizado(_)) = resultado {
                        let _ = self
                            .eventos
                            .send(Evento::TokenParado(self.registro.nome.clone()));
                    }
                    let _ = resposta.send(resultado);
                }
            }
        }
    }

    /// Roda `operacao` no token, subindo o driver se precisar. Um driver que
    /// morreu sobe de novo na próxima operação.
    fn com_o_token<T>(
        &mut self,
        operacao: impl FnOnce(&mut Token) -> Result<T, FalhaDoToken>,
    ) -> Result<T, FalhaDoToken> {
        let geracao = travar(&self.banco).geracao(self.registro.id)?;
        if self.token.as_ref().is_some_and(|(_, g)| *g != geracao) {
            self.token = None;
        }
        if self.token.is_none() {
            self.token = Some((self.abrir()?, geracao));
        }
        let (token, _) = self.token.as_mut().expect("aberto logo acima");
        let resultado = operacao(token);
        if let Err(FalhaDoToken::Driver(Falha::Processo(_))) = resultado {
            self.token = None;
        }
        resultado
    }

    fn abrir(&self) -> Result<Token, FalhaDoToken> {
        let driver = Driver::lancar(
            Command::new(self.drivers.join(&self.registro.driver)).args(&self.registro.argumentos),
        )?;
        Ok(Token::abrir(
            driver,
            GuardaNoBanco::novo(self.banco.clone(), self.registro.id),
        )?)
    }
}
