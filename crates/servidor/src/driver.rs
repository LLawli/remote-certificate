//! Um driver rodando: o processo filho e a conversa pelo contrato
//! (`docs/drivers.md`).

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use protocolo::{
    Apresentacao, Assinatura, Configurado, Erro, Listagem, Mecanismo, MensagemDoDriver, Operacao,
    Pedido, PedidoDeFatores, RespostaDeFatores, Segredo, VERSAO,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Quanto o driver tem para sair sozinho depois que o stdin fecha.
const PRAZO_PARA_SAIR: Duration = Duration::from_secs(2);

/// Responde um pedido de fatores no meio de uma operação; `None` desiste.
pub type Responder<'a> = dyn FnMut(&PedidoDeFatores) -> Option<BTreeMap<String, Segredo>> + 'a;

#[derive(Debug)]
pub enum Falha {
    /// O processo não subiu, morreu ou fechou o canal.
    Processo(io::Error),
    /// O driver mandou algo fora do contrato.
    Contrato(String),
    /// O driver respondeu com uma falha.
    Driver(Erro),
}

impl fmt::Display for Falha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Falha::Processo(e) => write!(f, "o driver não responde: {e}"),
            Falha::Contrato(o_que) => write!(f, "o driver saiu do contrato: {o_que}"),
            Falha::Driver(erro) => f.write_str(&erro.mensagem),
        }
    }
}

impl From<io::Error> for Falha {
    fn from(e: io::Error) -> Falha {
        Falha::Processo(e)
    }
}

/// O que o servidor faz com um driver. O [`Driver`] é a implementação de
/// verdade; os testes do [`crate::token`] usam uma em memória.
pub trait Conversa {
    fn apresentacao(&self) -> &Apresentacao;
    fn configurar(&mut self, valores: BTreeMap<String, Segredo>) -> Result<Configurado, Falha>;
    fn listar(&mut self) -> Result<Listagem, Falha>;
    fn assinar(
        &mut self,
        chave: &str,
        mecanismo: Mecanismo,
        dados: &[u8],
        fatores: &mut Responder<'_>,
    ) -> Result<Vec<u8>, Falha>;
}

pub struct Driver {
    filho: Child,
    entrada: Option<ChildStdin>,
    saida: BufReader<ChildStdout>,
    proximo_id: u64,
    apresentacao: Apresentacao,
}

impl Driver {
    /// Lança o driver e faz a apresentação. `programa` traz o executável, os
    /// argumentos e o ambiente; o stdin e o stdout são do contrato.
    pub fn lancar(programa: &mut Command) -> Result<Driver, Falha> {
        let mut filho = programa
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let entrada = filho.stdin.take();
        let saida = BufReader::new(filho.stdout.take().expect("stdout com pipe"));
        let mut driver = Driver {
            filho,
            entrada,
            saida,
            proximo_id: 1,
            apresentacao: Apresentacao {
                driver: String::new(),
                versao: String::new(),
                protocolo: VERSAO,
                fatores: Vec::new(),
                configuracao: Vec::new(),
            },
        };
        let apresentacao: Apresentacao =
            driver.pedir(Operacao::Apresentar { versao: VERSAO }, &mut |_| None)?;
        if apresentacao.protocolo != VERSAO {
            return Err(Falha::Contrato(format!(
                "fala o contrato v{}, o servidor fala o v{VERSAO}",
                apresentacao.protocolo
            )));
        }
        driver.apresentacao = apresentacao;
        Ok(driver)
    }

    fn pedir<T: DeserializeOwned>(
        &mut self,
        operacao: Operacao,
        fatores: &mut Responder<'_>,
    ) -> Result<T, Falha> {
        let id = self.proximo_id;
        self.proximo_id += 1;
        self.enviar(&Pedido { id, operacao })?;
        loop {
            match self.receber()? {
                MensagemDoDriver::Resultado { id: i, ok } if i == id => {
                    return serde_json::from_value(ok)
                        .map_err(|e| Falha::Contrato(format!("resultado ilegível: {e}")));
                }
                MensagemDoDriver::Falha { id: i, erro } if i == id => {
                    return Err(Falha::Driver(erro));
                }
                MensagemDoDriver::Pedir { id: i, pedir } if i == id => {
                    let resposta = match fatores(&pedir) {
                        Some(fatores) => RespostaDeFatores::Fatores { id, fatores },
                        None => RespostaDeFatores::Cancelar { id, cancelar: true },
                    };
                    self.enviar(&resposta)?;
                }
                _ => {
                    return Err(Falha::Contrato(format!(
                        "resposta que não é do pedido {id}"
                    )));
                }
            }
        }
    }

    fn enviar(&mut self, mensagem: &impl Serialize) -> io::Result<()> {
        let entrada = self
            .entrada
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let mut linha = serde_json::to_vec(mensagem)?;
        linha.push(b'\n');
        entrada.write_all(&linha)?;
        entrada.flush()
    }

    fn receber(&mut self) -> Result<MensagemDoDriver, Falha> {
        let mut linha = String::new();
        if protocolo::ler_linha(&mut self.saida, &mut linha)? == 0 {
            return Err(Falha::Processo(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "o driver fechou a saída",
            )));
        }
        serde_json::from_str(&linha).map_err(|e| Falha::Contrato(format!("mensagem ilegível: {e}")))
    }
}

impl Conversa for Driver {
    fn apresentacao(&self) -> &Apresentacao {
        &self.apresentacao
    }

    fn configurar(&mut self, valores: BTreeMap<String, Segredo>) -> Result<Configurado, Falha> {
        self.pedir(Operacao::Configurar { valores }, &mut |_| None)
    }

    fn listar(&mut self) -> Result<Listagem, Falha> {
        self.pedir(Operacao::Listar, &mut |_| None)
    }

    fn assinar(
        &mut self,
        chave: &str,
        mecanismo: Mecanismo,
        dados: &[u8],
        fatores: &mut Responder<'_>,
    ) -> Result<Vec<u8>, Falha> {
        let operacao = Operacao::Assinar {
            chave: chave.to_string(),
            mecanismo,
            dados: dados.to_vec(),
        };
        self.pedir::<Assinatura>(operacao, fatores)
            .map(|a| a.assinatura)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Fechar o stdin pede para o driver sair; se ele não sair, é morto.
        drop(self.entrada.take());
        let limite = Instant::now() + PRAZO_PARA_SAIR;
        while Instant::now() < limite {
            if let Ok(Some(_)) = self.filho.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.filho.kill();
        let _ = self.filho.wait();
    }
}
