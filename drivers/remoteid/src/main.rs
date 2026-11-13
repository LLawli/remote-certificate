//! Driver do RemoteID (Certisign) para o remote-certificate.
//!
//! Traduz o contrato de driver (`docs/drivers.md`) para o `remoteid servir` do
//! [RemoteID-linux](https://github.com/LLawli/RemoteID-linux), que roda como
//! processo filho. O `remoteid` é instalado junto deste driver.
//!
//! ```text
//! remote-certificate-driver-remoteid --estado <dir> [--remoteid <executável>] [--servidor <url>]
//! ```

mod servir;
mod traducao;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use protocolo::{
    Configurado, Erro, MensagemDoDriver, Operacao, Pedido, RespostaDeFatores, Segredo, TipoDeErro,
    VERSAO,
};
use serde_json::{Value, json};

use servir::Servir;

/// Quantos dígitos tem o PIN local que o driver gera (o RemoteID aceita de 4 a 6).
const DIGITOS_DO_PIN: usize = 6;

struct Opcoes {
    estado: PathBuf,
    remoteid: PathBuf,
    servidor: Option<String>,
}

impl Opcoes {
    fn ler(mut args: impl Iterator<Item = OsString>) -> Result<Opcoes, String> {
        let mut estado = None;
        let mut remoteid = None;
        let mut servidor = None;
        while let Some(arg) = args.next() {
            let mut valor = || args.next().ok_or(format!("falta o valor de {arg:?}"));
            match arg.to_str() {
                Some("--estado") => estado = Some(PathBuf::from(valor()?)),
                Some("--remoteid") => remoteid = Some(PathBuf::from(valor()?)),
                Some("--servidor") => servidor = Some(valor()?.to_string_lossy().into_owned()),
                _ => return Err(format!("argumento desconhecido: {arg:?}")),
            }
        }
        Ok(Opcoes {
            estado: estado.ok_or("falta --estado <dir>")?,
            remoteid: remoteid.unwrap_or_else(remoteid_vizinho),
            servidor,
        })
    }
}

/// O `remoteid` na mesma pasta deste executável; senão, o do PATH.
fn remoteid_vizinho() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join("remoteid")))
        .filter(|caminho| caminho.is_file())
        .unwrap_or_else(|| PathBuf::from("remoteid"))
}

fn main() -> ExitCode {
    if let Err(e) = memoria::endurecer_processo() {
        eprintln!("remoteid: não deu para proteger o processo: {e}");
        return ExitCode::FAILURE;
    }
    let opcoes = match Opcoes::ler(std::env::args_os().skip(1)) {
        Ok(opcoes) => opcoes,
        Err(mensagem) => {
            eprintln!("remoteid: {mensagem}");
            return ExitCode::from(2);
        }
    };
    let servir = match Servir::subir(&opcoes.remoteid, &opcoes.estado, opcoes.servidor.as_deref()) {
        Ok(servir) => servir,
        Err(e) => {
            eprintln!("remoteid: não subiu {:?}: {e}", opcoes.remoteid);
            return ExitCode::FAILURE;
        }
    };
    let mut driver = Driver {
        servir,
        entrada: io::stdin().lock(),
        saida: io::stdout().lock(),
    };
    match driver.atender() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("remoteid: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Driver<E, S> {
    servir: Servir,
    entrada: E,
    saida: S,
}

impl<E: BufRead, S: Write> Driver<E, S> {
    /// Atende até o servidor fechar o stdin.
    fn atender(&mut self) -> io::Result<()> {
        while let Some(linha) = self.ler_linha()? {
            let mensagem = match serde_json::from_str::<Pedido>(&linha) {
                Err(e) => MensagemDoDriver::Falha {
                    id: id_de(&linha),
                    erro: Erro {
                        tipo: TipoDeErro::PedidoInvalido,
                        mensagem: e.to_string(),
                    },
                },
                Ok(Pedido { id, operacao }) => match self.executar(id, operacao)? {
                    Ok(ok) => MensagemDoDriver::Resultado { id, ok },
                    Err(erro) => MensagemDoDriver::Falha { id, erro },
                },
            };
            self.escrever(&mensagem)?;
        }
        Ok(())
    }

    fn executar(&mut self, id: u64, operacao: Operacao) -> io::Result<Result<Value, Erro>> {
        match operacao {
            Operacao::Apresentar { versao } if versao != VERSAO => Ok(Err(Erro {
                tipo: TipoDeErro::VersaoIncompativel,
                mensagem: format!("este driver fala o contrato v{VERSAO}"),
            })),
            Operacao::Apresentar { .. } => Ok(Ok(json!(traducao::apresentacao()))),
            Operacao::Configurar { valores } => self.configurar(id, &valores),
            Operacao::Listar => Ok(self
                .conversar(id, json!({"id": id, "op": "estado"}))?
                .and_then(|visao| traducao::chaves(&visao))
                .map(|chaves| json!({ "chaves": chaves }))),
            Operacao::Assinar {
                chave,
                mecanismo,
                dados,
            } => {
                let entrada = match traducao::entrada(mecanismo, &dados) {
                    Ok(entrada) => entrada,
                    Err(erro) => return Ok(Err(erro)),
                };
                let pedido = traducao::assinar(id, &chave, entrada);
                Ok(self.conversar(id, pedido)?.and_then(|ok| {
                    let assinatura = ok["assinatura"]
                        .as_str()
                        .and_then(|b64| STANDARD.decode(b64).ok())
                        .ok_or_else(|| Erro {
                            tipo: TipoDeErro::Outro,
                            mensagem: "o remoteid não devolveu a assinatura".into(),
                        })?;
                    Ok(json!({ "assinatura": STANDARD.encode(assinatura) }))
                }))
            }
        }
    }

    /// Entra na conta com um PIN local novo, que volta para o servidor guardar.
    fn configurar(
        &mut self,
        id: u64,
        valores: &BTreeMap<String, Segredo>,
    ) -> io::Result<Result<Value, Erro>> {
        let (Some(email), Some(senha)) = (valores.get("email"), valores.get("senha")) else {
            return Ok(Err(Erro {
                tipo: TipoDeErro::PedidoInvalido,
                mensagem: "o RemoteID precisa de email e senha".into(),
            }));
        };
        let pin = gerar_pin()?;
        let pedido = json!({"id": id, "op": "entrar", "email": email.expor(),
                            "senha": senha.expor(), "pin": pin.expor()});
        Ok(self.conversar(id, pedido)?.map(|_| {
            json!(Configurado {
                guardar: BTreeMap::from([("pin".to_string(), pin)]),
            })
        }))
    }

    /// Manda um pedido ao `servir` e repassa ao servidor os fatores que ele
    /// pedir, até a resposta.
    fn conversar(&mut self, id: u64, pedido: Value) -> io::Result<Result<Value, Erro>> {
        self.servir.enviar(&pedido)?;
        loop {
            let mensagem = self.servir.receber()?;
            if mensagem["id"] != json!(id) {
                return Ok(Err(Erro {
                    tipo: TipoDeErro::Outro,
                    mensagem: "o remoteid respondeu outro pedido".into(),
                }));
            }
            if let Some(ok) = mensagem.get("ok") {
                return Ok(Ok(ok.clone()));
            }
            if let Some(erro) = mensagem.get("erro") {
                return Ok(Err(traducao::erro(
                    erro["tipo"].as_str().unwrap_or_default(),
                    erro["mensagem"].as_str().unwrap_or_default(),
                )));
            }
            let pedir = traducao::pedido(&mensagem["pedir"]);
            self.escrever(&MensagemDoDriver::Pedir { id, pedir })?;
            let resposta = match self.ler_linha()? {
                Some(linha) => serde_json::from_str::<RespostaDeFatores>(&linha).ok(),
                None => None,
            };
            let para_o_servir = match resposta {
                Some(RespostaDeFatores::Fatores { id: i, fatores }) if i == id => {
                    traducao::fatores(id, &fatores)
                }
                // Desistência, ou uma resposta fora do contrato: o `servir`
                // desiste da assinatura e responde `cancelado`.
                _ => json!({"id": id, "cancelar": true}),
            };
            self.servir.enviar(&para_o_servir)?;
        }
    }

    fn ler_linha(&mut self) -> io::Result<Option<String>> {
        loop {
            let mut linha = String::new();
            if protocolo::ler_linha(&mut self.entrada, &mut linha)? == 0 {
                return Ok(None);
            }
            if !linha.trim().is_empty() {
                return Ok(Some(linha));
            }
        }
    }

    fn escrever(&mut self, mensagem: &MensagemDoDriver) -> io::Result<()> {
        serde_json::to_writer(&mut self.saida, mensagem)?;
        self.saida.write_all(b"\n")?;
        self.saida.flush()
    }
}

/// O `id` de uma linha que não é um pedido válido, para a falha voltar a ele.
fn id_de(linha: &str) -> u64 {
    serde_json::from_str::<Value>(linha)
        .ok()
        .and_then(|v| v["id"].as_u64())
        .unwrap_or(0)
}

fn gerar_pin() -> io::Result<Segredo> {
    // 250 é o maior múltiplo de 10 que cabe num byte: os bytes acima dele são
    // descartados para todo dígito ter a mesma chance.
    const SEM_VIES: u8 = 250;
    let mut digitos = String::with_capacity(DIGITOS_DO_PIN);
    while digitos.len() < DIGITOS_DO_PIN {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(io::Error::other)?;
        let faltam = DIGITOS_DO_PIN - digitos.len();
        digitos.extend(
            bytes
                .iter()
                .filter(|&&b| b < SEM_VIES)
                .map(|b| char::from(b'0' + b % 10))
                .take(faltam),
        );
    }
    Ok(Segredo::novo(digitos))
}
