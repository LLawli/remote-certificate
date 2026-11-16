//! A conversa com o servidor pelo contrato (`docs/drivers.md`): JSON por
//! linha no stdin e no stdout, um pedido por vez.

use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

use protocolo::{
    Apresentacao, Assinatura, Campo, Configurado, Erro, Fator, LINHA_MAXIMA, Listagem,
    MensagemDoDriver, Operacao, Pedido, PedidoDeFatores, RespostaDeFatores, Segredo, TipoDeErro,
    TipoDeFator, VERSAO, ler_linha,
};
use serde::Serialize;

use crate::erro::erro;
use crate::estado::{Configuracao, Estado};
use crate::token::Token;

/// O único fator: o PIN do token, que o servidor guarda e responde sozinho.
pub const PIN: &str = "pin";
/// Campo do `configurar`: a série do token, para escolher entre vários
/// conectados no mesmo servidor. Vazio, vale o único conectado.
pub const SERIE: &str = "serie";

pub fn apresentacao() -> Apresentacao {
    Apresentacao {
        driver: "gd-burti".into(),
        versao: env!("CARGO_PKG_VERSION").into(),
        protocolo: VERSAO,
        fatores: vec![Fator {
            nome: PIN.into(),
            tipo: TipoDeFator::Guardado,
            rotulo: "PIN do token".into(),
        }],
        configuracao: vec![
            Campo {
                nome: SERIE.into(),
                rotulo: "Número de série do token".into(),
                secreto: false,
            },
            Campo {
                nome: PIN.into(),
                rotulo: "PIN do token".into(),
                secreto: true,
            },
        ],
    }
}

pub struct Driver<T> {
    token: T,
    estado: Estado,
    apresentado: bool,
}

impl<T: Token> Driver<T> {
    pub fn novo(token: T, estado: Estado) -> Self {
        Self {
            token,
            estado,
            apresentado: false,
        }
    }

    /// Atende pedidos até o stdin fechar.
    pub fn conversar(
        &mut self,
        entrada: &mut impl BufRead,
        saida: &mut impl Write,
    ) -> io::Result<()> {
        let mut linha = String::new();
        loop {
            linha.clear();
            if ler_linha(entrada, &mut linha)? == 0 {
                return Ok(());
            }
            if linha.trim().is_empty() {
                continue;
            }
            self.atender(&linha, entrada, saida)?;
        }
    }

    fn atender(
        &mut self,
        linha: &str,
        entrada: &mut impl BufRead,
        saida: &mut impl Write,
    ) -> io::Result<()> {
        let pedido = match serde_json::from_str::<Pedido>(linha) {
            Ok(pedido) => pedido,
            Err(e) => {
                // Uma operação nova, de um servidor mais novo, ainda traz o
                // `id`: a resposta volta nele.
                let id = serde_json::from_str::<serde_json::Value>(linha)
                    .ok()
                    .and_then(|v| v.get("id").and_then(|id| id.as_u64()))
                    .unwrap_or(0);
                let falha = erro(TipoDeErro::PedidoInvalido, format!("Pedido inválido: {e}"));
                return escrever(saida, &MensagemDoDriver::Falha { id, erro: falha });
            }
        };
        let id = pedido.id;
        let resultado = match pedido.operacao {
            Operacao::Apresentar { versao } => {
                self.apresentado = true;
                eprintln!("gd-burti: apresentação, servidor no contrato v{versao}");
                valor(&apresentacao())
            }
            _ if !self.apresentado => Err(erro(
                TipoDeErro::PedidoInvalido,
                "A conversa começa pela apresentação",
            )),
            Operacao::Configurar { valores } => self.configurar(valores),
            Operacao::Listar => self.listar(),
            Operacao::Assinar {
                chave,
                mecanismo,
                dados,
            } => self.assinar(id, &chave, mecanismo, &dados, entrada, saida)?,
        };
        let mensagem = match resultado {
            Ok(ok) => MensagemDoDriver::Resultado { id, ok },
            Err(falha) => {
                eprintln!(
                    "gd-burti: pedido {id}: {:?}: {}",
                    falha.tipo, falha.mensagem
                );
                MensagemDoDriver::Falha { id, erro: falha }
            }
        };
        escrever(saida, &mensagem)
    }

    fn serie(&self) -> Result<String, Erro> {
        match self.estado.ler() {
            Ok(Some(configuracao)) => Ok(configuracao.serie),
            Ok(None) => Err(erro(
                TipoDeErro::NaoConfigurado,
                "O token GD Burti ainda não foi configurado",
            )),
            Err(e) => Err(erro(
                TipoDeErro::Outro,
                format!(
                    "Não deu para ler a configuração em {}: {e}",
                    self.estado.diretorio().display()
                ),
            )),
        }
    }

    fn configurar(
        &mut self,
        valores: BTreeMap<String, Segredo>,
    ) -> Result<serde_json::Value, Erro> {
        let pin = valores
            .get(PIN)
            .filter(|pin| !pin.expor().is_empty())
            .ok_or_else(|| erro(TipoDeErro::PedidoInvalido, "Falta o PIN do token"))?;
        let serie = valores
            .get(SERIE)
            .map(|s| s.expor().trim())
            .filter(|s| !s.is_empty());
        let serie = self.token.configurar(serie, pin)?;
        self.estado
            .gravar(&Configuracao {
                serie: serie.clone(),
            })
            .map_err(|e| {
                erro(
                    TipoDeErro::Outro,
                    format!("Não deu para gravar a configuração: {e}"),
                )
            })?;
        eprintln!("gd-burti: configurado com o token de série {serie}");
        // O PIN volta para o servidor pelo próprio campo `pin`, que tem o nome
        // do fator guardado: não há nada que o driver gere.
        valor(&Configurado {
            guardar: BTreeMap::new(),
        })
    }

    fn listar(&mut self) -> Result<serde_json::Value, Erro> {
        let serie = self.serie()?;
        let chaves = self.token.listar(&serie)?;
        valor(&Listagem { chaves })
    }

    /// Confere o que dá sem o PIN, pede o PIN ao servidor e assina. Um PIN
    /// recusado volta como `fator_recusado`, sem pedir de novo: o token nunca
    /// recebe a mesma tentativa errada duas vezes.
    fn assinar(
        &mut self,
        id: u64,
        chave: &str,
        mecanismo: protocolo::Mecanismo,
        dados: &[u8],
        entrada: &mut impl BufRead,
        saida: &mut impl Write,
    ) -> io::Result<Result<serde_json::Value, Erro>> {
        let serie = match self.serie() {
            Ok(serie) => serie,
            Err(falha) => return Ok(Err(falha)),
        };
        if let Err(falha) = self.token.conferir(&serie, chave, mecanismo, dados) {
            return Ok(Err(falha));
        }
        let pin = match pedir_pin(id, entrada, saida)? {
            Ok(pin) => pin,
            Err(falha) => return Ok(Err(falha)),
        };
        eprintln!(
            "gd-burti: assinando {} bytes com a chave {chave}, {mecanismo:?}",
            dados.len()
        );
        Ok(self
            .token
            .assinar(&serie, chave, mecanismo, dados, &pin)
            .and_then(|assinatura| valor(&Assinatura { assinatura })))
    }
}

/// Pede o PIN no mesmo `id` e espera a resposta do servidor.
fn pedir_pin(
    id: u64,
    entrada: &mut impl BufRead,
    saida: &mut impl Write,
) -> io::Result<Result<Segredo, Erro>> {
    escrever(
        saida,
        &MensagemDoDriver::Pedir {
            id,
            pedir: PedidoDeFatores {
                fatores: vec![PIN.into()],
                recusa: None,
            },
        },
    )?;
    let mut linha = String::new();
    if ler_linha(entrada, &mut linha)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "o servidor fechou a conversa no meio do pedido do PIN",
        ));
    }
    let invalida = |motivo: &str| {
        Ok(Err(erro(
            TipoDeErro::PedidoInvalido,
            format!("Resposta ao pedido do PIN inválida: {motivo}"),
        )))
    };
    // A mensagem do serde não entra: ela pode citar o trecho da linha, que
    // traz o PIN.
    let Ok(resposta) = serde_json::from_str::<RespostaDeFatores>(&linha) else {
        return invalida("não é uma resposta de fatores");
    };
    match resposta {
        RespostaDeFatores::Cancelar { id: outro, .. } if outro != id => invalida("outro id"),
        RespostaDeFatores::Fatores { id: outro, .. } if outro != id => invalida("outro id"),
        RespostaDeFatores::Cancelar { .. } => {
            Ok(Err(erro(TipoDeErro::Cancelado, "O servidor cancelou")))
        }
        RespostaDeFatores::Fatores { mut fatores, .. } => match fatores.remove(PIN) {
            Some(pin) => Ok(Ok(pin)),
            None => invalida("sem o PIN"),
        },
    }
}

fn valor(resultado: &impl Serialize) -> Result<serde_json::Value, Erro> {
    serde_json::to_value(resultado).map_err(|e| erro(TipoDeErro::Outro, e.to_string()))
}

/// Uma mensagem por linha. Uma resposta que passaria do limite do contrato
/// vira uma falha, que cabe.
fn escrever(saida: &mut impl Write, mensagem: &MensagemDoDriver) -> io::Result<()> {
    let mut linha = serde_json::to_vec(mensagem).map_err(io::Error::other)?;
    if linha.len() >= LINHA_MAXIMA {
        let id = match mensagem {
            MensagemDoDriver::Resultado { id, .. }
            | MensagemDoDriver::Falha { id, .. }
            | MensagemDoDriver::Pedir { id, .. } => *id,
        };
        let falha = MensagemDoDriver::Falha {
            id,
            erro: erro(
                TipoDeErro::Outro,
                "A resposta passaria do limite de uma linha do contrato",
            ),
        };
        linha = serde_json::to_vec(&falha).map_err(io::Error::other)?;
    }
    linha.push(b'\n');
    saida.write_all(&linha)?;
    saida.flush()
}

#[cfg(test)]
mod testes {
    use std::cell::RefCell;
    use std::rc::Rc;

    use protocolo::{Chave, Mecanismo};
    use serde_json::{Value, json};

    use super::*;

    /// Um token falso que registra cada PIN que chegou a ele.
    #[derive(Default, Clone)]
    struct Falso {
        pin_certo: String,
        travado: bool,
        tentativas: Rc<RefCell<Vec<String>>>,
    }

    impl Falso {
        fn tentar(&self, pin: &Segredo) -> Result<(), Erro> {
            if self.travado {
                return Err(erro(TipoDeErro::Bloqueado, "travado"));
            }
            self.tentativas.borrow_mut().push(pin.expor().to_owned());
            if pin.expor() == self.pin_certo {
                Ok(())
            } else {
                Err(erro(TipoDeErro::FatorRecusado, "PIN incorreto"))
            }
        }
    }

    impl Token for Falso {
        fn configurar(&mut self, serie: Option<&str>, pin: &Segredo) -> Result<String, Erro> {
            self.tentar(pin)?;
            Ok(serie.unwrap_or("0011223344556677").to_owned())
        }
        fn listar(&mut self, _serie: &str) -> Result<Vec<Chave>, Erro> {
            Ok(vec![Chave {
                id: "f1".into(),
                rotulo: "Titular".into(),
                certificado: vec![0x30],
                mecanismos: vec![Mecanismo::RsaPkcs],
            }])
        }
        fn conferir(&mut self, _: &str, chave: &str, _: Mecanismo, _: &[u8]) -> Result<(), Erro> {
            if self.travado {
                return Err(erro(TipoDeErro::Bloqueado, "travado"));
            }
            if chave != "f1" {
                return Err(erro(TipoDeErro::ChaveAusente, "não há"));
            }
            Ok(())
        }
        fn assinar(
            &mut self,
            _: &str,
            _: &str,
            _: Mecanismo,
            _: &[u8],
            pin: &Segredo,
        ) -> Result<Vec<u8>, Erro> {
            self.tentar(pin)?;
            Ok(vec![0xAA])
        }
    }

    fn diretorio(nome: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("gd-burti-conversa-{nome}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Roda a conversa com as linhas dadas e devolve as respostas.
    fn conversar(token: Falso, nome: &str, linhas: &[Value]) -> Vec<Value> {
        let dir = diretorio(nome);
        let mut entrada = String::new();
        for linha in linhas {
            entrada.push_str(&linha.to_string());
            entrada.push('\n');
        }
        let mut saida = Vec::new();
        Driver::novo(token, Estado::em(&dir))
            .conversar(&mut entrada.as_bytes(), &mut saida)
            .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        String::from_utf8(saida)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn falso() -> Falso {
        Falso {
            pin_certo: "1234".into(),
            ..Falso::default()
        }
    }

    fn apresentar() -> Value {
        json!({"id": 1, "op": "apresentar", "versao": 0})
    }

    fn configurar(pin: &str) -> Value {
        json!({"id": 2, "op": "configurar", "valores": {"serie": "", "pin": pin}})
    }

    fn assinar(id: u64) -> Value {
        json!({"id": id, "op": "assinar", "chave": "f1", "mecanismo": "CKM_RSA_PKCS", "dados": "AQID"})
    }

    #[test]
    fn declara_so_o_pin_guardado() {
        let a = apresentacao();
        assert_eq!(a.fatores.len(), 1);
        assert_eq!(a.fatores[0].nome, PIN);
        assert_eq!(a.fatores[0].tipo, TipoDeFator::Guardado);
        let pin = a.configuracao.iter().find(|c| c.nome == PIN).unwrap();
        assert!(pin.secreto, "o PIN não aparece ao ser digitado");
    }

    #[test]
    fn sem_apresentacao_nada_feito() {
        let respostas = conversar(
            falso(),
            "sem-apresentacao",
            &[json!({"id": 1, "op": "listar"})],
        );
        assert_eq!(respostas[0]["erro"]["tipo"], "pedido_invalido");
    }

    #[test]
    fn sem_configurar_e_nao_configurado() {
        let respostas = conversar(
            falso(),
            "nao-configurado",
            &[apresentar(), json!({"id": 2, "op": "listar"})],
        );
        assert_eq!(respostas[1]["erro"]["tipo"], "nao_configurado");
    }

    #[test]
    fn operacao_nova_volta_no_mesmo_id() {
        let respostas = conversar(
            falso(),
            "operacao-nova",
            &[apresentar(), json!({"id": 9, "op": "trocar_pin"})],
        );
        assert_eq!(respostas[1]["id"], 9);
        assert_eq!(respostas[1]["erro"]["tipo"], "pedido_invalido");
    }

    #[test]
    fn assina_pedindo_o_pin_no_mesmo_id() {
        let token = falso();
        let tentativas = token.tentativas.clone();
        let respostas = conversar(
            token,
            "assina",
            &[
                apresentar(),
                configurar("1234"),
                assinar(3),
                json!({"id": 3, "fatores": {"pin": "1234"}}),
            ],
        );
        assert_eq!(respostas[1]["ok"], json!({"guardar": {}}));
        assert_eq!(
            respostas[2],
            json!({"id": 3, "pedir": {"fatores": ["pin"], "recusa": null}})
        );
        assert_eq!(respostas[3], json!({"id": 3, "ok": {"assinatura": "qg=="}}));
        assert_eq!(*tentativas.borrow(), ["1234", "1234"]);
    }

    #[test]
    fn pin_recusado_nao_e_pedido_de_novo() {
        let token = falso();
        let tentativas = token.tentativas.clone();
        let respostas = conversar(
            token,
            "pin-recusado",
            &[
                apresentar(),
                configurar("1234"),
                assinar(3),
                json!({"id": 3, "fatores": {"pin": "9999"}}),
            ],
        );
        // Depois do pedido, a falha, e nenhum outro pedido de PIN.
        assert!(respostas[2].get("pedir").is_some());
        assert_eq!(respostas[3]["erro"]["tipo"], "fator_recusado");
        assert_eq!(respostas.len(), 4);
        assert_eq!(*tentativas.borrow(), ["1234", "9999"]);
    }

    #[test]
    fn token_travado_nao_pede_o_pin() {
        let token = falso();
        let dir = diretorio("travado");
        Estado::em(&dir)
            .gravar(&Configuracao {
                serie: "0011223344556677".into(),
            })
            .unwrap();
        let tentativas = token.tentativas.clone();
        let entrada = format!("{}\n{}\n", apresentar(), assinar(3));
        let mut saida = Vec::new();
        Driver::novo(
            Falso {
                travado: true,
                ..token
            },
            Estado::em(&dir),
        )
        .conversar(&mut entrada.as_bytes(), &mut saida)
        .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        let respostas: Vec<Value> = String::from_utf8(saida)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(respostas.len(), 2);
        assert_eq!(respostas[1]["erro"]["tipo"], "bloqueado");
        assert!(tentativas.borrow().is_empty());
    }

    #[test]
    fn cancelar_e_cancelado() {
        let respostas = conversar(
            falso(),
            "cancelar",
            &[
                apresentar(),
                configurar("1234"),
                assinar(3),
                json!({"id": 3, "cancelar": true}),
            ],
        );
        assert_eq!(respostas[3]["erro"]["tipo"], "cancelado");
    }

    #[test]
    fn chave_ausente_nao_pede_o_pin() {
        let respostas = conversar(
            falso(),
            "chave-ausente",
            &[
                apresentar(),
                configurar("1234"),
                json!({"id": 3, "op": "assinar", "chave": "ff", "mecanismo": "CKM_RSA_PKCS", "dados": "AQID"}),
            ],
        );
        assert_eq!(respostas.len(), 3);
        assert_eq!(respostas[2]["erro"]["tipo"], "chave_ausente");
    }

    #[test]
    fn o_pin_nao_aparece_na_resposta_invalida() {
        // Uma resposta torta ao pedido do PIN: a falha não pode citar a linha.
        let respostas = conversar(
            falso(),
            "resposta-torta",
            &[
                apresentar(),
                configurar("1234"),
                assinar(3),
                json!({"id": 3, "fatores": {"pin": 5678}}),
            ],
        );
        assert_eq!(respostas[3]["erro"]["tipo"], "pedido_invalido");
        assert!(
            !respostas[3].to_string().contains("5678"),
            "{}",
            respostas[3]
        );
    }

    #[test]
    fn configurar_com_pin_recusado_nao_grava() {
        let dir = diretorio("configurar-recusado");
        let entrada = format!("{}\n{}\n", apresentar(), configurar("0000"));
        let mut saida = Vec::new();
        Driver::novo(falso(), Estado::em(&dir))
            .conversar(&mut entrada.as_bytes(), &mut saida)
            .unwrap();
        assert_eq!(Estado::em(&dir).ler().unwrap(), None);
        std::fs::remove_dir_all(dir).unwrap();
        assert!(String::from_utf8(saida).unwrap().contains("fator_recusado"));
    }
}
