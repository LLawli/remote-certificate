//! Um token configurado no servidor: o driver, os fatores guardados e se o
//! cofre ainda vale.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use protocolo::{Chave, Mecanismo, Segredo};

use crate::banco::{Banco, FalhaDoBanco, IdDoToken};
use crate::driver::{Conversa, Driver, Falha};
use crate::fatores::{Decisao, Motivo, Pessoa, a_guardar, decidir};

/// O que a guarda tem de um token.
pub struct Guardado {
    pub cofre: BTreeMap<String, Segredo>,
    /// Os fatores guardados que o token recusou, se ele está parado.
    pub desatualizado: Option<Vec<String>>,
}

/// Onde o token guarda o cofre e se está parado. Grava antes de o token
/// responder: um token parado continua parado depois de o servidor reiniciar.
pub trait Guarda {
    fn carregar(&mut self) -> Result<Guardado, FalhaDoBanco>;
    /// O cofre novo, e o token liberado.
    fn configurado(&mut self, cofre: &BTreeMap<String, Segredo>) -> Result<(), FalhaDoBanco>;
    /// O token recusou estes fatores guardados.
    fn desatualizado(&mut self, nomes: &[String]) -> Result<(), FalhaDoBanco>;
}

/// A [`Guarda`] de um token no banco do servidor.
pub struct GuardaNoBanco {
    banco: Arc<Mutex<Banco>>,
    token: IdDoToken,
}

impl GuardaNoBanco {
    pub fn novo(banco: Arc<Mutex<Banco>>, token: IdDoToken) -> GuardaNoBanco {
        GuardaNoBanco { banco, token }
    }

    fn banco(&self) -> std::sync::MutexGuard<'_, Banco> {
        // Um pânico com o banco na mão não deixa transação aberta (o SQLite
        // desfaz a que não terminou), então o banco continua usável.
        self.banco.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Guarda for GuardaNoBanco {
    fn carregar(&mut self) -> Result<Guardado, FalhaDoBanco> {
        let banco = self.banco();
        Ok(Guardado {
            cofre: banco.cofre(self.token)?,
            desatualizado: banco.desatualizado(self.token)?,
        })
    }

    fn configurado(&mut self, cofre: &BTreeMap<String, Segredo>) -> Result<(), FalhaDoBanco> {
        self.banco().configurado(self.token, cofre)
    }

    fn desatualizado(&mut self, nomes: &[String]) -> Result<(), FalhaDoBanco> {
        self.banco().marcar_desatualizado(self.token, nomes)
    }
}

#[derive(Debug)]
pub enum FalhaDoToken {
    Driver(Falha),
    /// O token recusou estes fatores guardados: o token fica parado até ser
    /// configurado de novo.
    Desatualizado(Vec<String>),
    /// O servidor desistiu antes do token decidir.
    Cancelado(Motivo),
    /// O banco não gravou; o token não muda de estado sem gravar.
    Banco(FalhaDoBanco),
}

impl fmt::Display for FalhaDoToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalhaDoToken::Driver(falha) => falha.fmt(f),
            FalhaDoToken::Desatualizado(nomes) => write!(
                f,
                "o token recusou {} guardado no servidor; configure de novo",
                nomes.join(", ")
            ),
            FalhaDoToken::Cancelado(motivo) => write!(f, "cancelado: {motivo:?}"),
            FalhaDoToken::Banco(falha) => falha.fmt(f),
        }
    }
}

impl From<Falha> for FalhaDoToken {
    fn from(falha: Falha) -> FalhaDoToken {
        FalhaDoToken::Driver(falha)
    }
}

impl From<FalhaDoBanco> for FalhaDoToken {
    fn from(falha: FalhaDoBanco) -> FalhaDoToken {
        FalhaDoToken::Banco(falha)
    }
}

pub struct Token<C: Conversa = Driver, G: Guarda = GuardaNoBanco> {
    driver: C,
    guarda: G,
    cofre: BTreeMap<String, Segredo>,
    desatualizado: Option<Vec<String>>,
}

impl<C: Conversa, G: Guarda> Token<C, G> {
    /// O token com o cofre e o estado que a guarda tem.
    pub fn abrir(driver: C, mut guarda: G) -> Result<Token<C, G>, FalhaDoBanco> {
        let Guardado {
            cofre,
            desatualizado,
        } = guarda.carregar()?;
        Ok(Token {
            driver,
            guarda,
            cofre,
            desatualizado,
        })
    }

    pub fn driver(&self) -> &C {
        &self.driver
    }

    /// Prepara o token e troca o cofre pelo que a configuração deixou.
    pub fn configurar(&mut self, valores: BTreeMap<String, Segredo>) -> Result<(), FalhaDoToken> {
        let gerados = self.driver.configurar(valores.clone())?.guardar;
        let cofre = a_guardar(&self.driver.apresentacao().fatores, &valores, gerados);
        self.guarda.configurado(&cofre)?;
        self.cofre = cofre;
        self.desatualizado = None;
        Ok(())
    }

    pub fn listar(&mut self) -> Result<Vec<Chave>, FalhaDoToken> {
        Ok(self.driver.listar()?.chaves)
    }

    pub fn assinar(
        &mut self,
        chave: &str,
        mecanismo: Mecanismo,
        dados: &[u8],
        pessoa: &mut dyn Pessoa,
    ) -> Result<Vec<u8>, FalhaDoToken> {
        if let Some(nomes) = &self.desatualizado {
            return Err(FalhaDoToken::Desatualizado(nomes.clone()));
        }
        let declarados = self.driver.apresentacao().fatores.clone();
        let cofre = &self.cofre;
        let mut motivo = None;
        let resultado = self
            .driver
            .assinar(chave, mecanismo, dados, &mut |pedido| match decidir(
                &declarados,
                pedido,
                cofre,
                pessoa,
            ) {
                Decisao::Responder(fatores) => Some(fatores),
                Decisao::Cancelar(m) => {
                    motivo = Some(m);
                    None
                }
            });
        match (resultado, motivo) {
            (Ok(assinatura), _) => Ok(assinatura),
            (Err(_), Some(Motivo::GuardadoRecusado(nomes))) => {
                // Parado na memória mesmo que o banco falhe: nesta vida do
                // processo o token não recebe outra tentativa.
                self.desatualizado = Some(nomes.clone());
                self.guarda.desatualizado(&nomes)?;
                Err(FalhaDoToken::Desatualizado(nomes))
            }
            (Err(_), Some(motivo)) => Err(FalhaDoToken::Cancelado(motivo)),
            (Err(falha), None) => Err(FalhaDoToken::Driver(falha)),
        }
    }
}

#[cfg(test)]
mod testes {
    use protocolo::{
        Apresentacao, Configurado, Erro, Fator, Listagem, PedidoDeFatores, TipoDeErro, TipoDeFator,
    };

    use super::*;
    use crate::driver::Responder;

    /// Um token físico com PIN: recusa o PIN que não for `certo`.
    struct TokenComPin {
        apresentacao: Apresentacao,
        certo: &'static str,
        tentativas: u32,
    }

    impl TokenComPin {
        fn novo(certo: &'static str) -> Self {
            TokenComPin {
                apresentacao: Apresentacao {
                    driver: "teste".into(),
                    versao: "0".into(),
                    protocolo: protocolo::VERSAO,
                    fatores: vec![Fator {
                        nome: "pin".into(),
                        tipo: TipoDeFator::Guardado,
                        rotulo: "PIN".into(),
                    }],
                    configuracao: Vec::new(),
                },
                certo,
                tentativas: 0,
            }
        }
    }

    impl Conversa for TokenComPin {
        fn apresentacao(&self) -> &Apresentacao {
            &self.apresentacao
        }

        fn configurar(&mut self, _: BTreeMap<String, Segredo>) -> Result<Configurado, Falha> {
            Ok(Configurado {
                guardar: BTreeMap::new(),
            })
        }

        fn listar(&mut self) -> Result<Listagem, Falha> {
            Ok(Listagem { chaves: Vec::new() })
        }

        fn assinar(
            &mut self,
            _: &str,
            _: Mecanismo,
            _: &[u8],
            fatores: &mut Responder<'_>,
        ) -> Result<Vec<u8>, Falha> {
            let mut recusa = None;
            loop {
                let pedido = PedidoDeFatores {
                    fatores: vec!["pin".into()],
                    recusa: recusa.clone(),
                };
                let cancelado = Falha::Driver(Erro {
                    tipo: TipoDeErro::Cancelado,
                    mensagem: "Cancelado".into(),
                });
                let resposta = fatores(&pedido).ok_or(cancelado)?;
                self.tentativas += 1;
                if resposta["pin"].expor() == self.certo {
                    return Ok(vec![1]);
                }
                recusa = Some("PIN incorreto".into());
            }
        }
    }

    /// Uma guarda que só lembra, como o banco faria.
    #[derive(Default)]
    struct EmMemoria {
        cofre: BTreeMap<String, Segredo>,
        desatualizado: Option<Vec<String>>,
    }

    impl Guarda for &mut EmMemoria {
        fn carregar(&mut self) -> Result<Guardado, FalhaDoBanco> {
            Ok(Guardado {
                cofre: self.cofre.clone(),
                desatualizado: self.desatualizado.clone(),
            })
        }

        fn configurado(&mut self, cofre: &BTreeMap<String, Segredo>) -> Result<(), FalhaDoBanco> {
            self.cofre = cofre.clone();
            self.desatualizado = None;
            Ok(())
        }

        fn desatualizado(&mut self, nomes: &[String]) -> Result<(), FalhaDoBanco> {
            self.desatualizado = Some(nomes.to_vec());
            Ok(())
        }
    }

    fn guardado(pin: &str) -> EmMemoria {
        EmMemoria {
            cofre: cofre(pin),
            desatualizado: None,
        }
    }

    struct Ninguem;

    impl Pessoa for Ninguem {
        fn pedir(&mut self, _: &[&Fator], _: Option<&str>) -> Option<BTreeMap<String, Segredo>> {
            None
        }
    }

    fn cofre(pin: &str) -> BTreeMap<String, Segredo> {
        BTreeMap::from([("pin".to_string(), Segredo::novo(pin.into()))])
    }

    #[test]
    fn pin_guardado_certo_assina_sem_perguntar_a_ninguem() {
        let mut guarda = guardado("4321");
        let mut token = Token::abrir(TokenComPin::novo("4321"), &mut guarda).unwrap();
        let assinatura = token.assinar("k", Mecanismo::RsaPkcs, b"x", &mut Ninguem);
        assert_eq!(assinatura.unwrap(), [1]);
    }

    #[test]
    fn pin_guardado_errado_gasta_uma_tentativa_e_para_o_token() {
        let mut guarda = guardado("0000");
        let mut token = Token::abrir(TokenComPin::novo("4321"), &mut guarda).unwrap();

        let falha = token.assinar("k", Mecanismo::RsaPkcs, b"x", &mut Ninguem);
        assert!(matches!(falha, Err(FalhaDoToken::Desatualizado(ref n)) if n == &["pin"]));
        assert_eq!(token.driver().tentativas, 1);

        // Parado: o token físico não recebe nenhuma tentativa a mais.
        let falha = token.assinar("k", Mecanismo::RsaPkcs, b"x", &mut Ninguem);
        assert!(matches!(falha, Err(FalhaDoToken::Desatualizado(_))));
        assert_eq!(token.driver().tentativas, 1);

        // Nem depois de o servidor reiniciar: a guarda lembra.
        drop(token);
        assert_eq!(
            guarda.desatualizado.as_deref(),
            Some(&["pin".to_string()][..])
        );
        let mut token = Token::abrir(TokenComPin::novo("4321"), &mut guarda).unwrap();
        let falha = token.assinar("k", Mecanismo::RsaPkcs, b"x", &mut Ninguem);
        assert!(matches!(falha, Err(FalhaDoToken::Desatualizado(_))));
        assert_eq!(token.driver().tentativas, 0);
    }

    #[test]
    fn configurar_de_novo_libera_o_token() {
        let mut guarda = guardado("0000");
        let mut token = Token::abrir(TokenComPin::novo("4321"), &mut guarda).unwrap();
        assert!(
            token
                .assinar("k", Mecanismo::RsaPkcs, b"x", &mut Ninguem)
                .is_err()
        );
        let valores = cofre("4321");
        token.configurar(valores).unwrap();
        let assinatura = token.assinar("k", Mecanismo::RsaPkcs, b"x", &mut Ninguem);
        assert_eq!(assinatura.unwrap(), [1]);
    }
}
