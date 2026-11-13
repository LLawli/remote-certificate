use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{Mecanismo, Segredo};

/// Um pedido do servidor ao driver. O `id` volta igual na resposta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pedido {
    pub id: u64,
    #[serde(flatten)]
    pub operacao: Operacao,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Operacao {
    /// Primeira mensagem de toda conversa: a versão do contrato que o servidor
    /// fala. O driver responde com uma [`Apresentacao`].
    Apresentar { versao: u32 },
    /// As chaves que o driver enxerga agora (um token físico pode ter saído).
    /// O driver responde com uma [`Listagem`].
    Listar,
    /// Assina `dados` com a chave `chave`. O driver pode pedir fatores no meio
    /// e responde com uma [`Assinatura`].
    Assinar {
        chave: String,
        mecanismo: Mecanismo,
        #[serde(with = "crate::b64")]
        dados: Vec<u8>,
    },
}

/// O que o driver manda: o resultado de um pedido, uma falha, ou um pedido de
/// fatores no meio da operação.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MensagemDoDriver {
    Resultado { id: u64, ok: serde_json::Value },
    Falha { id: u64, erro: Erro },
    Pedir { id: u64, pedir: PedidoDeFatores },
}

/// A resposta do servidor a um [`MensagemDoDriver::Pedir`], no mesmo `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RespostaDeFatores {
    Fatores {
        id: u64,
        fatores: BTreeMap<String, Segredo>,
    },
    Cancelar {
        id: u64,
        cancelar: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Erro {
    pub tipo: TipoDeErro,
    /// Para a pessoa ler; pode trazer o texto do fornecedor do token.
    pub mensagem: String,
}

/// O tipo de uma falha, estável, para o servidor decidir o que fazer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipoDeErro {
    PedidoInvalido,
    VersaoIncompativel,
    /// O token não está acessível: removido, servidor do fornecedor fora.
    TokenAusente,
    ChaveAusente,
    MecanismoNaoSuportado,
    /// O token recusou os fatores. Para um fator guardado, é sinal de que o
    /// segredo no servidor está desatualizado, não de erro de quem pediu.
    FatorRecusado,
    /// O próprio token travou (PIN do token bloqueado).
    Bloqueado,
    Cancelado,
    Rede,
    #[serde(other)]
    Outro,
}

/// Um fator que o driver pode pedir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fator {
    /// Como ele aparece em [`PedidoDeFatores::fatores`], por exemplo `pin`.
    pub nome: String,
    pub tipo: TipoDeFator,
    /// Para mostrar a quem vai digitar, por exemplo "Código do autenticador".
    pub rotulo: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TipoDeFator {
    /// Fica cifrado no servidor e é ele quem responde: o PIN do token, a senha
    /// de uma conta. Quem usa o token nunca o vê.
    Guardado,
    /// Vem da pessoa a cada vez e nunca é guardado: o OTP.
    DaPessoa,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedidoDeFatores {
    pub fatores: Vec<String>,
    /// A mensagem da tentativa anterior, quando o token recusou.
    pub recusa: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Apresentacao {
    /// Nome curto do driver, por exemplo `remoteid`.
    pub driver: String,
    /// Versão do próprio driver.
    pub versao: String,
    /// Versão do contrato que ele fala.
    pub protocolo: u32,
    pub fatores: Vec<Fator>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listagem {
    pub chaves: Vec<Chave>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chave {
    /// Estável enquanto o token existir; é o que [`Operacao::Assinar`] recebe.
    pub id: String,
    pub rotulo: String,
    /// O certificado X.509 em DER.
    #[serde(with = "crate::b64")]
    pub certificado: Vec<u8>,
    pub mecanismos: Vec<Mecanismo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assinatura {
    #[serde(with = "crate::b64")]
    pub assinatura: Vec<u8>,
}

#[cfg(test)]
mod testes {
    use serde_json::json;

    use super::*;

    #[test]
    fn pedido_de_assinatura_no_fio() {
        let pedido = Pedido {
            id: 7,
            operacao: Operacao::Assinar {
                chave: "1234;AC Teste".into(),
                mecanismo: Mecanismo::RsaPkcs,
                dados: vec![1, 2, 3],
            },
        };
        let fio = serde_json::to_value(&pedido).unwrap();
        assert_eq!(
            fio,
            json!({"id": 7, "op": "assinar", "chave": "1234;AC Teste",
                   "mecanismo": "CKM_RSA_PKCS", "dados": "AQID"})
        );
        assert_eq!(serde_json::from_value::<Pedido>(fio).unwrap(), pedido);
    }

    #[test]
    fn operacao_sem_campos() {
        let fio = r#"{"id": 1, "op": "listar"}"#;
        let pedido: Pedido = serde_json::from_str(fio).unwrap();
        assert_eq!(pedido.operacao, Operacao::Listar);
    }

    #[test]
    fn as_tres_mensagens_do_driver_se_distinguem() {
        let ler = |s: &str| serde_json::from_str::<MensagemDoDriver>(s).unwrap();

        assert!(matches!(
            ler(r#"{"id": 1, "ok": null}"#),
            MensagemDoDriver::Resultado { id: 1, .. }
        ));
        assert_eq!(
            ler(r#"{"id": 2, "erro": {"tipo": "cancelado", "mensagem": "Cancelado"}}"#),
            MensagemDoDriver::Falha {
                id: 2,
                erro: Erro {
                    tipo: TipoDeErro::Cancelado,
                    mensagem: "Cancelado".into()
                }
            }
        );
        assert_eq!(
            ler(r#"{"id": 3, "pedir": {"fatores": ["pin", "otp"], "recusa": null}}"#),
            MensagemDoDriver::Pedir {
                id: 3,
                pedir: PedidoDeFatores {
                    fatores: vec!["pin".into(), "otp".into()],
                    recusa: None
                }
            }
        );
    }

    #[test]
    fn tipo_de_erro_novo_vira_outro() {
        let erro: Erro =
            serde_json::from_str(r#"{"tipo": "cota_excedida", "mensagem": "x"}"#).unwrap();
        assert_eq!(erro.tipo, TipoDeErro::Outro);
    }

    #[test]
    fn resposta_de_fatores_nao_vaza_em_debug() {
        let resposta: RespostaDeFatores =
            serde_json::from_str(r#"{"id": 3, "fatores": {"pin": "1234", "otp": "987654"}}"#)
                .unwrap();
        let texto = format!("{resposta:?}");
        assert!(!texto.contains("1234"), "{texto}");
        assert!(!texto.contains("987654"), "{texto}");

        let cancelar: RespostaDeFatores =
            serde_json::from_str(r#"{"id": 3, "cancelar": true}"#).unwrap();
        assert_eq!(
            cancelar,
            RespostaDeFatores::Cancelar {
                id: 3,
                cancelar: true
            }
        );
    }

    #[test]
    fn apresentacao_declara_os_fatores() {
        let fio = json!({
            "driver": "remoteid", "versao": "0.5.0", "protocolo": 0,
            "fatores": [
                {"nome": "pin", "tipo": "guardado", "rotulo": "PIN do certificado"},
                {"nome": "otp", "tipo": "da_pessoa", "rotulo": "Código do autenticador"}
            ]
        });
        let apresentacao: Apresentacao = serde_json::from_value(fio).unwrap();
        assert_eq!(apresentacao.fatores[1].tipo, TipoDeFator::DaPessoa);
    }
}
